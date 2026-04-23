#!/usr/bin/env python3
"""
snmp-modulator server — FastAPI probe trigger + Prometheus metrics.

Endpoints:
  GET/POST /probe?host=<ip_or_fqdn>          Probe a single device by IP or name
  GET/POST /probe/netbox?<filter_params>     Probe devices matching any NetBox filter
  GET      /metrics                          Prometheus metrics
  GET      /health                           Liveness check
  GET      /docs                             Swagger UI (auto-generated)

/probe/netbox passes query parameters directly to pynetbox's dcim.devices.filter(),
so any NetBox API filter is valid:
  /probe/netbox?role_id=4&last_updated__lt=2025-10-01
  /probe/netbox?site=dc1&tag=snmp-ready
  /probe/netbox?manufacturer=cisco
"""

import logging
import os
import threading
import time
from typing import Annotated, Optional

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.multiprocess import MultiProcessCollector

from modulator import AUTH_POLICIES, Callbacks, MappingEngine, Modulator, NetboxClient, SnmpExporterClient

# ── Logging ───────────────────────────────────────────────────────────────────

_LOG_FMT  = "%(asctime)s %(levelname)1.1s %(name)-24s %(message)s"
_LOG_DATE = "%Y-%m-%dT%H:%M:%S"

logging.basicConfig(level=logging.INFO, format=_LOG_FMT, datefmt=_LOG_DATE)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logger = logging.getLogger("snmp-modulator.server")

logging.getLogger("uvicorn.error").name = "uvicorn"
logging.getLogger("uvicorn.access").propagate = False

_UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"modulator": {"format": _LOG_FMT, "datefmt": _LOG_DATE}},
    "handlers":   {"default":  {"class": "logging.StreamHandler", "formatter": "modulator"}},
    "loggers": {
        "uvicorn":        {"handlers": ["default"], "level": "INFO",    "propagate": False},
        "uvicorn.error":  {"handlers": ["default"], "level": "INFO",    "propagate": False},
        "uvicorn.access": {"handlers": [],          "level": "WARNING", "propagate": False},
    },
}

# ── Prometheus metrics ────────────────────────────────────────────────────────

_MULTIPROC_DIR = os.environ.get("PROMETHEUS_MULTIPROC_DIR", "")
if _MULTIPROC_DIR:
    os.makedirs(_MULTIPROC_DIR, exist_ok=True)

_custom_registry = CollectorRegistry()
_reg = {"registry": _custom_registry}

devices_processed_total = Counter(
    "modulator_devices_processed_total",
    "Total devices processed",
    ["result"],   # success | error
    **_reg,
)
module_tests_total = Counter(
    "modulator_module_tests_total",
    "SNMP module probe outcomes",
    ["module", "result"],   # result: useful | empty | error
    **_reg,
)
module_test_duration = Histogram(
    "modulator_module_test_duration_seconds",
    "Duration of individual SNMP module probes",
    ["module"],
    buckets=[1, 5, 10, 30, 60, 120],
    **_reg,
)
netbox_updates_total = Counter(
    "modulator_netbox_updates_total",
    "NetBox snmp_exporter_module field update outcomes",
    ["action"],   # changed | unchanged
    **_reg,
)
auth_probe_results_total = Counter(
    "modulator_auth_probe_results_total",
    "Auth profile probe outcomes",
    ["result"],   # resolved | failed | skipped
    **_reg,
)
probe_duration = Histogram(
    "modulator_probe_duration_seconds",
    "Total duration of a /probe or /probe/netbox call",
    buckets=[5, 30, 60, 120, 300, 600, 1800],
    **_reg,
)
probe_in_progress = Gauge(
    "modulator_probe_in_progress",
    "Number of probe jobs currently executing",
    multiprocess_mode="livesum",
    **_reg,
)


class _ServerCallbacks(Callbacks):
    def module_test(self, module: str, result: str) -> None:
        module_tests_total.labels(module=module, result=result).inc()

    def module_test_duration(self, module: str, duration: float) -> None:
        module_test_duration.labels(module=module).observe(duration)

    def netbox_update(self, action: str) -> None:
        netbox_updates_total.labels(action=action).inc()

    def device_processed(self, result: str) -> None:
        devices_processed_total.labels(result=result).inc()

    def auth_probed(self, result: str) -> None:
        auth_probe_results_total.labels(result=result).inc()


# ── Config ────────────────────────────────────────────────────────────────────

def _flag(env: str, default: bool = False) -> bool:
    raw = os.getenv(env, "")
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes")


_AUTH_TOKEN:     Optional[str] = os.getenv("MODULATOR_AUTH_TOKEN")
_METRICS_PATH:   str           = os.getenv("MODULATOR_METRICS_PATH", "/metrics")
_DRY_RUN:       bool = _flag("MODULATOR_DRY_RUN")
_MAPPING_FILE:  str  = os.getenv("MAPPING_FILE", "mapping.yaml")
_MAX_CONCURRENT: int           = int(os.getenv("MODULATOR_MAX_CONCURRENT_RUNS", "1"))

# ── Auth ──────────────────────────────────────────────────────────────────────

async def require_auth(authorization: Annotated[str, Header()] = "") -> None:
    """Bearer token auth. Disabled when MODULATOR_AUTH_TOKEN is not set."""
    if not _AUTH_TOKEN:
        return
    if authorization != f"Bearer {_AUTH_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="snmp-modulator",
    description="Probe NetBox devices against snmp-exporter and update snmp_exporter_module",
    version="1.0.0",
)

# Active probe job keys — prevents duplicate concurrent probes for the same target
_in_flight: set = set()
_in_flight_lock = threading.Lock()

_probe_semaphore = threading.Semaphore(_MAX_CONCURRENT)


def _make_clients():
    engine = MappingEngine(_MAPPING_FILE)

    module_policy = engine.module_policy

    nb = NetboxClient(
        url=os.environ["NETBOX_URL"],
        token=os.environ["NETBOX_TOKEN"],
        verify_tls=os.getenv("NETBOX_TLS_VERIFY", "true").lower() != "false",
        module_field=engine.module_field,
        auth_field=engine.auth_field,
        interval_field=engine.interval_field,
        timeout_field=engine.timeout_field,
        scrape_site_field=engine.scrape_site_field,
    )
    verify_tls = os.getenv("SNMP_EXPORTER_TLS_VERIFY", "true").lower() != "false"
    timeout    = int(os.getenv("SNMP_EXPORTER_TIMEOUT", "30"))
    snmp       = SnmpExporterClient(
        base_url=os.environ["SNMP_EXPORTER_URL"],
        verify_tls=verify_tls,
        timeout=timeout,
    )
    return nb, snmp, engine, module_policy


def _run_probe(job_key: str, devices_fn) -> None:
    """Execute a probe job in a background thread."""
    _probe_semaphore.acquire()
    probe_in_progress.inc()
    start = time.time()
    try:
        nb, snmp, engine, module_policy = _make_clients()
        mod = Modulator(nb, snmp, engine, dry_run=_DRY_RUN, module_policy=module_policy)
        devices = devices_fn(nb)
        mod.run(devices, callbacks=_ServerCallbacks())
    except Exception as exc:
        logger.error("Probe job %r failed: %s", job_key, exc, exc_info=True)
    finally:
        probe_in_progress.dec()
        probe_duration.observe(time.time() - start)
        _probe_semaphore.release()
        with _in_flight_lock:
            _in_flight.discard(job_key)
        logger.info("Probe job %r finished in %.1fs", job_key, time.time() - start)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.api_route(
    "/probe",
    methods=["GET", "POST"],
    status_code=202,
    dependencies=[Depends(require_auth)],
    summary="Probe a single device by IP or name",
)
async def probe_host(
    background_tasks: BackgroundTasks,
    host: Annotated[Optional[str], Query(description="Device IP or name")] = None,
) -> dict:
    """
    Trigger a probe for one device.  `host` can be an IP address or device name.
    Returns immediately (202); probe runs in the background.
    """
    if not host:
        raise HTTPException(status_code=400, detail="host parameter required")

    job_key = f"host:{host}"
    with _in_flight_lock:
        if job_key in _in_flight:
            return {"status": "skipped", "host": host, "reason": "already in progress"}
        _in_flight.add(job_key)

    def fetch(nb: NetboxClient):
        device = nb.get_device_by_host(host)
        if not device:
            logger.warning("Host %r not found in NetBox or ineligible", host)
            return []
        return [device]

    background_tasks.add_task(_run_probe, job_key, fetch)
    logger.info("Probe queued for host %r", host)
    return {"status": "queued", "host": host}


@app.api_route(
    "/probe/netbox",
    methods=["GET", "POST"],
    status_code=202,
    dependencies=[Depends(require_auth)],
    summary="Probe devices matching a NetBox filter",
)
async def probe_netbox(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Trigger a probe for all devices matching an arbitrary NetBox filter.

    All query parameters are forwarded directly to `dcim.devices.filter()`:

        /probe/netbox?role_id=4&last_updated__lt=2025-10-01
        /probe/netbox?site=dc1&tag=snmp-ready
        /probe/netbox?manufacturer=cisco

    Returns immediately (202); probe runs in the background.
    Duplicate requests with the same filter set are dropped.
    """
    grouped: dict = {}
    for k, v in request.query_params.multi_items():
        grouped.setdefault(k, []).append(v)
    filter_params = {k: v[0] if len(v) == 1 else v for k, v in grouped.items()}

    job_key = "netbox:" + "&".join(f"{k}={v}" for k, v in sorted(filter_params.items()))

    with _in_flight_lock:
        if job_key in _in_flight:
            return {"status": "skipped", "filter": filter_params, "reason": "already in progress"}
        _in_flight.add(job_key)

    def fetch(nb: NetboxClient):
        return nb.get_devices(**filter_params)

    background_tasks.add_task(_run_probe, job_key, fetch)
    logger.info("Probe queued for NetBox filter %s", filter_params)
    return {"status": "queued", "filter": filter_params}


@app.get(_METRICS_PATH, include_in_schema=False)
async def metrics() -> Response:
    if _MULTIPROC_DIR:
        reg = CollectorRegistry()
        MultiProcessCollector(reg)
        content = generate_latest(reg)
    else:
        content = generate_latest(_custom_registry)
    return Response(content=content, media_type=CONTENT_TYPE_LATEST)


@app.get("/health", summary="Liveness check")
async def health() -> dict:
    return {
        "status": "ok",
        "probe_in_progress": len(_in_flight),
        "in_flight": list(_in_flight),
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port    = int(os.getenv("MODULATOR_PORT", "8081"))
    workers = int(os.getenv("MODULATOR_WORKERS", "4"))
    logger.info("snmp-modulator server starting on port %d (%d workers)", port, workers)
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=port,
        workers=workers,
        log_config=_UVICORN_LOG_CONFIG,
    )
