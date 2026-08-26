#!/usr/bin/env python3
"""
snmp-modulator server — FastAPI probe trigger + Prometheus metrics.

Endpoints:
  GET/POST /probe?host=<ip_or_fqdn>          Probe a single device by IP or name
  GET/POST /probe/netbox?<filter_params>     Probe devices matching any NetBox filter
  GET      /rules                            Loaded mapping.yaml rules/config as JSON
                                               (add ?format=html for a browsable page)
  GET      /stats                            Device counts by auth/module + module mismatch, as JSON
  GET      /metrics                          Prometheus metrics
  GET      /health                           Liveness check (includes module-mismatch counts)
  GET      /docs                             Swagger UI (auto-generated)

/probe/netbox passes query parameters directly to pynetbox's dcim.devices.filter(),
so any NetBox API filter is valid:
  /probe/netbox?role_id=4&last_updated__lt=2025-10-01
  /probe/netbox?site=dc1&tag=snmp-ready
  /probe/netbox?manufacturer=cisco

/probe additionally accepts:
  wait=true       Block until the probe finishes and return its result as JSON
                   (default is fire-and-forget: 202 + background job). Not offered
                   on /probe/netbox — a filter can match many devices, and blocking
                   an HTTP request on an unbounded multi-device probe risks caller
                   timeouts and starves the concurrency semaphore for other callers.
                   If the probe queue is busy, waits up to MODULATOR_WAIT_TIMEOUT
                   (default 60s) for a free slot, then returns 503 rather than
                   hanging behind an unrelated bulk probe.
  dry_run=true|false   Override the server's dry-run mode for this call only.

Preview-then-confirm: a dry_run=true /probe result for a given host is cached
for MODULATOR_DRY_RUN_CACHE_TTL seconds (default 300). A plain (non-dry-run)
/probe call for that *same* host within the window commits the cached result
for real — no re-probing. One-shot: the cache entry is consumed on that commit.
"""

import asyncio
import html
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Annotated, Any, Optional

# When uvicorn runs with multiple workers, each worker has its own in-memory
# CollectorRegistry, so /metrics scrapes only see whichever worker happens to
# answer the request. Auto-enable PROMETHEUS_MULTIPROC_DIR so the prometheus_client
# multiprocess collector aggregates across workers. Must run BEFORE prometheus_client
# is imported so the multiprocess value class is selected on first metric creation.
#
# Master vs worker: only the master process gets here with the env var unset —
# workers spawned by uvicorn inherit it from master's environment. So this
# branch only runs once (in master), making the stale-file cleanup race-free.
if int(os.getenv("MODULATOR_WORKERS", "4")) > 1 and not os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
    _auto_multiproc_dir = "/tmp/modulator_metrics"
    os.makedirs(_auto_multiproc_dir, exist_ok=True)
    for _f in os.listdir(_auto_multiproc_dir):
        if _f.endswith(".db"):
            try:
                os.remove(os.path.join(_auto_multiproc_dir, _f))
            except OSError:
                pass
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = _auto_multiproc_dir
    print(
        f"[snmp-modulator] auto-enabled PROMETHEUS_MULTIPROC_DIR={_auto_multiproc_dir} "
        f"(MODULATOR_WORKERS>1)",
        flush=True,
    )

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.multiprocess import MultiProcessCollector

from modulator import (
    APP_NAME,
    Callbacks,
    MappingEngine,
    ModulationResult,
    Modulator,
    NetboxClient,
    SnmpExporterClient,
    __version__,
    compare_module_sets,
    fetch_liveness,
)

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
module_changes_total = Counter(
    "modulator_module_changes_total",
    "Per-module assignment deltas written back to NetBox",
    ["module", "action"],   # action: added | removed
    **_reg,
)
probe_duration = Histogram(
    "modulator_probe_duration_seconds",
    "Total duration of a /probe or /probe/netbox call",
    buckets=[5, 30, 60, 120, 300, 600, 1800],
    **_reg,
)
probe_running = Gauge(
    "modulator_probe_running",
    "Probe jobs actively executing (semaphore slot acquired)",
    multiprocess_mode="livesum",
    **_reg,
)
probe_queued = Gauge(
    "modulator_probe_queued",
    "Probe jobs accepted but not yet finished (running + waiting for a slot)",
    multiprocess_mode="livesum",
    **_reg,
)
probe_queue_depth = Gauge(
    "modulator_probe_queue_depth",
    "Probe jobs waiting for a free slot (excludes ones already running)",
    multiprocess_mode="livesum",
    **_reg,
)
liveness_query_up = Gauge(
    "modulator_liveness_query_up",
    "1 if the last liveness query (batch run) succeeded, 0 on error",
    multiprocess_mode="livemax",
    **_reg,
)
netbox_devices_by_auth = Gauge(
    "modulator_netbox_devices_by_auth",
    "Devices in NetBox per snmp auth profile (zero for profiles known to snmp-exporter but unused)",
    ["profile"],
    multiprocess_mode="livemax",
    **_reg,
)
netbox_devices_by_module = Gauge(
    "modulator_netbox_devices_by_module",
    "Devices in NetBox per snmp-exporter module (zero for modules known to snmp-exporter but unused)",
    ["module"],
    multiprocess_mode="livemax",
    **_reg,
)
netbox_devices_refresh_duration = Histogram(
    "modulator_netbox_devices_refresh_duration_seconds",
    "Duration of the NetBox device-count refresh cycle",
    buckets=[1, 5, 10, 30, 60, 120, 300],
    **_reg,
)


def _metric_samples(name: str) -> dict[tuple, float]:
    """Current values for a metric, aggregated across workers when multiprocess."""
    if _MULTIPROC_DIR:
        reg = CollectorRegistry()
        MultiProcessCollector(reg)
    else:
        reg = _custom_registry
    return {
        tuple(sorted(s.labels.items())): s.value
        for metric in reg.collect() if metric.name == name
        for s in metric.samples if s.name == name
    }


def _metric_value(name: str) -> float:
    return next(iter(_metric_samples(name).values()), 0.0)


def _devices_by_label(metric_name: str, label: str) -> dict:
    """{label_value: count} for a per-label device-count gauge, e.g.
    _devices_by_label("modulator_netbox_devices_by_auth", "profile")."""
    return {dict(k).get(label, "?"): int(v) for k, v in _metric_samples(metric_name).items()}


def _module_mismatch_snapshot() -> dict:
    """{'netbox_only': [...], 'snmp_exporter_only': [...]} — module names known
    to NetBox's custom-field choices but not snmp-exporter, and vice versa."""
    with _module_mismatch_lock:
        return {
            "netbox_only":        list(_module_mismatch["only_in_netbox"]),
            "snmp_exporter_only": list(_module_mismatch["only_in_snmp"]),
        }


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

    def module_changed(self, module: str, action: str) -> None:
        module_changes_total.labels(module=module, action=action).inc()


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
_WAIT_TIMEOUT:  float          = float(os.getenv("MODULATOR_WAIT_TIMEOUT", "60"))
_DEVICE_PARALLELISM: int       = int(os.getenv("MODULATOR_DEVICE_PARALLELISM", "1"))
_WORKERS: int                  = int(os.getenv("MODULATOR_WORKERS", "4"))
_NETBOX_REFRESH_INTERVAL: int = int(os.getenv("MODULATOR_NETBOX_REFRESH_INTERVAL", "3600"))

# Liveness gate: before a batch run probes a device, ask a Prometheus-compatible
# API (VictoriaMetrics vmselect) whether it's actually up, and skip it if not —
# SNMP itself isn't a reliable down-signal (wrong creds/module looks identical
# to actually-down), but a dedicated ICMP check is. Disabled unless a URL is
# configured; a query failure or a device missing from the results fails open
# (processed normally), same reasoning as pin_tag. Mirrors bit-discobox's
# DISCOBOX_LIVENESS_* config (fetch_liveness() is even the same function).
_LIVENESS_URL:       Optional[str] = os.getenv("MODULATOR_LIVENESS_URL") or None
_LIVENESS_QUERY:     str           = os.getenv("MODULATOR_LIVENESS_QUERY", 'probe_success{job="network-netbox-ping"}')
_LIVENESS_LABEL:     str           = os.getenv("MODULATOR_LIVENESS_LABEL", "instance")
_LIVENESS_KEY:       str           = os.getenv("MODULATOR_LIVENESS_KEY", "name").lower()  # "name" or "ip"
_LIVENESS_TIMEOUT:   int           = int(os.getenv("MODULATOR_LIVENESS_TIMEOUT", "15"))
_LIVENESS_TLS_VERIFY: bool         = os.getenv("MODULATOR_LIVENESS_TLS_VERIFY", "true").lower() != "false"

# pynetbox filter keys: alphanumeric + underscore (allowing pynetbox's __operator suffix style).
# Anything else (slashes, question marks, dots, etc.) is rejected before reaching NetBox.
_VALID_FILTER_KEY = re.compile(r"^[a-zA-Z0-9_]+$")

# ── Auth ──────────────────────────────────────────────────────────────────────

async def require_auth(authorization: Annotated[str, Header()] = "") -> None:
    """Bearer token auth. Disabled when MODULATOR_AUTH_TOKEN is not set."""
    if not _AUTH_TOKEN:
        return
    if authorization != f"Bearer {_AUTH_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


# ── App ───────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(app: FastAPI):
    is_device_count_leader = _acquire_device_count_leadership()
    if is_device_count_leader:
        _start_device_count_refresher()
    else:
        logger.info("NetBox device-count refresher not started: another worker already holds leadership")
    yield
    if is_device_count_leader:
        _release_device_count_leadership()


app = FastAPI(
    title="snmp-modulator",
    description="Probe NetBox devices against snmp-exporter and update snmp_exporter_module",
    version=__version__,
    lifespan=_lifespan,
)

# Active probe job keys — prevents duplicate concurrent probes for the same target
_in_flight: set = set()
_in_flight_lock = threading.Lock()

# Per-process cache of the most recent dry-run result set per job_key. Lets a
# caller preview with dry_run=true, then confirm with a plain (non-dry-run)
# call for the *same* query shortly after without re-probing — the previously
# measured/resolved values are just written for real. One-shot: consumed (and
# evicted) on the first non-dry-run hit, or dropped once MODULATOR_DRY_RUN_CACHE_TTL
# elapses. Same per-worker-process caveat as _in_flight above: with
# MODULATOR_WORKERS>1 this isn't shared across workers, so a commit routed to a
# different worker than the preview just falls back to a normal re-probe.
_dry_run_cache: dict = {}
_dry_run_cache_lock = threading.Lock()
_DRY_RUN_CACHE_TTL: float = float(os.getenv("MODULATOR_DRY_RUN_CACHE_TTL", "300"))

# Live per-job progress (module test results completed so far) while a probe is
# still in flight (job_key in _in_flight) — lets GET /probe/result show partial
# progress instead of a caller having to hold one long request open for the
# whole (serial, per-device) probe duration. Reset when a job starts, appended
# to as each module completes, cleared when the job finishes.
_probe_progress: dict = {}
_probe_progress_lock = threading.Lock()

# Last completed result per job_key, for every run (dry_run or not) — unlike
# _dry_run_cache this is NOT one-shot; GET /probe/result just reads it,
# repeatedly, until it's overwritten by that job_key's next run or
# MODULATOR_PROBE_RESULT_TTL elapses. Same per-worker-process caveat as
# _in_flight above.
_last_result_cache: dict = {}
_last_result_lock = threading.Lock()
_PROBE_RESULT_TTL: float = float(os.getenv("MODULATOR_PROBE_RESULT_TTL", "300"))

# NetBox module choices vs snmp-exporter modules — refreshed alongside device counts
_module_mismatch_lock = threading.Lock()
_module_mismatch: dict = {"only_in_netbox": [], "only_in_snmp": []}

_probe_semaphore = threading.Semaphore(_MAX_CONCURRENT)

# Device-count refresh leader election: with MODULATOR_WORKERS>1, _lifespan runs
# once per worker process, so only one worker may run _device_count_loop() or
# every refresh's NetBox/snmp-exporter query volume gets multiplied by the worker
# count. PID-based lock file: a crashed leader (without a clean shutdown) doesn't
# permanently wedge the refresh for the other workers.
_DEVICE_COUNT_LEADER_FILE: str = os.path.join(_MULTIPROC_DIR or "/tmp", "modulator.device-count-leader.pid")


def _acquire_device_count_leadership() -> bool:
    for _ in range(2):
        try:
            fd = os.open(_DEVICE_COUNT_LEADER_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                with open(_DEVICE_COUNT_LEADER_FILE) as f:
                    leader_pid = int(f.read().strip())
                os.kill(leader_pid, 0)
                return False  # leader still alive
            except (OSError, ValueError):
                pass  # stale lock (leader pid gone or file unreadable): reclaim it
            try:
                os.unlink(_DEVICE_COUNT_LEADER_FILE)
            except FileNotFoundError:
                pass
    return False


def _release_device_count_leadership() -> None:
    try:
        os.unlink(_DEVICE_COUNT_LEADER_FILE)
    except FileNotFoundError:
        pass


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
        touch_field=engine.touch_field,
        fast_module_field=engine.fast_module_field,
        fast_interval_field=engine.fast_interval_field,
        fast_timeout_field=engine.fast_timeout_field,
    )
    verify_tls = os.getenv("SNMP_EXPORTER_TLS_VERIFY", "true").lower() != "false"
    timeout    = int(os.getenv("SNMP_EXPORTER_TIMEOUT", "30"))
    snmp       = SnmpExporterClient(
        base_url=os.environ["SNMP_EXPORTER_URL"],
        verify_tls=verify_tls,
        timeout=timeout,
    )
    return nb, snmp, engine, module_policy


def _refresh_device_counts() -> None:
    """Update by-profile/by-module gauges from NetBox count queries.

    One cheap `?cf_<field>=<value>&limit=1` query per known auth profile and per
    known module — counts come from pagination metadata, no full fetch.
    """
    t0 = time.time()
    nb, snmp, engine, _ = _make_clients()

    if not snmp.auths and not snmp.modules:
        logger.warning("NetBox device counts: snmp-exporter /config returned no auths/modules — skipping")
        return

    only_in_netbox, only_in_snmp = compare_module_sets(nb._valid_modules, set(snmp.modules))
    with _module_mismatch_lock:
        _module_mismatch["only_in_netbox"] = only_in_netbox
        _module_mismatch["only_in_snmp"]   = only_in_snmp
    if only_in_netbox:
        logger.warning("Module(s) in NetBox but not in snmp-exporter: %s", only_in_netbox)
    if only_in_snmp:
        logger.warning("Module(s) in snmp-exporter but not in NetBox: %s", only_in_snmp)

    auth_ok = mod_ok = 0
    for profile in snmp.auths:
        try:
            n = nb.nb.dcim.devices.count(**{f"cf_{engine.auth_field}": profile})
            netbox_devices_by_auth.labels(profile=profile).set(n)
            auth_ok += 1
        except Exception as exc:
            logger.warning("NetBox device counts: auth count for %r failed: %s", profile, exc)

    for module in snmp.modules:
        try:
            n = nb.nb.dcim.devices.count(**{f"cf_{engine.module_field}": module})
            netbox_devices_by_module.labels(module=module).set(n)
            mod_ok += 1
        except Exception as exc:
            logger.warning("NetBox device counts: module count for %r failed: %s", module, exc)

    elapsed = time.time() - t0
    netbox_devices_refresh_duration.observe(elapsed)
    logger.info(
        "NetBox device counts: %d/%d auth profiles, %d/%d modules in %.1fs",
        auth_ok, len(snmp.auths), mod_ok, len(snmp.modules), elapsed,
    )


def _device_count_loop() -> None:
    while True:
        try:
            _refresh_device_counts()
        except Exception as exc:
            logger.exception("NetBox device counts refresh failed: %s", exc)
        time.sleep(_NETBOX_REFRESH_INTERVAL)


def _pop_cached_dry_run(job_key: str) -> Optional[list]:
    """Return and evict a still-fresh cached dry-run result set for job_key, or
    None if there's nothing cached or it's older than MODULATOR_DRY_RUN_CACHE_TTL.
    One-shot: a cache hit is consumed, so a repeated confirm doesn't keep
    replaying an increasingly stale result."""
    with _dry_run_cache_lock:
        entry = _dry_run_cache.pop(job_key, None)
    if entry is None:
        return None
    timestamp, results = entry
    if time.time() - timestamp > _DRY_RUN_CACHE_TTL:
        return None
    return results


def _cache_dry_run_results(job_key: str, results: list) -> None:
    with _dry_run_cache_lock:
        _dry_run_cache[job_key] = (time.time(), results)


def _record_module_progress(job_key: str, result) -> None:
    with _probe_progress_lock:
        _probe_progress.setdefault(job_key, []).append(result)


def _cache_last_result(job_key: str, dry_run: bool, results: list) -> None:
    with _last_result_lock:
        _last_result_cache[job_key] = (time.time(), dry_run, results)


def _fetch_liveness_or_none() -> Optional[dict]:
    """Fetch the liveness map for this run, or None if disabled/unavailable.

    None means "don't filter anything" (fail open) — same meaning whether
    liveness is disabled (_LIVENESS_URL unset) or the query just failed.
    Updates modulator_liveness_query_up either way.
    """
    if not _LIVENESS_URL:
        return None
    try:
        liveness = fetch_liveness(
            _LIVENESS_URL, _LIVENESS_QUERY,
            label=_LIVENESS_LABEL,
            timeout=_LIVENESS_TIMEOUT,
            verify_tls=_LIVENESS_TLS_VERIFY,
        )
        liveness_query_up.set(1)
        return liveness
    except Exception as exc:
        logger.warning("Liveness query failed — proceeding without filtering: %s", exc)
        liveness_query_up.set(0)
        return None


def _commit_cached_results(results: list) -> list:
    """Apply the NetBox writes for a previously cached dry-run result set,
    without re-probing. Mirrors the bookkeeping Modulator.run() would have
    done for a live, non-dry-run pass over the same devices."""
    nb, snmp, engine, _ = _make_clients()
    mod = Modulator(nb, snmp, engine, dry_run=False, device_parallelism=1)
    callbacks = _ServerCallbacks()
    for result in results:
        mod.commit(result, log=logging.getLogger(f"{APP_NAME}.{result.device_name}"))
        callbacks.netbox_update(action="changed" if result.changed else "unchanged")
        outcome = "error" if result.error else ("unreachable" if result.unreachable else "success")
        callbacks.device_processed(outcome)
    return results


def _run_probe(
    job_key: str,
    devices_fn,
    dry_run: Optional[bool] = None,
    acquire_timeout: Optional[float] = None,
    reraise: bool = False,
    honor_pins: bool = True,
) -> Optional[list]:
    """Execute a probe job. Returns list[ModulationResult], or None if no probe
    slot freed up within acquire_timeout seconds. Background jobs pass
    acquire_timeout=None and wait indefinitely for their turn; the synchronous
    wait=true path passes a bound so a busy queue can't hang the HTTP request
    behind an unrelated bulk probe.

    reraise controls what happens on an infra-level failure (NetBox/snmp-exporter
    unreachable, etc.): background jobs swallow and log it (False, default);
    wait=true passes True so the caller gets a real error instead of it being
    indistinguishable from "no matching device".

    honor_pins is forwarded to Modulator — /probe?host=X passes False (an
    explicit single host is deliberate, pin or not); /probe/netbox leaves the
    default True (a filter sweep should respect a device tagged pinned).

    A non-dry-run call for a job_key with a still-fresh cached dry-run result
    (see _dry_run_cache above) skips probing entirely and just commits that
    cached result for real.
    """
    start = time.time()
    resolved_dry_run = _DRY_RUN if dry_run is None else dry_run
    results: Optional[list] = None
    try:
        if not resolved_dry_run:
            cached = _pop_cached_dry_run(job_key)
            if cached is not None:
                logger.info(
                    "Probe job %r: committing %d cached dry-run result(s) — skipping re-probe",
                    job_key, len(cached),
                )
                return _commit_cached_results(cached)

        probe_queue_depth.inc()
        try:
            acquired = _probe_semaphore.acquire(timeout=acquire_timeout)
        finally:
            probe_queue_depth.dec()
        if not acquired:
            return None
        try:
            probe_running.inc()
            with _probe_progress_lock:
                _probe_progress[job_key] = []
            try:
                nb, snmp, engine, module_policy = _make_clients()
                # Only bother querying liveness for batch runs — an explicit
                # single-host request ignores it anyway (honor_pins=False).
                liveness = _fetch_liveness_or_none() if honor_pins else None
                mod = Modulator(
                    nb, snmp, engine,
                    dry_run=resolved_dry_run,
                    module_policy=module_policy,
                    device_parallelism=_DEVICE_PARALLELISM,
                    honor_pins=honor_pins,
                    liveness=liveness,
                    liveness_key=_LIVENESS_KEY,
                )
                devices = devices_fn(nb)
                results = mod.run(
                    devices, callbacks=_ServerCallbacks(),
                    on_module_result=lambda device, result: _record_module_progress(job_key, result),
                )
                if resolved_dry_run and results:
                    _cache_dry_run_results(job_key, results)
                _cache_last_result(job_key, resolved_dry_run, results if results else [])
            except Exception as exc:
                logger.exception("Probe job %r failed: %s", job_key, exc)
                if reraise:
                    raise
                results = []
            finally:
                probe_running.dec()
                probe_duration.observe(time.time() - start)
        finally:
            _probe_semaphore.release()
    finally:
        with _in_flight_lock:
            _in_flight.discard(job_key)
        with _probe_progress_lock:
            _probe_progress.pop(job_key, None)
        probe_queued.dec()
        logger.info("Probe job %r finished in %.1fs", job_key, time.time() - start)
    return results


# ── Routes ────────────────────────────────────────────────────────────────────

@app.api_route(
    "/probe",
    methods=["GET", "POST"],
    dependencies=[Depends(require_auth)],
    summary="Probe a single device by IP or name",
)
async def probe_host(
    background_tasks: BackgroundTasks,
    host: Annotated[Optional[str], Query(description="Device IP or name")] = None,
    wait: Annotated[
        bool, Query(description="Block until the probe finishes and return its result as JSON")
    ] = False,
    dry_run: Annotated[
        Optional[bool], Query(description="Override the server's dry-run mode for this call only")
    ] = None,
) -> dict:
    """
    Trigger a probe for one device.  `host` can be an IP address or device name.

    By default returns immediately (202); probe runs in the background.
    Pass `wait=true` to block until it finishes and get the result as JSON —
    e.g. for a NetBox plugin button showing the outcome inline.

    Preview then confirm: after a `dry_run=true` call, a plain call for the
    same host within MODULATOR_DRY_RUN_CACHE_TTL seconds commits that same
    result for real instead of re-probing.
    """
    if not host:
        raise HTTPException(status_code=400, detail="host parameter required")

    job_key = f"host:{host}"
    with _in_flight_lock:
        if job_key in _in_flight:
            if wait:
                raise HTTPException(status_code=409, detail=f"probe for {host!r} already in progress")
            return JSONResponse(
                status_code=202,
                content={"status": "skipped", "host": host, "reason": "already in progress"},
            )
        _in_flight.add(job_key)
    probe_queued.inc()

    def fetch(nb: NetboxClient):
        device = nb.get_device_by_host(host)
        if not device:
            logger.warning("Host %r not found in NetBox or ineligible", host)
            return []
        return [device]

    if wait:
        try:
            results = await asyncio.to_thread(
                _run_probe, job_key, fetch, dry_run, _WAIT_TIMEOUT, True, honor_pins=False,
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"probe failed: {exc}") from exc
        if results is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"probe queue busy — no slot freed up within {_WAIT_TIMEOUT:.0f}s "
                    f"(MODULATOR_MAX_CONCURRENT_RUNS={_MAX_CONCURRENT}); retry, or drop wait=true"
                ),
            )
        if not results:
            raise HTTPException(status_code=404, detail=f"host {host!r} not found in NetBox or ineligible")
        return {
            "status": "ok",
            "host": host,
            "dry_run": _DRY_RUN if dry_run is None else dry_run,
            "result": asdict(results[0]),
        }

    background_tasks.add_task(_run_probe, job_key, fetch, dry_run, honor_pins=False)
    logger.info("Probe queued for host %r", host)
    return JSONResponse(status_code=202, content={"status": "queued", "host": host})


@app.get(
    "/probe/result",
    dependencies=[Depends(require_auth)],
    summary="Poll for a queued probe's progress or finished result",
)
async def probe_result(
    host: Annotated[Optional[str], Query(description="Device IP or name — same value passed to /probe")] = None,
) -> Any:
    """
    Poll this after kicking off a background `/probe?host=<host>` call (the
    default, non-`wait=true` mode) — avoids holding one HTTP request open for
    the whole probe duration, which is unavoidably serial per device (modules
    on one device are always probed one at a time, never in parallel, so it
    can't be sped up — this just avoids blocking on it).

    Keyed by `host`, same as `/probe` — no job id to track client-side, just
    re-GET this with the same host param until `status` is `"done"`.

    `result` has the same shape in both states (an asdict'd `ModulationResult`)
    so a caller's rendering doesn't need to branch: while running, only
    `test_results` (modules probed so far) is populated; once done, every
    field is.

    Returns 202 while running, 200 once done, 404 if no probe for this host
    is in flight or was recently completed (nothing to report — submit one).
    """
    if not host:
        raise HTTPException(status_code=400, detail="host parameter required")
    job_key = f"host:{host}"

    with _in_flight_lock:
        running = job_key in _in_flight

    if running:
        with _probe_progress_lock:
            partial_results = list(_probe_progress.get(job_key, []))
        stub = ModulationResult(
            device_id=0, device_name=host,
            previous_modules=[], final_modules=[], changed=False,
            test_results=partial_results,
        )
        return JSONResponse(
            status_code=202,
            content={"status": "running", "host": host, "result": asdict(stub)},
        )

    with _last_result_lock:
        entry = _last_result_cache.get(job_key)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no probe found for {host!r} — submit one first")
    timestamp, dry_run, results = entry
    if time.time() - timestamp > _PROBE_RESULT_TTL:
        raise HTTPException(status_code=404, detail=f"probe result for {host!r} expired — submit a new one")
    if not results:
        raise HTTPException(status_code=404, detail=f"host {host!r} not found in NetBox or ineligible")
    return {"status": "done", "host": host, "dry_run": dry_run, "result": asdict(results[0])}


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

    # Reject obviously-malformed filter keys early — protects against pynetbox
    # silently ignoring junk and returning the entire fleet.
    bad = [k for k in filter_params if not _VALID_FILTER_KEY.match(k)]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=(
                f"invalid filter key(s) {bad!r} — keys must be alphanumeric/underscore "
                f"with optional __operator (e.g. site_id, last_updated__lt)"
            ),
        )

    job_key = "netbox:" + "&".join(f"{k}={v}" for k, v in sorted(filter_params.items()))

    with _in_flight_lock:
        if job_key in _in_flight:
            return {"status": "skipped", "filter": filter_params, "reason": "already in progress"}
        _in_flight.add(job_key)
    probe_queued.inc()

    def fetch(nb: NetboxClient):
        return nb.get_devices(**filter_params)

    background_tasks.add_task(_run_probe, job_key, fetch)
    logger.info("Probe queued for NetBox filter %s", filter_params)
    return {"status": "queued", "filter": filter_params}


def _rules_html(snap: dict) -> str:
    """Render a MappingEngine.snapshot() dict as a dashboard-styled HTML page."""
    esc = lambda s: html.escape(str(s))  # noqa: E731

    def modules_str(mods: dict) -> str:
        parts = [
            f'<span style="color:{color}">{key}</span>: {esc(", ".join(vals))}'
            for key, color in (("add", "#1D9E75"), ("try", "#9FE1CB"), ("block", "#B8722B"))
            if (vals := mods.get(key))
        ]
        if mods.get("interval") or mods.get("timeout"):
            interval, timeout = esc(mods.get("interval") or "-"), esc(mods.get("timeout") or "-")
            parts.append(f"floor: interval={interval} timeout={timeout}")
        fast = mods.get("fast") or {}
        fast_parts = [
            f'<span style="color:{color}">fast.{key}</span>: {esc(", ".join(vals))}'
            for key, color in (("add", "#1D9E75"), ("try", "#9FE1CB"), ("block", "#B8722B"))
            if (vals := fast.get(key))
        ]
        if fast.get("interval") or fast.get("timeout"):
            interval, timeout = esc(fast.get("interval") or "-"), esc(fast.get("timeout") or "-")
            fast_parts.append(f"fast floor: interval={interval} timeout={timeout}")
        parts.extend(fast_parts)
        return "<br>".join(parts) or "-"

    def match_str(match: dict) -> str:
        if not match:
            return "<i>(always matches)</i>"
        return "<br>".join(f"<code>{esc(k)}</code> ~ <code>{esc(v)}</code>" for k, v in match.items())

    def handlers_str(h: dict) -> str:
        parts = [f"{label}: {esc(', '.join(h[key]))}" for key, label in
                 (("add_tag", "+tag"), ("remove_tag", "-tag"), ("notify", "notify")) if h.get(key)]
        return "<br>".join(parts) or "-"

    rule_rows = "".join(
        f"<tr><td>{esc(rule['name'])}</td>"
        f"<td>{match_str(rule['match'])}</td>"
        f"<td>{modules_str(rule['modules'])}</td>"
        f"<td>{esc(rule['auth']) if rule['auth'] else '-'}</td>"
        f"<td>ok: {handlers_str(rule['on_success'])}<br>fail: {handlers_str(rule['on_fail'])}</td></tr>"
        for rule in snap["rules"]
    ) or "<tr><td colspan=5>no rules defined</td></tr>"

    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>snmp-modulator rules</title>
<style>{_DASHBOARD_CSS}</style></head><body>
<h1>snmp-modulator <small style="color:#888;font-size:.5em">v{__version__}</small> — rules</h1>
<p><a href="/">&larr; dashboard</a> &nbsp; <a href="/rules">raw json</a></p>

<h2>Config</h2>
<table>
  <tr><td>module_field / auth_field</td>
      <td>{esc(snap['module_field'])} / {esc(snap['auth_field'])}</td></tr>
  <tr><td>interval_field / timeout_field</td>
      <td>{esc(snap['interval_field'] or '-')} / {esc(snap['timeout_field'] or '-')}</td></tr>
  <tr><td>touch_field</td><td>{esc(snap['touch_field'] or '-')}</td></tr>
  <tr><td>default_interval / default_timeout</td>
      <td>{esc(snap['default_interval'])} / {esc(snap['default_timeout'])}</td></tr>
  <tr><td>fast_module_field</td><td>{esc(snap['fast_module_field'] or '-')}</td></tr>
  <tr><td>fast_interval_field / fast_timeout_field</td>
      <td>{esc(snap['fast_interval_field'] or '-')} / {esc(snap['fast_timeout_field'] or '-')}</td></tr>
  <tr><td>fast_default_interval / fast_default_timeout</td>
      <td>{esc(snap['fast_default_interval'])} / {esc(snap['fast_default_timeout'])}</td></tr>
  <tr><td>module_policy / auth_policy</td>
      <td>{esc(snap['module_policy'])} / {esc(snap['auth_policy'])}</td></tr>
  <tr><td>auth_probe_module</td><td>{esc(snap['auth_probe_module'])}</td></tr>
</table>

<h2>Defaults</h2>
<table>
  <tr><td>modules</td><td>{modules_str(snap['defaults']['modules'])}</td></tr>
  <tr><td>auth try</td><td>{esc(", ".join(snap['defaults']['auth']['try']) or '-')}</td></tr>
</table>

<h2>Rules ({len(snap['rules'])})</h2>
<table>
  <tr><th>Name</th><th>Match</th><th>Modules</th><th>Auth override</th><th>Handlers</th></tr>
  {rule_rows}
</table>
</body></html>"""


@app.get(
    "/rules",
    dependencies=[Depends(require_auth)],
    summary="View the loaded mapping.yaml rules and config",
)
async def rules(
    format: Annotated[str, Query(description="'json' (default) or 'html'")] = "json",
) -> Any:
    """
    Snapshot of the currently loaded mapping file — config, defaults, and every
    rule (with compiled regexes rendered back to their source pattern strings).
    Reloaded from disk on every call, so edits to MAPPING_FILE show up without
    a restart. `format=html` renders it as a browsable page instead of JSON.
    """
    if format not in ("json", "html"):
        raise HTTPException(status_code=400, detail="format must be 'json' or 'html'")
    try:
        engine = MappingEngine(_MAPPING_FILE)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"failed to load mapping file {_MAPPING_FILE!r}: {exc}") from exc

    snapshot = engine.snapshot()
    if format == "html":
        return HTMLResponse(_rules_html(snapshot))
    return snapshot


@app.get(_METRICS_PATH, include_in_schema=False)
async def metrics() -> Response:
    if _MULTIPROC_DIR:
        reg = CollectorRegistry()
        MultiProcessCollector(reg)
        content = generate_latest(reg)
    else:
        content = generate_latest(_custom_registry)
    return Response(content=content, media_type=CONTENT_TYPE_LATEST)


def _start_device_count_refresher() -> None:
    if _NETBOX_REFRESH_INTERVAL <= 0:
        logger.info("NetBox device counts refresh disabled (MODULATOR_NETBOX_REFRESH_INTERVAL<=0)")
        return
    threading.Thread(target=_device_count_loop, daemon=True, name="netbox-device-counts").start()
    logger.info("NetBox device counts refresher started (interval=%ds)", _NETBOX_REFRESH_INTERVAL)


# Shared by index() and /rules?format=html — palette matches banner.svg
# (teal-green on near-black), kept distinct from bit-discobox's purple/blue theme.
_DASHBOARD_CSS = """
  body { font-family: monospace; max-width: 860px; margin: 2em auto; padding: 0 1em;
          background: #0C0D10; color: #cfe8df; }
  h1 { color: #5DCAA5; }
  h2 { color: #9FE1CB; border-bottom: 1px solid #1a1d24; padding-bottom: .3em; }
  .badge { display:inline-block; padding: .2em .7em; border-radius: 4px; font-weight: bold; color: #fff; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .4em .8em; border-bottom: 1px solid #1a1d24; vertical-align: top; }
  th { color: #5DCAA5; }
  .endpoints td:first-child { color: #5DCAA5; }
  .endpoints td:nth-child(2) { color: #9FE1CB; }
  a { color: #5DCAA5; }
  code { color: #9FE1CB; }
"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index() -> str:
    with _in_flight_lock:
        in_flight = sorted(_in_flight)

    by_auth   = sorted(_devices_by_label("modulator_netbox_devices_by_auth", "profile").items())
    by_module = sorted(_devices_by_label("modulator_netbox_devices_by_module", "module").items())

    _no_data = "<tr><td colspan=2>no data yet</td></tr>"
    auth_rows = "".join(f"<tr><td>{p}</td><td>{n}</td></tr>" for p, n in by_auth) or _no_data
    module_rows = "".join(f"<tr><td>{m}</td><td>{n}</td></tr>" for m, n in by_module) or _no_data
    inflight_rows = "".join(f"<tr><td>{k}</td></tr>" for k in in_flight) or "<tr><td>none</td></tr>"

    mode_badge = (
        '<span class="badge" style="background:#B8722B">DRY RUN</span>'
        if _DRY_RUN else '<span class="badge" style="background:#1D9E75">live</span>'
    )
    refresh_str = f"{_NETBOX_REFRESH_INTERVAL}s" if _NETBOX_REFRESH_INTERVAL > 0 else "disabled"

    mismatch = _module_mismatch_snapshot()
    if mismatch["netbox_only"] or mismatch["snmp_exporter_only"]:
        mismatch_badge = '<span class="badge" style="background:#B8722B">mismatch</span>'
        mismatch_rows = (
            f"<tr><td>In NetBox, not in snmp-exporter</td><td>{', '.join(mismatch['netbox_only']) or '-'}</td></tr>"
            f"<tr><td>In snmp-exporter, not in NetBox</td>"
            f"<td>{', '.join(mismatch['snmp_exporter_only']) or '-'}</td></tr>"
        )
    else:
        mismatch_badge = '<span class="badge" style="background:#1D9E75">in sync</span>'
        mismatch_rows = ""

    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>snmp-modulator</title>
<style>{_DASHBOARD_CSS}</style></head><body>
<h1>snmp-modulator <small style="color:#888;font-size:.5em">v{__version__}</small></h1>
<p>Mode: {mode_badge}
&nbsp; Running: <b>{int(_metric_value("modulator_probe_running"))}</b>
&nbsp; Queued: <b>{int(_metric_value("modulator_probe_queued"))}</b>
&nbsp; Waiting for a slot: <b>{int(_metric_value("modulator_probe_queue_depth"))}</b>
&nbsp; Max concurrent: <b>{_MAX_CONCURRENT}</b> per worker
(<b>{_MAX_CONCURRENT * _WORKERS}</b> pod-wide across {_WORKERS} workers)
&nbsp; Device parallelism: <b>{_DEVICE_PARALLELISM}</b>
&nbsp; NetBox refresh: <b>{refresh_str}</b></p>

<h2>Endpoints</h2>
<table class="endpoints">
  <tr><th>Method</th><th>Path</th><th>Description</th></tr>
  <tr><td>GET/POST</td><td>/probe</td><td>Probe a single device by IP or name</td></tr>
  <tr><td>GET/POST</td><td>/probe/netbox</td><td>Probe devices matching a NetBox filter</td></tr>
  <tr><td>GET</td><td><a href=/rules?format=html>/rules</a></td>
      <td>Loaded mapping.yaml rules (JSON by default; link goes to <code>?format=html</code>)</td></tr>
  <tr><td>GET</td><td><a href=/stats>/stats</a></td>
      <td>Device counts by auth/module + module mismatch, as JSON</td></tr>
  <tr><td>GET</td><td><a href={_METRICS_PATH}>{_METRICS_PATH}</a></td><td>Prometheus metrics</td></tr>
  <tr><td>GET</td><td><a href=/health>/health</a></td><td>Liveness check</td></tr>
  <tr><td>GET</td><td><a href=/docs>/docs</a></td><td>Swagger UI</td></tr>
</table>
<p>Examples (POST recommended; GET also triggers the probe, so these aren't links):</p>
<ul>
  <li><code>/probe?host=10.0.0.5</code></li>
  <li><code>/probe?host=switch1.nms.admin.ch</code></li>
  <li><code>/probe?host=10.0.0.5&amp;wait=true&amp;dry_run=true</code> — blocks and returns the result as JSON</li>
  <li><code>/probe?host=10.0.0.5&amp;wait=true</code> — a plain follow-up call within
      {int(_DRY_RUN_CACHE_TTL)}s commits the dry run above for real, without re-probing</li>
  <li><code>/probe/netbox?role_id=4&amp;last_updated__lt=2025-10-01</code></li>
  <li><code>/probe/netbox?site=dc1&amp;tag=snmp-ready</code></li>
  <li><code>/probe/netbox?manufacturer=cisco</code></li>
</ul>

<h2>Module mismatch {mismatch_badge}</h2>
<table>{mismatch_rows or "<tr><td>NetBox module choices and snmp-exporter modules match</td></tr>"}</table>

<h2>In-flight jobs ({len(in_flight)})</h2>
<table>{inflight_rows}</table>

<h2>Devices by auth profile</h2>
<table><tr><th>Profile</th><th>Count</th></tr>{auth_rows}</table>

<h2>Devices by module</h2>
<table><tr><th>Module</th><th>Count</th></tr>{module_rows}</table>
</body></html>"""


@app.get(
    "/stats",
    dependencies=[Depends(require_auth)],
    summary="Device counts by auth profile / module, and NetBox <-> snmp-exporter module mismatch",
)
async def stats() -> dict:
    """
    JSON view of the numbers shown on the dashboard — the same
    modulator_netbox_devices_by_{auth,module} gauges and module-mismatch state,
    refreshed on the same MODULATOR_NETBOX_REFRESH_INTERVAL cycle. Useful for a
    NetBox plugin panel that wants these without scraping /metrics or the HTML.
    """
    mismatch = _module_mismatch_snapshot()
    return {
        "devices_by_auth_profile": _devices_by_label("modulator_netbox_devices_by_auth", "profile"),
        "devices_by_module":       _devices_by_label("modulator_netbox_devices_by_module", "module"),
        "module_mismatch": {
            **mismatch,
            "netbox_only_count":        len(mismatch["netbox_only"]),
            "snmp_exporter_only_count": len(mismatch["snmp_exporter_only"]),
        },
    }


@app.get("/health", summary="Liveness check")
async def health() -> dict:
    mismatch = _module_mismatch_snapshot()
    return {
        "status": "ok",
        "version": __version__,
        "probe_queued": len(_in_flight),
        "in_flight": list(_in_flight),
        "netbox_only_module_count":        len(mismatch["netbox_only"]),
        "snmp_exporter_only_module_count": len(mismatch["snmp_exporter_only"]),
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("MODULATOR_PORT", "8081"))
    logger.info("snmp-modulator v%s starting on port %d (%d workers)", __version__, port, _WORKERS)
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=port,
        workers=_WORKERS,
        log_config=_UVICORN_LOG_CONFIG,
    )
