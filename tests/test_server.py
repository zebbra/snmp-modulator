"""Unit tests for server.py — Prometheus registry isolation, filter-key
validation, and device-count refresh / probe-job bookkeeping.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_server.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

# Isolate Prometheus multiprocess state in a throwaway dir before server.py is
# imported — module-level code auto-enables PROMETHEUS_MULTIPROC_DIR otherwise.
_TMPDIR = tempfile.mkdtemp(prefix="modulator-test-")
os.environ["PROMETHEUS_MULTIPROC_DIR"] = _TMPDIR

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)


def _import_server_as(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, "server.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_server_imports_twice_without_registry_collision() -> None:
    # Under uvicorn multiprocessing, server.py can be loaded twice in one
    # process (once as __main__, once as "server"). Metrics must live on the
    # module's own _custom_registry, not prometheus_client's global default
    # REGISTRY, or the second import raises "Duplicated timeseries".
    _import_server_as("server_first_copy")
    _import_server_as("server_second_copy")


import server  # noqa: E402

# ── filter key validation ───────────────────────────────────────────────────────

def test_valid_filter_key_accepts_alnum_and_operator_suffix() -> None:
    assert server._VALID_FILTER_KEY.match("role_id")
    assert server._VALID_FILTER_KEY.match("last_updated__lt")
    assert server._VALID_FILTER_KEY.match("site")


def test_valid_filter_key_rejects_special_characters() -> None:
    assert not server._VALID_FILTER_KEY.match("role/id")
    assert not server._VALID_FILTER_KEY.match("role?id")
    assert not server._VALID_FILTER_KEY.match("role.id")
    assert not server._VALID_FILTER_KEY.match("")


# ── _refresh_device_counts ───────────────────────────────────────────────────────

def test_refresh_device_counts_sets_gauges_per_profile_and_module(monkeypatch) -> None:
    calls = []

    def fake_count(**kwargs):
        calls.append(kwargs)
        return 3

    fake_nb = SimpleNamespace(nb=SimpleNamespace(dcim=SimpleNamespace(devices=SimpleNamespace(count=fake_count))))
    fake_snmp = SimpleNamespace(auths=["public_v2"], modules=["if_mib"])
    fake_engine = SimpleNamespace(auth_field="snmp_auth_profile", module_field="snmp_exporter_module")

    monkeypatch.setattr(server, "_make_clients", lambda: (fake_nb, fake_snmp, fake_engine, "drop"))
    server._refresh_device_counts()

    assert server.netbox_devices_by_auth.labels(profile="public_v2")._value.get() == 3
    assert server.netbox_devices_by_module.labels(module="if_mib")._value.get() == 3
    assert {"cf_snmp_auth_profile": "public_v2"} in calls
    assert {"cf_snmp_exporter_module": "if_mib"} in calls


# ── _run_probe: semaphore + in-flight bookkeeping ───────────────────────────────

def test_run_probe_releases_semaphore_and_clears_in_flight(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )

    ran = []

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None):
            ran.append(devices)

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._in_flight.add("host:10.0.0.1")
    before = server.probe_in_progress._value.get()
    server._run_probe("host:10.0.0.1", lambda nb: ["dev1"])
    after = server.probe_in_progress._value.get()

    assert before == after  # incremented then decremented back to baseline
    assert ran == [["dev1"]]
    assert "host:10.0.0.1" not in server._in_flight


# ── _metric_samples / _metric_value ─────────────────────────────────────────────

def test_metric_samples_reads_labeled_gauge_values() -> None:
    server.netbox_devices_by_auth.labels(profile="public_v2").set(7)
    assert server._metric_samples("modulator_netbox_devices_by_auth")[(("profile", "public_v2"),)] == 7


def test_metric_value_reads_unlabeled_gauge() -> None:
    server.probe_in_progress.inc()
    try:
        assert server._metric_value("modulator_probe_in_progress") >= 1
    finally:
        server.probe_in_progress.dec()


# ── / dashboard ──────────────────────────────────────────────────────────────────

def test_index_lists_in_flight_jobs_and_device_counts() -> None:
    server.netbox_devices_by_auth.labels(profile="public_v2").set(5)
    server.netbox_devices_by_module.labels(module="if_mib").set(3)
    server._in_flight.add("host:10.0.0.1")
    try:
        html = asyncio.run(server.index())
    finally:
        server._in_flight.discard("host:10.0.0.1")

    assert "host:10.0.0.1" in html
    assert "public_v2" in html
    assert "if_mib" in html


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
