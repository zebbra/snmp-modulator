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

    fake_nb = SimpleNamespace(
        nb=SimpleNamespace(dcim=SimpleNamespace(devices=SimpleNamespace(count=fake_count))),
        _valid_modules=frozenset({"if_mib"}),
    )
    fake_snmp = SimpleNamespace(auths=["public_v2"], modules=["if_mib"])
    fake_engine = SimpleNamespace(auth_field="snmp_auth_profile", module_field="snmp_exporter_module")

    monkeypatch.setattr(server, "_make_clients", lambda: (fake_nb, fake_snmp, fake_engine, "drop"))
    server._refresh_device_counts()

    assert server.netbox_devices_by_auth.labels(profile="public_v2")._value.get() == 3
    assert server.netbox_devices_by_module.labels(module="if_mib")._value.get() == 3
    assert {"cf_snmp_auth_profile": "public_v2"} in calls
    assert {"cf_snmp_exporter_module": "if_mib"} in calls


def test_refresh_device_counts_populates_module_mismatch(monkeypatch) -> None:
    fake_nb = SimpleNamespace(
        nb=SimpleNamespace(dcim=SimpleNamespace(devices=SimpleNamespace(count=lambda **kw: 0))),
        _valid_modules=frozenset({"if_mib", "stale_module"}),
    )
    fake_snmp = SimpleNamespace(auths=[], modules=["if_mib", "new_module"])
    fake_engine = SimpleNamespace(auth_field="snmp_auth_profile", module_field="snmp_exporter_module")

    monkeypatch.setattr(server, "_make_clients", lambda: (fake_nb, fake_snmp, fake_engine, "drop"))
    server._refresh_device_counts()

    with server._module_mismatch_lock:
        assert server._module_mismatch["only_in_netbox"] == ["stale_module"]
        assert server._module_mismatch["only_in_snmp"]   == ["new_module"]


# ── device-count refresh leader election ────────────────────────────────────────

def test_acquire_device_count_leadership_succeeds_when_unclaimed() -> None:
    server._release_device_count_leadership()
    try:
        assert server._acquire_device_count_leadership() is True
        with open(server._DEVICE_COUNT_LEADER_FILE) as f:
            assert f.read().strip() == str(os.getpid())
    finally:
        server._release_device_count_leadership()


def test_acquire_device_count_leadership_fails_when_leader_alive() -> None:
    server._release_device_count_leadership()
    try:
        assert server._acquire_device_count_leadership() is True
        assert server._acquire_device_count_leadership() is False  # our own PID is alive
    finally:
        server._release_device_count_leadership()


def test_acquire_device_count_leadership_reclaims_stale_lock() -> None:
    server._release_device_count_leadership()
    try:
        with open(server._DEVICE_COUNT_LEADER_FILE, "w") as f:
            f.write("999999999")  # PID that (almost certainly) doesn't exist
        assert server._acquire_device_count_leadership() is True
        with open(server._DEVICE_COUNT_LEADER_FILE) as f:
            assert f.read().strip() == str(os.getpid())
    finally:
        server._release_device_count_leadership()


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


def test_run_probe_forwards_dry_run_override_to_modulator(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )
    monkeypatch.setattr(server, "_DRY_RUN", False)

    seen_kwargs = {}

    class FakeModulator:
        def __init__(self, *a, **kw):
            seen_kwargs.update(kw)

        def run(self, devices, callbacks=None):
            return []

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.2", lambda nb: [], dry_run=True)
    assert seen_kwargs["dry_run"] is True  # overrides server-wide _DRY_RUN=False for this call only


def test_run_probe_returns_none_when_no_slot_frees_up_in_time() -> None:
    assert server._probe_semaphore.acquire(blocking=False)  # occupy the only slot
    try:
        server._in_flight.add("host:busy")
        server.probe_jobs_in_flight.inc()
        result = server._run_probe("host:busy", lambda nb: ["dev1"], acquire_timeout=0.05)
    finally:
        server._probe_semaphore.release()

    assert result is None
    assert "host:busy" not in server._in_flight  # bookkeeping still cleared on timeout


def test_run_probe_swallows_infra_failure_by_default(monkeypatch) -> None:
    def boom():
        raise RuntimeError("netbox unreachable")

    monkeypatch.setattr(server, "_make_clients", boom)
    server._in_flight.add("host:10.0.0.3")

    result = server._run_probe("host:10.0.0.3", lambda nb: ["dev1"])

    assert result == []
    assert "host:10.0.0.3" not in server._in_flight


def test_run_probe_reraises_infra_failure_when_requested(monkeypatch) -> None:
    def boom():
        raise RuntimeError("netbox unreachable")

    monkeypatch.setattr(server, "_make_clients", boom)
    server._in_flight.add("host:10.0.0.4")

    with pytest.raises(RuntimeError, match="netbox unreachable"):
        server._run_probe("host:10.0.0.4", lambda nb: ["dev1"], reraise=True)

    # semaphore + in-flight bookkeeping still cleaned up despite the raise
    assert "host:10.0.0.4" not in server._in_flight
    assert server._probe_semaphore.acquire(blocking=False)
    server._probe_semaphore.release()


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


def test_index_shows_pod_wide_max_concurrent(monkeypatch) -> None:
    monkeypatch.setattr(server, "_MAX_CONCURRENT", 2)
    monkeypatch.setattr(server, "_WORKERS", 4)
    html = asyncio.run(server.index())
    assert "pod-wide across 4 workers" in html
    assert "<b>8</b> pod-wide" in html


def test_index_shows_module_mismatch_when_present() -> None:
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = ["stale_module"]
        server._module_mismatch["only_in_snmp"]   = ["new_module"]
    try:
        html = asyncio.run(server.index())
    finally:
        with server._module_mismatch_lock:
            server._module_mismatch["only_in_netbox"] = []
            server._module_mismatch["only_in_snmp"]   = []

    assert "stale_module" in html
    assert "new_module" in html
    assert "mismatch" in html


def test_index_shows_in_sync_when_no_mismatch() -> None:
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = []
        server._module_mismatch["only_in_snmp"]   = []
    html = asyncio.run(server.index())
    assert "in sync" in html


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
