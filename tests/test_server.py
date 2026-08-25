"""Unit tests for server.py — Prometheus registry isolation, filter-key
validation, and device-count refresh / probe-job bookkeeping.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_server.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import time
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

        def run(self, devices, callbacks=None, on_module_result=None):
            ran.append(devices)

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._in_flight.add("host:10.0.0.1")
    before = server.probe_running._value.get()
    server._run_probe("host:10.0.0.1", lambda nb: ["dev1"])
    after = server.probe_running._value.get()

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

        def run(self, devices, callbacks=None, on_module_result=None):
            return []

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.2", lambda nb: [], dry_run=True)
    assert seen_kwargs["dry_run"] is True  # overrides server-wide _DRY_RUN=False for this call only


def test_run_probe_forwards_honor_pins_to_modulator(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )
    seen_kwargs = {}

    class FakeModulator:
        def __init__(self, *a, **kw):
            seen_kwargs.update(kw)

        def run(self, devices, callbacks=None, on_module_result=None):
            return []

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.5", lambda nb: [], honor_pins=False)
    assert seen_kwargs["honor_pins"] is False

    server._run_probe("host:10.0.0.6", lambda nb: [])
    assert seen_kwargs["honor_pins"] is True  # default — batch/unspecified callers respect the pin


def test_run_probe_returns_none_when_no_slot_frees_up_in_time() -> None:
    assert server._probe_semaphore.acquire(blocking=False)  # occupy the only slot
    try:
        server._in_flight.add("host:busy")
        server.probe_queued.inc()
        before = server.probe_queue_depth._value.get()
        result = server._run_probe("host:busy", lambda nb: ["dev1"], acquire_timeout=0.05)
        after = server.probe_queue_depth._value.get()
    finally:
        server._probe_semaphore.release()

    assert result is None
    assert "host:busy" not in server._in_flight  # bookkeeping still cleared on timeout
    assert before == after  # queue_depth incremented while waiting, decremented after the timeout


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


# ── _run_probe: dry-run result cache ────────────────────────────────────────────

def test_run_probe_caches_results_on_dry_run(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )
    fake_result = SimpleNamespace(changed=True, error=None, unreachable=False)

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None, on_module_result=None):
            return [fake_result]

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.10", lambda nb: ["dev1"], dry_run=True)

    with server._dry_run_cache_lock:
        assert "host:10.0.0.10" in server._dry_run_cache
        _, cached = server._dry_run_cache["host:10.0.0.10"]
        assert cached == [fake_result]


def test_run_probe_commits_cached_dry_run_without_reprobing(monkeypatch) -> None:
    fake_result = SimpleNamespace(
        device_id=1, device_name="sw1", changed=True, error=None, unreachable=False,
    )
    with server._dry_run_cache_lock:
        server._dry_run_cache["host:10.0.0.11"] = (time.time(), [fake_result])

    committed = []

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None, on_module_result=None):
            raise AssertionError("must not re-probe when a fresh dry-run result is cached")

        def commit(self, result, log=None):
            committed.append(result)

    monkeypatch.setattr(server, "Modulator", FakeModulator)
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )

    def boom(nb):
        raise AssertionError("must not fetch devices when replaying a cached result")

    results = server._run_probe("host:10.0.0.11", boom, dry_run=False)

    assert committed == [fake_result]
    assert results == [fake_result]
    with server._dry_run_cache_lock:
        assert "host:10.0.0.11" not in server._dry_run_cache  # one-shot: consumed


def test_run_probe_reprobes_when_cached_dry_run_expired(monkeypatch) -> None:
    fake_result = SimpleNamespace(changed=False, error=None, unreachable=False)
    with server._dry_run_cache_lock:
        server._dry_run_cache["host:10.0.0.12"] = (time.time() - server._DRY_RUN_CACHE_TTL - 1, [fake_result])

    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )

    ran = []

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None, on_module_result=None):
            ran.append(devices)
            return []

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.12", lambda nb: ["dev1"], dry_run=False)

    assert ran == [["dev1"]]  # expired cache entry ignored — fell through to a real probe


# ── _run_probe: progress tracking + last-result cache ───────────────────────────

def test_run_probe_records_progress_and_last_result(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )
    fake_result = SimpleNamespace(changed=False, error=None, unreachable=False)
    seen_progress: list = []

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None, on_module_result=None):
            on_module_result(devices[0], "module-result-1")
            seen_progress.append(list(server._probe_progress["host:10.0.0.20"]))
            return [fake_result]

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.20", lambda nb: ["dev1"], dry_run=False)

    assert seen_progress == [["module-result-1"]]  # visible mid-run
    assert "host:10.0.0.20" not in server._probe_progress  # cleared once finished

    with server._last_result_lock:
        timestamp, dry_run, results = server._last_result_cache["host:10.0.0.20"]
    assert dry_run is False
    assert results == [fake_result]


# ── GET /probe/result ────────────────────────────────────────────────────────────

def test_probe_result_404_when_nothing_known(monkeypatch) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.probe_result(host="10.0.0.30"))
    assert exc_info.value.status_code == 404


def test_probe_result_running_reports_partial_progress() -> None:
    from modulator import ModuleTestResult

    server._in_flight.add("host:10.0.0.31")
    server._probe_progress["host:10.0.0.31"] = [
        ModuleTestResult(module="system", useful=True, metric_count=3, duration_seconds=0.2, profile="normal"),
    ]
    try:
        response = asyncio.run(server.probe_result(host="10.0.0.31"))
        assert response.status_code == 202
        body = json.loads(response.body)
        assert body["status"] == "running"
        assert body["result"]["test_results"][0]["module"] == "system"
        assert body["result"]["final_modules"] == []  # not known yet, but key is present
    finally:
        server._in_flight.discard("host:10.0.0.31")
        server._probe_progress.pop("host:10.0.0.31", None)


def test_probe_result_done_reports_full_result() -> None:
    from modulator import ModulationResult

    result = ModulationResult(
        device_id=1, device_name="sw1",
        previous_modules=[], final_modules=["if_full"], changed=True, test_results=[],
    )
    with server._last_result_lock:
        server._last_result_cache["host:10.0.0.32"] = (time.time(), True, [result])

    response = asyncio.run(server.probe_result(host="10.0.0.32"))
    assert response == {"status": "done", "host": "10.0.0.32", "dry_run": True, "result": server.asdict(result)}


def test_probe_result_404_when_last_result_expired() -> None:
    result = SimpleNamespace(changed=True, error=None, unreachable=False)
    with server._last_result_lock:
        server._last_result_cache["host:10.0.0.33"] = (
            time.time() - server._PROBE_RESULT_TTL - 1, False, [result],
        )

    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.probe_result(host="10.0.0.33"))
    assert exc_info.value.status_code == 404


# ── _metric_samples / _metric_value ─────────────────────────────────────────────

def test_metric_samples_reads_labeled_gauge_values() -> None:
    server.netbox_devices_by_auth.labels(profile="public_v2").set(7)
    assert server._metric_samples("modulator_netbox_devices_by_auth")[(("profile", "public_v2"),)] == 7


def test_metric_value_reads_unlabeled_gauge() -> None:
    server.probe_running.inc()
    try:
        assert server._metric_value("modulator_probe_running") >= 1
    finally:
        server.probe_running.dec()


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


# ── /rules ───────────────────────────────────────────────────────────────────

_RULES_MAPPING = """
modules:
  policy: drop
rules:
  - name: "Cisco generic"
    match:
      device_type.manufacturer.slug: "cisco"
    modules:
      try: [cisco_generic]
"""


def test_rules_json_returns_snapshot_from_mapping_file(tmp_path, monkeypatch) -> None:
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(_RULES_MAPPING)
    monkeypatch.setattr(server, "_MAPPING_FILE", str(mapping))

    result = asyncio.run(server.rules(format="json"))

    assert result["rules"][0]["name"] == "Cisco generic"
    assert result["rules"][0]["match"] == {"device_type.manufacturer.slug": "cisco"}


def test_rules_html_renders_a_browsable_page(tmp_path, monkeypatch) -> None:
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(_RULES_MAPPING)
    monkeypatch.setattr(server, "_MAPPING_FILE", str(mapping))

    response = asyncio.run(server.rules(format="html"))

    assert isinstance(response, server.HTMLResponse)
    body = response.body.decode()
    assert "Cisco generic" in body
    assert "cisco" in body


def test_rules_rejects_invalid_format(tmp_path, monkeypatch) -> None:
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(_RULES_MAPPING)
    monkeypatch.setattr(server, "_MAPPING_FILE", str(mapping))

    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.rules(format="xml"))
    assert exc_info.value.status_code == 400


def test_rules_surfaces_missing_mapping_file_as_500(monkeypatch) -> None:
    monkeypatch.setattr(server, "_MAPPING_FILE", "/nonexistent/mapping.yaml")

    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.rules(format="json"))
    assert exc_info.value.status_code == 500


# ── /stats, /health, and the module-mismatch/devices-by-label helpers ──────────

def test_module_mismatch_snapshot_uses_friendly_public_key_names() -> None:
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = ["stale_module"]
        server._module_mismatch["only_in_snmp"]   = ["new_module"]
    try:
        snap = server._module_mismatch_snapshot()
    finally:
        with server._module_mismatch_lock:
            server._module_mismatch["only_in_netbox"] = []
            server._module_mismatch["only_in_snmp"]   = []

    assert snap == {"netbox_only": ["stale_module"], "snmp_exporter_only": ["new_module"]}


def test_stats_returns_device_counts_and_module_mismatch() -> None:
    server.netbox_devices_by_auth.labels(profile="stats_test_profile").set(4)
    server.netbox_devices_by_module.labels(module="stats_test_module").set(7)
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = ["stale_module"]
        server._module_mismatch["only_in_snmp"]   = ["new_module", "other_module"]
    try:
        result = asyncio.run(server.stats())
    finally:
        with server._module_mismatch_lock:
            server._module_mismatch["only_in_netbox"] = []
            server._module_mismatch["only_in_snmp"]   = []

    assert result["devices_by_auth_profile"]["stats_test_profile"] == 4
    assert result["devices_by_module"]["stats_test_module"] == 7
    assert result["module_mismatch"]["netbox_only"] == ["stale_module"]
    assert result["module_mismatch"]["snmp_exporter_only"] == ["new_module", "other_module"]
    assert result["module_mismatch"]["netbox_only_count"] == 1
    assert result["module_mismatch"]["snmp_exporter_only_count"] == 2


def test_health_includes_module_mismatch_counts_but_not_full_lists() -> None:
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = ["a"]
        server._module_mismatch["only_in_snmp"]   = ["b", "c"]
    try:
        result = asyncio.run(server.health())
    finally:
        with server._module_mismatch_lock:
            server._module_mismatch["only_in_netbox"] = []
            server._module_mismatch["only_in_snmp"]   = []

    assert result["netbox_only_module_count"] == 1
    assert result["snmp_exporter_only_module_count"] == 2
    assert result["status"] == "ok"
    assert result["version"] == server.__version__
    assert "netbox_only" not in result  # /health stays a cheap, unauthenticated liveness check


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
