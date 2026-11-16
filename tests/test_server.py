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


def _index_html() -> str:
    from starlette.requests import Request
    req = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": []})
    return server.index(req).body.decode()


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


# ── liveness gate ────────────────────────────────────────────────────────────────

def test_fetch_liveness_or_none_disabled_without_url(monkeypatch) -> None:
    monkeypatch.setattr(server, "_LIVENESS_URL", None)
    assert server._fetch_liveness_or_none() is None


def test_fetch_liveness_or_none_returns_map_and_sets_gauge_on_success(monkeypatch) -> None:
    monkeypatch.setattr(server, "_LIVENESS_URL", "http://vm")
    monkeypatch.setattr(server, "fetch_liveness", lambda *a, **kw: {"sw1": True, "sw2": False})

    result = server._fetch_liveness_or_none()

    assert result == {"sw1": True, "sw2": False}
    assert server._metric_value("modulator_liveness_query_up") == 1


def test_fetch_liveness_or_none_fails_open_and_clears_gauge_on_error(monkeypatch) -> None:
    monkeypatch.setattr(server, "_LIVENESS_URL", "http://vm")

    def boom(*a, **kw):
        raise RuntimeError("vmselect unreachable")

    monkeypatch.setattr(server, "fetch_liveness", boom)

    result = server._fetch_liveness_or_none()

    assert result is None
    assert server._metric_value("modulator_liveness_query_up") == 0


def test_run_probe_only_queries_liveness_for_batch_runs(monkeypatch) -> None:
    monkeypatch.setattr(
        server, "_make_clients",
        lambda: (SimpleNamespace(), SimpleNamespace(), SimpleNamespace(), "drop"),
    )
    calls = []
    monkeypatch.setattr(server, "_fetch_liveness_or_none", lambda: calls.append(1) or {"sw1": False})

    class FakeModulator:
        def __init__(self, *a, **kw):
            pass

        def run(self, devices, callbacks=None, on_module_result=None):
            return []

    monkeypatch.setattr(server, "Modulator", FakeModulator)

    server._run_probe("host:10.0.0.7", lambda nb: [], honor_pins=False)
    assert calls == []   # explicit single host — never queried

    server._run_probe("netbox:role=switch", lambda nb: [])
    assert calls == [1]   # batch — queried once


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
        html = _index_html()
    finally:
        server._in_flight.discard("host:10.0.0.1")

    assert "host:10.0.0.1" in html
    assert "public_v2" in html
    assert "if_mib" in html


def test_index_shows_pod_wide_max_concurrent(monkeypatch) -> None:
    monkeypatch.setattr(server, "_MAX_CONCURRENT", 2)
    monkeypatch.setattr(server, "_WORKERS", 4)
    html = _index_html()
    assert "<b>8</b> pod-wide across 4 workers" in html


def test_index_shows_module_mismatch_when_present() -> None:
    with server._module_mismatch_lock:
        server._module_mismatch["only_in_netbox"] = ["stale_module"]
        server._module_mismatch["only_in_snmp"]   = ["new_module"]
    try:
        html = _index_html()
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
    html = _index_html()
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


def _patch_match_clients(monkeypatch, tmp_path, device):
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(_RULES_MAPPING)
    engine = server.MappingEngine(str(mapping))
    nb = SimpleNamespace(get_device_by_id=lambda device_id: device if device and device.id == device_id else None)
    snmp = SimpleNamespace(modules=["cisco_generic", "if_full", "system"], auths=[])
    monkeypatch.setattr(server, "_make_clients", lambda: (nb, snmp, engine, engine.module_policy))


def test_rules_match_returns_evaluation_for_device(tmp_path, monkeypatch) -> None:
    from modulator import DeviceInfo

    nb_device = SimpleNamespace(device_type=SimpleNamespace(manufacturer=SimpleNamespace(slug="cisco")), tags=[])
    device = DeviceInfo(id=5, name="sw5", primary_ip="10.0.0.5", snmp_auth_profile="",
                        current_modules=[], nb_device=nb_device)
    _patch_match_clients(monkeypatch, tmp_path, device)

    result = asyncio.run(server.rules_match(device_id=5))

    assert result["device"]["name"] == "sw5"
    assert [r["name"] for r in result["matched_rules"]] == ["Cisco generic"]
    assert result["modules"]["try"] == ["cisco_generic"]
    assert result["version"] == server.__version__


def test_rules_match_unknown_device_is_404(tmp_path, monkeypatch) -> None:
    _patch_match_clients(monkeypatch, tmp_path, None)

    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.rules_match(device_id=99))
    assert exc_info.value.status_code == 404


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


# ── /modules/add|remove|replace ──────────────────────────────────────────────

def _edit_engine(tmp_path):
    from modulator import MappingEngine
    path = tmp_path / "mapping.yaml"
    path.write_text("pin_tag: pin-snmp\nmodules:\n  field: snmp_exporter_module\nrules: []\n")
    return MappingEngine(str(path))


def _edit_device(id, modules):
    from modulator import DeviceInfo
    return DeviceInfo(
        id=id, name=f"sw{id}", primary_ip=f"10.0.0.{id}", snmp_auth_profile="v2",
        current_modules=list(modules), nb_device=SimpleNamespace(tags=[]),
    )


class FakeEditNetboxClient:
    def __init__(self, valid=None):
        self._valid_modules = valid
        self._valid_modules_fast = None
        self.bulk_calls: list = []

    def bulk_set_modules(self, field_name, updates, changelog_message, chunk_size=100):
        self.bulk_calls.append((field_name, dict(updates), changelog_message))
        return {}


def _request(query: str):
    from starlette.requests import Request
    return Request({"type": "http", "method": "POST", "path": "/", "query_string": query.encode(), "headers": []})


class FakeBackgroundTasks:
    def __init__(self):
        self.tasks: list = []

    def add_task(self, fn, *args, **kwargs):
        self.tasks.append((fn, args, kwargs))


@pytest.fixture
def edit_env(tmp_path, monkeypatch):
    engine = _edit_engine(tmp_path)
    nb = FakeEditNetboxClient(valid=frozenset({"if_full", "if_updown_state", "if_status", "cisco-generic"}))
    fetched: list = []

    def get_devices(**kw):
        fetched.append(kw)
        return [_edit_device(1, ["if_full"]), _edit_device(2, ["if_status"])]

    nb.get_devices = get_devices
    snmp = SimpleNamespace(modules=["if_full", "if_updown_state", "if_status", "cisco-generic"])
    monkeypatch.setattr(server, "_make_clients", lambda: (nb, snmp, engine, "drop"))
    monkeypatch.setattr(server, "_EDIT_JOB_DIR", str(tmp_path / "jobs"))
    return SimpleNamespace(nb=nb, fetched=fetched)


def _start(endpoint, query: str):
    bg = FakeBackgroundTasks()
    resp = asyncio.run(endpoint(_request(query), bg))
    return resp, bg


def _run_queued(bg) -> None:
    for fn, args, kwargs in bg.tasks:
        fn(*args, **kwargs)


def test_modules_add_runs_job_and_result_is_pollable(edit_env) -> None:
    resp, bg = _start(server.modules_add, "module=if_updown_state&cf_snmp_exporter_module=if_full")
    job = resp["job"]
    assert resp["status"] == "running" and resp["result_url"] == f"/modules/result?job={job}"

    running = asyncio.run(server.modules_result(job=job))
    assert running.status_code == 202

    _run_queued(bg)
    done = asyncio.run(server.modules_result(job=job))
    assert done["status"] == "done"
    assert done["summary"]["changed"] == 2
    assert edit_env.fetched == [{"cf_snmp_exporter_module": "if_full"}]
    assert edit_env.nb.bulk_calls[0][1] == {1: ["if_full", "if_updown_state"], 2: ["if_status", "if_updown_state"]}


def test_modules_add_requires_a_filter(edit_env) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        _start(server.modules_add, "module=if_updown_state")
    assert exc_info.value.status_code == 400


def test_modules_add_rejects_unknown_module_before_queueing(edit_env) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        _start(server.modules_add, "module=if_typo&site=dc1")
    assert exc_info.value.status_code == 400
    assert "if_typo" in exc_info.value.detail


def test_modules_remove_narrows_filter_to_devices_carrying_the_module(edit_env) -> None:
    resp, bg = _start(server.modules_remove, "module=cisco-generic")
    assert resp["filter"] == {"cf_snmp_exporter_module": "cisco-generic"}
    resp, _ = _start(server.modules_remove, "module=cisco-generic,if_status&site=dc1")
    assert resp["filter"] == {"site": "dc1", "cf_snmp_exporter_module": ["cisco-generic", "if_status"]}


def test_modules_replace_only_touches_devices_that_had_an_old_module(edit_env) -> None:
    resp, bg = _start(server.modules_replace, "old=if_status&new=if_full")
    _run_queued(bg)
    done = asyncio.run(server.modules_result(job=resp["job"]))
    assert done["summary"]["changed"] == 1
    assert edit_env.nb.bulk_calls[0][1] == {2: ["if_full"]}


def test_modules_replace_rejects_overlap(edit_env) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        _start(server.modules_replace, "old=if_full&new=if_full")
    assert exc_info.value.status_code == 400


def test_modules_result_without_job_lists_jobs_newest_first(edit_env) -> None:
    assert asyncio.run(server.modules_result()) == {"jobs": []}
    first, bg = _start(server.modules_add, "module=if_updown_state&cf_snmp_exporter_module=if_full")
    _run_queued(bg)
    second, _ = _start(server.modules_remove, "module=cisco-generic")

    jobs = asyncio.run(server.modules_result())["jobs"]
    assert [j["job"] for j in jobs] == [second["job"], first["job"]]
    assert [j["status"] for j in jobs] == ["running", "done"]
    assert "devices" not in jobs[1] and jobs[1]["summary"]["changed"] == 2
    assert jobs[1]["result_url"] == f"/modules/result?job={first['job']}"


def test_modules_result_404_for_unknown_job(edit_env) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        asyncio.run(server.modules_result(job="0" * 32))
    assert exc_info.value.status_code == 404


# ── /probe/run ───────────────────────────────────────────────────────────────

class FakeRunModulator:
    """Stands in for Modulator: one canned result per device, records commits."""
    instances: list = []

    def __init__(self, nb, snmp, engine, dry_run=False, **kwargs):
        self.dry_run = dry_run
        self.probed: list = []
        self.committed: list = []
        FakeRunModulator.instances.append(self)

    def run(self, devices, callbacks=None, **kwargs):
        from modulator import ModulationResult, ModuleTestResult
        device = devices[0]
        self.probed.append(device.id)
        if device.id == 3:
            return [ModulationResult(device.id, device.name, ["if_status"], ["if_status"], False, [],
                                     auth_profile="v2", unreachable=True)]
        return [ModulationResult(
            device.id, device.name, sorted(device.current_modules), ["if_full"], True,
            [ModuleTestResult("if_full", True, 10, 0.5)], auth_profile="v3", auth_changed=True,
        )]

    def commit(self, result, log=None):
        self.committed.append(result.device_id)


def _run_device(id, modules, tags=()):
    from modulator import DeviceInfo
    return DeviceInfo(
        id=id, name=f"sw{id}", primary_ip=f"10.0.0.{id}", snmp_auth_profile="v2",
        current_modules=list(modules), nb_device=SimpleNamespace(tags=[SimpleNamespace(slug=t) for t in tags]),
    )


@pytest.fixture
def run_env(tmp_path, monkeypatch):
    engine = _edit_engine(tmp_path)
    nb = SimpleNamespace(devices=[
        _run_device(1, ["if_status"]), _run_device(2, ["if_status"], tags=["pin-snmp"]),
        _run_device(3, ["if_status"]), _run_device(4, ["if_status"]),
    ])

    def get_devices(**kw):
        ids = kw.get("id")
        ids = None if ids is None else {int(i) for i in (ids if isinstance(ids, list) else [ids])}
        return [d for d in nb.devices if ids is None or d.id in ids]

    nb.get_devices = get_devices
    monkeypatch.setattr(server, "_make_clients", lambda: (nb, SimpleNamespace(), engine, "drop"))
    monkeypatch.setattr(server, "_RUN_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(server, "Modulator", FakeRunModulator)
    monkeypatch.setattr(server, "_fetch_liveness_or_none", lambda: None)
    started: list = []
    monkeypatch.setattr(server, "_start_run_worker", lambda run, devices: started.append((run, devices)))
    FakeRunModulator.instances = []
    return SimpleNamespace(nb=nb, started=started)


def _post_run(query: str, dry_run=True, limit=None):
    return asyncio.run(server.probe_run(_request(query), dry_run=dry_run, limit=limit))


def _work(run_env) -> None:
    run, devices = run_env.started.pop()
    server._probe_run_worker(run, devices)


def test_probe_run_requires_a_filter(run_env) -> None:
    with pytest.raises(server.HTTPException) as exc_info:
        _post_run("dry_run=true")
    assert exc_info.value.status_code == 400


def test_probe_run_status_none_before_any_run(run_env) -> None:
    assert asyncio.run(server.probe_run_status())["status"] == "none"


def test_probe_run_caps_and_counts_pinned(run_env) -> None:
    resp = _post_run("site=dc1", limit=2)
    assert resp["status"] == "running"
    assert {k: resp[k] for k in ("selected", "queued", "over_limit", "pinned")} == \
        {"selected": 4, "queued": 2, "over_limit": 1, "pinned": 1}
    snap = asyncio.run(server.probe_run_status())
    assert [(d["device_id"], d["status"]) for d in snap["devices"]] == [(1, "queued"), (2, "skipped"), (3, "queued")]
    assert snap["devices"][1]["reason"] == "pinned"


def test_probe_run_second_post_while_running_is_409(run_env) -> None:
    _post_run("site=dc1")
    with pytest.raises(server.HTTPException) as exc_info:
        _post_run("site=dc1")
    assert exc_info.value.status_code == 409 and exc_info.value.detail == "run active"


def test_probe_run_dry_run_reports_per_device_results(run_env) -> None:
    _post_run("site=dc1")
    _work(run_env)
    snap = asyncio.run(server.probe_run_status())
    assert snap["status"] == "done" and snap["dry_run"] is True
    assert {k: snap[k] for k in ("total", "done", "remaining", "ok", "skipped", "unreachable", "changed")} == \
        {"total": 4, "done": 4, "remaining": 0, "ok": 2, "skipped": 1, "unreachable": 1, "changed": 2}
    first = snap["devices"][0]
    assert first["previous_modules"] == ["if_status"] and first["final_modules"] == ["if_full"]
    assert (first["auth_profile_old"], first["auth_profile_new"]) == ("v2", "v3")
    assert first["changed"] is True and first["source"] == "probe" and first["duration_s"] is not None
    assert snap["devices"][2]["status"] == "unreachable"
    # the lock is gone, a new run can start
    assert _post_run("site=dc1")["status"] == "running"


def test_probe_run_apply_commits_from_cache_without_probing(run_env) -> None:
    _post_run("site=dc1")
    _work(run_env)
    run_env.nb.devices[3] = _run_device(4, ["if_status", "if_mib"])   # changed in NetBox since the dry run
    _post_run("id=1&id=4", dry_run=False)
    _work(run_env)
    apply = FakeRunModulator.instances[-1]
    assert apply.committed == [1] and apply.probed == [4]
    sources = {d["device_id"]: d["source"] for d in asyncio.run(server.probe_run_status())["devices"]}
    assert sources[1] == "cache" and sources[4] == "probe"


def test_probe_run_cache_expires(run_env, monkeypatch) -> None:
    _post_run("site=dc1")
    _work(run_env)
    monkeypatch.setattr(server, "_RUN_CACHE_TTL", -1)
    _post_run("id=1", dry_run=False)
    _work(run_env)
    assert FakeRunModulator.instances[-1].probed == [1]


def test_probe_run_cancel_drops_devices_not_started(run_env) -> None:
    _post_run("site=dc1")
    snap = asyncio.run(server.probe_run_cancel())
    assert snap["status"] == "running"
    _work(run_env)
    snap = asyncio.run(server.probe_run_status())
    assert snap["status"] == "cancelled" and snap["cancelled"] == 3


def test_probe_run_interrupted_when_lock_owner_is_gone(run_env) -> None:
    _post_run("site=dc1")
    with open(server._run_path("run.lock"), "w") as f:
        f.write("999999999 0")
    assert asyncio.run(server.probe_run_status())["status"] == "interrupted"
    assert _post_run("site=dc1")["status"] == "running"


def test_index_shows_bulk_probe_run_and_module_edits(run_env, tmp_path, monkeypatch) -> None:
    _post_run("site=dc1")
    _work(run_env)
    monkeypatch.setattr(server, "_EDIT_JOB_DIR", str(tmp_path / "jobs"))
    server._write_edit_job("a" * 32, {
        "status": "running", "job": "a" * 32, "op": "add", "started": time.time(), "profile": "normal",
        "add": ["if_updown_state"], "remove": [], "filter": {"site": "dc1"}, "dry_run": False,
    })
    html = _index_html()
    assert "if_status → <b>if_full</b>" in html and "v2 → <b>v3</b>" in html
    assert "unreachable" in html and "pinned" in html
    assert "add <span class=\"muted\">+</span>if_updown_state" in html


def test_docs_served_without_cdn_when_assets_present(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(server, "_SWAGGER_ASSETS", {"swagger_js_url": "/static/swagger/swagger-ui-bundle.js",
                                                   "swagger_css_url": "/static/swagger/swagger-ui.css"})
    html = asyncio.run(server.swagger_ui()).body.decode()
    assert "/static/swagger/swagger-ui-bundle.js" in html and "cdn.jsdelivr" not in html
