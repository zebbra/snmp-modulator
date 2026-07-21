"""Unit tests for Modulator.process_device — auth resolution, module policy
handling, on_fail/on_success handler dispatch, and the unreachable guard.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_process_device.py
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import DeviceInfo, MappingEngine, Modulator, ModuleTestResult


class FakeNetboxClient:
    """Records every write the Modulator makes; no real HTTP/pynetbox calls."""

    def __init__(self):
        self._valid_modules = None
        self.tag_updates: list = []
        self.module_updates: list = []
        self.auth_updates: list = []
        self.polling_updates: list = []

    def get_polling_step_values(self, field_name):
        return None

    def update_auth_profile(self, device_id, profile):
        self.auth_updates.append((device_id, profile))

    def apply_tag_changes(self, device_id, add_tags, remove_tags):
        self.tag_updates.append((device_id, list(add_tags), list(remove_tags)))

    def update_snmp_modules(self, device_id, modules, add_tags=(), remove_tags=(),
                            polling_interval=None, polling_timeout=None):
        self.module_updates.append((device_id, list(modules), list(add_tags), list(remove_tags)))

    def update_polling(self, device_id, interval=None, timeout=None):
        self.polling_updates.append((device_id, interval, timeout))


class FakeSnmpExporterClient:
    """modules/auths are pre-seeded; probe()/probe_auth() are scripted per test."""

    def __init__(self, modules=(), auths=(), probe_results=None, working_auths=()):
        self.modules = list(modules)
        self.auths = list(auths)
        self._probe_results = probe_results or {}   # module -> ModuleTestResult
        self._working_auths = set(working_auths)
        self._session = SimpleNamespace(get=lambda url, timeout=10: SimpleNamespace(status_code=200))

    def probe_auth(self, target, auth, canary_module):
        return auth in self._working_auths

    def probe(self, target, module, auth):
        return self._probe_results.get(
            module, ModuleTestResult(module=module, useful=False, metric_count=0, duration_seconds=0.1)
        )


def _engine(tmp_path, text: str) -> MappingEngine:
    path = tmp_path / "mapping.yaml"
    path.write_text(text)
    return MappingEngine(str(path))


def _device(current_modules=(), snmp_auth_profile="", nb_device=None, **kw) -> DeviceInfo:
    return DeviceInfo(
        id=kw.pop("id", 1),
        name=kw.pop("name", "sw1"),
        primary_ip=kw.pop("primary_ip", "10.0.0.1"),
        snmp_auth_profile=snmp_auth_profile,
        current_modules=list(current_modules),
        nb_device=nb_device if nb_device is not None else SimpleNamespace(),
        **kw,
    )


# ── on_fail handlers must fire on early-return auth-failure paths ─────────────

MAPPING_LAST_RESORT = """
auth:
  policy: drop
defaults:
  auth:
    try: [_ALL]
rules:
  - name: last-resort
    match: {}
    on_fail:
      add_tag: [fixme-snmp]
"""


def test_auth_all_candidates_fail_applies_on_fail_tag(tmp_path) -> None:
    # Regression: _apply_handlers used to be called with [] instead of the
    # matched rules, so the fixme-snmp tag was never applied here.
    engine = _engine(tmp_path, MAPPING_LAST_RESORT)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(modules=["if_mib"], auths=["public_v2", "private_v2"])
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device()
    result = mod.process_device(dev)
    assert result.error == "no working auth profile found"
    assert nb.tag_updates == [(1, ["fixme-snmp"], [])]


MAPPING_NO_AUTH_CANDIDATES = """
auth:
  policy: try
rules:
  - name: last-resort
    match: {}
    on_fail:
      add_tag: [fixme-snmp]
"""


def test_no_auth_candidates_configured_applies_on_fail_tag(tmp_path) -> None:
    # Same bug, second call site: auth_policy=try/drop with an empty
    # defaults.auth.try list.
    engine = _engine(tmp_path, MAPPING_NO_AUTH_CANDIDATES)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(modules=["if_mib"], auths=[])
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device()
    result = mod.process_device(dev)
    assert result.error == "no auth candidates configured"
    assert nb.tag_updates == [(1, ["fixme-snmp"], [])]


# ── block:_ALL veto must survive module_policy=use/try ─────────────────────────

MAPPING_BLOCK_ALL_USE = """
modules:
  policy: use
rules:
  - name: no-snmp
    match:
      role.slug: "wireless-ap"
    modules:
      block: [_ALL]
    auth:
      use: public_v2
"""


def test_block_all_veto_not_resurrected_by_module_policy_use(tmp_path) -> None:
    # Regression: block_set previously held the literal "_ALL" sentinel, so
    # `existing = current_modules - block_set` didn't remove anything and
    # module_policy=use silently resurrected the vetoed modules.
    engine = _engine(tmp_path, MAPPING_BLOCK_ALL_USE)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(modules=["if_mib"], auths=["public_v2"])
    mod = Modulator(nb, snmp, engine, module_policy="use")
    dev = _device(
        current_modules=["if_mib", "legacy_module"],
        snmp_auth_profile="public_v2",
        nb_device=SimpleNamespace(role=SimpleNamespace(slug="wireless-ap")),
    )
    result = mod.process_device(dev)
    assert result.final_modules == []
    assert result.changed is True
    assert nb.module_updates == [(1, [], [], [])]


# ── successful probe writes the new module set ─────────────────────────────────

MAPPING_SUCCESS = """
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    add: [if_mib]
    try: [entity_sensor]
"""


def test_process_device_success_writes_new_module_set(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_SUCCESS)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib", "entity_sensor"],
        auths=[],
        probe_results={
            "entity_sensor": ModuleTestResult(
                module="entity_sensor", useful=True, metric_count=5, duration_seconds=1.2
            ),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)
    assert result.final_modules == ["entity_sensor", "if_mib"]
    assert result.changed is True
    assert result.auth_changed is False
    assert nb.module_updates == [(1, ["entity_sensor", "if_mib"], [], [])]


# ── unreachable guard preserves the existing module list ───────────────────────

MAPPING_UNREACHABLE = """
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    try: [entity_sensor, if_mib]
"""


def test_unreachable_guard_preserves_existing_modules_when_all_probes_useless(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_UNREACHABLE)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(modules=["entity_sensor", "if_mib"], auths=[])
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(current_modules=["entity_sensor", "if_mib"], snmp_auth_profile="public_v2")
    result = mod.process_device(dev)
    assert result.unreachable is True
    assert result.final_modules == ["entity_sensor", "if_mib"]
    assert result.changed is False
    assert nb.module_updates == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
