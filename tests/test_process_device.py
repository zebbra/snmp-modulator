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

from modulator import DeviceInfo, MappingEngine, ModulationResult, Modulator, ModuleTestResult


class FakeNetboxClient:
    """Records every write the Modulator makes; no real HTTP/pynetbox calls."""

    def __init__(self):
        self._valid_modules = None
        self.tag_updates: list = []
        self.module_updates: list = []
        self.auth_updates: list = []
        self.polling_updates: list = []
        self.fast_module_updates: list = []
        self.fast_polling_updates: list = []
        self.touch_calls: list = []

    def get_polling_step_values(self, field_name):
        return None

    def touch(self, device_id):
        self.touch_calls.append(device_id)

    def update_auth_profile(self, device_id, profile):
        self.auth_updates.append((device_id, profile))

    def apply_tag_changes(self, device_id, add_tags, remove_tags):
        self.tag_updates.append((device_id, list(add_tags), list(remove_tags)))

    def update_snmp_modules(self, device_id, modules, add_tags=(), remove_tags=(),
                            polling_interval=None, polling_timeout=None,
                            fast_modules=None, fast_polling_interval=None, fast_polling_timeout=None):
        self.module_updates.append((device_id, list(modules), list(add_tags), list(remove_tags)))
        self.fast_module_updates.append((device_id, list(fast_modules) if fast_modules is not None else None))
        self.polling_updates.append((device_id, polling_interval, polling_timeout))
        self.fast_polling_updates.append((device_id, fast_polling_interval, fast_polling_timeout))

    def update_polling(self, device_id, interval=None, timeout=None, fast_interval=None, fast_timeout=None):
        self.polling_updates.append((device_id, interval, timeout))
        self.fast_polling_updates.append((device_id, fast_interval, fast_timeout))


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


# ── canary short-circuit ──────────────────────────────────────────────────────

MAPPING_CANARY = """
auth:
  policy: use
  probe_module: system
modules:
  policy: drop
defaults:
  modules:
    try: [system, if_mib, cisco_generic]
"""


def test_canary_failure_skips_remaining_module_probes(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_CANARY)
    nb = FakeNetboxClient()

    probed: list = []

    class TrackingSnmp(FakeSnmpExporterClient):
        def probe(self, target, module, auth):
            probed.append(module)
            return super().probe(target, module, auth)

    snmp = TrackingSnmp(
        modules=["system", "if_mib", "cisco_generic"],
        auths=[],
        probe_results={
            "system": ModuleTestResult(
                module="system", useful=False, metric_count=0, duration_seconds=30.0,
                error="Read timed out",
            ),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(current_modules=["if_mib"], snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert probed == ["system"]  # if_mib/cisco_generic never probed once the canary failed
    assert result.unreachable is True
    assert result.final_modules == ["if_mib"]
    assert nb.module_updates == []


# ── modules unknown to snmp-exporter are skipped, not probed ───────────────────

MAPPING_UNKNOWN_MODULE = """
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    add: [typo_module_add]
    try: [if_mib, typo_module_try]
"""


def test_module_unknown_to_snmp_exporter_is_never_probed(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_UNKNOWN_MODULE)
    nb = FakeNetboxClient()

    probed: list = []

    class TrackingSnmp(FakeSnmpExporterClient):
        def probe(self, target, module, auth):
            probed.append(module)
            return super().probe(target, module, auth)

    snmp = TrackingSnmp(
        modules=["if_mib"],  # snmp-exporter has never heard of typo_module_add/try
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert probed == ["if_mib"]  # typo_module_try never sent to snmp-exporter
    assert result.final_modules == ["if_mib"]  # typo_module_add never written either
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


# ── stale/unparseable existing polling field must not abort the device ────────

MAPPING_POLLING = """
auth:
  policy: use
modules:
  policy: drop
  interval_field: snmp_polling_interval
  timeout_field: snmp_polling_timeout
defaults:
  modules:
    try: [if_mib]
"""


def test_process_device_survives_stale_unparseable_polling_field(tmp_path) -> None:
    # Regression: a device whose snmp_polling_interval custom field holds a
    # legacy value ("1h") no longer in the NetBox choice set used to blow up
    # _parse_duration and abort the whole device — silently discarding an
    # otherwise-valid module update.
    engine = _engine(tmp_path, MAPPING_POLLING)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 180, 300]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=1.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(current_modules=[], snmp_auth_profile="public_v2", polling_interval="1h")
    result = mod.process_device(dev)

    assert result.error is None
    assert result.changed is True


# ── fast polling profile ─────────────────────────────────────────────────────────

MAPPING_FAST = """
auth:
  policy: use
modules:
  policy: drop
  fast:
    field: snmp_exporter_module_fast
defaults:
  modules:
    try: [if_mib]
rules:
  - name: fast-rule
    match: {}
    modules:
      fast:
        try: [if_traffic]
"""


def test_fast_profile_writes_separate_field_and_excludes_from_normal(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_FAST)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib", "if_traffic"],
        auths=[],
        probe_results={
            "if_mib":     ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2),
            "if_traffic": ModuleTestResult(module="if_traffic", useful=True, metric_count=5, duration_seconds=0.1),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.final_modules == ["if_mib"]
    assert result.final_modules_fast == ["if_traffic"]
    assert result.changed is True
    assert nb.module_updates == [(1, ["if_mib"], [], [])]
    assert nb.fast_module_updates == [(1, ["if_traffic"])]


def test_fast_profile_wins_when_module_also_in_normal_try(tmp_path) -> None:
    # A module resolved into the fast profile must never also end up in the
    # normal one, and must only be probed once even if both a default `try`
    # and a rule's `fast.try` name it.
    engine = _engine(tmp_path, """
auth:
  policy: use
modules:
  policy: drop
  fast:
    field: snmp_exporter_module_fast
defaults:
  modules:
    try: [if_mib, if_traffic]
rules:
  - name: fast-rule
    match: {}
    modules:
      fast:
        try: [if_traffic]
""")
    nb = FakeNetboxClient()
    probed: list = []

    class TrackingSnmp(FakeSnmpExporterClient):
        def probe(self, target, module, auth):
            probed.append(module)
            return super().probe(target, module, auth)

    snmp = TrackingSnmp(
        modules=["if_mib", "if_traffic"],
        auths=[],
        probe_results={
            "if_mib":     ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2),
            "if_traffic": ModuleTestResult(module="if_traffic", useful=True, metric_count=5, duration_seconds=0.1),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert sorted(probed) == ["if_mib", "if_traffic"]   # each probed exactly once
    assert result.final_modules == ["if_mib"]
    assert result.final_modules_fast == ["if_traffic"]


def test_fast_section_ignored_when_fast_field_not_configured(tmp_path) -> None:
    # A rule can declare modules.fast.try, but without modules.fast.field at
    # the top level nothing is written anywhere for it — and it's still probed
    # since it's in defaults.try, just resolved as a normal module.
    engine = _engine(tmp_path, """
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    try: [if_traffic]
rules:
  - name: fast-rule
    match: {}
    modules:
      fast:
        try: [if_traffic]
""")
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_traffic"],
        auths=[],
        probe_results={
            "if_traffic": ModuleTestResult(module="if_traffic", useful=True, metric_count=5, duration_seconds=0.1),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.final_modules == ["if_traffic"]
    assert result.final_modules_fast == []
    assert nb.fast_module_updates == [(1, None)]


MAPPING_INTERVAL_FLOOR = """
auth:
  policy: use
modules:
  policy: drop
  interval_field: snmp_polling_interval
  timeout_field: snmp_polling_timeout
  default_interval: 3m
  default_timeout: 2m
defaults:
  modules:
    try: [if_mib]
rules:
  - name: remote-site
    match: {}
    modules:
      interval: 15m
      timeout: 5m
"""


def test_rule_interval_floor_raises_recommendation_above_measured_duration(tmp_path) -> None:
    # A quick-responding device matched by a floor rule must still be bumped to
    # the floor — the floor isn't just "whatever measured duration implies".
    engine = _engine(tmp_path, MAPPING_INTERVAL_FLOOR)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 180, 300, 600, 900]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=1.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.polling_timeout == "5m"
    assert result.polling_interval == "15m"
    assert result.resolved_timeout == "5m"
    assert result.resolved_interval == "15m"
    assert result.final_modules == ["if_mib"]
    # module list also changed here — verify the recommendation actually reaches
    # the NetBox write call, not just the returned result object.
    assert nb.polling_updates == [(1, "15m", "5m")]
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


def test_interval_recovers_down_after_a_prior_slow_probe_inflated_it(tmp_path) -> None:
    # A previous run's slow probe pushed the device to 1h. This run's probe is
    # fast again — the recommendation must come back down to the mapping.yaml
    # floor (15m), not stay pinned at 1h forever just because 1h is currently
    # in NetBox and higher than the floor.
    engine = _engine(tmp_path, MAPPING_INTERVAL_FLOOR)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 180, 300, 600, 900, 3600]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=1.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(
        current_modules=["if_mib"], snmp_auth_profile="public_v2",
        polling_interval="1h", polling_timeout="5m",
    )
    result = mod.process_device(dev)

    assert result.polling_interval == "15m"   # decreased back to the floor
    assert result.polling_timeout is None      # already at the floor — no change needed
    assert result.resolved_interval == "15m"
    assert nb.polling_updates == [(1, "15m", None)]


def test_interval_never_drops_below_the_configured_floor(tmp_path) -> None:
    # Even an instant probe can't push the recommendation below the floor.
    engine = _engine(tmp_path, MAPPING_INTERVAL_FLOOR)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 180, 300, 600, 900, 3600]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(current_modules=["if_mib"], snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.resolved_interval == "15m"
    assert result.resolved_timeout == "5m"


def test_resolved_polling_reported_even_when_unchanged(tmp_path) -> None:
    # polling_interval/timeout stay None when nothing needs writing, but
    # resolved_interval/timeout should still report the effective value in
    # place — a caller previewing a device shouldn't see nulls just because
    # nothing changed.
    engine = _engine(tmp_path, MAPPING_INTERVAL_FLOOR)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 180, 300, 600, 900]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={
            "if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=1.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(
        current_modules=["if_mib"], snmp_auth_profile="public_v2",
        polling_interval="15m", polling_timeout="5m",
    )
    result = mod.process_device(dev)

    assert result.changed is False
    assert result.polling_interval is None
    assert result.polling_timeout is None
    assert result.resolved_interval == "15m"
    assert result.resolved_timeout == "5m"
    assert nb.module_updates == []


MAPPING_FAST_POLLING = """
auth:
  policy: use
modules:
  policy: drop
  fast:
    field: snmp_exporter_module_fast
    interval_field: snmp_polling_interval_fast
    timeout_field: snmp_polling_timeout_fast
    default_interval: 1m
    default_timeout: 20s
defaults:
  modules:
    try: [if_mib]
rules:
  - name: fast-rule
    match: {}
    modules:
      fast:
        try: [if_traffic]
"""


def test_resolved_polling_fast_reported_without_choice_sets(tmp_path) -> None:
    # No interval_field/timeout_field configured for the normal profile in this
    # mapping (calculation disabled there), but the fast profile's choice sets
    # are still available — resolved_interval_fast/timeout_fast should reflect
    # that independently, and final_modules_fast lists which modules are fast.
    engine = _engine(tmp_path, MAPPING_FAST_POLLING)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 120, 300]

    snmp = FakeSnmpExporterClient(
        modules=["if_mib", "if_traffic"],
        auths=[],
        probe_results={
            "if_mib":     ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2),
            "if_traffic": ModuleTestResult(module="if_traffic", useful=True, metric_count=5, duration_seconds=0.1),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.final_modules == ["if_mib"]
    assert result.final_modules_fast == ["if_traffic"]
    assert result.resolved_interval is None      # normal profile has no choice sets configured
    assert result.resolved_interval_fast == "1m"  # falls back to fast_default_interval
    assert result.resolved_timeout_fast == "30s"  # rounded up from fast_default_timeout (20s)


# ── Modulator.commit(): replay a resolved result without re-probing ────────────

MAPPING_COMMIT = """
auth:
  policy: use
modules:
  policy: drop
  fast:
    field: snmp_exporter_module_fast
defaults:
  modules:
    try: [if_mib]
"""


def _commit_modulator(tmp_path) -> tuple:
    engine = _engine(tmp_path, MAPPING_COMMIT)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(modules=["if_mib"], auths=[])
    return Modulator(nb, snmp, engine, module_policy="drop"), nb


def test_commit_writes_modules_tags_fast_and_auth_when_changed(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=["if_mib"], final_modules=["if_mib", "entity_sensor"],
        changed=True, test_results=[],
        auth_profile="public_v2", auth_changed=True,
        final_modules_fast=["if_traffic"],
        pending_add_tags=["snmp-ready"], pending_remove_tags=["discover"],
    )
    mod.commit(result)

    assert nb.auth_updates == [(7, "public_v2")]
    assert nb.module_updates == [(7, ["if_mib", "entity_sensor"], ["snmp-ready"], ["discover"])]
    assert nb.fast_module_updates == [(7, ["if_traffic"])]


def test_commit_applies_tags_only_when_modules_unchanged(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=["if_mib"], final_modules=["if_mib"],
        changed=False, test_results=[],
        pending_add_tags=["fixme-snmp"],
    )
    mod.commit(result)

    assert nb.tag_updates == [(7, ["fixme-snmp"], [])]
    assert nb.module_updates == []
    assert nb.touch_calls == []


def test_commit_touches_device_on_pure_noop_success(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=["if_mib"], final_modules=["if_mib"],
        changed=False,
        test_results=[ModuleTestResult(module="if_mib", useful=True, metric_count=3, duration_seconds=0.2)],
    )
    mod.commit(result)

    assert nb.touch_calls == [7]
    assert nb.tag_updates == []


def test_commit_skips_touch_when_unreachable(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=["if_mib"], final_modules=["if_mib"],
        changed=False,
        test_results=[ModuleTestResult(module="if_mib", useful=False, metric_count=0, duration_seconds=0.2)],
        unreachable=True,
    )
    mod.commit(result)

    assert nb.touch_calls == []


def test_commit_is_a_noop_on_errored_result(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=[], final_modules=[],
        changed=False, test_results=[], error="no working auth profile found",
    )
    mod.commit(result)

    assert nb.module_updates == [] and nb.tag_updates == [] and nb.auth_updates == [] and nb.touch_calls == []


def test_process_device_live_write_matches_commit(tmp_path) -> None:
    # process_device's non-dry-run path now delegates to commit() — verify the
    # end-to-end live flow still writes exactly as before the refactor.
    engine = _engine(tmp_path, MAPPING_COMMIT)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib"],
        auths=[],
        probe_results={"if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.3)},
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.final_modules == ["if_mib"]
    assert result.changed is True
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


MAPPING_BOTH_PROFILES_FLOOR = """
auth:
  policy: use
modules:
  policy: drop
  interval_field: snmp_polling_interval
  timeout_field: snmp_polling_timeout
  default_interval: 5m
  default_timeout: 2m
  fast:
    field: snmp_exporter_module_fast
    interval_field: snmp_polling_interval_fast
    timeout_field: snmp_polling_timeout_fast
    default_interval: 1m
    default_timeout: 20s
defaults:
  modules:
    try: [system]
rules:
  - name: group-specific
    match: {}
    modules:
      interval: 15m
      fast:
        interval: 5m
        try: [if_traffic]
"""


def test_normal_and_fast_polling_both_written_when_modules_change(tmp_path) -> None:
    # Regression check: a device matching rules with distinct normal/fast
    # interval floors and a changed module list must get BOTH profiles'
    # polling_interval/timeout in the actual NetBox write, not just one.
    engine = _engine(tmp_path, MAPPING_BOTH_PROFILES_FLOOR)
    nb = FakeNetboxClient()
    nb.get_polling_step_values = lambda field_name: [30, 60, 90, 120, 180, 240, 300, 600, 900]

    snmp = FakeSnmpExporterClient(
        modules=["system", "if_traffic"],
        auths=[],
        probe_results={
            "system":     ModuleTestResult(module="system", useful=True, metric_count=8, duration_seconds=9.5),
            "if_traffic": ModuleTestResult(module="if_traffic", useful=True, metric_count=2, duration_seconds=0.0),
        },
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop")
    dev = _device(snmp_auth_profile="public_v2")
    result = mod.process_device(dev)

    assert result.final_modules == ["system"]
    assert result.final_modules_fast == ["if_traffic"]
    assert result.polling_interval == "15m"
    assert result.polling_interval_fast == "5m"
    assert nb.module_updates == [(1, ["system"], [], [])]
    assert nb.fast_module_updates == [(1, ["if_traffic"])]
    # This is the exact bug report: verify BOTH interval writes actually reach
    # the NetBox call, not just the returned ModulationResult fields.
    assert nb.polling_updates == [(1, "15m", result.polling_timeout)]
    assert nb.fast_polling_updates == [(1, "5m", result.polling_timeout_fast)]


# ── pin_tag: skip a device entirely on batch runs, never on an explicit host ────

MAPPING_PIN_TAG = """
pin_tag: pin-snmp
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    try: [if_mib]
"""


def _tagged_device(*slugs, **kw) -> DeviceInfo:
    tags = [SimpleNamespace(slug=s) for s in slugs]
    return _device(nb_device=SimpleNamespace(tags=tags), snmp_auth_profile="public_v2", **kw)


def test_pinned_device_skipped_on_batch_run(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_PIN_TAG)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib"], auths=[],
        probe_results={"if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2)},
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop", honor_pins=True)
    dev = _tagged_device("pin-snmp", current_modules=["if_mib"])
    result = mod.process_device(dev)

    assert result.skipped == "pinned"
    assert result.error is None
    assert result.changed is False
    assert result.final_modules == ["if_mib"]   # untouched, not wiped
    assert nb.module_updates == []
    assert nb.auth_updates == []


def test_explicit_single_host_ignores_pin_tag(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_PIN_TAG)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib"], auths=[],
        probe_results={"if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2)},
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop", honor_pins=False)
    dev = _tagged_device("pin-snmp")
    result = mod.process_device(dev)

    assert result.skipped is None
    assert result.final_modules == ["if_mib"]
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


def test_untagged_device_processed_normally_even_with_pin_tag_configured(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_PIN_TAG)
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib"], auths=[],
        probe_results={"if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2)},
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop", honor_pins=True)
    dev = _tagged_device("some-other-tag")
    result = mod.process_device(dev)

    assert result.skipped is None
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


def test_pin_tag_disabled_by_default(tmp_path) -> None:
    # No pin_tag configured in mapping.yaml — even a device tagged "pin-snmp"
    # (a bare coincidence, or the tag exists in NetBox but this deployment
    # hasn't opted in) is processed normally.
    engine = _engine(tmp_path, """
auth:
  policy: use
modules:
  policy: drop
defaults:
  modules:
    try: [if_mib]
""")
    nb = FakeNetboxClient()
    snmp = FakeSnmpExporterClient(
        modules=["if_mib"], auths=[],
        probe_results={"if_mib": ModuleTestResult(module="if_mib", useful=True, metric_count=5, duration_seconds=0.2)},
    )
    mod = Modulator(nb, snmp, engine, module_policy="drop", honor_pins=True)
    dev = _tagged_device("pin-snmp")
    result = mod.process_device(dev)

    assert result.skipped is None
    assert nb.module_updates == [(1, ["if_mib"], [], [])]


def test_commit_is_a_noop_on_a_pinned_result(tmp_path) -> None:
    mod, nb = _commit_modulator(tmp_path)
    result = ModulationResult(
        device_id=7, device_name="sw1",
        previous_modules=["if_mib"], final_modules=["if_mib"],
        changed=False, test_results=[], skipped="pinned",
    )
    mod.commit(result)

    assert nb.module_updates == [] and nb.tag_updates == [] and nb.touch_calls == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
