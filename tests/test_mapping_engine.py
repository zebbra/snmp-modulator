"""Unit tests for MappingEngine (rule evaluation, auth resolution, handlers)
and the duration/step helpers in modulator.py.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_mapping_engine.py
"""
from __future__ import annotations

import json
import logging
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import (
    DeviceInfo,
    MappingEngine,
    _current_duration_or_default,
    _format_duration,
    _parse_duration,
    _round_up_to_step,
    compare_module_sets,
)


def _engine(tmp_path, text: str) -> MappingEngine:
    path = tmp_path / "mapping.yaml"
    path.write_text(text)
    return MappingEngine(str(path))


def _device(nb_device=None, current_modules=(), snmp_auth_profile="", **kw) -> DeviceInfo:
    return DeviceInfo(
        id=kw.pop("id", 1),
        name=kw.pop("name", "sw1"),
        primary_ip=kw.pop("primary_ip", "10.0.0.1"),
        snmp_auth_profile=snmp_auth_profile,
        current_modules=list(current_modules),
        nb_device=nb_device if nb_device is not None else SimpleNamespace(),
        **kw,
    )


# ── touch_field: defaults, override, disable ───────────────────────────────────

def test_touch_field_defaults_when_omitted(tmp_path) -> None:
    engine = _engine(tmp_path, "modules:\n  policy: drop\n")
    assert engine.touch_field == "snmp_modulator_last_updated"


def test_touch_field_honors_explicit_override(tmp_path) -> None:
    engine = _engine(tmp_path, "touch_field: my_custom_field\nmodules:\n  policy: drop\n")
    assert engine.touch_field == "my_custom_field"


def test_touch_field_disabled_when_set_empty(tmp_path) -> None:
    engine = _engine(tmp_path, 'touch_field: ""\nmodules:\n  policy: drop\n')
    assert engine.touch_field is None


# ── evaluate(): defaults + rule accumulation ───────────────────────────────────

MAPPING_ROLE_RULES = """
modules:
  policy: drop
auth:
  policy: use

defaults:
  modules:
    add: [if_mib]
    try: [entity_sensor]

rules:
  - name: cisco-extra
    match:
      role.slug: "switch"
    modules:
      try: [cisco_ios_extra]
      block: [entity_sensor]
"""


def test_evaluate_accumulates_defaults_and_matching_rules(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_ROLE_RULES)
    dev = _device(nb_device=SimpleNamespace(role=SimpleNamespace(slug="switch")))
    unconditional, test_set, block_set, names, rules = engine.evaluate(dev, known_modules=[])
    assert unconditional == {"if_mib"}
    # entity_sensor was in defaults.try but blocked by the matching rule
    assert test_set == {"cisco_ios_extra"}
    assert block_set == {"entity_sensor"}
    assert names == ["cisco-extra"]
    assert len(rules) == 1


def test_evaluate_non_matching_role_only_gets_defaults(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_ROLE_RULES)
    dev = _device(nb_device=SimpleNamespace(role=SimpleNamespace(slug="router")))
    unconditional, test_set, block_set, names, rules = engine.evaluate(dev, known_modules=[])
    assert unconditional == {"if_mib"}
    assert test_set == {"entity_sensor"}
    assert block_set == set()
    assert names == []


# ── evaluate(): _ALL sentinel expansion ────────────────────────────────────────

MAPPING_ALL_TRY = """
modules:
  policy: drop
defaults:
  modules:
    try: [_ALL]
"""


def test_evaluate_all_in_try_expands_to_known_modules(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_ALL_TRY)
    dev = _device()
    _, test_set, _, _, _ = engine.evaluate(dev, known_modules=["if_mib", "cisco_ios"])
    assert test_set == {"if_mib", "cisco_ios"}


# ── evaluate(): modules unknown to snmp-exporter are dropped ────────────────────

MAPPING_UNKNOWN_MODULE = """
modules:
  policy: drop
defaults:
  modules:
    add: [typo_module_add]
    try: [if_mib, typo_module_try]
"""


def test_evaluate_drops_module_unknown_to_snmp_exporter(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_UNKNOWN_MODULE)
    dev = _device()
    unconditional, test_set, _, _, _ = engine.evaluate(dev, known_modules=["if_mib"])
    assert unconditional == set()          # typo_module_add isn't a real module — dropped
    assert test_set == {"if_mib"}          # typo_module_try dropped, if_mib kept


def test_evaluate_keeps_everything_when_known_modules_unavailable(tmp_path) -> None:
    # snmp-exporter /config failed to load (known_modules empty) — don't let a
    # transient fetch failure silently drop every configured module.
    engine = _engine(tmp_path, MAPPING_UNKNOWN_MODULE)
    dev = _device()
    unconditional, test_set, _, _, _ = engine.evaluate(dev, known_modules=[])
    assert unconditional == {"typo_module_add"}
    assert test_set == {"if_mib", "typo_module_try"}


MAPPING_BLOCK_ALL = """
modules:
  policy: drop
rules:
  - name: no-snmp
    match:
      role.slug: "wireless-ap"
    modules:
      block: [_ALL]
"""


def test_evaluate_block_all_nuclear_veto_clears_unconditional_and_test(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_BLOCK_ALL)
    dev = _device(
        nb_device=SimpleNamespace(role=SimpleNamespace(slug="wireless-ap")),
        current_modules=["if_mib", "stale_module"],
    )
    unconditional, test_set, block_set, names, _ = engine.evaluate(
        dev, known_modules=["if_mib", "cisco_ios"]
    )
    assert unconditional == set()
    assert test_set == set()
    # Regression: block_set used to keep the literal "_ALL" sentinel instead of
    # real module names, so module_policy=use/try could resurrect pre-existing
    # modules. It must now cover every known module AND the device's own
    # current modules (including ones no longer known to snmp-exporter).
    assert block_set >= {"if_mib", "cisco_ios", "stale_module"}
    assert names == ["no-snmp"]


# ── evaluate_handlers(): merge + conflict resolution ───────────────────────────

MAPPING_HANDLERS = """
rules:
  - name: r1
    match: {}
    on_success:
      add_tag: [snmp-verified, shared-tag]
  - name: r2
    match: {}
    on_success:
      remove_tag: [fixme-snmp, shared-tag]
"""


def test_evaluate_handlers_merges_multiple_rules_and_drops_conflicts(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_HANDLERS)
    dev = _device()
    _, _, _, _, matched_rules = engine.evaluate(dev)
    handlers = engine.evaluate_handlers(matched_rules, success=True)
    # shared-tag requested by both add and remove — dropped from both
    assert handlers["add_tags"] == ["snmp-verified"]
    assert handlers["remove_tags"] == ["fixme-snmp"]


# ── evaluate_auth(): rule-level vs global policy ───────────────────────────────

MAPPING_AUTH_USE = """
auth:
  policy: try
rules:
  - name: fixed-auth
    match:
      role.slug: "legacy"
    auth:
      use: ~
"""


def test_evaluate_auth_rule_use_null_clears_field(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_AUTH_USE)
    dev = _device(nb_device=SimpleNamespace(role=SimpleNamespace(slug="legacy")))
    fixed, candidates, _canary, rule_name = engine.evaluate_auth(dev, known_auths=[])
    assert fixed == ""
    assert candidates == []
    assert rule_name == "fixed-auth"


MAPPING_AUTH_TRY_ALL = """
auth:
  policy: try
defaults:
  auth:
    try: [public_v2]
rules:
  - name: rule-try
    match:
      role.slug: "switch"
    auth:
      try: [_ALL]
"""


def test_evaluate_auth_rule_try_expands_all_and_appends_current_last(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_AUTH_TRY_ALL)
    dev = _device(
        nb_device=SimpleNamespace(role=SimpleNamespace(slug="switch")),
        snmp_auth_profile="legacy_v2",
    )
    fixed, candidates, _canary, rule_name = engine.evaluate_auth(
        dev, known_auths=["public_v2", "private_v2"]
    )
    assert fixed is None
    assert candidates == ["public_v2", "private_v2", "legacy_v2"]
    assert rule_name == "rule-try"


def test_evaluate_auth_global_policy_use_trusts_current_value(tmp_path) -> None:
    engine = _engine(tmp_path, "auth:\n  policy: use\n")
    dev = _device(snmp_auth_profile="public_v2")
    fixed, candidates, _canary, rule_name = engine.evaluate_auth(dev)
    assert fixed == "public_v2"
    assert candidates == []
    assert rule_name is None


MAPPING_AUTH_DROP = """
auth:
  policy: drop
defaults:
  auth:
    try: [public_v2, private_v2]
"""


def test_evaluate_auth_global_policy_drop_uses_defaults_only(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_AUTH_DROP)
    dev = _device(snmp_auth_profile="whatever")
    fixed, candidates, _canary, rule_name = engine.evaluate_auth(dev)
    assert fixed is None
    assert candidates == ["public_v2", "private_v2"]  # current value NOT appended (policy=drop)
    assert rule_name is None


# ── snapshot(): JSON-serializable view for /rules ───────────────────────────────

MAPPING_SNAPSHOT = """
touch_field: my_touch_field
modules:
  field: snmp_exporter_module
  policy: try
  interval_field: snmp_polling_interval
  default_interval: 5m
auth:
  field: snmp_auth_profile
  policy: try
defaults:
  modules:
    try: [system]
  auth:
    try: [public_v2]
rules:
  - name: "Cisco generic"
    match:
      device_type.manufacturer.slug: "cisco"
    modules:
      try: [cisco_generic]
      block: [if_full]
    auth:
      use: legacy_v2
    on_success:
      add_tag: [snmp-ready]
    on_fail:
      remove_tag: [snmp-ready]
      notify: [oncall]
"""


def test_snapshot_renders_compiled_regexes_back_to_source_strings(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_SNAPSHOT)
    snap = engine.snapshot()

    assert snap["rules"][0]["match"] == {"device_type.manufacturer.slug": "cisco"}
    # every value must be a plain, JSON-serializable type — no compiled re.Pattern objects
    json.dumps(snap)


def test_snapshot_reflects_top_level_config_and_defaults(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_SNAPSHOT)
    snap = engine.snapshot()

    assert snap["touch_field"] == "my_touch_field"
    assert snap["module_policy"] == "try"
    assert snap["auth_policy"] == "try"
    assert snap["default_interval"] == "5m"
    assert snap["defaults"]["modules"]["try"] == ["system"]
    assert snap["defaults"]["auth"]["try"] == ["public_v2"]


def test_snapshot_includes_rule_modules_auth_and_handlers(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_SNAPSHOT)
    rule = engine.snapshot()["rules"][0]

    assert rule["name"] == "Cisco generic"
    assert rule["modules"] == {
        "add": [], "try": ["cisco_generic"], "block": ["if_full"],
        "interval": None, "timeout": None,
        "fast": {"add": [], "try": [], "block": [], "interval": None, "timeout": None},
    }
    assert rule["auth"] == {"use": "legacy_v2"}
    assert rule["on_success"]["add_tag"] == ["snmp-ready"]
    assert rule["on_fail"]["remove_tag"] == ["snmp-ready"]
    assert rule["on_fail"]["notify"] == ["oncall"]


def test_snapshot_with_no_rules_returns_empty_list(tmp_path) -> None:
    engine = _engine(tmp_path, "modules:\n  policy: drop\n")
    assert engine.snapshot()["rules"] == []


# ── fast polling profile ─────────────────────────────────────────────────────────

def test_fast_config_defaults_to_unconfigured(tmp_path) -> None:
    engine = _engine(tmp_path, "modules:\n  policy: drop\n")
    assert engine.fast_module_field is None
    assert engine.fast_interval_field is None
    assert engine.fast_timeout_field is None


MAPPING_FAST_CONFIG = """
modules:
  policy: drop
  fast:
    field:            snmp_exporter_module_fast
    interval_field:   snmp_polling_interval_fast
    timeout_field:    snmp_polling_timeout_fast
    default_interval: 90s
    default_timeout:  15s
"""


def test_fast_config_reads_field_names_and_defaults(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_FAST_CONFIG)
    assert engine.fast_module_field == "snmp_exporter_module_fast"
    assert engine.fast_interval_field == "snmp_polling_interval_fast"
    assert engine.fast_timeout_field == "snmp_polling_timeout_fast"
    assert engine.fast_default_interval == 90
    assert engine.fast_default_timeout == 15


def test_evaluate_fast_returns_empty_when_field_not_configured(tmp_path) -> None:
    # A rule can declare modules.fast.try, but without modules.fast.field at the
    # top level the whole feature is off — nothing should be resolved into it.
    engine = _engine(tmp_path, """
modules:
  policy: drop
rules:
  - name: has-fast-section
    match: {}
    modules:
      fast:
        try: [if_traffic]
""")
    dev = _device()
    _, _, _, _, matched_rules = engine.evaluate(dev, known_modules=[])
    unconditional, test_set, block_set = engine.evaluate_fast(dev, matched_rules, known_modules=[])
    assert (unconditional, test_set, block_set) == (set(), set(), set())


def test_evaluate_fast_accumulates_from_matched_rules(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_FAST_CONFIG + """
rules:
  - name: fast-rule
    match:
      role.slug: "switch"
    modules:
      fast:
        add: [if_traffic_fast_add]
        try: [if_traffic]
        block: [if_full]
""")
    dev = _device(nb_device=SimpleNamespace(role=SimpleNamespace(slug="switch")))
    _, _, _, _, matched_rules = engine.evaluate(dev, known_modules=[])
    unconditional, test_set, block_set = engine.evaluate_fast(dev, matched_rules, known_modules=[])
    assert unconditional == {"if_traffic_fast_add"}
    assert test_set == {"if_traffic"}
    assert block_set == {"if_full"}


def test_evaluate_fast_drops_module_unknown_to_snmp_exporter(tmp_path) -> None:
    engine = _engine(tmp_path, MAPPING_FAST_CONFIG + """
rules:
  - name: fast-rule
    match: {}
    modules:
      fast:
        try: [if_traffic, typo_module_fast]
""")
    dev = _device()
    _, _, _, _, matched_rules = engine.evaluate(dev, known_modules=[])
    _, test_set, _ = engine.evaluate_fast(dev, matched_rules, known_modules=["if_traffic"])
    assert test_set == {"if_traffic"}


def test_resolve_polling_floors_takes_max_across_matched_rules_and_default(tmp_path) -> None:
    engine = _engine(tmp_path, """
modules:
  policy: drop
  default_interval: 3m
  default_timeout:  2m
  fast:
    field: snmp_exporter_module_fast
rules:
  - name: remote-a
    match: {}
    modules:
      interval: 10m
      fast:
        interval: 1m
  - name: remote-b
    match: {}
    modules:
      interval: 15m
      timeout: 5m
      fast:
        timeout: 20s
""")
    dev = _device()
    _, _, _, _, matched_rules = engine.evaluate(dev, known_modules=[])
    interval_floor, timeout_floor, fast_interval_floor, fast_timeout_floor = (
        engine.resolve_polling_floors(matched_rules)
    )
    assert interval_floor == 15 * 60        # higher of the two matched rules
    assert timeout_floor == 5 * 60          # only remote-b set a normal timeout floor
    assert fast_interval_floor == 60        # only remote-a set a fast interval floor
    assert fast_timeout_floor == 20         # only remote-b set a fast timeout floor


# ── duration / step helpers ─────────────────────────────────────────────────────

def test_parse_duration_variants() -> None:
    assert _parse_duration("30s") == 30
    assert _parse_duration("2m") == 120
    assert _parse_duration("90") == 90
    assert _parse_duration("1h") == 3600


def test_current_duration_or_default_falls_back_on_unparseable_legacy_value(caplog) -> None:
    log = logging.getLogger("test")
    with caplog.at_level(logging.WARNING):
        assert _current_duration_or_default("garbage", 120, "polling interval", log) == 120
    assert "garbage" in caplog.text


def test_current_duration_or_default_parses_valid_value() -> None:
    log = logging.getLogger("test")
    assert _current_duration_or_default("1h", 120, "polling timeout", log) == 3600


def test_current_duration_or_default_uses_default_when_unset() -> None:
    log = logging.getLogger("test")
    assert _current_duration_or_default(None, 120, "polling timeout", log) == 120


def test_format_duration_prefers_minutes_when_exact() -> None:
    assert _format_duration(120) == "2m"
    assert _format_duration(90) == "90s"


def test_round_up_to_step_rounds_up_past_a_boundary() -> None:
    # Regression: previously int()-truncated the input before comparing to
    # steps, so 30.6 rounded DOWN to 30 instead of up to 60.
    assert _round_up_to_step(30.6, [30, 60, 120]) == 60


def test_round_up_to_step_exact_match_returns_the_step() -> None:
    assert _round_up_to_step(30.0, [30, 60, 120]) == 30


def test_round_up_to_step_caps_at_max_step() -> None:
    assert _round_up_to_step(999.0, [30, 60, 120]) == 120


# ── compare_module_sets ─────────────────────────────────────────────────────────

def test_compare_module_sets_finds_both_directions() -> None:
    only_netbox, only_snmp = compare_module_sets(
        frozenset({"if_mib", "cisco_generic", "stale_module"}),
        {"if_mib", "cisco_generic", "new_module"},
    )
    assert only_netbox == ["stale_module"]
    assert only_snmp == ["new_module"]


def test_compare_module_sets_in_sync_returns_empty() -> None:
    only_netbox, only_snmp = compare_module_sets(frozenset({"if_mib"}), {"if_mib"})
    assert only_netbox == []
    assert only_snmp == []


def test_compare_module_sets_empty_when_either_side_missing() -> None:
    assert compare_module_sets(None, {"if_mib"}) == ([], [])
    assert compare_module_sets(frozenset({"if_mib"}), set()) == ([], [])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
