"""Unit tests for MappingEngine (rule evaluation, auth resolution, handlers)
and the duration/step helpers in modulator.py.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_mapping_engine.py
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import (
    DeviceInfo,
    MappingEngine,
    _format_duration,
    _parse_duration,
    _round_up_to_step,
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


# ── duration / step helpers ─────────────────────────────────────────────────────

def test_parse_duration_variants() -> None:
    assert _parse_duration("30s") == 30
    assert _parse_duration("2m") == 120
    assert _parse_duration("90") == 90


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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
