"""Unit tests for the bulk module edit path — apply_module_edit's set
arithmetic, ModuleEditor (pins, profiles, replace semantics, dry run),
and NetboxClient.bulk_set_modules' chunking/retry. The /modules/* endpoints
are covered in test_server.py (server.py must only be imported there).

Run with `pytest tests/` or directly:
    python -m pytest tests/test_module_edit.py
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import DeviceInfo, MappingEngine, ModuleEditor, NetboxClient, apply_module_edit

# ── apply_module_edit ───────────────────────────────────────────────────────────

def test_apply_module_edit_appends_new_module_keeping_order() -> None:
    final, added, removed, in_other = apply_module_edit(["system", "if_full"], [], ["if_updown_state"], set())
    assert final == ["system", "if_full", "if_updown_state"]
    assert added == ["if_updown_state"] and removed == [] and in_other == []


def test_apply_module_edit_is_a_noop_when_module_already_present() -> None:
    final, added, removed, _ = apply_module_edit(["if_full", "if_updown_state"], [], ["if_updown_state"], set())
    assert final == ["if_full", "if_updown_state"]
    assert added == [] and removed == []


def test_apply_module_edit_removes_then_adds() -> None:
    final, added, removed, _ = apply_module_edit(
        ["system", "if_status", "if_error"], [], ["if_full"], {"if_status", "if_error", "if_traffic"},
    )
    assert final == ["system", "if_full"]
    assert added == ["if_full"]
    assert removed == ["if_status", "if_error"]


def test_apply_module_edit_leaves_module_already_in_other_profile() -> None:
    # A module lives in exactly one profile; an edit of the normal field must
    # not duplicate one that's already in the fast field.
    final, added, _, in_other = apply_module_edit(["if_full"], ["if_updown_state"], ["if_updown_state"], set())
    assert final == ["if_full"]
    assert added == [] and in_other == ["if_updown_state"]


# ── ModuleEditor ─────────────────────────────────────────────────────────────

class FakeNetboxClient:
    def __init__(self, valid=None, valid_fast=None, errors=None):
        self._valid_modules = valid
        self._valid_modules_fast = valid_fast
        self._errors = errors or {}
        self.bulk_calls: list = []

    def bulk_set_modules(self, field_name, updates, changelog_message, chunk_size=100):
        self.bulk_calls.append((field_name, dict(updates), changelog_message))
        return {d: e for d, e in self._errors.items() if d in updates}


class RecordingCallbacks:
    def __init__(self):
        self.updates: list = []
        self.changes: list = []

    def netbox_update(self, action):
        self.updates.append(action)

    def module_changed(self, module, action):
        self.changes.append((module, action))


def _engine(tmp_path, fast: bool = False, pin_tag: str = "pin-snmp") -> MappingEngine:
    text = f"pin_tag: {pin_tag}\nmodules:\n  field: snmp_exporter_module\n"
    if fast:
        text += "  fast:\n    field: snmp_exporter_module_fast\n"
    text += "rules: []\n"
    path = tmp_path / "mapping.yaml"
    path.write_text(text)
    return MappingEngine(str(path))


def _device(id, modules, fast_modules=(), tags=()):
    nb_device = SimpleNamespace(tags=[SimpleNamespace(slug=t) for t in tags])
    return DeviceInfo(
        id=id, name=f"sw{id}", primary_ip=f"10.0.0.{id}", snmp_auth_profile="v2",
        current_modules=list(modules), current_modules_fast=list(fast_modules), nb_device=nb_device,
    )


def test_editor_writes_only_changed_devices_in_one_bulk_call(tmp_path) -> None:
    nb = FakeNetboxClient()
    cb = RecordingCallbacks()
    devices = [_device(1, ["if_full"]), _device(2, ["if_full", "if_updown_state"])]
    results = ModuleEditor(nb, _engine(tmp_path)).run(devices, ["if_updown_state"], [], callbacks=cb)

    assert nb.bulk_calls == [(
        "snmp_exporter_module", {1: ["if_full", "if_updown_state"]},
        "SNMPModulator module edit: +if_updown_state",
    )]
    assert [r.changed for r in results] == [True, False]
    assert cb.updates == ["changed", "unchanged"]
    assert cb.changes == [("if_updown_state", "added")]


def test_editor_skips_pinned_devices(tmp_path) -> None:
    nb = FakeNetboxClient()
    results = ModuleEditor(nb, _engine(tmp_path)).run([_device(1, ["if_full"], tags=["pin-snmp"])], ["x"], [])
    assert results[0].skipped == "pinned" and not results[0].changed
    assert nb.bulk_calls == []


def test_editor_fast_profile_targets_fast_field(tmp_path) -> None:
    nb = FakeNetboxClient()
    editor = ModuleEditor(nb, _engine(tmp_path, fast=True), profile="fast")
    results = editor.run([_device(1, ["if_full"], fast_modules=["if_traffic"])], ["if_updown_state"], [])
    assert nb.bulk_calls[0][:2] == ("snmp_exporter_module_fast", {1: ["if_traffic", "if_updown_state"]})
    assert results[0].previous_modules == ["if_traffic"]


def test_editor_fast_profile_requires_fast_field_configured(tmp_path) -> None:
    with pytest.raises(ValueError, match="modules.fast.field"):
        ModuleEditor(FakeNetboxClient(), _engine(tmp_path), profile="fast")


def test_editor_replace_does_not_add_where_nothing_was_removed(tmp_path) -> None:
    # A replace must never hand `new` to a device that had none of `old` —
    # e.g. a broad caller filter like site=dc1 would otherwise add if_full everywhere.
    nb = FakeNetboxClient()
    devices = [_device(1, ["system", "if_status"]), _device(2, ["system"])]
    results = ModuleEditor(nb, _engine(tmp_path)).run(
        devices, ["if_full"], ["if_status", "if_error"], add_only_if_removed=True,
    )
    assert nb.bulk_calls[0][1] == {1: ["system", "if_full"]}
    assert results[1].changed is False and results[1].final_modules == ["system"]


def test_editor_dry_run_writes_nothing_and_counts_no_module_changes(tmp_path) -> None:
    nb = FakeNetboxClient()
    cb = RecordingCallbacks()
    results = ModuleEditor(nb, _engine(tmp_path), dry_run=True).run([_device(1, [])], ["if_full"], [], callbacks=cb)
    assert nb.bulk_calls == []
    assert results[0].changed and results[0].final_modules == ["if_full"]
    assert cb.changes == []


def test_editor_records_per_device_write_errors(tmp_path) -> None:
    nb = FakeNetboxClient(errors={2: "400 bad choice"})
    cb = RecordingCallbacks()
    results = ModuleEditor(nb, _engine(tmp_path)).run([_device(1, []), _device(2, [])], ["if_full"], [], callbacks=cb)
    assert results[0].error is None
    assert results[1].error == "400 bad choice"
    assert cb.changes == [("if_full", "added")]


def test_editor_unknown_modules_checks_choices_and_snmp_exporter(tmp_path) -> None:
    nb = FakeNetboxClient(valid=frozenset({"if_full", "if_updown_state", "only_nb"}))
    editor = ModuleEditor(nb, _engine(tmp_path))
    assert editor.unknown_modules(["if_full", "nope", "only_nb"], ["if_full", "if_updown_state"]) == ["nope", "only_nb"]
    assert editor.unknown_modules(["only_nb"], None) == []


# ── NetboxClient.bulk_set_modules ──────────────────────────────────────────────

class FakeBulkEndpoint:
    def __init__(self, bad_ids=()):
        self.calls: list = []
        self._bad = set(bad_ids)

    def update(self, objects):
        self.calls.append([o["id"] for o in objects])
        if any(o["id"] in self._bad for o in objects):
            raise RuntimeError("400 invalid")
        return objects


def _bulk_client(endpoint) -> NetboxClient:
    client = NetboxClient.__new__(NetboxClient)
    client.nb = SimpleNamespace(dcim=SimpleNamespace(devices=endpoint))
    return client


def test_bulk_set_modules_chunks_and_sends_only_the_module_field() -> None:
    sent = []
    endpoint = FakeBulkEndpoint()
    endpoint.update = lambda objects: sent.append(objects)
    errors = _bulk_client(endpoint).bulk_set_modules("f", {1: ["a"], 2: ["b"], 3: ["c"]}, "msg", chunk_size=2)
    assert errors == {}
    assert [[o["id"] for o in chunk] for chunk in sent] == [[1, 2], [3]]
    # Only the module field — touch_field and other custom fields must stay untouched.
    assert sent[0][0] == {"id": 1, "custom_fields": {"f": ["a"]}, "changelog_message": "msg"}


def test_bulk_set_modules_retries_failed_chunk_device_by_device() -> None:
    endpoint = FakeBulkEndpoint(bad_ids={2})
    errors = _bulk_client(endpoint).bulk_set_modules("f", {1: ["a"], 2: ["b"], 3: ["c"]}, "msg", chunk_size=3)
    assert list(errors) == [2]
    assert endpoint.calls == [[1, 2, 3], [1], [2], [3]]
