"""Unit tests for NetboxClient.get_devices() — the fleet-wide-match safety
check and device-eligibility filtering.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_netbox_client.py
"""
from __future__ import annotations

import os
import sys
from datetime import date
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import NetboxClient


class FakeDevice:
    def __init__(self, id, name, primary_ip4=None, custom_fields=None):
        self.id = id
        self.name = name
        self.primary_ip4 = primary_ip4
        self.custom_fields = custom_fields or {}


class FakeDeviceEndpoint:
    def __init__(self, all_devices, matcher=None):
        self._all = all_devices
        # matcher(dev, **kwargs) -> bool ; default: everything matches
        self._matcher = matcher or (lambda dev, **kw: True)

    def count(self, **kwargs):
        return sum(1 for d in self._all if self._matcher(d, **kwargs))

    def filter(self, **kwargs):
        return [d for d in self._all if self._matcher(d, **kwargs)]


def _client(devices, matcher=None) -> NetboxClient:
    client = NetboxClient.__new__(NetboxClient)
    client.nb = SimpleNamespace(dcim=SimpleNamespace(devices=FakeDeviceEndpoint(devices, matcher)))
    client._module_field = "snmp_exporter_module"
    client._auth_field = "snmp_auth_profile"
    client._interval_field = "snmp_polling_interval"
    client._timeout_field = "snmp_polling_timeout"
    client._fast_module_field = None
    client._fast_interval_field = None
    client._fast_timeout_field = None
    client._valid_modules = None
    client._valid_modules_fast = None
    return client


def _ip_addr(ip: str):
    return SimpleNamespace(address=f"{ip}/24")


def test_get_devices_refuses_filter_matching_entire_fleet() -> None:
    devices = [
        FakeDevice(1, "sw1", primary_ip4=_ip_addr("10.0.0.1")),
        FakeDevice(2, "sw2", primary_ip4=_ip_addr("10.0.0.2")),
    ]
    # Simulates NetBox silently ignoring an unknown/typo'd filter key and
    # returning the whole fleet regardless of the filter passed.
    client = _client(devices, matcher=lambda dev, **kw: True)
    result = client.get_devices(role_id=999)
    assert result == []


def test_get_devices_allows_filter_matching_a_subset() -> None:
    devices = [
        FakeDevice(1, "sw1", primary_ip4=_ip_addr("10.0.0.1"), custom_fields={"snmp_auth_profile": "public_v2"}),
        FakeDevice(2, "sw2", primary_ip4=_ip_addr("10.0.0.2"), custom_fields={"snmp_auth_profile": "public_v2"}),
    ]

    def matcher(dev, **kw):
        if "role_id" in kw:
            return dev.id == 1
        return True

    client = _client(devices, matcher)
    result = client.get_devices(role_id=4)
    assert [d.name for d in result] == ["sw1"]
    assert result[0].snmp_auth_profile == "public_v2"


def test_get_devices_skips_devices_without_primary_ip() -> None:
    devices = [
        FakeDevice(1, "sw1", primary_ip4=_ip_addr("10.0.0.1")),
        FakeDevice(2, "sw2-no-ip", primary_ip4=None),
    ]
    client = _client(devices)
    result = client.get_devices()
    assert [d.name for d in result] == ["sw1"]


def test_get_device_by_id_returns_device_without_primary_ip() -> None:
    devices = [FakeDevice(7, "sw-no-ip", custom_fields={"snmp_exporter_module": ["system"]})]
    client = _client(devices)
    client.nb.dcim.devices.get = lambda device_id: next((d for d in devices if d.id == device_id), None)

    device = client.get_device_by_id(7)

    assert device.name == "sw-no-ip"
    assert device.primary_ip == ""
    assert device.current_modules == ["system"]
    assert client.get_device_by_id(8) is None


# ── touch_field: written on real changes, left alone otherwise ────────────────

class RecordingDevice:
    def __init__(self, id, tags=()):
        self.id = id
        self.tags = list(tags)
        self.updates: list = []

    def update(self, payload):
        self.updates.append(payload)


def _client_for_writes(device, touch_field=None) -> NetboxClient:
    client = NetboxClient.__new__(NetboxClient)
    client.nb = SimpleNamespace(
        dcim=SimpleNamespace(devices=SimpleNamespace(get=lambda id: device)),
        extras=SimpleNamespace(tags=SimpleNamespace(get=lambda slug: SimpleNamespace(id=99, slug=slug))),
    )
    client._module_field   = "snmp_exporter_module"
    client._auth_field      = "snmp_auth_profile"
    client._interval_field  = "snmp_polling_interval"
    client._timeout_field   = "snmp_polling_timeout"
    client._touch_field     = touch_field
    client._valid_modules   = None
    return client


def test_update_snmp_modules_touches_when_configured() -> None:
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field="snmp_modulator_last_updated")
    client.update_snmp_modules(1, ["if_mib"])
    assert dev.updates[0]["custom_fields"]["snmp_modulator_last_updated"] == date.today().isoformat()


def test_update_snmp_modules_no_touch_when_disabled() -> None:
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field=None)
    client.update_snmp_modules(1, ["if_mib"])
    assert "snmp_modulator_last_updated" not in dev.updates[0]["custom_fields"]


def test_update_auth_profile_touches_when_configured() -> None:
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field="snmp_modulator_last_updated")
    client.update_auth_profile(1, "public_v2")
    assert dev.updates[0]["custom_fields"]["snmp_modulator_last_updated"] == date.today().isoformat()


def test_apply_tag_changes_touches_when_configured() -> None:
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field="snmp_modulator_last_updated")
    client.apply_tag_changes(1, ["fixme-snmp"], [])
    assert dev.updates[0]["custom_fields"]["snmp_modulator_last_updated"] == date.today().isoformat()
    assert "tags" in dev.updates[0]


def test_update_polling_not_touched_when_nothing_changes() -> None:
    # Regression: touch_field must reflect real changes only — a no-op polling
    # call (both interval and timeout None) must not write anything at all.
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field="snmp_modulator_last_updated")
    client.update_polling(1)
    assert dev.updates == []


def test_update_polling_touches_when_value_changes() -> None:
    dev = RecordingDevice(1)
    client = _client_for_writes(dev, touch_field="snmp_modulator_last_updated")
    client.update_polling(1, interval="5m")
    assert dev.updates[0]["custom_fields"]["snmp_modulator_last_updated"] == date.today().isoformat()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
