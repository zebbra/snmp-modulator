"""Unit tests for NetboxClient.get_devices() — the fleet-wide-match safety
check and device-eligibility filtering.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_netbox_client.py
"""
from __future__ import annotations

import os
import sys
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
    client._valid_modules = None
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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
