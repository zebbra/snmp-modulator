"""Unit tests for modulator.fetch_liveness() — instant PromQL query against a
VictoriaMetrics/Prometheus-compatible API, mapped to a {key: alive} dict.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_liveness.py
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modulator import fetch_liveness


def _response(status: str, result: list, error: str = None) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = lambda: None
    payload = {"status": status, "data": {"result": result}}
    if error:
        payload["error"] = error
    resp.json.return_value = payload
    return resp


def test_fetch_liveness_maps_label_to_bool_by_value() -> None:
    result = [
        {"metric": {"instance": "sw1"}, "value": [1700000000, "1"]},
        {"metric": {"instance": "sw2"}, "value": [1700000000, "0"]},
    ]
    with patch("modulator.requests.get", return_value=_response("success", result)):
        liveness = fetch_liveness("http://vm", 'probe_success{job="x"}')
    assert liveness == {"sw1": True, "sw2": False}


def test_fetch_liveness_multiple_series_same_key_ors_together() -> None:
    # A device with several series (e.g. IPv4 + IPv6 probes) counts as up if
    # any one of them reports alive.
    result = [
        {"metric": {"instance": "sw1"}, "value": [0, "0"]},
        {"metric": {"instance": "sw1"}, "value": [0, "1"]},
    ]
    with patch("modulator.requests.get", return_value=_response("success", result)):
        liveness = fetch_liveness("http://vm", 'probe_success{job="x"}')
    assert liveness == {"sw1": True}


def test_fetch_liveness_strips_cidr_suffix_from_ip_labels() -> None:
    result = [{"metric": {"netbox_primary_ip": "10.0.0.5/24"}, "value": [0, "1"]}]
    with patch("modulator.requests.get", return_value=_response("success", result)):
        liveness = fetch_liveness("http://vm", "up", label="netbox_primary_ip")
    assert liveness == {"10.0.0.5": True}


def test_fetch_liveness_skips_series_missing_the_label() -> None:
    result = [
        {"metric": {}, "value": [0, "1"]},
        {"metric": {"instance": "sw1"}, "value": [0, "1"]},
    ]
    with patch("modulator.requests.get", return_value=_response("success", result)):
        liveness = fetch_liveness("http://vm", 'probe_success{job="x"}')
    assert liveness == {"sw1": True}


def test_fetch_liveness_raises_on_query_error_status() -> None:
    with patch("modulator.requests.get", return_value=_response("error", [], error="bad query")):
        with pytest.raises(RuntimeError, match="bad query"):
            fetch_liveness("http://vm", "invalid{")


def test_fetch_liveness_raises_on_http_error() -> None:
    resp = MagicMock()
    resp.raise_for_status.side_effect = Exception("connection refused")
    with patch("modulator.requests.get", return_value=resp):
        with pytest.raises(Exception, match="connection refused"):
            fetch_liveness("http://vm", 'probe_success{job="x"}')


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
