"""Unit tests for SnmpExporterClient._parse()/_evaluate() — data-row counting
from the Prometheus text exposition format snmp-exporter returns.

Run with `pytest tests/` or directly:
    python -m pytest tests/test_snmp_exporter_client.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulator import SnmpExporterClient

_PARSE = SnmpExporterClient._parse
_EVALUATE = SnmpExporterClient._evaluate


# A module returning one metric family across multiple interfaces (label rows),
# plus the usual housekeeping/internal metrics snmp-exporter always adds.
_MULTI_ROW_RESPONSE = """\
# HELP ifOperStatus The current operational state of the interface.
# TYPE ifOperStatus gauge
ifOperStatus{ifIndex="1"} 1
ifOperStatus{ifIndex="2"} 1
ifOperStatus{ifIndex="3"} 2
ifDescr{ifIndex="1"} "Gi0/1"
up 1
scrape_duration_seconds 0.842
scrape_samples_scraped 4
snmp_scrape_walk_duration_seconds 0.5
snmp_scrape_pdus_returned 4
"""


def test_evaluate_counts_every_data_row_not_just_distinct_metric_names() -> None:
    first_seen, row_names = _PARSE(_MULTI_ROW_RESPONSE)
    useful, count, _ = _EVALUATE(first_seen, row_names)
    # 3x ifOperStatus rows (one per interface) — deduping by name would give 1.
    # ifDescr is string-valued (skipped by _parse), housekeeping/snmp_scrape_*
    # excluded by _evaluate.
    assert count == 3
    assert useful is True


def test_evaluate_excludes_housekeeping_and_snmp_scrape_metrics() -> None:
    response = """\
up 1
scrape_duration_seconds 0.1
scrape_samples_post_metric_relabeling 2
scrape_samples_scraped 2
scrape_series_added 2
snmp_scrape_walk_duration_seconds 0.05
snmp_scrape_pdus_returned 2
"""
    first_seen, row_names = _PARSE(response)
    useful, count, scrape_duration = _EVALUATE(first_seen, row_names)
    assert count == 0
    assert useful is False
    assert scrape_duration == 0.1


def test_parse_skips_string_valued_and_comment_lines() -> None:
    response = """\
# a comment
ifDescr{ifIndex="1"} "Gi0/1"
ifOperStatus{ifIndex="1"} 1
"""
    first_seen, row_names = _PARSE(response)
    assert "ifDescr" not in first_seen
    assert row_names == ["ifOperStatus"]


def test_parse_first_seen_keeps_only_first_value_per_family() -> None:
    response = """\
ifInOctets{ifIndex="1"} 100
ifInOctets{ifIndex="2"} 200
"""
    first_seen, row_names = _PARSE(response)
    assert first_seen == {"ifInOctets": 100.0}   # first occurrence only
    assert row_names == ["ifInOctets", "ifInOctets"]  # but every row counted


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
