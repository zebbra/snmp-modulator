#!/usr/bin/env python3
"""
snmp-modulator — core library.

Probes NetBox devices against snmp-exporter modules and writes back
the snmp_exporter_module custom field with only modules that return
useful data (per the mapping YAML).
"""

__version__ = "1.10.0"

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Optional

import pynetbox
import requests
import urllib3
import yaml

APP_NAME = "SNMPModulator"

logger = logging.getLogger(APP_NAME)

MODULE_POLICIES   = ("use", "try", "drop")
EXISTING_POLICIES = MODULE_POLICIES   # backward-compat alias
AUTH_POLICIES     = ("use", "try", "drop")

# ── Duration helpers ──────────────────────────────────────────────────────────

# Valid choice values for snmp_polling_timeout and snmp_polling_interval fields


def _parse_duration(s: str) -> int:
    """Parse '30s', '1m', '90s', '3m', '1h' etc. to seconds."""
    s = s.strip()
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


def _format_duration(seconds: int) -> str:
    """Format seconds to a duration string (e.g. 120 → '2m', 90 → '90s', 3600 → '1h').

    Hour-scale values must be checked first — 3600 % 60 == 0 too, so without
    this ordering an exact hour would format as "60m" instead of "1h" and get
    rejected by NetBox (whose choice sets offer "1h"/"2h", not "60m"/"120m").
    """
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _current_duration_or_default(value: Optional[str], default: int, label: str, log) -> int:
    """Parse a device's existing polling field, falling back to `default` (with a
    warning) if it holds a stale/unparseable value — e.g. an hour-scale value left
    over from before a NetBox choice set was tightened to only allow smaller steps."""
    if not value:
        return default
    try:
        return _parse_duration(value)
    except (ValueError, AttributeError):
        log.warning("Existing %s %r is not parseable — using default (%ds)", label, value, default)
        return default


def _round_up_to_step(seconds: float, steps: list) -> int:
    """Round up to the nearest value in steps; cap at the maximum step."""
    for step in steps:
        if step >= seconds:
            return step
    return steps[-1]


def _recommend_polling(probed_durations: list, interval_steps: list, timeout_steps: list,
                        interval_floor_s: int, timeout_floor_s: int,
                        cur_interval_s: int, cur_timeout_s: int,
                        label: str, log) -> tuple:
    """Shared normal/fast polling recommendation.

    Total probe duration is rounded up to the nearest NetBox choice-set step,
    then raised to at least the resolved floor (global default or a rule's
    interval/timeout override, whichever is higher) — this floor is the only
    lower bound; a device's *current* NetBox value plays no part in it. That's
    deliberate: the floor is "the slowest cadence the mapping ever intends for
    this device," not "whatever a single unlucky slow probe happened to push
    it to previously." A device that once had a bad probe pushing it up to 1h
    recovers back down to its real floor once probes are fast again, instead
    of being stuck there forever (which the old "only ever raise, compared
    against whatever's currently in NetBox" behavior did).

    Returns (new_interval, new_timeout, resolved_interval, resolved_timeout):
    new_* is only non-None when it differs from the device's current value
    (either direction) — that's what gets written to NetBox. resolved_* is
    always this run's recommendation, changed or not — useful for callers
    that want to report the effective interval/timeout regardless of whether
    anything actually changed.
    """
    total_s = sum(probed_durations)
    rec_timeout_s  = max(_round_up_to_step(total_s * 1.5, timeout_steps),
                         _round_up_to_step(timeout_floor_s, timeout_steps))
    rec_interval_s = max(_round_up_to_step(rec_timeout_s * 2, interval_steps),
                         _round_up_to_step(interval_floor_s, interval_steps))

    new_timeout  = _format_duration(rec_timeout_s)  if rec_timeout_s  != cur_timeout_s  else None
    new_interval = _format_duration(rec_interval_s) if rec_interval_s != cur_interval_s else None

    if new_timeout or new_interval:
        cur_timeout_fmt  = _format_duration(cur_timeout_s)
        cur_interval_fmt = _format_duration(cur_interval_s)
        timeout_part  = f"timeout: {cur_timeout_fmt}→{new_timeout}" if new_timeout else "timeout: ok"
        interval_part = f"interval: {cur_interval_fmt}→{new_interval}" if new_interval else "interval: ok"
        suffix = f"  {timeout_part}  {interval_part}"
    else:
        suffix = "  ok"
    log.info(
        "Polling(%s): total_probe=%.1fs  rec_timeout=%s  rec_interval=%s%s",
        label, total_s, _format_duration(rec_timeout_s), _format_duration(rec_interval_s), suffix,
    )
    return new_interval, new_timeout, _format_duration(rec_interval_s), _format_duration(rec_timeout_s)


def _drop_unknown_modules(unconditional: set, test: set, known_modules, label: str) -> tuple:
    """Drop modules mapping.yaml references that snmp-exporter doesn't actually
    know about (per /config) — a typo'd or stale module name would otherwise
    either waste a doomed probe (try) or get written to NetBox for a module
    that can never be scraped (add). No-op when known_modules is empty
    (snmp-exporter /config not loaded yet) — better to attempt everything than
    to have a transient fetch failure silently drop every module.
    """
    if not known_modules:
        return unconditional, test
    known = set(known_modules)
    unknown = (unconditional | test) - known
    if unknown:
        logger.warning("%s module(s) not known to snmp-exporter — skipping: %s", label, sorted(unknown))
    return unconditional & known, test & known


def compare_module_sets(nb_valid_modules: Optional[frozenset], snmp_modules: set) -> tuple:
    """Diff NetBox's module choice set against snmp-exporter's known modules.

    Returns (only_in_netbox, only_in_snmp) sorted lists — empty on either side
    when one of the two sources isn't available yet.
    """
    if not nb_valid_modules or not snmp_modules:
        return [], []
    return sorted(nb_valid_modules - snmp_modules), sorted(snmp_modules - nb_valid_modules)


def fetch_liveness(
    url: str,
    query: str,
    label: str = "instance",
    timeout: int = 15,
    verify_tls: bool = True,
) -> dict:
    """
    Run an instant PromQL query against a Prometheus-compatible API (e.g.
    VictoriaMetrics vmselect) and map each series' `label` value to a
    liveness verdict: True when the sample value is > 0.

    A device with multiple series counts as up if any of them is > 0. Label
    values carrying a CIDR suffix (relevant when label picks out an IP rather
    than a hostname) are normalized to the bare address.

    Raises on HTTP or payload errors — the caller decides fail-open behavior
    (a query failure should mean "treat every device as unknown", never
    "treat every device as down").
    """
    resp = requests.get(
        f"{url.rstrip('/')}/api/v1/query",
        params={"query": query},
        timeout=timeout,
        verify=verify_tls,
        headers={"Accept": "application/json", "User-Agent": APP_NAME},
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("status") != "success":
        raise RuntimeError(f"liveness query failed: {payload.get('error') or 'unknown error'}")

    liveness: dict = {}
    for series in payload.get("data", {}).get("result", []):
        key = str(series.get("metric", {}).get(label) or "").split("/")[0]
        if not key:
            continue
        try:
            alive = float(series["value"][1]) > 0
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        liveness[key] = liveness.get(key, False) or alive
    return liveness


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DeviceInfo:
    id: int
    name: str
    primary_ip: str             # bare IP, prefix stripped
    snmp_auth_profile: str      # from custom_fields.snmp_auth_profile
    current_modules: list       # from custom_fields.snmp_exporter_module
    polling_interval: Optional[str] = None   # e.g. "3m" — None means use default
    polling_timeout:  Optional[str] = None   # e.g. "2m" — None means use default
    current_modules_fast: list = field(default_factory=list)   # fast-profile counterpart; empty when unconfigured
    polling_interval_fast: Optional[str] = None
    polling_timeout_fast:  Optional[str] = None
    nb_device: Any = None       # raw pynetbox Record for flexible match key traversal


@dataclass
class ModuleTestResult:
    module: str
    useful: bool
    metric_count: int           # non-housekeeping data rows returned (every label combo, not deduped by name)
    duration_seconds: float     # scrape_duration_seconds or wall-clock fallback
    error: Optional[str] = None
    profile: Optional[str] = None   # "normal" | "fast" — which profile tried this module; set by process_device


@dataclass
class ModulationResult:
    device_id: int
    device_name: str
    previous_modules: list
    final_modules: list
    changed: bool
    test_results: list          # list[ModuleTestResult] — try-modules only
    auth_profile: Optional[str] = None   # resolved auth profile used for probing
    auth_changed: bool = False           # True if auth profile differs from NetBox — written by commit()
    polling_interval: Optional[str] = None   # new interval written to NetBox (None = unchanged)
    polling_timeout:  Optional[str] = None   # new timeout written to NetBox (None = unchanged)
    resolved_interval: Optional[str] = None  # effective interval after this run, changed or not
    resolved_timeout:  Optional[str] = None  # effective timeout after this run, changed or not
    previous_modules_fast: list = field(default_factory=list)
    final_modules_fast:    list = field(default_factory=list)
    changed_fast: bool = False               # True if final_modules_fast differs from previous_modules_fast
    fast_profile_enabled: bool = False        # True if modules.fast.field is configured in mapping.yaml
    polling_interval_fast: Optional[str] = None
    polling_timeout_fast:  Optional[str] = None
    resolved_interval_fast: Optional[str] = None
    resolved_timeout_fast:  Optional[str] = None
    pending_add_tags:    list = field(default_factory=list)   # on_success/on_fail tags — applied by commit()
    pending_remove_tags: list = field(default_factory=list)
    unreachable: bool = False                # all probes returned useless; existing module list preserved
    skipped: Optional[str] = None            # reason the device was skipped entirely, e.g. "pinned" (not an error)
    error: Optional[str] = None


# ── NetBox client ─────────────────────────────────────────────────────────────

class _ChangelogSession(requests.Session):
    """requests.Session that injects changelog_message into every write body."""

    def __init__(self, changelog_message: str):
        super().__init__()
        self._changelog_message = changelog_message
        self.headers.update({"User-Agent": APP_NAME})

    def request(self, method, url, **kwargs):
        if method.upper() in ("POST", "PATCH", "PUT") and self._changelog_message:
            json_data = kwargs.get("json")
            if isinstance(json_data, dict):
                kwargs["json"] = {**json_data, "changelog_message": self._changelog_message}
        return super().request(method, url, **kwargs)


class NetboxClient:
    def __init__(
        self,
        url: str,
        token: str,
        verify_tls: bool = True,
        module_field: str = "snmp_exporter_module",
        auth_field: str = "snmp_auth_profile",
        interval_field: str = "snmp_polling_interval",
        timeout_field: str = "snmp_polling_timeout",
        touch_field: Optional[str] = None,
        fast_module_field: Optional[str] = None,
        fast_interval_field: Optional[str] = None,
        fast_timeout_field: Optional[str] = None,
    ):
        session = _ChangelogSession(APP_NAME)
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            session.verify = False
        self.nb = pynetbox.api(url, token=token)
        self.nb.http_session = session
        self._module_field       = module_field
        self._auth_field         = auth_field
        self._interval_field     = interval_field
        self._timeout_field      = timeout_field
        self._touch_field        = touch_field
        self._fast_module_field   = fast_module_field
        self._fast_interval_field = fast_interval_field
        self._fast_timeout_field  = fast_timeout_field
        self._valid_modules: Optional[frozenset] = self._fetch_module_choices(self._module_field)
        self._valid_modules_fast: Optional[frozenset] = (
            self._fetch_module_choices(self._fast_module_field) if self._fast_module_field else None
        )

    def _fetch_module_choices(self, field_name: str) -> Optional[frozenset]:
        """Fetch valid choices for a module multi-select field from NetBox.

        NetBox 3.3+ stores choices on a linked CustomFieldChoiceSet; older
        versions exposed them directly on the custom field.
        """
        try:
            cf = self.nb.extras.custom_fields.get(name=field_name)
            if not cf:
                return None

            # NetBox 3.3+: choices live on a separate CustomFieldChoiceSet.
            # NetBox 4.x uses extra_choices; older versions used choices.
            choice_set = getattr(cf, "choice_set", None)
            if choice_set:
                cs = self.nb.extras.custom_field_choice_sets.get(choice_set.id)
                if cs:
                    raw = getattr(cs, "extra_choices", None) or getattr(cs, "choices", None)
                    if raw:
                        choices = frozenset(c[0] for c in raw)
                        logger.info("NetBox module field %r: %d valid choice(s)", field_name, len(choices))
                        return choices

            # Older NetBox: choices directly on the custom field
            direct = getattr(cf, "choices", None)
            if direct:
                choices = frozenset(c.value for c in direct)
                logger.info("NetBox module field %r: %d valid choice(s)", field_name, len(choices))
                return choices

        except Exception as exc:
            logger.warning(
                "Could not fetch NetBox choices for %r: %s — unknown modules will not be filtered",
                field_name, exc,
            )
        return None

    def _fetch_choice_values(self, field_name: str) -> Optional[list]:
        """Return the raw value list (str) of a NetBox selection custom field's
        choice set, or None if the field/choice set is missing or unfetchable."""
        try:
            cf = self.nb.extras.custom_fields.get(name=field_name)
            if not cf:
                return None
            choice_set = getattr(cf, "choice_set", None)
            if not choice_set:
                return None
            cs = self.nb.extras.custom_field_choice_sets.get(choice_set.id)
            if not cs:
                return None
            raw = getattr(cs, "extra_choices", None) or getattr(cs, "choices", None)
            if not raw:
                return None
            return [c[0] for c in raw]
        except Exception as exc:
            logger.warning("Could not fetch choice set for %r: %s", field_name, exc)
            return None

    def get_polling_step_values(self, field_name: str) -> Optional[list]:
        """Return the sorted seconds list parsed from a polling-step choice set,
        or None when the field is not a selection field with a choice set."""
        values = self._fetch_choice_values(field_name)
        if not values:
            return None
        steps = []
        for v in values:
            try:
                steps.append(_parse_duration(str(v)))
            except (ValueError, AttributeError):
                logger.warning("Choice set %r contains unparseable value %r — skipping", field_name, v)
        if not steps:
            return None
        return sorted(set(steps))

    def get_devices(self, **netbox_filter_kwargs) -> list:
        """
        Fetch devices from NetBox using arbitrary filter kwargs passed directly to
        pynetbox's dcim.devices.filter().  has_primary_ip=True is always injected.

        Returns list[DeviceInfo].  Devices without primary_ip4 or the configured
        auth field are logged and skipped.

        Safety: NetBox silently ignores unknown filter params and returns the entire
        fleet. If the caller passed any user filter and the count equals the
        unfiltered total, refuse rather than probe everything by accident.
        """
        netbox_filter_kwargs.setdefault("has_primary_ip", True)

        user_filters = {k: v for k, v in netbox_filter_kwargs.items() if k != "has_primary_ip"}
        if user_filters:
            filtered_count   = self.nb.dcim.devices.count(**netbox_filter_kwargs)
            unfiltered_count = self.nb.dcim.devices.count(has_primary_ip=True)
            if unfiltered_count > 1 and filtered_count == unfiltered_count:
                logger.error(
                    "NetBox filter %s matched all %d eligible devices — refusing "
                    "(likely typo or unknown filter key)",
                    user_filters, unfiltered_count,
                )
                return []

        devices = []
        for dev in self.nb.dcim.devices.filter(**netbox_filter_kwargs):
            if not dev.primary_ip4:
                logger.warning("Device %r has no primary_ip4 — skipping", dev.name)
                continue

            primary_ip = dev.primary_ip4.address.split("/")[0]

            cf = dev.custom_fields or {}
            snmp_auth_profile = cf.get(self._auth_field) or ""

            current_modules = self._flatten_multiselect(cf.get(self._module_field))
            current_modules_fast = (
                self._flatten_multiselect(cf.get(self._fast_module_field))
                if self._fast_module_field else []
            )

            devices.append(DeviceInfo(
                id=dev.id,
                name=dev.name,
                primary_ip=primary_ip,
                snmp_auth_profile=snmp_auth_profile,
                current_modules=current_modules,
                polling_interval=cf.get(self._interval_field) or None,
                polling_timeout=cf.get(self._timeout_field)   or None,
                current_modules_fast=current_modules_fast,
                polling_interval_fast=(
                    (cf.get(self._fast_interval_field) or None) if self._fast_interval_field else None
                ),
                polling_timeout_fast=(
                    (cf.get(self._fast_timeout_field) or None) if self._fast_timeout_field else None
                ),
                nb_device=dev,
            ))

        logger.info("Fetched %d eligible device(s) from NetBox", len(devices))
        return devices

    @staticmethod
    def _flatten_multiselect(raw: Any) -> list:
        """Normalize a NetBox multi-select custom field value to a list of strings."""
        if not isinstance(raw, list):
            return []
        return [item["value"] if isinstance(item, dict) else str(item) for item in raw]

    def get_device_by_host(self, host: str) -> Optional[DeviceInfo]:
        """
        Look up a single device by IP address or name (exact, case-insensitive).
        Returns None if not found or if the device is ineligible (no IP / no auth field).
        """
        dev = None

        # Try primary IP match via IPAM
        for addr in self.nb.ipam.ip_addresses.filter(address=host):
            if addr.assigned_object_type == "dcim.interface" and addr.assigned_object:
                iface = self.nb.dcim.interfaces.get(addr.assigned_object.id)
                if iface and iface.device:
                    dev = self.nb.dcim.devices.get(iface.device.id)
                    break

        # Fall back to device primary_ip4 scan
        if not dev:
            for candidate in self.nb.dcim.devices.filter(q=host, has_primary_ip=True):
                if candidate.primary_ip4 and candidate.primary_ip4.address.split("/")[0] == host:
                    dev = candidate
                    break

        # Fall back to name match
        if not dev:
            results = list(self.nb.dcim.devices.filter(name__ie=host, has_primary_ip=True))
            dev = results[0] if results else None

        if not dev:
            return None

        results = self.get_devices(id=dev.id)
        return results[0] if results else None

    def update_snmp_modules(self, device_id: int, modules: list,
                            add_tags: list = (), remove_tags: list = (),
                            polling_interval: Optional[str] = None,
                            polling_timeout: Optional[str] = None,
                            fast_modules: Optional[list] = None,
                            fast_polling_interval: Optional[str] = None,
                            fast_polling_timeout: Optional[str] = None) -> None:
        """Update the module multi-select custom field, optionally batching tag/polling
        changes and the fast-profile module field/interval/timeout (when configured)."""
        if self._valid_modules is not None:
            unknown = [m for m in modules if m not in self._valid_modules]
            if unknown:
                logger.warning("Dropping module(s) not in NetBox choices: %s", unknown)
                modules = [m for m in modules if m in self._valid_modules]
        dev = self.nb.dcim.devices.get(device_id)
        cf = {self._module_field: modules}
        if polling_interval is not None:
            cf[self._interval_field] = polling_interval
        if polling_timeout is not None:
            cf[self._timeout_field] = polling_timeout
        if fast_modules is not None and self._fast_module_field:
            if self._valid_modules_fast is not None:
                unknown = [m for m in fast_modules if m not in self._valid_modules_fast]
                if unknown:
                    logger.warning("Dropping fast module(s) not in NetBox choices: %s", unknown)
                    fast_modules = [m for m in fast_modules if m in self._valid_modules_fast]
            cf[self._fast_module_field] = fast_modules
            if fast_polling_interval is not None and self._fast_interval_field:
                cf[self._fast_interval_field] = fast_polling_interval
            if fast_polling_timeout is not None and self._fast_timeout_field:
                cf[self._fast_timeout_field] = fast_polling_timeout
        if self._touch_field:
            cf[self._touch_field] = date.today().isoformat()
        payload = {"custom_fields": cf}
        if add_tags or remove_tags:
            payload["tags"] = self._compute_tags(dev, add_tags, remove_tags)
        dev.update(payload)

    def bulk_set_modules(self, field_name: str, updates: dict, changelog_message: str,
                         chunk_size: int = 100) -> dict:
        """Set a module multi-select field on many devices via NetBox bulk PATCH
        ({device_id: modules}), chunk_size devices per request. Only that one
        custom field is sent — NetBox merges custom_fields on PATCH, so every
        other field (incl. touch_field) stays as it is.

        A failed chunk is retried device by device so one bad record can't
        sink the other 99. Returns {device_id: error} for the ones that failed."""
        def _item(device_id, modules):
            return {"id": device_id, "custom_fields": {field_name: modules}, "changelog_message": changelog_message}

        errors = {}
        items = list(updates.items())
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i + chunk_size]
            try:
                self.nb.dcim.devices.update([_item(d, m) for d, m in chunk])
            except Exception as exc:
                logger.warning("Bulk update of %d device(s) failed (%s) — retrying one by one", len(chunk), exc)
                for d, m in chunk:
                    try:
                        self.nb.dcim.devices.update([_item(d, m)])
                    except Exception as exc2:
                        logger.error("Updating %s on device %d failed: %s", field_name, d, exc2)
                        errors[d] = str(exc2)
        return errors

    def update_polling(self, device_id: int,
                       interval: Optional[str] = None,
                       timeout: Optional[str] = None,
                       fast_interval: Optional[str] = None,
                       fast_timeout: Optional[str] = None) -> None:
        """Update polling interval/timeout fields standalone (when modules unchanged)."""
        cf = {}
        if interval is not None:
            cf[self._interval_field] = interval
        if timeout is not None:
            cf[self._timeout_field] = timeout
        if fast_interval is not None and self._fast_interval_field:
            cf[self._fast_interval_field] = fast_interval
        if fast_timeout is not None and self._fast_timeout_field:
            cf[self._fast_timeout_field] = fast_timeout
        if cf:
            if self._touch_field:
                cf[self._touch_field] = date.today().isoformat()
            dev = self.nb.dcim.devices.get(device_id)
            dev.update({"custom_fields": cf})

    def update_auth_profile(self, device_id: int, profile: str) -> None:
        """Update the SNMP auth profile text custom field."""
        cf = {self._auth_field: profile}
        if self._touch_field:
            cf[self._touch_field] = date.today().isoformat()
        dev = self.nb.dcim.devices.get(device_id)
        dev.update({"custom_fields": cf})

    def apply_tag_changes(self, device_id: int, add_tags: list, remove_tags: list) -> None:
        """Add/remove tags on a device (standalone, when no module update is needed)."""
        dev = self.nb.dcim.devices.get(device_id)
        payload = {"tags": self._compute_tags(dev, add_tags, remove_tags)}
        if self._touch_field:
            payload["custom_fields"] = {self._touch_field: date.today().isoformat()}
        dev.update(payload)

    def touch(self, device_id: int) -> None:
        """Stamp the touch field alone, for a successful reconcile that changed nothing else."""
        if not self._touch_field:
            return
        dev = self.nb.dcim.devices.get(device_id)
        dev.update({"custom_fields": {self._touch_field: date.today().isoformat()}})

    def _compute_tags(self, dev, add_slugs: list, remove_slugs: list) -> list:
        """Compute the new tag list given slugs to add and remove."""
        remove_set = set(remove_slugs)
        current = [{"id": t.id} for t in dev.tags if t.slug not in remove_set]
        existing_slugs = {t.slug for t in dev.tags}
        for slug in add_slugs:
            if slug not in existing_slugs:
                tag = self.nb.extras.tags.get(slug=slug)
                if tag:
                    current.append({"id": tag.id})
                else:
                    logger.warning("Tag slug %r not found in NetBox — skipping", slug)
        return current


# ── SNMP Exporter client ──────────────────────────────────────────────────────

# Prometheus metric names that carry no useful SNMP data
_HOUSEKEEPING_METRICS = frozenset({
    "up",
    "scrape_duration_seconds",
    "scrape_samples_post_metric_relabeling",
    "scrape_samples_scraped",
    "scrape_series_added",
})


class SnmpExporterClient:
    def __init__(self, base_url: str, verify_tls: bool = True, timeout: int = 30):
        self._base_url    = base_url.rstrip("/")
        self._verify_tls  = verify_tls
        self._timeout     = timeout
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": APP_NAME})
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._session.verify = False

        self.modules: list = []   # all module names from /config
        self.auths:   list = []   # all auth profile names from /config
        self._load_config()

    def _load_config(self) -> None:
        """
        Fetch /config from snmp-exporter to discover available modules and auth profiles.
        Populates self.modules and self.auths.  Best-effort — failure is logged and
        _ALL expansion will treat the list as empty (with a warning at probe time).
        """
        try:
            resp = self._session.get(
                f"{self._base_url}/config", timeout=self._timeout
            )
            resp.raise_for_status()
            cfg = yaml.safe_load(resp.text) or {}
            self.modules = sorted(cfg.get("modules", {}).keys())
            self.auths   = sorted(cfg.get("auths",   {}).keys())
            logger.info(
                "snmp-exporter config loaded: %d module(s), %d auth profile(s)",
                len(self.modules), len(self.auths),
            )
        except Exception as exc:
            logger.warning(
                "Could not fetch snmp-exporter /config — _ALL expansion unavailable: %s", exc
            )

    def clone(self, base_url: str) -> "SnmpExporterClient":
        """Return a new client sharing TLS/timeout settings but pointing at base_url."""
        return SnmpExporterClient(base_url, self._verify_tls, self._timeout)

    def probe(self, target: str, module: str, auth: str) -> ModuleTestResult:
        """
        GET /snmp?target=<target>&module=<module>&auth=<auth>

        Returns ModuleTestResult.  On HTTP/connection error useful=False with error set.
        """
        url = f"{self._base_url}/snmp"
        params = {"target": target, "module": module, "auth": auth}
        t0 = time.monotonic()
        try:
            resp = self._session.get(url, params=params, timeout=self._timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            elapsed = time.monotonic() - t0
            return ModuleTestResult(
                module=module,
                useful=False,
                metric_count=0,
                duration_seconds=round(elapsed, 1),
                error=str(exc),
            )

        elapsed = time.monotonic() - t0
        first_seen, row_names = self._parse(resp.text)
        useful, metric_count, scrape_duration = self._evaluate(first_seen, row_names)

        return ModuleTestResult(
            module=module,
            useful=useful,
            metric_count=metric_count,
            duration_seconds=round(scrape_duration if scrape_duration > 0 else elapsed, 1),
        )

    def probe_auth(self, target: str, auth: str, canary_module: str) -> bool:
        """
        Returns True if the auth profile is working (up=1.0 from canary_module probe).
        Used exclusively for auth discovery — does not build ModuleTestResult overhead.
        """
        url = f"{self._base_url}/snmp"
        params = {"target": target, "module": canary_module, "auth": auth}
        logger.debug("probe_auth GET %s params=%s", url, params)
        try:
            resp = self._session.get(url, params=params, timeout=self._timeout)
        except requests.RequestException as exc:
            logger.debug("probe_auth %r: request failed: %s", auth, exc)
            return False
        if resp.status_code != 200:
            body = resp.text.strip().splitlines()[0] if resp.text else ""
            logger.debug("probe_auth %r: HTTP %d — %s", auth, resp.status_code, body[:200])
            return False
        first_seen, row_names = self._parse(resp.text)
        up = first_seen.get("up", 0.0)
        useful, useful_count, _ = self._evaluate(first_seen, row_names)
        logger.debug("probe_auth %r: up=%s  useful=%d  rows=%d",
                     auth, up, useful_count, len(row_names))
        return up == 1.0 or useful

    @staticmethod
    def _parse(text: str) -> tuple:
        """
        Parse Prometheus text exposition format.

        Strips label sets, skips comments and non-numeric values (string
        metrics like ifDescr). Returns (first_seen, row_names):
          first_seen — {metric_name: first_seen_value}, one entry per metric
            family — for looking up scalar/singleton values like `up` or
            `scrape_duration_seconds`, where cardinality is 1 by nature.
          row_names — the metric name of every numeric data row parsed, in
            order, including every repeated family across all its label
            combinations (e.g. one ifOperStatus entry per interface) — for
            counting actual returned data volume, not just which metric
            families were present.
        """
        first_seen: dict = {}
        row_names: list = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Strip label set: metric{labels} value  →  metric value
            if "{" in line:
                name = line[:line.index("{")].strip()
                rest = line[line.rindex("}") + 1:].strip()
            else:
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                name, rest = parts[0], parts[1]

            # First token of rest is the value (second may be timestamp)
            try:
                value = float(rest.split()[0])
            except (ValueError, IndexError):
                continue  # string-valued metric (ifDescr etc.) — skip

            if name not in first_seen:
                first_seen[name] = value
            row_names.append(name)

        return first_seen, row_names

    @staticmethod
    def _evaluate(first_seen: dict, row_names: list) -> tuple:
        """
        Returns (useful, data_row_count, scrape_duration_seconds).

        data_row_count is the total number of returned data rows (every label
        combination, e.g. one per interface) that aren't housekeeping metrics
        or snmp-exporter's internal "snmp_scrape_*" walk-progress metrics —
        i.e. actual returned SNMP data volume, not just how many distinct
        metric names were present.

        useful = data_row_count > 0.
        """
        def _is_data_row(name: str) -> bool:
            return name not in _HOUSEKEEPING_METRICS and not name.startswith("snmp_scrape_")

        data_row_count = sum(1 for name in row_names if _is_data_row(name))
        scrape_duration = first_seen.get("scrape_duration_seconds", 0.0)
        return data_row_count > 0, data_row_count, scrape_duration


# ── Mapping engine ────────────────────────────────────────────────────────────

def _get_field(obj: Any, dotted_path: str) -> Any:
    """
    Traverse a pynetbox Record or nested dict using dot-notation.
    Returns the raw value — caller is responsible for stringification.

    Works for:
      role.slug              → obj.role.slug
      device_type.model      → obj.device_type.model
      custom_fields.source   → obj.custom_fields["source"]  (dict access)
      status.value           → obj.status.value
      tags                   → list of pynetbox tag Records
    """
    for part in dotted_path.split("."):
        if obj is None:
            return None
        obj = obj.get(part) if isinstance(obj, dict) else getattr(obj, part, None)
    return obj


class MappingEngine:
    def __init__(self, mapping_path: str):
        with open(mapping_path) as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            raise ValueError(f"Mapping file {mapping_path!r} must be a YAML mapping")

        # ── Top-level settings (overridable via CLI) ─────────────────────────
        modules_cfg = raw.get("modules", {})
        auth_cfg    = raw.get("auth",    {})

        self.module_field:     str = modules_cfg.get("field",           "snmp_exporter_module")
        self.auth_field:       str = auth_cfg.get("field",              "snmp_auth_profile")
        self.interval_field:   Optional[str] = modules_cfg.get("interval_field")  or None
        self.timeout_field:    Optional[str] = modules_cfg.get("timeout_field")   or None
        # Written with today's date whenever a device is actually changed (module,
        # auth, tag, or polling field write) — never touched if nothing changed.
        # Omit or set empty to disable.
        self.touch_field:      Optional[str] = raw.get("touch_field", "snmp_modulator_last_updated") or None
        # A device tagged with this NetBox tag slug is skipped entirely — auth,
        # modules, and polling all left untouched — on batch runs (Modulator
        # constructed with honor_pins=True, the default). An explicit single-host
        # request (honor_pins=False) always processes the device regardless, on
        # the assumption that deliberately naming a host is itself informed
        # consent to change it. Omit/empty to disable the feature outright.
        self.pin_tag:          Optional[str] = raw.get("pin_tag") or None
        self.default_interval: int = _parse_duration(modules_cfg.get("default_interval", "3m"))
        self.default_timeout:  int = _parse_duration(modules_cfg.get("default_timeout",  "2m"))

        # ── Fast polling profile (optional second module/interval/timeout field
        # set) — e.g. if_traffic polled every minute while everything else stays
        # on the normal cadence. Opt-in per rule via modules.fast.{add,try,block};
        # omitting the whole `fast:` block here disables the feature entirely.
        fast_cfg = modules_cfg.get("fast") or {}
        self.fast_module_field:    Optional[str] = fast_cfg.get("field")          or None
        self.fast_interval_field:  Optional[str] = fast_cfg.get("interval_field") or None
        self.fast_timeout_field:   Optional[str] = fast_cfg.get("timeout_field")  or None
        self.fast_default_interval: int = _parse_duration(fast_cfg.get("default_interval", "1m"))
        self.fast_default_timeout:  int = _parse_duration(fast_cfg.get("default_timeout",  "20s"))

        self.module_policy:  str = modules_cfg.get("policy", "drop")
        if self.module_policy not in MODULE_POLICIES:
            raise ValueError(
                f"mapping modules.policy must be one of {MODULE_POLICIES}, "
                f"got {self.module_policy!r}"
            )
        self.auth_policy:       str = auth_cfg.get("policy", "use")
        if self.auth_policy not in AUTH_POLICIES:
            raise ValueError(
                f"mapping auth.policy must be one of {AUTH_POLICIES}, "
                f"got {self.auth_policy!r}"
            )
        self.auth_probe_module: str = auth_cfg.get("probe_module", "system")

        # ── Defaults ──────────────────────────────────────────────────────────
        defaults = raw.get("defaults", {})
        def_mod  = defaults.get("modules", {})
        self._default_add: list        = list(def_mod.get("add",   []))
        self._default_try: list        = list(def_mod.get("try",   []))
        self._default_block: list      = list(def_mod.get("block", []))
        self._default_auth_try: list   = list(defaults.get("auth", {}).get("try", []))

        # ── Rules ─────────────────────────────────────────────────────────────
        self._rules = []
        for r in raw.get("rules", []):
            mod      = r.get("modules", {})
            fast_mod = mod.get("fast") or {}
            self._rules.append({
                "name":           r.get("name", "(unnamed)"),
                "compiled_match": self._compile_match(r.get("match", {})),
                "add":            list(mod.get("add",   [])),
                "try":            list(mod.get("try",   [])),
                "block":          list(mod.get("block", [])),
                # Floor overrides — raise the normal-profile interval/timeout
                # recommendation for devices this rule matches (e.g. remote sites).
                # None means "no floor beyond the global default".
                "interval":       _parse_duration(str(mod["interval"])) if mod.get("interval") is not None else None,
                "timeout":        _parse_duration(str(mod["timeout"]))  if mod.get("timeout")  is not None else None,
                "fast_add":       list(fast_mod.get("add",   [])),
                "fast_try":       list(fast_mod.get("try",   [])),
                "fast_block":     list(fast_mod.get("block", [])),
                "fast_interval":  (
                    _parse_duration(str(fast_mod["interval"])) if fast_mod.get("interval") is not None else None
                ),
                "fast_timeout":   (
                    _parse_duration(str(fast_mod["timeout"])) if fast_mod.get("timeout") is not None else None
                ),
                "auth":           r.get("auth"),
                "on_success":     self._parse_handlers(r.get("on_success") or {}),
                "on_fail":        self._parse_handlers(r.get("on_fail")    or {}),
            })

        logger.info(
            "Mapping loaded: %d rule(s)  defaults: add=%d try=%d block=%d  "
            "module_policy=%s  auth_policy=%s  module_field=%r  auth_field=%r  touch_field=%r  fast_module_field=%r",
            len(self._rules),
            len(self._default_add),
            len(self._default_try),
            len(self._default_block),
            self.module_policy,
            self.auth_policy,
            self.module_field,
            self.auth_field,
            self.touch_field,
            self.fast_module_field,
        )

    @staticmethod
    def _compile_match(match_dict: dict) -> dict:
        """Compile each regex pattern once (case-insensitive full-match)."""
        return {
            field_path: re.compile(str(pattern), re.IGNORECASE)
            for field_path, pattern in match_dict.items()
        }

    def snapshot(self) -> dict:
        """JSON-serializable view of the loaded mapping — config, defaults, and
        rules (compiled regex patterns rendered back to their source strings)."""
        return {
            "module_field":    self.module_field,
            "auth_field":      self.auth_field,
            "interval_field":  self.interval_field,
            "timeout_field":   self.timeout_field,
            "touch_field":     self.touch_field,
            "pin_tag":         self.pin_tag,
            "default_interval": _format_duration(self.default_interval),
            "default_timeout":  _format_duration(self.default_timeout),
            "fast_module_field":     self.fast_module_field,
            "fast_interval_field":   self.fast_interval_field,
            "fast_timeout_field":    self.fast_timeout_field,
            "fast_default_interval": _format_duration(self.fast_default_interval),
            "fast_default_timeout":  _format_duration(self.fast_default_timeout),
            "module_policy":    self.module_policy,
            "auth_policy":      self.auth_policy,
            "auth_probe_module": self.auth_probe_module,
            "defaults": {
                "modules": {
                    "add":   list(self._default_add),
                    "try":   list(self._default_try),
                    "block": list(self._default_block),
                },
                "auth": {"try": list(self._default_auth_try)},
            },
            "rules": [
                {
                    "name":  rule["name"],
                    "match": {field: pattern.pattern for field, pattern in rule["compiled_match"].items()},
                    "modules": {
                        "add": rule["add"], "try": rule["try"], "block": rule["block"],
                        "interval": _format_duration(rule["interval"]) if rule["interval"] is not None else None,
                        "timeout":  _format_duration(rule["timeout"])  if rule["timeout"]  is not None else None,
                        "fast": {
                            "add": rule["fast_add"], "try": rule["fast_try"], "block": rule["fast_block"],
                            "interval": (
                                _format_duration(rule["fast_interval"]) if rule["fast_interval"] is not None else None
                            ),
                            "timeout": (
                                _format_duration(rule["fast_timeout"]) if rule["fast_timeout"] is not None else None
                            ),
                        },
                    },
                    "auth":       rule["auth"],
                    "on_success": rule["on_success"],
                    "on_fail":    rule["on_fail"],
                }
                for rule in self._rules
            ],
        }

    def evaluate(self, device: DeviceInfo, known_modules: list = ()) -> tuple:
        """
        Returns (unconditional_set, test_set, block_set, matched_rule_names, matched_rules).

        Resolution:
          1. Seed from defaults
          2. Accumulate matching rules (additive — all matching rules contribute)
          3. _ALL in block → nuclear veto: unconditional and test both cleared
          4. _ALL in test  → expand to known_modules (from snmp-exporter /config)
          5. Normal per-module block veto applied
          6. unconditional modules removed from test (no point testing what's always added)
          7. Modules unknown to snmp-exporter (per known_modules) dropped from both sets

        matched_rules is the list of matching rule dicts — passed to evaluate_handlers
        to avoid re-walking rules a second time.
        """
        unconditional: set  = set(self._default_add)
        test: set           = set(self._default_try)
        block: set          = set(self._default_block)
        matched_names: list = []
        matched_rules: list = []

        for rule in self._rules:
            if self._match_rule(rule, device):
                matched_names.append(rule["name"])
                matched_rules.append(rule)
                unconditional.update(rule["add"])
                test.update(rule["try"])
                block.update(rule["block"])

        # _ALL in block — nuclear veto, nothing survives. Expand to every known
        # module plus the device's current modules so module_policy=use/try
        # can't resurrect pre-existing modules the veto is meant to strip.
        if "_ALL" in block:
            full_block = (block - {"_ALL"}) | set(known_modules) | set(device.current_modules)
            return set(), set(), full_block, matched_names, matched_rules

        # _ALL in test — expand to every known module
        if "_ALL" in test:
            if not known_modules:
                logger.warning("_ALL in try but no module list available (snmp-exporter /config not loaded)")
            test = (test - {"_ALL"}) | set(known_modules)

        # Normal per-module veto
        unconditional -= block
        test -= block
        test -= unconditional  # already added unconditionally — no need to probe

        unconditional, test = _drop_unknown_modules(unconditional, test, known_modules, "mapping")

        return unconditional, test, block, matched_names, matched_rules

    def evaluate_fast(self, device: DeviceInfo, matched_rules: list, known_modules: list = ()) -> tuple:
        """
        Fast-profile counterpart to evaluate() — accumulates modules.fast.{add,try,block}
        from rules already matched by evaluate() (no second rule walk needed).

        Returns (unconditional_set, test_set, block_set) — empty sets when the fast
        profile isn't configured (modules.fast.field unset) or no matched rule
        declares a fast section. Unlike the normal profile, fast has no defaults
        section — it's opt-in per rule only.
        """
        if not self.fast_module_field:
            return set(), set(), set()

        unconditional: set = set()
        test: set          = set()
        block: set         = set()
        for rule in matched_rules:
            unconditional.update(rule["fast_add"])
            test.update(rule["fast_try"])
            block.update(rule["fast_block"])

        if "_ALL" in block:
            full_block = (block - {"_ALL"}) | set(known_modules) | set(device.current_modules_fast)
            return set(), set(), full_block

        if "_ALL" in test:
            if not known_modules:
                logger.warning("_ALL in fast try but no module list available (snmp-exporter /config not loaded)")
            test = (test - {"_ALL"}) | set(known_modules)

        unconditional -= block
        test -= block
        test -= unconditional

        unconditional, test = _drop_unknown_modules(unconditional, test, known_modules, "fast mapping")

        return unconditional, test, block

    def resolve_polling_floors(self, matched_rules: list) -> tuple:
        """
        Returns (interval_floor_s, timeout_floor_s, fast_interval_floor_s, fast_timeout_floor_s)
        in seconds — the highest value across the global default and every matched
        rule's modules.interval/timeout (and modules.fast.interval/timeout) override.
        Used as a floor on top of the measured-duration recommendation, so e.g. a
        remote-site rule can guarantee at least a 15m normal interval regardless of
        how fast that device actually responds.
        """
        interval_floor      = self.default_interval
        timeout_floor       = self.default_timeout
        fast_interval_floor = self.fast_default_interval
        fast_timeout_floor  = self.fast_default_timeout
        for rule in matched_rules:
            if rule["interval"] is not None:
                interval_floor = max(interval_floor, rule["interval"])
            if rule["timeout"] is not None:
                timeout_floor = max(timeout_floor, rule["timeout"])
            if rule["fast_interval"] is not None:
                fast_interval_floor = max(fast_interval_floor, rule["fast_interval"])
            if rule["fast_timeout"] is not None:
                fast_timeout_floor = max(fast_timeout_floor, rule["fast_timeout"])
        return interval_floor, timeout_floor, fast_interval_floor, fast_timeout_floor

    def _match_rule(self, rule: dict, device: DeviceInfo) -> bool:
        """All patterns in compiled_match must match. Absent key = wildcard."""
        for field_path, pattern in rule["compiled_match"].items():
            raw = _get_field(device.nb_device, field_path)
            # List fields (e.g. tags): match if any element's slug matches,
            # falling back to str() for non-slug objects.
            if isinstance(raw, (list, tuple)):
                values = [getattr(item, "slug", None) or str(item) for item in raw]
                matched = any(pattern.fullmatch(v) for v in values)
                display = values
            else:
                display = str(raw) if raw is not None else ""
                matched = bool(pattern.fullmatch(display))
            logger.debug(
                "  rule %-40s  %s  %-45s  pattern=%-30s  value=%r",
                f"[{rule['name']}]",
                "MATCH" if matched else "MISS ",
                field_path,
                pattern.pattern,
                display,
            )
            if not matched:
                return False
        return True

    @staticmethod
    def _parse_handlers(cfg: dict) -> dict:
        """Normalise an on_success / on_fail block into lists."""
        def _listify(v):
            return list(v) if isinstance(v, (list, tuple)) else ([v] if v else [])
        return {
            "add_tag":    _listify(cfg.get("add_tag",  [])),
            "remove_tag": _listify(cfg.get("remove_tag", [])),
            "notify":     _listify(cfg.get("notify",   [])),
        }

    def evaluate_handlers(self, matched_rules: list, success: bool) -> dict:
        """
        Collect on_success / on_fail handlers from pre-matched rules (from evaluate()).
        Returns merged {'add_tags': list, 'remove_tags': list, 'notify': list}.
        Tags that appear in both add and remove are dropped from both.
        """
        add_tags:    set = set()
        remove_tags: set = set()
        notify:      list = []
        key = "on_success" if success else "on_fail"
        for rule in matched_rules:
            h = rule[key]
            add_tags.update(h["add_tag"])
            remove_tags.update(h["remove_tag"])
            notify.extend(h["notify"])
        conflict = add_tags & remove_tags
        if conflict:
            logger.warning("Tags in both add and remove — skipping: %s", sorted(conflict))
        return {
            "add_tags":    sorted(add_tags - conflict),
            "remove_tags": sorted(remove_tags - conflict),
            "notify":      notify,
        }

    def evaluate_auth(self, device: DeviceInfo, known_auths: list = ()) -> tuple:
        """
        Returns (fixed_profile, candidates, canary_module, matched_rule_name).

          fixed_profile      — if not None, use directly without probing.
                               Empty string means "clear the field" (auth.use: ~ or auth.use: "").
          candidates         — ordered list of profiles to probe (empty when fixed_profile is set).
                               _ALL expands to known_auths from snmp-exporter /config.
          canary_module      — SNMP module to use as auth probe canary.
          matched_rule_name  — name of the rule that provided auth config, or None.

        Resolution:
          Rule-level auth always takes precedence over the global auth_policy:
            auth.use  → unconditional, no probe (works regardless of global policy)
            auth.try  → probe candidates in declared order (works regardless of
                         global policy; global policy=try appends current NetBox
                         value as a last-resort fallback)
          If no rule matches with an auth section, global policy is the fallback:
            use  → trust NetBox value as-is, no probe
            try  → probe defaults.auth.try in order, NetBox value appended last
            drop → use defaults.auth.try candidates only
        """
        canary = self.auth_probe_module
        for rule in self._rules:
            if rule["auth"] is None:
                continue
            if not self._match_rule(rule, device):
                continue
            auth_cfg = rule["auth"]
            rule_canary = auth_cfg.get("probe_module", canary)

            if "use" in auth_cfg:
                # Unconditional — no probe needed; None/null → "" (clear the field)
                profile = auth_cfg["use"] if auth_cfg["use"] is not None else ""
                return profile, [], rule_canary, rule["name"]

            if "try" in auth_cfg:
                # Rule explicitly requests auth probing — overrides global auth_policy=use
                candidates = self._expand_auth_all(list(auth_cfg["try"]), known_auths)
                if self.auth_policy == "try":
                    candidates = _append_unique(device.snmp_auth_profile, candidates)
                return None, candidates, rule_canary, rule["name"]

        # No matching rule with auth section — apply global policy
        if self.auth_policy == "use":
            return device.snmp_auth_profile, [], canary, None
        candidates = self._expand_auth_all(list(self._default_auth_try), known_auths)
        if self.auth_policy == "try":
            candidates = _append_unique(device.snmp_auth_profile, candidates)
        return None, candidates, canary, None

    @staticmethod
    def _expand_auth_all(candidates: list, known_auths: list) -> list:
        """Replace _ALL sentinel with the full known auth list."""
        if "_ALL" not in candidates:
            return candidates
        if not known_auths:
            logger.warning("_ALL in auth.try but no auth list available (snmp-exporter /config not loaded)")
        others = [c for c in candidates if c != "_ALL"]
        expanded = list(known_auths)
        # Preserve any explicitly listed profiles that aren't in known_auths
        for c in others:
            if c not in expanded:
                expanded.append(c)
        return expanded


def _is_pinned(device: DeviceInfo, pin_tag: Optional[str]) -> bool:
    """True if the device carries the mapping's pin_tag (a human set it deliberately)."""
    if not pin_tag:
        return False
    raw_tags = _get_field(device.nb_device, "tags") or []
    return pin_tag in {getattr(t, "slug", None) or str(t) for t in raw_tags}


def _append_unique(value: str, lst: list) -> list:
    """Return lst with value appended as a last-resort fallback, deduped."""
    if value and (not lst or lst[-1] != value):
        return [x for x in lst if x != value] + [value]
    return lst


# ── Callbacks (injected by server.py to avoid coupling the lib to prometheus) ─

class Callbacks:
    """Base class — override in server.py to wire up Prometheus counters."""
    def module_test(self, module: str, result: str) -> None:
        pass

    def module_test_duration(self, module: str, duration: float) -> None:
        pass

    def netbox_update(self, action: str) -> None:
        pass

    def device_processed(self, result: str) -> None:
        pass

    def auth_probed(self, result: str) -> None:
        """result: resolved | failed | skipped (auth_policy=use or auth.use rule)"""
        pass

    def module_changed(self, module: str, action: str) -> None:
        """action: added | removed (per-module delta vs previous NetBox value)"""
        pass


# ── Modulator (orchestration) ─────────────────────────────────────────────────


class Modulator:
    def __init__(
        self,
        nb: NetboxClient,
        snmp: SnmpExporterClient,
        engine: MappingEngine,
        dry_run: bool = False,
        module_policy: str = "drop",
        device_parallelism: int = 1,
        honor_pins: bool = True,
        liveness: Optional[dict] = None,
        liveness_key: str = "name",
    ):
        """
        module_policy controls how modules already in snmp_exporter_module are handled:
          drop  — ignore existing modules entirely; mapping is sole source of truth
          try   — probe existing modules; keep if they still return useful data
          use   — keep existing modules unconditionally (non-destructive / append mode)
        block veto always applies regardless of policy.

        device_parallelism: number of devices probed concurrently within one run
        (1 = sequential). SNMP probing is I/O-bound, so threads scale well.

        honor_pins: when True (the default — meant for batch/scheduled runs), a
        device tagged with engine.pin_tag is skipped entirely, untouched, and
        liveness (below) is consulted. Pass False for an explicit single-host
        request (e.g. /probe?host=X, cli.py --host) — deliberately naming a
        host is itself informed consent to change/probe it, so neither the
        pin nor a "device is down" liveness verdict applies there. Both
        signals share the same batch-vs-explicit reasoning, hence one flag.

        liveness: optional {key: bool} from fetch_liveness(), fetched once per
        batch run (not per device) by the caller and passed in. A device whose
        key maps to False is skipped before any SNMP probing at all — skips
        the pointless probe against a host ICMP already reports as down (SNMP
        itself isn't a reliable down-signal: wrong creds/module looks the
        same as actually-down). A device missing from the dict (never
        monitored, or the query failed) is *not* skipped — fail open, same
        principle as honor_pins. Only consulted when honor_pins is True.

        liveness_key: which DeviceInfo attribute the liveness dict is keyed
        by — "name" (default, matches this deployment's ping job labeling by
        device name) or "ip" (device.primary_ip).
        """
        if module_policy not in MODULE_POLICIES:
            raise ValueError(f"module_policy must be one of {MODULE_POLICIES}, got {module_policy!r}")
        if device_parallelism < 1:
            raise ValueError(f"device_parallelism must be >= 1, got {device_parallelism}")
        if liveness_key not in ("name", "ip"):
            raise ValueError(f"liveness_key must be 'name' or 'ip', got {liveness_key!r}")
        self.nb          = nb
        self.snmp        = snmp   # fallback / single-site client (SNMP_EXPORTER_URL)
        self.engine      = engine
        self.dry_run     = dry_run
        self.module_policy = module_policy
        self.device_parallelism = device_parallelism
        self.honor_pins  = honor_pins
        self.liveness      = liveness
        self.liveness_key  = liveness_key

        # Polling step ladders are sourced from the NetBox selection custom fields.
        # When either choice set is unavailable, polling calculation is disabled.
        self._interval_steps: Optional[list] = None
        self._timeout_steps:  Optional[list] = None
        if engine.interval_field:
            self._interval_steps = nb.get_polling_step_values(engine.interval_field)
            if self._interval_steps:
                logger.info("Interval steps from NetBox %r: %s", engine.interval_field, self._interval_steps)
            else:
                logger.warning(
                    "Interval steps unavailable for %r — polling calculation disabled", engine.interval_field
                )
        if engine.timeout_field:
            self._timeout_steps = nb.get_polling_step_values(engine.timeout_field)
            if self._timeout_steps:
                logger.info("Timeout steps from NetBox %r: %s", engine.timeout_field, self._timeout_steps)
            else:
                logger.warning("Timeout steps unavailable for %r — polling calculation disabled", engine.timeout_field)

        self._fast_interval_steps: Optional[list] = None
        self._fast_timeout_steps:  Optional[list] = None
        if engine.fast_interval_field:
            self._fast_interval_steps = nb.get_polling_step_values(engine.fast_interval_field)
            if self._fast_interval_steps:
                logger.info(
                    "Fast interval steps from NetBox %r: %s", engine.fast_interval_field, self._fast_interval_steps
                )
            else:
                logger.warning(
                    "Fast interval steps unavailable for %r — fast polling calculation disabled",
                    engine.fast_interval_field,
                )
        if engine.fast_timeout_field:
            self._fast_timeout_steps = nb.get_polling_step_values(engine.fast_timeout_field)
            if self._fast_timeout_steps:
                logger.info(
                    "Fast timeout steps from NetBox %r: %s", engine.fast_timeout_field, self._fast_timeout_steps
                )
            else:
                logger.warning(
                    "Fast timeout steps unavailable for %r — fast polling calculation disabled",
                    engine.fast_timeout_field,
                )

        self._compare_module_sets()

    def _apply_handlers(self, device: DeviceInfo, matched_rules: list, success: bool, log) -> None:
        """Apply on_success / on_fail tag changes for early-return paths (auth failures)."""
        handlers = self.engine.evaluate_handlers(matched_rules, success=success)
        add_tags    = handlers["add_tags"]
        remove_tags = handlers["remove_tags"]
        if not add_tags and not remove_tags:
            return
        log.info("Tag changes — add=%s remove=%s", add_tags, remove_tags)
        if not self.dry_run:
            self.nb.apply_tag_changes(device.id, add_tags, remove_tags)
        else:
            log.info("DRY RUN — would update tags: add=%s remove=%s", add_tags, remove_tags)

    def commit(self, result: ModulationResult, log=None) -> None:
        """Apply a computed ModulationResult's NetBox writes for real.

        This is the single place that turns a resolved result into actual
        NetBox API calls — used both by process_device's live (non-dry-run)
        path, and to replay a previously cached dry-run result later without
        re-probing (e.g. server.py: preview with dry_run=true, then confirm
        with a plain, non-dry-run call for the same query shortly after).

        No-op on an errored or skipped result — nothing meaningful was
        resolved (or the device was deliberately left untouched, e.g. pinned).
        """
        if result.error or result.skipped:
            return
        log = log or logging.getLogger(f"{APP_NAME}.{result.device_name}")

        success = (
            bool(result.final_modules or result.final_modules_fast)
            and not any(r.error for r in result.test_results)
            and not result.unreachable
        )
        fast_field_note = (
            f"  {self.engine.fast_module_field}={result.final_modules_fast}" if self.engine.fast_module_field else ""
        )

        if result.auth_changed:
            self.nb.update_auth_profile(result.device_id, result.auth_profile)

        if result.changed:
            self.nb.update_snmp_modules(
                result.device_id, result.final_modules,
                add_tags=result.pending_add_tags, remove_tags=result.pending_remove_tags,
                polling_interval=result.polling_interval, polling_timeout=result.polling_timeout,
                fast_modules=result.final_modules_fast if self.engine.fast_module_field else None,
                fast_polling_interval=result.polling_interval_fast, fast_polling_timeout=result.polling_timeout_fast,
            )
            log.info("NetBox updated: %s=%s%s", self.engine.module_field, result.final_modules, fast_field_note)
        else:
            touched = False
            if result.pending_add_tags or result.pending_remove_tags:
                self.nb.apply_tag_changes(result.device_id, result.pending_add_tags, result.pending_remove_tags)
                touched = True
            any_polling = (
                result.polling_interval or result.polling_timeout
                or result.polling_interval_fast or result.polling_timeout_fast
            )
            if any_polling:
                self.nb.update_polling(
                    result.device_id, interval=result.polling_interval, timeout=result.polling_timeout,
                    fast_interval=result.polling_interval_fast, fast_timeout=result.polling_timeout_fast,
                )
                touched = True
            if not touched and success:
                self.nb.touch(result.device_id)

    def _compare_module_sets(self) -> None:
        """Warn if NetBox module choices and snmp-exporter modules are out of sync."""
        only_in_netbox, only_in_snmp = compare_module_sets(self.nb._valid_modules, set(self.snmp.modules))
        if only_in_netbox:
            logger.warning("Module(s) in NetBox but not in snmp-exporter: %s", only_in_netbox)
        if only_in_snmp:
            logger.warning("Module(s) in snmp-exporter but not in NetBox: %s", only_in_snmp)
        if not only_in_netbox and not only_in_snmp and self.nb._valid_modules and self.snmp.modules:
            logger.debug(
                "NetBox choices and snmp-exporter modules are in sync (%d)", len(self.nb._valid_modules)
            )

    def run(
        self,
        devices: list,
        callbacks: Optional[Callbacks] = None,
        on_module_result: Optional[Callable[[DeviceInfo, ModuleTestResult], None]] = None,
    ) -> list:
        """Process a list of DeviceInfo objects and return list[ModulationResult].

        With device_parallelism > 1, devices are probed concurrently via a
        ThreadPoolExecutor. Per-device log lines remain distinguishable by IP
        because each device gets its own logger.

        on_module_result, if given, fires synchronously right after each
        module probe completes (module probing itself always stays serial per
        device — this is purely a way for a caller to observe progress, e.g.
        server.py surfacing partial results to a polling client while a probe
        is still in flight). Called with (device, ModuleTestResult); may be
        invoked from multiple threads at once when device_parallelism > 1.
        """
        if callbacks is None:
            callbacks = Callbacks()

        logger.info(
            "Starting run: %d device(s)  parallelism=%d",
            len(devices), self.device_parallelism,
        )

        def _one(device: DeviceInfo) -> ModulationResult:
            result = self.process_device(device, callbacks, on_module_result=on_module_result)
            if result.skipped:
                outcome = result.skipped
            elif result.error:
                outcome = "error"
            elif result.unreachable:
                outcome = "unreachable"
            else:
                outcome = "success"
            callbacks.device_processed(outcome)
            return result

        if self.device_parallelism <= 1:
            results = [_one(d) for d in devices]
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(
                max_workers=self.device_parallelism,
                thread_name_prefix="dev",
            ) as ex:
                results = list(ex.map(_one, devices))

        skip  = sum(1 for r in results if r.skipped)
        ok    = sum(1 for r in results if not r.error and not r.unreachable and not r.skipped)
        err   = sum(1 for r in results if r.error)
        unrch = sum(1 for r in results if r.unreachable)
        chg   = sum(1 for r in results if r.changed)
        logger.info(
            "Run complete: %d device(s)  ok=%d err=%d unreachable=%d skipped=%d changed=%d",
            len(results), ok, err, unrch, skip, chg,
        )
        return results

    @staticmethod
    def _skip_result(device: DeviceInfo, reason: str) -> ModulationResult:
        """Build a no-op ModulationResult for a device that was never
        probed/resolved at all — pinned, or reported down by liveness."""
        previous_modules      = sorted(device.current_modules)
        previous_modules_fast = sorted(device.current_modules_fast)
        return ModulationResult(
            device_id=device.id,
            device_name=device.name,
            previous_modules=previous_modules,
            final_modules=previous_modules,
            changed=False,
            test_results=[],
            previous_modules_fast=previous_modules_fast,
            final_modules_fast=previous_modules_fast,
            skipped=reason,
        )

    def process_device(
        self,
        device: DeviceInfo,
        callbacks: Optional[Callbacks] = None,
        on_module_result: Optional[Callable[[DeviceInfo, ModuleTestResult], None]] = None,
    ) -> ModulationResult:
        if callbacks is None:
            callbacks = Callbacks()

        log = logging.getLogger(f"{APP_NAME}.{device.primary_ip}")

        if self.honor_pins and _is_pinned(device, self.engine.pin_tag):
            log.info(
                "Device tagged %r — pinned by a human, skipping untouched (batch run)",
                self.engine.pin_tag,
            )
            return self._skip_result(device, "pinned")

        if self.honor_pins and self.liveness is not None:
            key = device.name if self.liveness_key == "name" else device.primary_ip
            alive = self.liveness.get(key)
            if alive is False:
                log.info("Liveness reports %r down — skipping probe (batch run)", key)
                return self._skip_result(device, "offline")

        active_snmp = self.snmp
        log.info("── device %s  name=%r  auth=%r",
                 device.primary_ip, device.name, device.snmp_auth_profile)

        try:
            # Evaluate rules upfront — needed for handlers even if auth fails early
            unconditional, test_set, block_set, matched_names, matched_rules = self.engine.evaluate(
                device, known_modules=active_snmp.modules
            )

            # ── Auth resolution ───────────────────────────────────────────────
            fixed_auth, auth_candidates, canary_module, auth_rule = self.engine.evaluate_auth(
                device, known_auths=active_snmp.auths
            )
            if auth_rule:
                log.info("Auth rule matched: %r", auth_rule)
            resolved_auth = device.snmp_auth_profile
            auth_changed  = False

            if fixed_auth is not None:
                # auth_policy=use (fixed_auth == current) or auth.use rule match
                resolved_auth = fixed_auth
                if not resolved_auth:
                    # Empty auth with no discovery attempted — probing would be pointless
                    log.warning("Auth: profile is empty and auth_policy=use — skipping device")
                    callbacks.auth_probed("failed")
                    self._apply_handlers(device, matched_rules, success=False, log=log)
                    return ModulationResult(
                        device_id=device.id,
                        device_name=device.name,
                        previous_modules=sorted(device.current_modules),
                        final_modules=sorted(device.current_modules),
                        changed=False,
                        test_results=[],
                        auth_profile=None,
                        auth_changed=False,
                        error="empty auth profile",
                    )
                auth_changed  = fixed_auth != device.snmp_auth_profile
                if auth_changed:
                    if self.dry_run:
                        log.info("DRY RUN — would update auth to %r (was %r)", fixed_auth, device.snmp_auth_profile)
                    else:
                        log.info("Auth: rule specifies %r (was %r)", fixed_auth, device.snmp_auth_profile)
                    # actual write deferred to commit() — see its docstring
                callbacks.auth_probed("skipped")

            elif auth_candidates:
                resolved_auth = None
                log.info("Auth: probing %d candidate(s) with canary=%r: %s",
                         len(auth_candidates), canary_module, auth_candidates)
                for candidate in auth_candidates:
                    log.info("Auth: trying %r", candidate)
                    if active_snmp.probe_auth(device.primary_ip, candidate, canary_module):
                        resolved_auth = candidate
                        log.info("Auth: resolved to %r", candidate)
                        break
                    log.info("Auth: %r failed", candidate)

                if resolved_auth is None:
                    log.warning("Auth: no working profile found for %r — skipping device", device.name)
                    callbacks.auth_probed("failed")
                    self._apply_handlers(device, matched_rules, success=False, log=log)
                    return ModulationResult(
                        device_id=device.id,
                        device_name=device.name,
                        previous_modules=sorted(device.current_modules),
                        final_modules=sorted(device.current_modules),
                        changed=False,
                        test_results=[],
                        auth_profile=None,
                        auth_changed=False,
                        error="no working auth profile found",
                    )

                callbacks.auth_probed("resolved")
                auth_changed = resolved_auth != device.snmp_auth_profile
                if auth_changed:
                    if self.dry_run:
                        log.info("DRY RUN — would update auth: %r → %r", device.snmp_auth_profile, resolved_auth)
                    else:
                        log.info("Auth: %r → %r", device.snmp_auth_profile, resolved_auth)
                    # actual write deferred to commit() — see its docstring

            else:
                # auth_policy try/drop but no candidates configured
                log.warning(
                    "Auth: policy is %r but no candidates for %r — skipping device",
                    self.engine.auth_policy, device.name,
                )
                callbacks.auth_probed("failed")
                self._apply_handlers(device, matched_rules, success=False, log=log)
                return ModulationResult(
                    device_id=device.id,
                    device_name=device.name,
                    previous_modules=sorted(device.current_modules),
                    final_modules=sorted(device.current_modules),
                    changed=False,
                    test_results=[],
                    auth_profile=None,
                    auth_changed=False,
                    error="no auth candidates configured",
                )

            # ── Module evaluation ─────────────────────────────────────────────
            log.info("Module rules matched: %s", matched_names if matched_names else "(none)")

            fast_unconditional, fast_test_set, fast_block_set = self.engine.evaluate_fast(
                device, matched_rules, known_modules=active_snmp.modules
            )

            # Apply existing-module policy — same policy governs both profiles.
            existing = set(device.current_modules) - block_set
            if self.module_policy == "use":
                unconditional |= existing
            elif self.module_policy == "try":
                test_set |= existing - unconditional

            existing_fast = set(device.current_modules_fast) - fast_block_set
            if self.module_policy == "use":
                fast_unconditional |= existing_fast
            elif self.module_policy == "try":
                fast_test_set |= existing_fast - fast_unconditional

            log.debug(
                "Modules — add=%s try=%s block=%s  fast: add=%s try=%s block=%s",
                sorted(unconditional), sorted(test_set), sorted(block_set),
                sorted(fast_unconditional), sorted(fast_test_set), sorted(fast_block_set),
            )

            # Probe each try-module (normal + fast, one pass — a module can only be
            # probed once regardless of which profile it ends up written to) using
            # the resolved auth profile. Test the canary module first when it's in
            # the set — the auth_candidates path already confirms reachability via
            # probe_auth before we get here, but fixed_auth skips that, so without
            # this a fully offline device would otherwise burn the full per-module
            # timeout on every module before anything gives up.
            combined_test = test_set | fast_test_set
            test_results: list = []
            probe_order = sorted(combined_test)
            if canary_module in combined_test:
                probe_order.remove(canary_module)
                probe_order.insert(0, canary_module)

            for module in probe_order:
                result = active_snmp.probe(device.primary_ip, module, resolved_auth)
                result.profile = "fast" if module in fast_test_set else "normal"
                test_results.append(result)
                outcome = "error" if result.error else ("useful" if result.useful else "empty")
                err_str = result.error.split(" for url:")[0] if result.error else ""
                log.info(
                    "  %-22s  %-6s  %3d metrics  %.1fs%s",
                    module, outcome, result.metric_count, result.duration_seconds,
                    f"  {err_str}" if err_str else "",
                )
                callbacks.module_test(module=module, result=outcome)
                callbacks.module_test_duration(module=module, duration=result.duration_seconds)
                if on_module_result:
                    on_module_result(device, result)

                if module == canary_module and result.error:
                    log.warning(
                        "Reachability canary (%s) failed — device likely unreachable; "
                        "skipping remaining %d module probe(s)",
                        canary_module, len(probe_order) - 1,
                    )
                    break

            # Build final module sets. Fast wins on overlap — anything resolved into
            # the fast profile is removed from the normal one so nothing is polled
            # (or written) under both profiles at once.
            useful_modules = {r.module for r in test_results if r.useful}
            final_modules_fast = sorted(fast_unconditional | (useful_modules & fast_test_set))
            final_modules = sorted(
                (unconditional | (useful_modules & test_set)) - set(final_modules_fast)
            )
            previous_modules      = sorted(device.current_modules)
            previous_modules_fast = sorted(device.current_modules_fast)

            # Unreachable guard: if every probe ran but none returned useful data
            # AND the device had a populated module list (either profile), treat as
            # unreachable and preserve the existing lists rather than wiping them.
            all_probes_failed = bool(test_results) and not any(r.useful for r in test_results)
            unreachable       = all_probes_failed and bool(previous_modules or previous_modules_fast)
            if unreachable:
                log.warning(
                    "All %d module probes returned no useful data — device may be unreachable; "
                    "preserving existing module list(s)", len(test_results),
                )
                final_modules      = previous_modules
                final_modules_fast = previous_modules_fast

            changed      = final_modules != previous_modules
            changed_fast = final_modules_fast != previous_modules_fast
            modules_changed = changed or changed_fast

            if changed:
                added   = sorted(set(final_modules) - set(previous_modules))
                removed = sorted(set(previous_modules) - set(final_modules))
                log.info("Modules changed — added=%s removed=%s", added, removed)
                for m in added:
                    callbacks.module_changed(module=m, action="added")
                for m in removed:
                    callbacks.module_changed(module=m, action="removed")
            if changed_fast:
                added_fast   = sorted(set(final_modules_fast) - set(previous_modules_fast))
                removed_fast = sorted(set(previous_modules_fast) - set(final_modules_fast))
                log.info("Modules changed (fast) — added=%s removed=%s", added_fast, removed_fast)
                for m in added_fast:
                    callbacks.module_changed(module=m, action="added")
                for m in removed_fast:
                    callbacks.module_changed(module=m, action="removed")

            # ── Polling calculation ───────────────────────────────────────────
            # Requires both NetBox choice sets to be available; otherwise skipped.
            # Floors come from the global default and any matched rule's
            # modules.interval/timeout (or modules.fast.interval/timeout) override.
            interval_floor_s, timeout_floor_s, fast_interval_floor_s, fast_timeout_floor_s = (
                self.engine.resolve_polling_floors(matched_rules)
            )
            final_set      = set(final_modules)
            final_set_fast = set(final_modules_fast)
            probed_durations      = [r.duration_seconds for r in test_results if r.module in final_set]
            probed_durations_fast = [r.duration_seconds for r in test_results if r.module in final_set_fast]

            new_interval = new_timeout = new_interval_fast = new_timeout_fast = None
            resolved_interval = resolved_timeout = resolved_interval_fast = resolved_timeout_fast = None

            if self._interval_steps and self._timeout_steps:
                cur_interval_s = _current_duration_or_default(
                    device.polling_interval, self.engine.default_interval, "polling interval", log
                )
                cur_timeout_s = _current_duration_or_default(
                    device.polling_timeout, self.engine.default_timeout, "polling timeout", log
                )
                if unreachable:
                    # don't trust durations from a likely-unreachable device — report
                    # what's currently in effect, but don't recommend raising it
                    resolved_interval = _format_duration(cur_interval_s)
                    resolved_timeout  = _format_duration(cur_timeout_s)
                else:
                    new_interval, new_timeout, resolved_interval, resolved_timeout = _recommend_polling(
                        probed_durations, self._interval_steps, self._timeout_steps,
                        interval_floor_s, timeout_floor_s, cur_interval_s, cur_timeout_s,
                        "normal", log,
                    )
            elif probed_durations and not unreachable:
                log.info(
                    "Polling: total_probe=%.1fs  (calculation skipped — choice set unavailable)",
                    sum(probed_durations),
                )

            if self.engine.fast_module_field and self._fast_interval_steps and self._fast_timeout_steps:
                cur_interval_fast_s = _current_duration_or_default(
                    device.polling_interval_fast, self.engine.fast_default_interval, "fast interval", log
                )
                cur_timeout_fast_s = _current_duration_or_default(
                    device.polling_timeout_fast, self.engine.fast_default_timeout, "fast timeout", log
                )
                if unreachable:
                    resolved_interval_fast = _format_duration(cur_interval_fast_s)
                    resolved_timeout_fast  = _format_duration(cur_timeout_fast_s)
                else:
                    new_interval_fast, new_timeout_fast, resolved_interval_fast, resolved_timeout_fast = (
                        _recommend_polling(
                            probed_durations_fast, self._fast_interval_steps, self._fast_timeout_steps,
                            fast_interval_floor_s, fast_timeout_floor_s, cur_interval_fast_s, cur_timeout_fast_s,
                            "fast", log,
                        )
                    )
            elif probed_durations_fast and self.engine.fast_module_field and not unreachable:
                log.info(
                    "Polling(fast): total_probe=%.1fs  (calculation skipped — choice set unavailable)",
                    sum(probed_durations_fast),
                )

            # ── Handlers + NetBox write ───────────────────────────────────────
            # success requires a non-empty final module set (either profile) AND no
            # probe errors. Vacuously-true (no probing at all, e.g. nuclear veto) is
            # treated as failure so on_fail handlers fire (e.g. "Last-resort discovery"
            # adds fixme/snmp when the device has no auth and nothing could be probed).
            success  = (
                bool(final_modules or final_modules_fast)
                and not any(r.error for r in test_results)
                and not unreachable
            )
            handlers = self.engine.evaluate_handlers(matched_rules, success=success)
            add_tags    = handlers["add_tags"]
            remove_tags = handlers["remove_tags"]
            notify_urls = handlers["notify"]
            if add_tags or remove_tags:
                log.info("Tag changes — add=%s remove=%s", add_tags, remove_tags)

            result = ModulationResult(
                device_id=device.id,
                device_name=device.name,
                previous_modules=previous_modules,
                final_modules=final_modules,
                changed=modules_changed,
                test_results=test_results,
                auth_profile=resolved_auth,
                auth_changed=auth_changed,
                polling_interval=new_interval,
                polling_timeout=new_timeout,
                resolved_interval=resolved_interval,
                resolved_timeout=resolved_timeout,
                previous_modules_fast=previous_modules_fast,
                final_modules_fast=final_modules_fast,
                changed_fast=changed_fast,
                fast_profile_enabled=bool(self.engine.fast_module_field),
                polling_interval_fast=new_interval_fast,
                polling_timeout_fast=new_timeout_fast,
                resolved_interval_fast=resolved_interval_fast,
                resolved_timeout_fast=resolved_timeout_fast,
                pending_add_tags=add_tags,
                pending_remove_tags=remove_tags,
                unreachable=unreachable,
            )

            if not self.dry_run:
                self.commit(result, log=log)
            else:
                fast_field_note = (
                    f"  {self.engine.fast_module_field}={final_modules_fast}" if self.engine.fast_module_field else ""
                )
                if modules_changed:
                    log.info("DRY RUN — would set: %s=%s%s", self.engine.module_field, final_modules, fast_field_note)
                if add_tags or remove_tags:
                    log.info("DRY RUN — would update tags: add=%s remove=%s", add_tags, remove_tags)
                if new_interval or new_timeout:
                    log.info("DRY RUN — would update polling: interval=%s timeout=%s", new_interval, new_timeout)
                if new_interval_fast or new_timeout_fast:
                    log.info("DRY RUN — would update polling (fast): interval=%s timeout=%s",
                             new_interval_fast, new_timeout_fast)

            callbacks.netbox_update(action="changed" if modules_changed else "unchanged")

            for url in notify_urls:
                try:
                    resp = active_snmp._session.get(url, timeout=10)
                    log.info("Notify %s → %d", url, resp.status_code)
                except Exception as exc:
                    log.warning("Notify %s failed: %s", url, exc)

            return result

        except Exception as exc:
            log.exception("Failed to process %r: %s", device.name, exc)
            return ModulationResult(
                device_id=device.id,
                device_name=device.name,
                previous_modules=sorted(device.current_modules),
                final_modules=sorted(device.current_modules),
                changed=False,
                test_results=[],
                error=str(exc),
            )


# ── Bulk module edit (no probing) ─────────────────────────────────────────────

EDIT_PROFILES = ("normal", "fast")


@dataclass
class EditResult:
    device_id: int
    device_name: str
    previous_modules: list
    final_modules: list
    added: list
    removed: list
    changed: bool
    in_other_profile: list = field(default_factory=list)  # requested adds left alone: already in the other profile
    skipped: Optional[str] = None   # "pinned"
    error: Optional[str] = None


def apply_module_edit(current: list, other_profile: list, add: list, remove: list) -> tuple:
    """Pure set arithmetic for one device's module list: drop `remove`, then
    append `add` (existing order kept, new modules appended in request order).

    A module to add that already sits in the *other* profile's field is left
    where it is — a module lives in exactly one profile, and an edit doesn't
    move it. Returns (final, added, removed, in_other_profile)."""
    removed = [m for m in current if m in remove]
    final   = [m for m in current if m not in remove]
    in_other, added = [], []
    for m in dict.fromkeys(add):
        if m in final:
            continue
        if m in other_profile:
            in_other.append(m)
        else:
            added.append(m)
    return final + added, added, removed, in_other


class ModuleEditor:
    """Bulk add/remove modules on the devices a NetBox filter selects — pure
    NetBox edit, no SNMP probing, no mapping.yaml rules. Meant for fast
    fleet-wide rollouts (e.g. add if_updown_state wherever if_full already is)
    that a full re-probe of thousands of devices would take hours for.

    Deliberately leaves touch_field alone: it means "last probed", and this
    isn't a probe. Honors pin_tag like any batch run."""

    def __init__(
        self,
        nb: NetboxClient,
        engine: "MappingEngine",
        profile: str = "normal",
        dry_run: bool = False,
        honor_pins: bool = True,
        chunk_size: int = 100,
    ):
        if profile not in EDIT_PROFILES:
            raise ValueError(f"profile must be one of {EDIT_PROFILES}, got {profile!r}")
        if profile == "fast" and not engine.fast_module_field:
            raise ValueError("profile=fast requested but modules.fast.field is not configured in mapping.yaml")
        self.nb         = nb
        self.engine     = engine
        self.profile    = profile
        self.dry_run    = dry_run
        self.honor_pins = honor_pins
        self.chunk_size = chunk_size

    @property
    def field_name(self) -> str:
        return self.engine.fast_module_field if self.profile == "fast" else self.engine.module_field

    def unknown_modules(self, modules: list, known_modules: Optional[list] = None) -> list:
        """Modules that can't be added: not a NetBox choice for the target field,
        or (when known_modules is given) not defined in snmp-exporter."""
        valid = self.nb._valid_modules_fast if self.profile == "fast" else self.nb._valid_modules
        return [
            m for m in modules
            if (valid is not None and m not in valid) or (known_modules and m not in known_modules)
        ]

    def run(self, devices: list, add: list, remove: list, add_only_if_removed: bool = False,
            callbacks: Optional[Callbacks] = None) -> list:
        """add_only_if_removed makes it a replace: a device that carried none of
        `remove` doesn't get `add` either."""
        if callbacks is None:
            callbacks = Callbacks()
        add, remove = list(dict.fromkeys(add)), set(remove)
        changelog = f"{APP_NAME} module edit: " + " ".join([f"+{m}" for m in add] + [f"-{m}" for m in sorted(remove)])

        results, updates = [], {}
        for device in devices:
            if self.profile == "fast":
                current, other = device.current_modules_fast, device.current_modules
            else:
                current, other = device.current_modules, device.current_modules_fast
            if self.honor_pins and _is_pinned(device, self.engine.pin_tag):
                results.append(EditResult(
                    device.id, device.name, list(current), list(current), [], [], False, skipped="pinned",
                ))
                continue
            final, added, removed, in_other = apply_module_edit(current, other, add, remove)
            if add_only_if_removed and not removed:
                final, added, in_other = list(current), [], []
            changed = bool(added or removed)
            results.append(EditResult(
                device.id, device.name, list(current), final, added, removed, changed, in_other_profile=in_other,
            ))
            if changed:
                updates[device.id] = final

        errors = {}
        if updates and not self.dry_run:
            errors = self.nb.bulk_set_modules(self.field_name, updates, changelog, chunk_size=self.chunk_size)

        for r in results:
            if r.device_id in errors:
                r.error = errors[r.device_id]
                continue
            if r.skipped:
                continue
            callbacks.netbox_update(action="changed" if r.changed else "unchanged")
            if not self.dry_run:
                for m in r.added:
                    callbacks.module_changed(m, "added")
                for m in r.removed:
                    callbacks.module_changed(m, "removed")

        logger.info(
            "Module edit complete (%s%s): %d device(s)  changed=%d pinned=%d errors=%d  [%s]",
            self.field_name, ", DRY RUN" if self.dry_run else "", len(results),
            sum(1 for r in results if r.changed and not r.error),
            sum(1 for r in results if r.skipped), len(errors), changelog,
        )
        return results
