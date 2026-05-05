#!/usr/bin/env python3
"""
snmp-modulator — core library.

Probes NetBox devices against snmp-exporter modules and writes back
the snmp_exporter_module custom field with only modules that return
useful data (per the mapping YAML).
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

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
    """Parse '30s', '1m', '90s', '3m' etc. to seconds."""
    s = s.strip()
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


def _format_duration(seconds: int) -> str:
    """Format seconds to a duration string (e.g. 120 → '2m', 90 → '90s')."""
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _round_up_to_step(seconds: float, steps: list) -> int:
    """Round up to the nearest value in steps; cap at the maximum step."""
    target = int(seconds)
    for step in steps:
        if step >= target:
            return step
    return steps[-1]


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
    nb_device: Any = None       # raw pynetbox Record for flexible match key traversal


@dataclass
class ModuleTestResult:
    module: str
    useful: bool
    metric_count: int           # non-housekeeping metrics found
    duration_seconds: float     # scrape_duration_seconds or wall-clock fallback
    error: Optional[str] = None


@dataclass
class ModulationResult:
    device_id: int
    device_name: str
    previous_modules: list
    final_modules: list
    changed: bool
    test_results: list          # list[ModuleTestResult] — try-modules only
    auth_profile: Optional[str] = None   # resolved auth profile used for probing
    auth_changed: bool = False           # True if auth profile was written back to NetBox
    polling_interval: Optional[str] = None   # new interval written to NetBox (None = unchanged)
    polling_timeout:  Optional[str] = None   # new timeout written to NetBox (None = unchanged)
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
    ):
        session = _ChangelogSession(APP_NAME)
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            session.verify = False
        self.nb = pynetbox.api(url, token=token)
        self.nb.http_session = session
        self._module_field      = module_field
        self._auth_field        = auth_field
        self._interval_field    = interval_field
        self._timeout_field     = timeout_field
        self._valid_modules: Optional[frozenset] = self._fetch_module_choices()

    def _fetch_module_choices(self) -> Optional[frozenset]:
        """Fetch valid choices for the module multi-select field from NetBox.

        NetBox 3.3+ stores choices on a linked CustomFieldChoiceSet; older
        versions exposed them directly on the custom field.
        """
        try:
            cf = self.nb.extras.custom_fields.get(name=self._module_field)
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
                        logger.info("NetBox module field %r: %d valid choice(s)", self._module_field, len(choices))
                        return choices

            # Older NetBox: choices directly on the custom field
            direct = getattr(cf, "choices", None)
            if direct:
                choices = frozenset(c.value for c in direct)
                logger.info("NetBox module field %r: %d valid choice(s)", self._module_field, len(choices))
                return choices

        except Exception as exc:
            logger.warning("Could not fetch NetBox choices for %r: %s — unknown modules will not be filtered", self._module_field, exc)
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

            cf_modules = cf.get(self._module_field) or []
            if isinstance(cf_modules, list):
                current_modules = [
                    item["value"] if isinstance(item, dict) else str(item)
                    for item in cf_modules
                ]
            else:
                current_modules = []

            devices.append(DeviceInfo(
                id=dev.id,
                name=dev.name,
                primary_ip=primary_ip,
                snmp_auth_profile=snmp_auth_profile,
                current_modules=current_modules,
                polling_interval=cf.get(self._interval_field) or None,
                polling_timeout=cf.get(self._timeout_field)   or None,
                nb_device=dev,
            ))

        logger.info("Fetched %d eligible device(s) from NetBox", len(devices))
        return devices

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
                            polling_timeout: Optional[str] = None) -> None:
        """Update the module multi-select custom field, optionally batching tag/polling changes."""
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
        payload = {"custom_fields": cf}
        if add_tags or remove_tags:
            payload["tags"] = self._compute_tags(dev, add_tags, remove_tags)
        dev.update(payload)

    def update_polling(self, device_id: int,
                       interval: Optional[str] = None,
                       timeout: Optional[str] = None) -> None:
        """Update polling interval/timeout fields standalone (when modules unchanged)."""
        cf = {}
        if interval is not None:
            cf[self._interval_field] = interval
        if timeout is not None:
            cf[self._timeout_field] = timeout
        if cf:
            dev = self.nb.dcim.devices.get(device_id)
            dev.update({"custom_fields": cf})

    def update_auth_profile(self, device_id: int, profile: str) -> None:
        """Update the SNMP auth profile text custom field."""
        dev = self.nb.dcim.devices.get(device_id)
        dev.update({"custom_fields": {self._auth_field: profile}})

    def apply_tag_changes(self, device_id: int, add_tags: list, remove_tags: list) -> None:
        """Add/remove tags on a device (standalone, when no module update is needed)."""
        dev = self.nb.dcim.devices.get(device_id)
        dev.update({"tags": self._compute_tags(dev, add_tags, remove_tags)})

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
                duration_seconds=elapsed,
                error=str(exc),
            )

        elapsed = time.monotonic() - t0
        metrics = self._parse(resp.text)
        useful, metric_count, scrape_duration = self._evaluate(metrics)

        return ModuleTestResult(
            module=module,
            useful=useful,
            metric_count=metric_count,
            duration_seconds=scrape_duration if scrape_duration > 0 else elapsed,
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
        metrics = self._parse(resp.text)
        up = metrics.get("up", 0.0)
        useful, useful_count, _ = self._evaluate(metrics)
        logger.debug("probe_auth %r: up=%s  useful=%d  metrics=%d",
                     auth, up, useful_count, len(metrics))
        return up == 1.0 or useful

    @staticmethod
    def _parse(text: str) -> dict:
        """
        Parse Prometheus text exposition format into {metric_name: first_seen_value}.

        Strips label sets, skips comments and non-numeric values (string metrics
        like ifDescr).  Only the first occurrence of each metric family is kept —
        we care about presence, not cardinality.
        """
        metrics: dict = {}
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

            if name not in metrics:
                metrics[name] = value

        return metrics

    @staticmethod
    def _evaluate(metrics: dict) -> tuple:
        """
        Returns (useful, useful_metric_count, scrape_duration_seconds).

        Useful = any metric that is not in the housekeeping set and does not
        start with "snmp_scrape_" (snmp-exporter internal walk metrics).
        """
        useful_count = sum(
            1 for name in metrics
            if name not in _HOUSEKEEPING_METRICS
            and not name.startswith("snmp_scrape_")
        )
        scrape_duration = metrics.get("scrape_duration_seconds", 0.0)
        return useful_count > 0, useful_count, scrape_duration


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
        self.default_interval: int = _parse_duration(modules_cfg.get("default_interval", "3m"))
        self.default_timeout:  int = _parse_duration(modules_cfg.get("default_timeout",  "2m"))

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
            mod = r.get("modules", {})
            self._rules.append({
                "name":           r.get("name", "(unnamed)"),
                "compiled_match": self._compile_match(r.get("match", {})),
                "add":            list(mod.get("add",   [])),
                "try":            list(mod.get("try",   [])),
                "block":          list(mod.get("block", [])),
                "auth":           r.get("auth"),
                "on_success":     self._parse_handlers(r.get("on_success") or {}),
                "on_fail":        self._parse_handlers(r.get("on_fail")    or {}),
            })

        logger.info(
            "Mapping loaded: %d rule(s)  defaults: add=%d try=%d block=%d  "
            "module_policy=%s  auth_policy=%s  module_field=%r  auth_field=%r",
            len(self._rules),
            len(self._default_add),
            len(self._default_try),
            len(self._default_block),
            self.module_policy,
            self.auth_policy,
            self.module_field,
            self.auth_field,
        )

    @staticmethod
    def _compile_match(match_dict: dict) -> dict:
        """Compile each regex pattern once (case-insensitive full-match)."""
        return {
            field_path: re.compile(str(pattern), re.IGNORECASE)
            for field_path, pattern in match_dict.items()
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

        # _ALL in block — nuclear veto, nothing survives
        if "_ALL" in block:
            return set(), set(), block, matched_names, matched_rules

        # _ALL in test — expand to every known module
        if "_ALL" in test:
            if not known_modules:
                logger.warning("_ALL in try but no module list available (snmp-exporter /config not loaded)")
            test = (test - {"_ALL"}) | set(known_modules)

        # Normal per-module veto
        unconditional -= block
        test -= block
        test -= unconditional  # already added unconditionally — no need to probe

        return unconditional, test, block, matched_names, matched_rules

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
    ):
        """
        module_policy controls how modules already in snmp_exporter_module are handled:
          drop  — ignore existing modules entirely; mapping is sole source of truth
          try   — probe existing modules; keep if they still return useful data
          use   — keep existing modules unconditionally (non-destructive / append mode)
        block veto always applies regardless of policy.

        device_parallelism: number of devices probed concurrently within one run
        (1 = sequential). SNMP probing is I/O-bound, so threads scale well.
        """
        if module_policy not in MODULE_POLICIES:
            raise ValueError(f"module_policy must be one of {MODULE_POLICIES}, got {module_policy!r}")
        if device_parallelism < 1:
            raise ValueError(f"device_parallelism must be >= 1, got {device_parallelism}")
        self.nb          = nb
        self.snmp        = snmp   # fallback / single-site client (SNMP_EXPORTER_URL)
        self.engine      = engine
        self.dry_run     = dry_run
        self.module_policy = module_policy
        self.device_parallelism = device_parallelism

        # Polling step ladders are sourced from the NetBox selection custom fields.
        # When either choice set is unavailable, polling calculation is disabled.
        self._interval_steps: Optional[list] = None
        self._timeout_steps:  Optional[list] = None
        if engine.interval_field:
            self._interval_steps = nb.get_polling_step_values(engine.interval_field)
            if self._interval_steps:
                logger.info("Interval steps from NetBox %r: %s", engine.interval_field, self._interval_steps)
            else:
                logger.warning("Interval steps unavailable for %r — polling calculation disabled", engine.interval_field)
        if engine.timeout_field:
            self._timeout_steps = nb.get_polling_step_values(engine.timeout_field)
            if self._timeout_steps:
                logger.info("Timeout steps from NetBox %r: %s", engine.timeout_field, self._timeout_steps)
            else:
                logger.warning("Timeout steps unavailable for %r — polling calculation disabled", engine.timeout_field)

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

    def _compare_module_sets(self) -> None:
        """Warn if NetBox module choices and snmp-exporter modules are out of sync."""
        nb_choices = self.nb._valid_modules
        if not nb_choices:
            return
        snmp_modules = set(self.snmp.modules)
        if not snmp_modules:
            return
        only_in_netbox = nb_choices - snmp_modules
        only_in_snmp   = snmp_modules - nb_choices
        if only_in_netbox:
            logger.warning("Module(s) in NetBox but not in snmp-exporter: %s", sorted(only_in_netbox))
        if only_in_snmp:
            logger.warning("Module(s) in snmp-exporter but not in NetBox: %s", sorted(only_in_snmp))
        if not only_in_netbox and not only_in_snmp:
            logger.debug("NetBox choices and snmp-exporter modules are in sync (%d)", len(nb_choices))

    def run(
        self,
        devices: list,
        callbacks: Optional[Callbacks] = None,
    ) -> list:
        """Process a list of DeviceInfo objects and return list[ModulationResult].

        With device_parallelism > 1, devices are probed concurrently via a
        ThreadPoolExecutor. Per-device log lines remain distinguishable by IP
        because each device gets its own logger.
        """
        if callbacks is None:
            callbacks = Callbacks()

        logger.info(
            "Starting run: %d device(s)  parallelism=%d",
            len(devices), self.device_parallelism,
        )

        def _one(device: DeviceInfo) -> ModulationResult:
            result = self.process_device(device, callbacks)
            callbacks.device_processed("error" if result.error else "success")
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

        ok  = sum(1 for r in results if not r.error)
        err = sum(1 for r in results if r.error)
        chg = sum(1 for r in results if r.changed)
        logger.info("Run complete: %d device(s)  ok=%d err=%d changed=%d", len(results), ok, err, chg)
        return results

    def process_device(self, device: DeviceInfo, callbacks: Optional[Callbacks] = None) -> ModulationResult:
        if callbacks is None:
            callbacks = Callbacks()

        log = logging.getLogger(f"{APP_NAME}.{device.primary_ip}")

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
                    log.info("Auth: rule specifies %r (was %r)", fixed_auth, device.snmp_auth_profile)
                    if not self.dry_run:
                        self.nb.update_auth_profile(device.id, fixed_auth)
                    else:
                        log.info("DRY RUN — would update auth to %r", fixed_auth)
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
                    self._apply_handlers(device, [], success=False, log=log)
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
                    log.info("Auth: %r → %r", device.snmp_auth_profile, resolved_auth)
                    if not self.dry_run:
                        self.nb.update_auth_profile(device.id, resolved_auth)
                    else:
                        log.info("DRY RUN — would update auth to %r", resolved_auth)

            else:
                # auth_policy try/drop but no candidates configured
                log.warning(
                    "Auth: policy is %r but no candidates for %r — skipping device",
                    self.engine.auth_policy, device.name,
                )
                callbacks.auth_probed("failed")
                self._apply_handlers(device, [], success=False, log=log)
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

            # Apply existing-module policy
            existing = set(device.current_modules) - block_set
            if self.module_policy == "use":
                unconditional |= existing
            elif self.module_policy == "try":
                test_set |= existing - unconditional

            log.debug(
                "Modules — add=%s try=%s block=%s",
                sorted(unconditional), sorted(test_set), sorted(block_set),
            )

            # Probe each try-module using the resolved auth profile
            test_results: list = []
            for module in sorted(test_set):
                result = active_snmp.probe(device.primary_ip, module, resolved_auth)
                test_results.append(result)
                outcome = "error" if result.error else ("useful" if result.useful else "empty")
                err_str = result.error.split(" for url:")[0] if result.error else ""
                log.info(
                    "  %-22s  %-6s  %3d metrics  %.2fs%s",
                    module, outcome, result.metric_count, result.duration_seconds,
                    f"  {err_str}" if err_str else "",
                )
                callbacks.module_test(module=module, result=outcome)
                callbacks.module_test_duration(module=module, duration=result.duration_seconds)

            # Build final module set
            useful_modules = {r.module for r in test_results if r.useful}
            final_modules  = sorted(unconditional | useful_modules)
            previous_modules = sorted(device.current_modules)
            changed = final_modules != previous_modules

            if changed:
                added   = sorted(set(final_modules) - set(previous_modules))
                removed = sorted(set(previous_modules) - set(final_modules))
                log.info("Modules changed — added=%s removed=%s", added, removed)
                for m in added:
                    callbacks.module_changed(module=m, action="added")
                for m in removed:
                    callbacks.module_changed(module=m, action="removed")

            # ── Polling calculation ───────────────────────────────────────────
            # Requires both NetBox choice sets to be available; otherwise skipped.
            final_set = set(final_modules)
            probed_durations = [r.duration_seconds for r in test_results if r.module in final_set]
            new_interval = new_timeout = None
            if probed_durations and self._timeout_steps and self._interval_steps:
                total_s = sum(probed_durations)
                rec_timeout_s  = _round_up_to_step(total_s * 1.5, self._timeout_steps)
                rec_interval_s = _round_up_to_step(rec_timeout_s * 2, self._interval_steps)

                cur_timeout_s  = _parse_duration(device.polling_timeout)  if device.polling_timeout  else self.engine.default_timeout
                cur_interval_s = _parse_duration(device.polling_interval) if device.polling_interval else self.engine.default_interval
                if rec_timeout_s  > cur_timeout_s:
                    new_timeout  = _format_duration(rec_timeout_s)
                if rec_interval_s > cur_interval_s:
                    new_interval = _format_duration(rec_interval_s)

                log.info(
                    "Polling: total_probe=%.1fs  rec_timeout=%s  rec_interval=%s%s",
                    total_s,
                    _format_duration(rec_timeout_s),
                    _format_duration(rec_interval_s),
                    f"  timeout→{new_timeout}  interval→{new_interval}"
                    if (new_timeout or new_interval) else "  ok",
                )
            elif probed_durations:
                log.info(
                    "Polling: total_probe=%.1fs  (calculation skipped — choice set unavailable)",
                    sum(probed_durations),
                )

            # ── Handlers + NetBox write ───────────────────────────────────────
            # success requires a non-empty final module set AND no probe errors.
            # Vacuously-true (no probing at all, e.g. nuclear veto) is treated as
            # failure so on_fail handlers fire (e.g. "Last-resort discovery" adds
            # fixme/snmp when the device has no auth and nothing could be probed).
            success  = bool(final_modules) and not any(r.error for r in test_results)
            handlers = self.engine.evaluate_handlers(matched_rules, success=success)
            add_tags    = handlers["add_tags"]
            remove_tags = handlers["remove_tags"]
            notify_urls = handlers["notify"]
            if add_tags or remove_tags:
                log.info("Tag changes — add=%s remove=%s", add_tags, remove_tags)

            if not self.dry_run:
                if changed:
                    self.nb.update_snmp_modules(device.id, final_modules,
                                                add_tags=add_tags, remove_tags=remove_tags,
                                                polling_interval=new_interval,
                                                polling_timeout=new_timeout)
                    log.info("NetBox updated: snmp_exporter_module=%s", final_modules)
                else:
                    if add_tags or remove_tags:
                        self.nb.apply_tag_changes(device.id, add_tags, remove_tags)
                    if new_interval or new_timeout:
                        self.nb.update_polling(device.id, interval=new_interval, timeout=new_timeout)
            else:
                if changed:
                    log.info("DRY RUN — would set: snmp_exporter_module=%s", final_modules)
                if add_tags or remove_tags:
                    log.info("DRY RUN — would update tags: add=%s remove=%s", add_tags, remove_tags)
                if new_interval or new_timeout:
                    log.info("DRY RUN — would update polling: interval=%s timeout=%s", new_interval, new_timeout)

            callbacks.netbox_update(action="changed" if changed else "unchanged")

            for url in notify_urls:
                try:
                    resp = active_snmp._session.get(url, timeout=10)
                    log.info("Notify %s → %d", url, resp.status_code)
                except Exception as exc:
                    log.warning("Notify %s failed: %s", url, exc)

            return ModulationResult(
                device_id=device.id,
                device_name=device.name,
                previous_modules=previous_modules,
                final_modules=final_modules,
                changed=changed,
                test_results=test_results,
                auth_profile=resolved_auth,
                auth_changed=auth_changed,
                polling_interval=new_interval,
                polling_timeout=new_timeout,
            )

        except Exception as exc:
            log.error("Failed to process %r: %s", device.name, exc, exc_info=True)
            return ModulationResult(
                device_id=device.id,
                device_name=device.name,
                previous_modules=sorted(device.current_modules),
                final_modules=sorted(device.current_modules),
                changed=False,
                test_results=[],
                error=str(exc),
            )
