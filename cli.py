#!/usr/bin/env python3
"""
snmp-modulator CLI — one-shot probe run.

Usage:
    # Single device by IP or name
    python cli.py --host 10.0.0.1
    python cli.py --host switch.example.com --dry-run --debug

    # Devices matching a NetBox filter (URL-encoded query string)
    python cli.py --netbox-filter "role=switch&site=dc1"
    python cli.py --netbox-filter "manufacturer=cisco&last_updated__lt=2025-10-01"
    python cli.py --netbox-filter "role_id=4" --dry-run

Settings hierarchy (last wins):
    mapping.yaml  →  environment variable  →  CLI argument
"""

import logging
import os
import sys
import urllib.parse

import click

from modulator import AUTH_POLICIES, MODULE_POLICIES, MappingEngine, Modulator, NetboxClient, SnmpExporterClient


@click.command()
@click.option("--host",
              default=None,
              envvar="MODULATOR_HOST",
              help="Device IP or name to probe (mutually exclusive with --netbox-filter).")
@click.option("--netbox-filter",
              default=None,
              envvar="NB_FILTER",
              help="URL-encoded NetBox filter, e.g. 'role=switch&site=dc1'. "
                   "Passed directly to dcim.devices.filter().")
@click.option("--mapping",
              default="mapping.yaml",
              show_default=True,
              envvar="MAPPING_FILE",
              help="Path to mapping YAML.")
@click.option("--module-policy",
              default=None,
              type=click.Choice(MODULE_POLICIES),
              help="How to treat modules already in the module field: "
                   "drop=ignore, try=re-probe, use=keep unconditionally. "
                   "Overrides mapping.yaml modules.policy.")
@click.option("--auth-policy",
              default=None,
              type=click.Choice(AUTH_POLICIES),
              help="How to handle the SNMP auth profile: "
                   "use=trust NetBox value, try=validate then discover, "
                   "drop=discover from scratch. Overrides mapping.yaml auth_policy.")
@click.option("--module-field",
              default=None,
              help="NetBox custom field name for the module list. "
                   "Overrides mapping.yaml netbox_fields.module_field.")
@click.option("--auth-field",
              default=None,
              help="NetBox custom field name for the SNMP auth profile. "
                   "Overrides mapping.yaml netbox_fields.auth_field.")
@click.option("--dry-run",
              is_flag=True,
              default=False,
              envvar="MODULATOR_DRY_RUN",
              help="Log changes without writing to NetBox.")
@click.option("--device-parallelism",
              type=int,
              default=1,
              envvar="MODULATOR_DEVICE_PARALLELISM",
              help="Number of devices probed concurrently within one run (1 = sequential).")
@click.option("--debug",
              is_flag=True,
              default=False,
              help="Enable debug logging.")
def main(host, netbox_filter, mapping, module_policy, auth_policy, module_field, auth_field, dry_run, device_parallelism, debug):
    """Run SNMP module modulation for matching NetBox devices."""

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    log = logging.getLogger("snmp-modulator.cli")

    if host and netbox_filter:
        log.error("--host and --netbox-filter are mutually exclusive")
        sys.exit(1)
    if not host and not netbox_filter:
        log.error("One of --host or --netbox-filter is required")
        sys.exit(1)

    # Load mapping — provides all settings; CLI args override where provided
    engine = MappingEngine(mapping)

    resolved_module_policy = module_policy or engine.module_policy
    resolved_auth_policy   = auth_policy   or engine.auth_policy
    resolved_module_field  = module_field  or engine.module_field
    resolved_auth_field    = auth_field    or engine.auth_field

    # Apply CLI overrides directly to engine so evaluate_auth picks them up
    engine.auth_policy = resolved_auth_policy

    log.debug(
        "Settings: module_policy=%s  auth_policy=%s  module_field=%r  auth_field=%r",
        resolved_module_policy, resolved_auth_policy, resolved_module_field, resolved_auth_field,
    )

    nb = NetboxClient(
        url=os.environ["NETBOX_URL"],
        token=os.environ["NETBOX_TOKEN"],
        verify_tls=os.getenv("NETBOX_TLS_VERIFY", "true").lower() != "false",
        module_field=resolved_module_field,
        auth_field=resolved_auth_field,
        interval_field=engine.interval_field,
        timeout_field=engine.timeout_field,
    )
    verify_tls = os.getenv("SNMP_EXPORTER_TLS_VERIFY", "true").lower() != "false"
    timeout    = int(os.getenv("SNMP_EXPORTER_TIMEOUT", "30"))
    snmp       = SnmpExporterClient(
        base_url=os.environ["SNMP_EXPORTER_URL"],
        verify_tls=verify_tls,
        timeout=timeout,
    )
    mod = Modulator(
        nb, snmp, engine,
        dry_run=dry_run,
        module_policy=resolved_module_policy,
        device_parallelism=device_parallelism,
    )

    if dry_run:
        log.info("DRY RUN mode — NetBox will not be updated")

    if host:
        device = nb.get_device_by_host(host)
        if not device:
            log.error(
                "Host %r not found in NetBox or ineligible (no primary IP / no %r field)",
                host, resolved_auth_field,
            )
            sys.exit(1)
        devices = [device]
    else:
        qs = netbox_filter.lstrip("?")
        filter_kwargs = {
            k: v[0] if len(v) == 1 else v
            for k, v in urllib.parse.parse_qs(qs, keep_blank_values=False).items()
        }
        log.info("NetBox filter: %s", filter_kwargs)
        devices = nb.get_devices(**filter_kwargs)
        if not devices:
            log.warning("No eligible devices found for filter: %s", filter_kwargs)
            sys.exit(0)

    results = mod.run(devices)

    errors  = [r for r in results if r.error]
    changed = [r for r in results if r.changed]

    if errors:
        log.error("%d device(s) failed: %s", len(errors), [r.device_name for r in errors])
        sys.exit(1)

    log.info("Done: %d device(s) processed, %d changed", len(results), len(changed))
    sys.exit(0)


if __name__ == "__main__":
    main()
