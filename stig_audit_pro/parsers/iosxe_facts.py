"""Basic IOS-XE fact parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from stig_audit_pro.parsers.iosxe_running_config import parse_running_config


@dataclass(slots=True)
class DeviceFacts:
    hostname: str = "unknown"
    version: str | None = None
    model: str | None = None
    serial_number: str | None = None


def parse_facts(running_config: str = "", show_version: str = "", show_inventory: str = "") -> DeviceFacts:
    running = parse_running_config(running_config) if running_config else None
    hostname = running.hostname if running and running.hostname else "unknown"
    version: str | None = None
    model: str | None = None
    serial: str | None = None

    version_match = re.search(r"Cisco IOS XE Software, Version\s+([^\r\n]+)", show_version)
    if version_match:
        version = version_match.group(1).strip()

    model_match = re.search(r"[Cc]isco\s+([A-Z0-9-]+)\s+\([^)]*\)\s+processor", show_version)
    if model_match:
        model = model_match.group(1).strip()

    serial_match = re.search(r"SN:\s*([A-Z0-9]+)", show_inventory)
    if serial_match:
        serial = serial_match.group(1).strip()

    return DeviceFacts(hostname=hostname, version=version, model=model, serial_number=serial)
