"""Parser for DHCP snooping state."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from stig_audit_pro.parsers.common import normalize_interface_name, parse_vlan_list


@dataclass(slots=True)
class DhcpSnoopingInfo:
    global_enabled: bool = False
    vlans: set[int] = field(default_factory=set)
    trusted_interfaces: set[str] = field(default_factory=set)


def _parse_running_config(text: str) -> DhcpSnoopingInfo:
    info = DhcpSnoopingInfo()
    current_interface: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped == "!":
            current_interface = None
            continue
        if stripped.startswith("interface "):
            current_interface = normalize_interface_name(stripped.removeprefix("interface ").strip())
            continue
        if stripped == "ip dhcp snooping":
            info.global_enabled = True
        elif stripped.startswith("ip dhcp snooping vlan "):
            info.vlans.update(parse_vlan_list(stripped.removeprefix("ip dhcp snooping vlan ")))
        elif stripped == "ip dhcp snooping trust" and current_interface:
            info.trusted_interfaces.add(current_interface)
    return info


def _parse_show_output(text: str) -> DhcpSnoopingInfo:
    info = DhcpSnoopingInfo()
    capture_vlans = False
    capture_trust_table = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if not stripped:
            capture_vlans = False
            continue
        if "dhcp snooping is enabled" in lowered:
            info.global_enabled = True
        elif "dhcp snooping is disabled" in lowered:
            info.global_enabled = False
        elif "configured on following vlan" in lowered or "operational on following vlan" in lowered:
            capture_vlans = True
            continue
        elif "interface" in lowered and "trusted" in lowered:
            capture_trust_table = True
            continue
        elif capture_vlans:
            info.vlans.update(parse_vlan_list(stripped))
            continue
        elif capture_trust_table and not stripped.startswith("-"):
            parts = stripped.split()
            if len(parts) >= 2 and re.match(r"^[A-Za-z]", parts[0]):
                trusted_value = parts[1].lower()
                if trusted_value in {"yes", "trusted", "true"}:
                    info.trusted_interfaces.add(normalize_interface_name(parts[0]))
    return info


def parse_dhcp_snooping(show_output: str = "", running_config: str = "") -> DhcpSnoopingInfo:
    running = _parse_running_config(running_config)
    shown = _parse_show_output(show_output)
    return DhcpSnoopingInfo(
        global_enabled=running.global_enabled or shown.global_enabled,
        vlans=running.vlans | shown.vlans,
        trusted_interfaces=running.trusted_interfaces | shown.trusted_interfaces,
    )
