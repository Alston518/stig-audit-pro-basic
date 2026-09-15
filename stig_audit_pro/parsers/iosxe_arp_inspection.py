"""Parser for Dynamic ARP Inspection state."""

from __future__ import annotations

from dataclasses import dataclass, field

from stig_audit_pro.parsers.common import normalize_interface_name, parse_vlan_list


@dataclass(slots=True)
class ArpInspectionInfo:
    vlans: set[int] = field(default_factory=set)
    trusted_interfaces: set[str] = field(default_factory=set)


def _parse_running_config(text: str) -> ArpInspectionInfo:
    info = ArpInspectionInfo()
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
        if stripped.startswith("ip arp inspection vlan "):
            info.vlans.update(parse_vlan_list(stripped.removeprefix("ip arp inspection vlan ")))
        elif stripped == "ip arp inspection trust" and current_interface:
            info.trusted_interfaces.add(current_interface)
    return info


def _parse_show_output(text: str) -> ArpInspectionInfo:
    info = ArpInspectionInfo()
    in_vlan_table = False
    in_interface_table = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if not stripped:
            continue
        if lowered.startswith("vlan") and "configuration" in lowered:
            in_vlan_table = True
            in_interface_table = False
            continue
        if lowered.startswith("interface") and "trust state" in lowered:
            in_interface_table = True
            in_vlan_table = False
            continue
        if stripped.startswith("-"):
            continue
        if in_vlan_table:
            parts = stripped.split()
            if parts and parts[0].isdigit() and any(part.lower().startswith("enabled") for part in parts[1:]):
                info.vlans.add(int(parts[0]))
        elif in_interface_table:
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].lower() == "trusted":
                info.trusted_interfaces.add(normalize_interface_name(parts[0]))
    return info


def parse_arp_inspection(show_output: str = "", running_config: str = "") -> ArpInspectionInfo:
    running = _parse_running_config(running_config)
    shown = _parse_show_output(show_output)
    return ArpInspectionInfo(
        vlans=running.vlans | shown.vlans,
        trusted_interfaces=running.trusted_interfaces | shown.trusted_interfaces,
    )
