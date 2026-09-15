"""Parser for show interfaces trunk."""

from __future__ import annotations

from dataclasses import dataclass, field

from stig_audit_pro.parsers.common import looks_like_interface, normalize_interface_name, parse_vlan_list


@dataclass(slots=True)
class TrunkInfo:
    name: str
    mode: str = ""
    encapsulation: str = ""
    status: str = ""
    native_vlan: int | None = None
    allowed_vlans: set[int] = field(default_factory=set)
    active_vlans: set[int] = field(default_factory=set)
    forwarding_not_pruned_vlans: set[int] = field(default_factory=set)


def _ensure_trunk(trunks: dict[str, TrunkInfo], name: str) -> TrunkInfo:
    normalized = normalize_interface_name(name)
    if normalized not in trunks:
        trunks[normalized] = TrunkInfo(name=normalized)
    return trunks[normalized]


def _parse_vlan_section_line(line: str) -> tuple[str, str] | None:
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    if not looks_like_interface(parts[0]):
        return None
    return parts[0], parts[1]


def parse_interfaces_trunk(text: str) -> dict[str, TrunkInfo]:
    trunks: dict[str, TrunkInfo] = {}
    section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip().lstrip("\ufeff")
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if stripped.startswith("Port"):
            lowered = stripped.lower()
            if "encapsulation" in lowered and "native vlan" in lowered:
                section = "mode"
            elif "vlans allowed on trunk" in lowered:
                section = "allowed"
            elif "allowed and active" in lowered:
                section = "active"
            elif "spanning tree forwarding" in lowered:
                section = "forwarding"
            else:
                section = None
            continue

        if section == "mode":
            parts = stripped.split()
            if len(parts) >= 5 and looks_like_interface(parts[0]):
                trunk = _ensure_trunk(trunks, parts[0])
                trunk.mode = parts[1]
                trunk.encapsulation = parts[2]
                trunk.status = parts[3]
                trunk.native_vlan = int(parts[4]) if parts[4].isdigit() else None
            continue

        parsed = _parse_vlan_section_line(stripped)
        if parsed is None or section is None:
            continue
        interface_name, vlan_text = parsed
        trunk = _ensure_trunk(trunks, interface_name)
        vlans = parse_vlan_list(vlan_text)
        if section == "allowed":
            trunk.allowed_vlans = vlans
        elif section == "active":
            trunk.active_vlans = vlans
        elif section == "forwarding":
            trunk.forwarding_not_pruned_vlans = vlans

    return trunks
