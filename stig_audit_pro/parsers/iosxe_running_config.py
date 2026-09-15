"""Parser for IOS-XE running configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from stig_audit_pro.parsers.common import normalize_interface_name, parse_vlan_list


@dataclass(slots=True)
class InterfaceConfig:
    name: str
    shutdown: bool = False
    switchport_mode: str | None = None
    access_vlan: int | None = None
    trunk_allowed_vlans: set[int] | None = None
    description: str | None = None
    channel_group: str | None = None
    raw_lines: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RunningConfig:
    hostname: str | None = None
    global_lines: list[str] = field(default_factory=list)
    sections: dict[str, list[str]] = field(default_factory=dict)
    interfaces: dict[str, InterfaceConfig] = field(default_factory=dict)


def _close_section(
    header: str | None,
    lines: list[str],
    sections: dict[str, list[str]],
    global_lines: list[str],
) -> None:
    if not header:
        return
    if lines:
        sections[header] = list(lines)
    else:
        global_lines.append(header)


def _parse_interface(header: str, lines: list[str]) -> InterfaceConfig:
    name = normalize_interface_name(header.removeprefix("interface").strip())
    config = InterfaceConfig(name=name, raw_lines=list(lines))
    for line in lines:
        stripped = line.strip()
        if stripped == "shutdown":
            config.shutdown = True
        elif stripped == "no shutdown":
            config.shutdown = False
        elif stripped.startswith("description "):
            config.description = stripped.removeprefix("description ").strip()
        elif stripped.startswith("switchport mode "):
            config.switchport_mode = stripped.removeprefix("switchport mode ").strip()
        elif stripped.startswith("switchport access vlan "):
            vlan_text = stripped.removeprefix("switchport access vlan ").strip()
            if vlan_text.isdigit():
                config.access_vlan = int(vlan_text)
        elif stripped.startswith("switchport trunk allowed vlan"):
            vlan_text = stripped.removeprefix("switchport trunk allowed vlan").strip()
            operation = "replace"
            for keyword in ("add", "remove", "except"):
                if vlan_text.startswith(keyword):
                    operation = keyword
                    vlan_text = vlan_text.removeprefix(keyword).strip()
                    break
            parsed = parse_vlan_list(vlan_text)
            if operation in {"replace", "add"}:
                config.trunk_allowed_vlans = (config.trunk_allowed_vlans or set()) | parsed
            elif operation == "remove":
                base = config.trunk_allowed_vlans or set(range(1, 4095))
                config.trunk_allowed_vlans = base - parsed
            elif operation == "except":
                config.trunk_allowed_vlans = set(range(1, 4095)) - parsed
        elif stripped.startswith("channel-group "):
            match = re.match(r"channel-group\s+(\S+)", stripped)
            if match:
                config.channel_group = match.group(1)
    return config


def parse_running_config(text: str) -> RunningConfig:
    sections: dict[str, list[str]] = {}
    global_lines: list[str] = []
    current_header: str | None = None
    current_lines: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "!":
            _close_section(current_header, current_lines, sections, global_lines)
            current_header = None
            current_lines = []
            continue
        if line[0].isspace():
            if current_header is not None:
                current_lines.append(stripped)
            continue
        _close_section(current_header, current_lines, sections, global_lines)
        current_header = stripped
        current_lines = []

    _close_section(current_header, current_lines, sections, global_lines)

    hostname: str | None = None
    for line in global_lines:
        if line.startswith("hostname "):
            hostname = line.removeprefix("hostname ").strip()
            break

    interfaces: dict[str, InterfaceConfig] = {}
    for header, lines in sections.items():
        if header.startswith("interface "):
            interface = _parse_interface(header, lines)
            interfaces[interface.name] = interface

    return RunningConfig(
        hostname=hostname,
        global_lines=global_lines,
        sections=sections,
        interfaces=interfaces,
    )
