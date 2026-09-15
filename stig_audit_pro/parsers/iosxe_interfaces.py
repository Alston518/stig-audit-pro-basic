"""Parser for show interfaces status."""

from __future__ import annotations

from dataclasses import dataclass

from stig_audit_pro.parsers.common import normalize_interface_name


@dataclass(slots=True)
class InterfaceStatus:
    name: str
    status: str
    vlan: int | None = None
    name_column: str = ""
    duplex: str = ""
    speed: str = ""
    media_type: str = ""


def _parse_vlan(value: str) -> int | None:
    text = value.strip()
    return int(text) if text.isdigit() else None


def _column_positions(header: str) -> list[int]:
    labels = ["Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"]
    positions: list[int] = []
    for label in labels:
        positions.append(header.index(label))
    return positions


def _slice_columns(line: str, positions: list[int]) -> list[str]:
    padded = line + " " * 120
    values: list[str] = []
    for index, start in enumerate(positions):
        end = positions[index + 1] if index + 1 < len(positions) else len(padded)
        values.append(padded[start:end].strip())
    return values


def parse_interfaces_status(text: str) -> dict[str, InterfaceStatus]:
    interfaces: dict[str, InterfaceStatus] = {}
    positions: list[int] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n").lstrip("\ufeff")
        if not line.strip():
            continue
        if line.lstrip().startswith("Port") and "Status" in line and "Vlan" in line:
            positions = _column_positions(line)
            continue
        if positions is None or line.strip().startswith("---"):
            continue
        values = _slice_columns(line, positions)
        if len(values) < 7 or not values[0]:
            continue
        name = normalize_interface_name(values[0])
        interfaces[name] = InterfaceStatus(
            name=name,
            name_column=values[1],
            status=values[2].lower(),
            vlan=_parse_vlan(values[3]),
            duplex=values[4],
            speed=values[5],
            media_type=values[6],
        )
    return interfaces
