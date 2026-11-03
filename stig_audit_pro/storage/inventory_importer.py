"""Import and validate a master inventory CSV into device groups."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from collections.abc import Iterable

from stig_audit_pro.storage.device_groups import (
    DeviceGroup,
    DeviceGroupValidationError,
    DeviceTargetRecord,
    normalize_device_addresses,
)


class InventoryImportError(ValueError):
    """Raised when a master inventory cannot be safely grouped."""


@dataclass(frozen=True)
class InventoryImportPlan:
    groups: tuple[DeviceGroup, ...]
    source_rows: int


def inventory_template_csv() -> str:
    """Return a starter CSV that can be downloaded and filled in."""

    return (
        "building,profile,platform,hostname,ip\n"
        "Building 1,Building_1,IOS XE,SW-B1-01,10.10.1.11\n"
        "Building 1,Building_1,IOS XE,SW-B1-02,10.10.1.12\n"
        "Building 2,Building_2,IOS XE,SW-B2-01,10.10.2.11\n"
    )


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().casefold())


def _header_map(fieldnames: list[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise InventoryImportError("The inventory CSV must include a header row")
    result: dict[str, str] = {}
    for field in fieldnames:
        name = str(field or "").strip().casefold()
        if name:
            result[name] = field
    return result


def _find_header(headers: dict[str, str], choices: tuple[str, ...], label: str) -> str:
    for choice in choices:
        if choice in headers:
            return headers[choice]
    raise InventoryImportError(f"The inventory CSV needs a {label} column")


def build_inventory_plan(source: str, profile_names: Iterable[str]) -> InventoryImportPlan:
    """Validate and group a master inventory CSV without writing files."""

    reader = csv.DictReader(io.StringIO(source))
    headers = _header_map(reader.fieldnames)
    building_header = _find_header(headers, ("building", "site", "location", "group"), "building")
    address_header = _find_header(headers, ("ip", "address", "host", "hostname"), "device address")
    profile_header = next((headers[name] for name in ("profile", "site_profile") if name in headers), None)
    platform_header = next((headers[name] for name in ("platform", "os") if name in headers), None)

    profile_map: dict[str, str] = {}
    for profile in profile_names:
        value = str(profile).strip()
        if value:
            normalized = _key(value)
            if normalized in profile_map and profile_map[normalized] != value:
                raise InventoryImportError(f"Profile names are ambiguous: {profile_map[normalized]} and {value}")
            profile_map[normalized] = value

    grouped: dict[str, dict[str, object]] = {}
    seen_devices: dict[str, int] = {}
    source_rows = 0
    for row in reader:
        line_number = reader.line_num
        if not any(str(value or "").strip() for value in row.values()):
            continue
        source_rows += 1
        building = str(row.get(building_header, "") or "").strip()
        if not building:
            raise InventoryImportError(f"Row {line_number}: building is required")
        address = str(row.get(address_header, "") or "").strip()
        if not address:
            raise InventoryImportError(f"Row {line_number}: device address is required")
        try:
            address = normalize_device_addresses([address])[0]
        except DeviceGroupValidationError as exc:
            raise InventoryImportError(f"Row {line_number}: {exc}") from exc

        profile_raw = str(row.get(profile_header, "") or "").strip() if profile_header else ""
        profile = profile_map.get(_key(profile_raw)) if profile_raw else profile_map.get(_key(building))
        if not profile:
            requested = profile_raw or building
            raise InventoryImportError(
                f"Row {line_number}: no saved profile matches '{requested}'; "
                "add a profile column or create a profile with that name"
            )
        platform = str(row.get(platform_header, "") or "").strip() if platform_header else ""
        group_key = _key(building)
        existing = grouped.get(group_key)
        if existing is None:
            existing = {
                "name": building,
                "profile": profile,
                "platform": platform.casefold(),
                "addresses": [],
            }
            grouped[group_key] = existing
        elif existing["profile"] != profile:
            raise InventoryImportError(
                f"Building '{existing['name']}' has multiple profiles; split it into separate groups"
            )
        elif existing["platform"] and platform and existing["platform"] != platform.casefold():
            raise InventoryImportError(
                f"Building '{existing['name']}' has multiple platforms; split it into separate groups"
            )
        elif not existing["platform"] and platform:
            existing["platform"] = platform.casefold()
        if address.casefold() in seen_devices:
            raise InventoryImportError(
                f"Row {line_number}: duplicate device '{address}' (already seen on row {seen_devices[address.casefold()]})"
            )
        seen_devices[address.casefold()] = line_number
        existing["addresses"].append(address)

    if not source_rows:
        raise InventoryImportError("The inventory CSV does not contain any device rows")

    groups = tuple(
        DeviceGroup(
            group_name=str(data["name"]),
            profile_name=str(data["profile"]),
            targets=[DeviceTargetRecord(ip=address) for address in data["addresses"]],
        )
        for data in grouped.values()
    )
    return InventoryImportPlan(groups=groups, source_rows=source_rows)

