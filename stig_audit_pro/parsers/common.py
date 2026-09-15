"""Shared IOS-XE parsing helpers."""

from __future__ import annotations

import re

_INTERFACE_ALIASES = {
    "gi": "GigabitEthernet",
    "gig": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "ten": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    "fo": "FortyGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "tw": "TwentyFiveGigE",
    "twe": "TwentyFiveGigE",
    "twentyfivegige": "TwentyFiveGigE",
    "po": "Port-channel",
    "port-channel": "Port-channel",
    "vlan": "Vlan",
    "lo": "Loopback",
    "loopback": "Loopback",
}

_PHYSICAL_PREFIXES = (
    "GigabitEthernet",
    "TenGigabitEthernet",
    "FastEthernet",
    "Ethernet",
    "FortyGigabitEthernet",
    "TwentyFiveGigE",
)


def normalize_interface_name(name: str) -> str:
    value = name.strip()
    if not value:
        return value
    match = re.match(r"^([A-Za-z-]+)(.*)$", value)
    if not match:
        return value
    prefix, suffix = match.groups()
    canonical = _INTERFACE_ALIASES.get(prefix.lower())
    if not canonical:
        return value
    return f"{canonical}{suffix}"


def is_physical_interface(name: str) -> bool:
    normalized = normalize_interface_name(name)
    return normalized.startswith(_PHYSICAL_PREFIXES)


def looks_like_interface(value: str) -> bool:
    normalized = normalize_interface_name(value)
    return bool(re.match(r"^[A-Za-z-]+\d", normalized)) or normalized.startswith("Port-channel")


def parse_vlan_list(value: str | None) -> set[int]:
    if value is None:
        return set()
    raw = value.strip().lower()
    if not raw or raw in {"none", "--", "routed", "notconnect"}:
        return set()
    if raw == "all":
        return set(range(1, 4095))

    cleaned = raw.replace("vlans", "").replace("vlan", "")
    cleaned = cleaned.replace("active", "").replace(" ", "")
    vlans: set[int] = set()
    for token in cleaned.split(","):
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if start_text.isdigit() and end_text.isdigit():
                start = int(start_text)
                end = int(end_text)
                vlans.update(range(start, end + 1))
            continue
        if token.isdigit():
            vlans.add(int(token))
    return {vlan for vlan in vlans if 1 <= vlan <= 4094}


def vlan_set_to_text(vlans: set[int]) -> str:
    if not vlans:
        return "none"
    return ",".join(str(vlan) for vlan in sorted(vlans))
