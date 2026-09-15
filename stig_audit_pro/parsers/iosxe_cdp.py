"""Parser for ``show cdp neighbors detail`` output."""

from __future__ import annotations

import re
from dataclasses import dataclass

from stig_audit_pro.parsers.common import normalize_interface_name


@dataclass(slots=True)
class CdpNeighbor:
    device_id: str
    local_interface: str = ""
    remote_interface: str = ""
    platform: str = ""
    capabilities: str = ""

    @property
    def is_switch(self) -> bool:
        words = {word.lower() for word in re.findall(r"[A-Za-z]+", self.capabilities)}
        return "switch" in words or "s" in words


def _neighbor_blocks(text: str) -> list[str]:
    starts = list(re.finditer(r"(?im)^Device ID\s*:\s*", text))
    return [
        text[start.start() : (starts[index + 1].start() if index + 1 < len(starts) else len(text))]
        for index, start in enumerate(starts)
    ]


def _field(block: str, label: str) -> str:
    match = re.search(rf"(?im)^{re.escape(label)}\s*:\s*(.+?)\s*$", block)
    return match.group(1).strip() if match else ""


def parse_cdp_neighbors_detail(text: str) -> list[CdpNeighbor]:
    """Return directly connected CDP neighbors with normalized local interfaces."""

    neighbors: list[CdpNeighbor] = []
    for block in _neighbor_blocks(text):
        device_id = _field(block, "Device ID")
        if not device_id:
            continue

        interface_match = re.search(
            r"(?im)^Interface\s*:\s*([^,]+),\s*Port ID \(outgoing port\)\s*:\s*(.+?)\s*$",
            block,
        )
        local_interface = ""
        remote_interface = ""
        if interface_match:
            local_interface = normalize_interface_name(interface_match.group(1).strip())
            remote_interface = interface_match.group(2).strip()

        platform = ""
        capabilities = ""
        platform_match = re.search(
            r"(?im)^Platform\s*:\s*(.*?),\s*Capabilities\s*:\s*(.*?)\s*$",
            block,
        )
        if platform_match:
            platform = platform_match.group(1).strip()
            capabilities = platform_match.group(2).strip()
        else:
            platform = _field(block, "Platform")
            capabilities = _field(block, "Capabilities")

        neighbors.append(
            CdpNeighbor(
                device_id=device_id,
                local_interface=local_interface,
                remote_interface=remote_interface,
                platform=platform,
                capabilities=capabilities,
            )
        )
    return neighbors
