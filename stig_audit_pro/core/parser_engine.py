"""Combine command outputs into a parsed IOS-XE device view."""

from __future__ import annotations

from dataclasses import dataclass, field

from stig_audit_pro.parsers.iosxe_acls import AclParseResult, parse_acls
from stig_audit_pro.parsers.iosxe_arp_inspection import ArpInspectionInfo, parse_arp_inspection
from stig_audit_pro.parsers.iosxe_cdp import CdpNeighbor, parse_cdp_neighbors_detail
from stig_audit_pro.parsers.iosxe_dhcp_snooping import DhcpSnoopingInfo, parse_dhcp_snooping
from stig_audit_pro.parsers.iosxe_facts import DeviceFacts, parse_facts
from stig_audit_pro.parsers.iosxe_interfaces import InterfaceStatus, parse_interfaces_status
from stig_audit_pro.parsers.iosxe_running_config import InterfaceConfig, RunningConfig, parse_running_config
from stig_audit_pro.parsers.iosxe_trunks import TrunkInfo, parse_interfaces_trunk


@dataclass(slots=True)
class InterfaceView:
    name: str
    config: InterfaceConfig | None = None
    status: InterfaceStatus | None = None

    @property
    def shutdown(self) -> bool | None:
        return self.config.shutdown if self.config else None

    @property
    def switchport_mode(self) -> str | None:
        if self.config and self.config.switchport_mode:
            return self.config.switchport_mode
        # IOS-XE reports a numeric VLAN for access ports in "show interfaces
        # status". Use that as a fallback when the running config relies on the
        # default access mode and has no explicit "switchport mode access".
        if self.status and self.status.vlan is not None:
            return "access"
        return None

    @property
    def access_vlan(self) -> int | None:
        if self.config and self.config.access_vlan is not None:
            return self.config.access_vlan
        if self.status and self.status.vlan is not None:
            return self.status.vlan
        return None

    @property
    def operational_status(self) -> str | None:
        return self.status.status if self.status else None


@dataclass(slots=True)
class ParsedDeviceData:
    raw_outputs: dict[str, str]
    facts: DeviceFacts
    running_config: RunningConfig
    interfaces: dict[str, InterfaceView] = field(default_factory=dict)
    trunks: dict[str, TrunkInfo] = field(default_factory=dict)
    acls: AclParseResult = field(default_factory=AclParseResult)
    dhcp_snooping: DhcpSnoopingInfo = field(default_factory=DhcpSnoopingInfo)
    arp_inspection: ArpInspectionInfo = field(default_factory=ArpInspectionInfo)
    cdp_neighbors: list[CdpNeighbor] = field(default_factory=list)
    parser_warnings: list[str] = field(default_factory=list)


def parse_outputs(outputs: dict[str, str]) -> ParsedDeviceData:
    running_text = outputs.get("show running-config", "")
    status_text = outputs.get("show interfaces status", "")
    trunk_text = outputs.get("show interfaces trunk", "")
    acl_text = outputs.get("show ip access-lists", "")
    dhcp_text = outputs.get("show ip dhcp snooping", "")
    arp_text = outputs.get("show ip arp inspection", "")

    running_config = parse_running_config(running_text)
    status_interfaces = parse_interfaces_status(status_text)
    names = set(running_config.interfaces) | set(status_interfaces)
    interfaces = {
        name: InterfaceView(
            name=name,
            config=running_config.interfaces.get(name),
            status=status_interfaces.get(name),
        )
        for name in sorted(names)
    }

    return ParsedDeviceData(
        raw_outputs=outputs,
        facts=parse_facts(
            running_config=running_text,
            show_version=outputs.get("show version", ""),
            show_inventory=outputs.get("show inventory", ""),
        ),
        running_config=running_config,
        interfaces=interfaces,
        trunks=parse_interfaces_trunk(trunk_text),
        acls=parse_acls(show_ip_access_lists=acl_text, running_config=running_text),
        dhcp_snooping=parse_dhcp_snooping(show_output=dhcp_text, running_config=running_text),
        arp_inspection=parse_arp_inspection(show_output=arp_text, running_config=running_text),
        cdp_neighbors=parse_cdp_neighbors_detail(outputs.get("show cdp neighbors detail", "")),
    )
