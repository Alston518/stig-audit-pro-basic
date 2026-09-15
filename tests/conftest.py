from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_DIR = PROJECT_ROOT / "tests" / "sample_outputs"

COMMAND_FILES = {
    "show running-config": "show_running_config.txt",
    "show vtp status": "show_vtp_status.txt",
    "show interfaces status": "show_interfaces_status.txt",
    "show interfaces switchport | include Negotiation of Trunking": "show_interfaces_switchport_negotiation.txt",
    "show interfaces trunk": "show_interfaces_trunk.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
    "show ip dhcp snooping": "show_ip_dhcp_snooping.txt",
    "show ip arp inspection": "show_ip_arp_inspection.txt",
    "show snmp user": "show_snmp_user.txt",
    "show version": "show_version.txt",
}


def load_outputs(kind: str) -> dict[str, str]:
    base = SAMPLE_DIR / kind
    return {
        command: (base / filename).read_text(encoding="utf-8")
        for command, filename in COMMAND_FILES.items()
    }


def load_l2_checks():
    from stig_audit_pro.core.yaml_loader import load_check_library

    return load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml").checks


def check_by_vuln(vuln_id: str):
    checks = {check.vuln_id: check for check in load_l2_checks()}
    return checks[vuln_id]


def load_profile():
    from stig_audit_pro.core.yaml_loader import load_profile

    return load_profile(DATA_DIR / "profiles" / "example_site.yaml")
