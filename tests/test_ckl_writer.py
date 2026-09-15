from __future__ import annotations

import xml.etree.ElementTree as ET

from stig_audit_pro.core.result_model import CheckResult, FindingObject
from stig_audit_pro.stig.ckl_writer import (
    checklist_vuln_ids,
    extract_ckl_asset,
    write_completed_ckl,
)


CKL_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <HOST_NAME></HOST_NAME>
    <HOST_IP></HOST_IP>
    <HOST_FQDN></HOST_FQDN>
  </ASSET>
  <STIGS>
    <iSTIG>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>V-220665</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>Not_Reviewed</STATUS>
        <FINDING_DETAILS></FINDING_DETAILS>
        <COMMENTS>Existing analyst note.</COMMENTS>
      </VULN>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>V-220666</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>Not_Reviewed</STATUS>
        <FINDING_DETAILS></FINDING_DETAILS>
        <COMMENTS></COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""


def _result(vuln_id: str, status: str) -> CheckResult:
    return CheckResult(
        ip="172.16.100.55",
        hostname="ACCESS-SW01",
        vuln_id=vuln_id,
        stig_family="IOSXE_L2",
        title="Test requirement",
        severity="cat2",
        status=status,
        failed_objects=(
            [
                FindingObject(
                    object_type="interface",
                    object_name="GigabitEthernet1/0/2",
                    details="required command missing",
                )
            ]
            if status == "Open"
            else []
        ),
        finding_details="Automated finding details.",
        comments="Automated result comment.",
    )


def _child_text(parent: ET.Element, name: str) -> str:
    child = parent.find(name)
    assert child is not None
    return child.text or ""


def _vuln_by_id(root: ET.Element, vuln_id: str) -> ET.Element:
    for vuln in root.findall(".//VULN"):
        for data in vuln.findall("STIG_DATA"):
            if (
                _child_text(data, "VULN_ATTRIBUTE") == "Vuln_Num"
                and _child_text(data, "ATTRIBUTE_DATA") == vuln_id
            ):
                return vuln
    raise AssertionError(f"{vuln_id} not found")


def test_extract_ckl_asset_uses_hostname_domain_and_vlan_300_ip():
    outputs = {
        "show running-config": """\
hostname ACCESS-SW01
ip domain name example.mil
!
interface Vlan300
 description Management
 ip address 192.0.2.30 255.255.255.0
 no shutdown
!
"""
    }

    asset = extract_ckl_asset(outputs, "172.16.100.55", management_vlan=300)

    assert asset.hostname == "ACCESS-SW01"
    assert asset.fqdn == "ACCESS-SW01.example.mil"
    assert asset.management_ip == "192.0.2.30"
    assert asset.scan_ip == "172.16.100.55"


def test_extract_ckl_asset_falls_back_to_scan_ip_without_management_svi():
    asset = extract_ckl_asset(
        {"show running-config": "hostname ACCESS-SW02\n"},
        "172.16.100.56",
        management_vlan=300,
    )

    assert asset.management_ip == "172.16.100.56"


def test_write_completed_ckl_populates_asset_results_and_preserves_template(tmp_path):
    source = tmp_path / "blank.ckl"
    destination = tmp_path / "completed.ckl"
    source.write_text(CKL_TEMPLATE, encoding="utf-8")
    asset = extract_ckl_asset(
        {
            "show running-config": """\
hostname ACCESS-SW01
interface Vlan300
 ip address 192.0.2.30 255.255.255.0
!
"""
        },
        "172.16.100.55",
    )

    summary = write_completed_ckl(
        source,
        destination,
        [_result("V-220665", "NotAFinding"), _result("V-220666", "Open")],
        asset,
        append_comments=True,
    )

    assert source.read_text(encoding="utf-8") == CKL_TEMPLATE
    assert summary.updated_vuln_ids == ("V-220665", "V-220666")
    assert summary.unmatched_result_ids == ()
    root = ET.parse(destination).getroot()
    asset_xml = root.find("ASSET")
    assert asset_xml is not None
    assert _child_text(asset_xml, "HOST_NAME") == "ACCESS-SW01"
    assert _child_text(asset_xml, "HOST_IP") == "192.0.2.30"

    passed = _vuln_by_id(root, "V-220665")
    failed = _vuln_by_id(root, "V-220666")
    assert _child_text(passed, "STATUS") == "NotAFinding"
    assert _child_text(failed, "STATUS") == "Open"
    assert "Automated finding details." in _child_text(failed, "FINDING_DETAILS")
    assert "Existing analyst note." in _child_text(passed, "COMMENTS")
    assert "STIG Audit Pro automated result" in _child_text(passed, "COMMENTS")


def test_checklist_vuln_ids_and_unmatched_results(tmp_path):
    source = tmp_path / "blank.ckl"
    destination = tmp_path / "completed.ckl"
    source.write_text(CKL_TEMPLATE, encoding="utf-8")
    asset = extract_ckl_asset({}, "172.16.100.55")

    assert checklist_vuln_ids(source) == {"V-220665", "V-220666"}
    summary = write_completed_ckl(
        source,
        destination,
        [_result("V-999999", "Open")],
        asset,
    )

    assert summary.updated_vuln_ids == ()
    assert summary.unmatched_result_ids == ("V-999999",)
