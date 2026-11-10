from __future__ import annotations

import csv
import xml.etree.ElementTree as ET
from io import StringIO
from pathlib import Path

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile
from stig_audit_pro.reports.audit_report import build_text_report
from stig_audit_pro.reports.basic_summary import Filter, render_csv, render_html, summarize
from stig_audit_pro.stig.ckl_writer import CklAsset, render_completed_ckl


ROOT = Path(__file__).resolve().parents[1]


def test_iosxe_release_reaches_findings_and_reports():
    pack = load_check_library(ROOT / "data/checks/iosxe_l2.yaml")
    profile = load_profile(ROOT / "data/profiles/base_iosxe_access.yaml")
    assert pack.stig_release
    assert {check.source_release for check in pack.checks} == {pack.stig_release}
    finding = CheckEngine(profile).evaluate(pack.checks[0], {}, "192.0.2.10")
    assert finding.stig_release == pack.stig_release
    assert pack.stig_release in build_text_report([finding])
    summary = summarize([finding], Filter())
    assert pack.stig_release in render_html(summary).decode("utf-8")
    rows = list(csv.DictReader(StringIO(render_csv(summary).decode("utf-8-sig"))))
    assert rows[0]["STIG Release"] == pack.stig_release
    checklist = render_completed_ckl(
        ROOT / "Checklist Templates/IOSXE_L2_Template.ckl",
        [finding],
        CklAsset(scan_ip="192.0.2.10", hostname="switch", management_ip="192.0.2.10"),
    )
    assert any(pack.stig_release in (item.text or "") for item in ET.fromstring(checklist).iter("COMMENTS"))


def test_ios_starter_packs_remain_unvalidated():
    for name in ("ios_l2.yaml", "ios_ndm.yaml"):
        pack = load_check_library(ROOT / "data/checks" / name)
        assert pack.validation_status == "unvalidated"
        assert {check.source_release for check in pack.checks} == {pack.stig_release}
