from pathlib import Path

from stig_audit_pro.application.preflight_service import PreflightService, PreflightSeverity
from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile
from stig_audit_pro.infrastructure.persistence import Database


ROOT = Path(__file__).resolve().parents[1]


def _inputs():
    checks = load_check_library(ROOT / "data/checks/iosxe_l2.yaml").checks
    profile = load_profile(ROOT / "data/profiles/base_iosxe_access.yaml")
    return checks, profile


def test_preflight_ready_with_plain_language_warning(tmp_path):
    checks, profile = _inputs()
    result = PreflightService().validate(
        targets=[DeviceTarget("10.0.0.1")], checks=checks, profile=profile,
        stig_families=["IOSXE_L2"], database=Database(tmp_path / "audit.sqlite3"),
        evidence_root=tmp_path / "evidence", report_directory=tmp_path / "reports",
    )
    assert result.ready
    assert all(issue.severity is not PreflightSeverity.BLOCKING for issue in result.issues)


def test_preflight_blocks_duplicates_invalid_addresses_and_missing_profile():
    checks, _profile = _inputs()
    result = PreflightService().validate(
        targets=[DeviceTarget("bad host"), DeviceTarget("bad host")], checks=checks,
        profile=None, stig_families=["IOSXE_L2"],
    )
    assert not result.ready
    assert {issue.code for issue in result.blocking_issues} >= {"INVALID_DEVICE", "DUPLICATE_DEVICES", "NO_PROFILE"}
