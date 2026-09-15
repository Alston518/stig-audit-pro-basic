from types import SimpleNamespace

from stig_audit_pro.application.check_fixture_service import CheckFixtureService
from stig_audit_pro.core.automation_confidence import AutomationConfidence, classify_automation
from stig_audit_pro.core.models import CheckDefinition, SiteProfile


def test_verified_requires_current_review_and_complete_passing_fixtures():
    mapping = SimpleNamespace(automated=True, check_type="command_contains", last_reviewed_stig_fingerprint="abc")
    assert classify_automation(mapping=mapping, current_rule_fingerprint="abc", yaml_valid=True, commands_valid=True, fixtures_complete=True, fixtures_passing=True) is AutomationConfidence.VERIFIED
    assert classify_automation(mapping=mapping, current_rule_fingerprint="changed", yaml_valid=True, commands_valid=True, fixtures_complete=True, fixtures_passing=True) is AutomationConfidence.REVIEW_REQUIRED
    assert classify_automation(mapping=mapping, current_rule_fingerprint="abc", yaml_valid=True, commands_valid=True, fixtures_complete=False, fixtures_passing=True) is AutomationConfidence.UNTESTED


def test_manual_and_missing_are_explicit():
    manual = SimpleNamespace(automated=False, check_type="manual_review", last_reviewed_stig_fingerprint=None)
    assert classify_automation(mapping=manual, current_rule_fingerprint="abc", yaml_valid=True, commands_valid=True, fixtures_complete=False, fixtures_passing=False) is AutomationConfidence.MANUAL
    assert classify_automation(mapping=None, current_rule_fingerprint="abc", yaml_valid=True, commands_valid=True, fixtures_complete=False, fixtures_passing=False) is AutomationConfidence.MISSING


def test_standardized_good_and_bad_fixtures_use_production_engine(tmp_path):
    check = CheckDefinition(
        vuln_id="V-TEST", title="Fixture check", stig_family="TEST", severity="cat2",
        check_type="command_contains", commands=["show running-config"],
        conditions={"command": "show running-config", "contains": "service timestamps"},
    )
    root = tmp_path / "test" / "V-TEST"
    for name, output, status in (("compliant", "service timestamps", "NotAFinding"), ("noncompliant", "hostname SW1", "Open")):
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "show_running_config.txt").write_text(output, encoding="utf-8")
        (directory / "expected.json").write_text(f'{{"status": "{status}"}}', encoding="utf-8")
    summary = CheckFixtureService(tmp_path).run_check(check, SiteProfile(profile_name="fixture"))
    assert summary.complete
    assert summary.passed
