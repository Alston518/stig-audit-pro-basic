from pathlib import Path

from stig_audit_pro.stig.stig_diff import YamlImpactType, compare_stig_releases
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file


FIXTURES = Path(__file__).parent / "fixtures"


def test_yaml_impact_is_actionable_for_every_synthetic_change():
    old = parse_xccdf_file(FIXTURES / "stig_release_1.xml", "IOSXE_L2")
    new = parse_xccdf_file(FIXTURES / "stig_release_2.xml", "IOSXE_L2")
    diff = compare_stig_releases(
        old, new, checks_dir=FIXTURES / "stig_diff_checks.yaml"
    )
    impacts = {item.vuln_id: item for item in diff.yaml_impacts}

    assert impacts["V-100"].impact == YamlImpactType.NO_ACTION_REQUIRED
    assert impacts["V-200"].impact == YamlImpactType.RETIRE_CHECK_REVIEW
    assert impacts["V-300"].impact == YamlImpactType.METADATA_UPDATE
    assert impacts["V-400"].impact == YamlImpactType.AUTOMATION_REVIEW_REQUIRED
    assert impacts["V-500"].impact == YamlImpactType.FIX_GUIDANCE_CHANGED
    assert impacts["V-600"].impact == YamlImpactType.METADATA_UPDATE
    assert impacts["V-700"].impact == YamlImpactType.NEW_CHECK_REQUIRED
    assert impacts["V-400"].yaml_file.endswith("stig_diff_checks.yaml")
    assert "new DISA check procedure" in impacts["V-400"].recommended_action
