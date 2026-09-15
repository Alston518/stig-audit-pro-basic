from __future__ import annotations

import zipfile
from pathlib import Path

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.stig.stig_comparator import (
    compare_stig_metadata,
    load_stig_benchmarks,
)
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata


def _rule(
    *,
    vuln_id: str,
    stig_id: str,
    title: str,
    severity: str = "medium",
    check_text: str = "Review the configuration.",
    fix_text: str = "Configure the required setting.",
) -> StigRuleMetadata:
    return StigRuleMetadata(
        vuln_id=vuln_id,
        group_id=vuln_id,
        rule_id=f"SV-{vuln_id.removeprefix('V-')}r1_rule",
        stig_id=stig_id,
        title=title,
        severity=severity,
        check_text=check_text,
        fix_text=fix_text,
    )


def _benchmark(
    family: str,
    version: str,
    rules: list[StigRuleMetadata],
) -> StigBenchmarkMetadata:
    return StigBenchmarkMetadata(
        family=family,
        benchmark_id=f"{family}_benchmark",
        title=f"{family} STIG",
        version=version,
        rules=rules,
    )


def test_compare_matches_stable_stig_id_and_maps_profile_impacts(tmp_path: Path):
    old_rule = _rule(
        vuln_id="V-100001",
        stig_id="CISC-ND-000010",
        title="Limit management sessions.",
        check_text="Limit sessions to an organization-defined value.",
    )
    new_rule = _rule(
        vuln_id="V-200001",
        stig_id="CISC-ND-000010",
        title="Limit management sessions.",
        severity="high",
        check_text="Limit concurrent sessions to the approved organization-defined value.",
    )
    check = CheckDefinition(
        vuln_id="V-100001",
        stig_id="CISC-ND-000010",
        title="Limit management sessions.",
        stig_family="IOSXE_NDM",
        severity="cat2",
        check_type="manual_review",
        automated=False,
        conditions={"maximum_sessions_profile_key": "max_concurrent_management_sessions"},
    )
    profiles_dir = tmp_path / "data" / "profiles"
    profiles_dir.mkdir(parents=True)
    (profiles_dir / "base_iosxe_access.yaml").write_text(
        "profile_name: base_iosxe_access\nvariables:\n  max_concurrent_management_sessions: 16\n",
        encoding="utf-8",
    )
    (profiles_dir / "building_1.yaml").write_text(
        "profile_name: building_1\nvariables:\n  max_concurrent_management_sessions: 8\n",
        encoding="utf-8",
    )
    check_path = tmp_path / "data" / "checks" / "iosxe_ndm.yaml"

    changes, unchanged = compare_stig_metadata(
        [_benchmark("IOSXE_NDM", "V1R1", [old_rule])],
        [_benchmark("IOSXE_NDM", "V2R1", [new_rule])],
        checks=[check],
        check_sources={check.vuln_id: check_path},
        profiles_dir=profiles_dir,
        workspace_root=tmp_path,
    )

    assert unchanged == 0
    assert len(changes) == 1
    change = changes[0]
    assert change.kind == "Changed"
    assert change.control_id == "CISC-ND-000010"
    assert set(change.changed_fields) >= {"Vulnerability ID", "Rule ID", "Group ID", "Severity", "Check text"}
    assert change.check_path == "data/checks/iosxe_ndm.yaml"
    assert change.profile_keys == ("variables.max_concurrent_management_sessions",)
    assert change.base_profile_path == "data/profiles/base_iosxe_access.yaml"
    assert change.site_profile_paths == ("data/profiles/building_1.yaml",)


def test_compare_uses_unique_title_to_recognize_control_renumbering():
    old_rule = _rule(vuln_id="V-100", stig_id="OLD-100", title="Same requirement title")
    new_rule = _rule(vuln_id="V-200", stig_id="NEW-200", title="Same requirement title")

    changes, unchanged = compare_stig_metadata(
        [_benchmark("IOSXE_L2", "V1R1", [old_rule])],
        [_benchmark("IOSXE_L2", "V2R1", [new_rule])],
    )

    assert unchanged == 0
    assert len(changes) == 1
    assert changes[0].kind == "Changed"
    assert "STIG ID" in changes[0].changed_fields
    assert "Vulnerability ID" in changes[0].changed_fields


def test_compare_reports_added_removed_and_unchanged_controls():
    unchanged_old = _rule(vuln_id="V-1", stig_id="CISC-L2-000010", title="Unchanged")
    unchanged_new = _rule(vuln_id="V-1", stig_id="CISC-L2-000010", title="Unchanged")
    removed = _rule(vuln_id="V-2", stig_id="CISC-L2-000020", title="Removed")
    added = _rule(vuln_id="V-3", stig_id="CISC-L2-000030", title="Added")

    changes, unchanged = compare_stig_metadata(
        [_benchmark("IOSXE_L2", "V1R1", [unchanged_old, removed])],
        [_benchmark("IOSXE_L2", "V2R1", [unchanged_new, added])],
    )

    assert unchanged == 1
    assert [(change.kind, change.control_id) for change in changes] == [
        ("Added", "CISC-L2-000030"),
        ("Removed", "CISC-L2-000020"),
    ]


def test_load_stig_benchmarks_reads_all_xccdf_files_from_combined_zip(tmp_path: Path):
    l2_xml = _xccdf_xml("L2S", "CISC-L2-000010", "V-100001")
    ndm_xml = _xccdf_xml("NDM", "CISC-ND-000010", "V-200001")
    zip_path = tmp_path / "U_Cisco_IOS-XE_Switch_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("L2/U_L2S-xccdf.xml", l2_xml)
        archive.writestr("NDM/U_NDM-xccdf.xml", ndm_xml)
        archive.writestr("resources/metadata.xml", "<metadata />")

    all_benchmarks = load_stig_benchmarks(zip_path)
    ndm_benchmarks = load_stig_benchmarks(zip_path, family="IOSXE_NDM")

    assert {benchmark.family for benchmark in all_benchmarks} == {"IOSXE_L2", "IOSXE_NDM"}
    assert len(ndm_benchmarks) == 1
    assert ndm_benchmarks[0].rules[0].stig_id == "CISC-ND-000010"
    assert ndm_benchmarks[0].rules[0].discussion == "Why this control matters."
    assert ndm_benchmarks[0].rules[0].identifiers == ["CCI-000001"]


def test_markdown_report_contains_actionable_local_targets(tmp_path: Path):
    old_rule = _rule(vuln_id="V-1", stig_id="CISC-L2-000010", title="Old title")
    new_rule = _rule(vuln_id="V-1", stig_id="CISC-L2-000010", title="New title")
    from stig_audit_pro.stig.stig_comparator import StigComparisonReport

    changes, unchanged = compare_stig_metadata(
        [_benchmark("IOSXE_L2", "V1R1", [old_rule])],
        [_benchmark("IOSXE_L2", "V2R1", [new_rule])],
    )
    report = StigComparisonReport(
        old_source="old.zip",
        new_source="new.zip",
        old_benchmarks=(_benchmark("IOSXE_L2", "V1R1", [old_rule]),),
        new_benchmarks=(_benchmark("IOSXE_L2", "V2R1", [new_rule]),),
        changes=tuple(changes),
        unchanged_count=unchanged,
    )

    markdown = report.to_markdown()

    assert "# STIG Comparison Report" in markdown
    assert "data/checks/iosxe_l2.yaml" in markdown
    assert "Old title" in markdown
    assert "New title" in markdown


def _xccdf_xml(family_marker: str, stig_id: str, vuln_id: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="Cisco_{family_marker}_STIG">
  <title>Cisco IOS-XE Switch {family_marker} Security Technical Implementation Guide</title>
  <version>V2R1</version>
  <status date="2026-07-01">accepted</status>
  <Group id="{vuln_id}">
    <title>{vuln_id}</title>
    <Rule id="SV-{vuln_id.removeprefix('V-')}r1_rule" severity="medium">
      <version>{stig_id}</version>
      <title>Sample control</title>
      <description>Why this control matters.</description>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
      <check><check-content>Review the configuration.</check-content></check>
      <fixtext>Configure the setting.</fixtext>
    </Rule>
  </Group>
</Benchmark>
"""
