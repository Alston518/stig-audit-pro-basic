from __future__ import annotations

from pathlib import Path

import pytest

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.gui.main_window import _build_checklist_template_jobs


def _check(vuln_id: str, family: str) -> CheckDefinition:
    return CheckDefinition(
        vuln_id=vuln_id,
        title=f"{family} test check",
        stig_family=family,
        severity="cat2",
        check_type="manual_review",
        automated=False,
    )


def _write_ckl(path: Path, *vuln_ids: str) -> Path:
    vulns = "\n".join(
        f"""
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>{vuln_id}</ATTRIBUTE_DATA>
        </STIG_DATA>
      </VULN>"""
        for vuln_id in vuln_ids
    )
    path.write_text(
        f"""\
<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET />
  <STIGS>
    <iSTIG>{vulns}
    </iSTIG>
  </STIGS>
</CHECKLIST>
""",
        encoding="utf-8",
    )
    return path


def _checks_by_family() -> dict[str, list[CheckDefinition]]:
    return {
        "IOSXE_L2": [_check("V-220665", "IOSXE_L2")],
        "IOSXE_NDM": [_check("V-220525", "IOSXE_NDM")],
    }


def test_combined_run_uses_combined_template_when_it_matches(tmp_path):
    combined = _write_ckl(tmp_path / "combined.ckl", "V-220665", "V-220525")

    jobs = _build_checklist_template_jobs(
        {"IOSXE_L2", "IOSXE_NDM"},
        {"IOSXE_L2": None, "IOSXE_NDM": None, "COMBINED": combined},
        _checks_by_family(),
    )

    assert [(job.file_label, job.families) for job in jobs] == [
        ("IOSXE_L2_NDM", frozenset({"IOSXE_L2", "IOSXE_NDM"}))
    ]


def test_combined_run_can_use_separate_l2_and_ndm_templates(tmp_path):
    l2 = _write_ckl(tmp_path / "l2.ckl", "V-220665")
    ndm = _write_ckl(tmp_path / "ndm.ckl", "V-220525")

    jobs = _build_checklist_template_jobs(
        {"IOSXE_L2", "IOSXE_NDM"},
        {"IOSXE_L2": l2, "IOSXE_NDM": ndm, "COMBINED": None},
        _checks_by_family(),
    )

    assert [(job.file_label, job.families) for job in jobs] == [
        ("IOSXE_L2", frozenset({"IOSXE_L2"})),
        ("IOSXE_NDM", frozenset({"IOSXE_NDM"})),
    ]


def test_combined_run_falls_back_when_combined_template_is_not_combined(tmp_path):
    l2 = _write_ckl(tmp_path / "l2.ckl", "V-220665")
    ndm = _write_ckl(tmp_path / "ndm.ckl", "V-220525")
    combined = _write_ckl(tmp_path / "combined.ckl", "V-220665")

    jobs = _build_checklist_template_jobs(
        {"IOSXE_L2", "IOSXE_NDM"},
        {"IOSXE_L2": l2, "IOSXE_NDM": ndm, "COMBINED": combined},
        _checks_by_family(),
    )

    assert [job.file_label for job in jobs] == ["IOSXE_L2", "IOSXE_NDM"]


def test_combined_run_requires_combined_or_both_separate_templates(tmp_path):
    l2 = _write_ckl(tmp_path / "l2.ckl", "V-220665")

    with pytest.raises(ValueError, match="combined L2 and NDM CKL template"):
        _build_checklist_template_jobs(
            {"IOSXE_L2", "IOSXE_NDM"},
            {"IOSXE_L2": l2, "IOSXE_NDM": None, "COMBINED": None},
            _checks_by_family(),
        )
