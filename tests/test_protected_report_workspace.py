from pathlib import Path

from stig_audit_pro.gui.protected_reports import ProtectedReportWorkspace


def protected_name(ip: str, report_type: str, run: str = "95895e0c") -> str:
    dashed = ip.replace(".", "-")
    last = ip.rsplit(".", 1)[-1]
    return f"{last}_IOSXE_NDM_03NOV2026_{dashed}-bc6a86bfe394_{run}.{report_type}.sapenc"


def test_workspace_groups_current_report_names_by_ip_and_type_without_reading_files(tmp_path):
    workspace = ProtectedReportWorkspace()
    txt = tmp_path / protected_name("172.16.100.156", "txt")
    ckl = tmp_path / protected_name("172.16.100.156", "ckl")

    imported = workspace.add([txt, ckl])

    assert imported.added == 2
    assert imported.duplicates == 0
    assert imported.rejected == ()
    assert workspace.devices() == ("172.16.100.156",)
    assert workspace.type_options("172.16.100.156") == ("TXT", "CKL")
    assert workspace.resolve("172.16.100.156", "TXT").path == txt.resolve()
    assert workspace.resolve("172.16.100.156", "CKL").path == ckl.resolve()


def test_workspace_deduplicates_exact_paths_and_clear_removes_everything(tmp_path):
    workspace = ProtectedReportWorkspace()
    report = tmp_path / protected_name("172.16.100.157", "txt")

    first = workspace.add([report, report])
    second = workspace.add([report])

    assert first.added == 1
    assert first.duplicates == 1
    assert second.added == 0
    assert second.duplicates == 1
    assert len(workspace.reports()) == 1
    workspace.clear()
    assert workspace.devices() == ()
    assert workspace.reports() == ()


def test_workspace_uses_safe_filename_label_for_legacy_report_and_rejects_bad_types(tmp_path):
    workspace = ProtectedReportWorkspace()
    legacy = tmp_path / "older-switch-report.txt.sapenc"
    unsupported = tmp_path / "secret.bin.sapenc"
    cleartext = tmp_path / "not-protected.txt"

    imported = workspace.add([legacy, unsupported, cleartext])

    assert imported.added == 1
    assert len(imported.rejected) == 2
    assert workspace.devices() == ("older-switch-report",)
    assert workspace.type_options("older-switch-report") == ("TXT",)


def test_same_ip_and_type_from_different_runs_remain_individually_selectable(tmp_path):
    workspace = ProtectedReportWorkspace()
    first = tmp_path / protected_name("172.16.100.158", "txt", "runone01")
    second = tmp_path / protected_name("172.16.100.158", "txt", "runtwo02")

    workspace.add([first, second])
    options = workspace.type_options("172.16.100.158")

    assert len(options) == 2
    assert options[0].startswith("TXT — ")
    assert options[1].startswith("TXT — ")
    assert options[0] != options[1]
    assert {workspace.resolve("172.16.100.158", option).path for option in options} == {
        first.resolve(), second.resolve()
    }
