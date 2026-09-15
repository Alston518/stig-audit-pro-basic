from pathlib import Path

from stig_audit_pro.storage.operator_workspace import ensure_operator_workspace


def test_operator_workspace_creates_clear_input_and_output_folders(tmp_path: Path) -> None:
    workspace = ensure_operator_workspace(tmp_path / "Workspace")

    assert workspace.stig_packages.is_dir()
    assert workspace.ckl_templates.is_dir()
    assert workspace.completed_ckls.is_dir()
    assert workspace.reports.is_dir()
    assert workspace.backups.is_dir()
    guide = workspace.root / "README - START HERE.txt"
    text = guide.read_text(encoding="utf-8")
    assert "Blank CKL Templates" in text
    assert "DO NOT MOVE BY HAND" in text


def test_operator_workspace_does_not_overwrite_customer_guide(tmp_path: Path) -> None:
    root = tmp_path / "Workspace"
    root.mkdir()
    guide = root / "README - START HERE.txt"
    guide.write_text("customer note", encoding="utf-8")

    ensure_operator_workspace(root)

    assert guide.read_text(encoding="utf-8") == "customer note"
