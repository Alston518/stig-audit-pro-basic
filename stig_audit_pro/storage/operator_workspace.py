"""User-facing input and output folders for normal operator workflows."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_documents_dir

from stig_audit_pro.licensing.paths import application_data_dir


@dataclass(frozen=True, slots=True)
class OperatorWorkspace:
    """Stable, understandable locations shown by file-selection dialogs."""

    root: Path
    stig_packages: Path
    ckl_templates: Path
    device_imports: Path
    offline_evidence: Path
    completed_ckls: Path
    reports: Path
    audit_packages: Path
    backups: Path
    support_bundles: Path
    stig_comparisons: Path

    @classmethod
    def from_root(cls, root: str | Path) -> "OperatorWorkspace":
        selected = Path(root).expanduser().resolve()
        return cls(
            root=selected,
            stig_packages=selected / "01 - STIG Packages",
            ckl_templates=selected / "02 - Blank CKL Templates",
            device_imports=selected / "03 - Device Imports",
            offline_evidence=selected / "04 - Offline Evidence",
            completed_ckls=selected / "05 - Completed CKLs",
            reports=selected / "06 - Reports",
            audit_packages=selected / "07 - Audit Packages",
            backups=selected / "08 - Backups",
            support_bundles=selected / "09 - Support Bundles",
            stig_comparisons=selected / "10 - STIG Comparisons",
        )

    @property
    def directories(self) -> tuple[Path, ...]:
        return (
            self.stig_packages,
            self.ckl_templates,
            self.device_imports,
            self.offline_evidence,
            self.completed_ckls,
            self.reports,
            self.audit_packages,
            self.backups,
            self.support_bundles,
            self.stig_comparisons,
        )


def default_operator_workspace() -> OperatorWorkspace:
    """Return the per-user Documents workspace used by the desktop app."""

    return OperatorWorkspace.from_root(
        Path(user_documents_dir()) / "STIG Audit Pro" / "Workspace"
    )


def ensure_operator_workspace(
    root: str | Path | None = None,
) -> OperatorWorkspace:
    """Create missing operator folders without replacing any existing files."""

    workspace = (
        default_operator_workspace()
        if root is None
        else OperatorWorkspace.from_root(root)
    )
    workspace.root.mkdir(parents=True, exist_ok=True)
    for directory in workspace.directories:
        directory.mkdir(parents=True, exist_ok=True)

    guide = workspace.root / "README - START HERE.txt"
    if not guide.exists():
        managed = application_data_dir().resolve()
        content = (
            "STIG AUDIT PRO - WHERE EVERYTHING GOES\n"
            "=======================================\n\n"
            "This Workspace folder is for files you choose, import, or export.\n\n"
            "01 - STIG Packages\n"
            "  New DISA ZIP/XML downloads used by STIG Update Center.\n"
            "02 - Blank CKL Templates\n"
            "  Blank/current CKLs exported from DISA STIG Viewer. Keep L2 and NDM\n"
            "  templates here. STIG Audit Pro never overwrites these templates.\n"
            "03 - Device Imports\n"
            "  CSV/TXT device lists for the Targets screen. Never put passwords here.\n"
            "04 - Offline Evidence\n"
            "  Previously collected, read-only command output for offline audits.\n"
            "05 - Completed CKLs\n"
            "  The default destination for CKLs populated during an audit.\n"
            "06 - Reports\n"
            "  TXT, CSV, JSON, and Excel reports.\n"
            "07 - Audit Packages\n"
            "  Portable historical-audit ZIP exports and imports.\n"
            "08 - Backups\n"
            "  Application-data backups made from Administration.\n"
            "09 - Support Bundles\n"
            "  Sanitized diagnostic bundles for troubleshooting.\n"
            "10 - STIG Comparisons\n"
            "  Exported STIG difference reports.\n\n"
            "APP-MANAGED DATA (DO NOT MOVE BY HAND)\n"
            f"  {managed}\n\n"
            "The running app stores its database, editable YAML checks, Site Profiles,\n"
            "device groups, presets, imported STIG library, logs, and immutable audit\n"
            "evidence there. Use Administration > Files & Folders to open the exact\n"
            "managed folders. Back up data before making advanced/manual edits.\n\n"
            "Credentials are session-only and do not belong in this workspace.\n"
        )
        temporary = guide.with_name(f".{guide.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(content, encoding="utf-8")
            os.replace(temporary, guide)
        finally:
            temporary.unlink(missing_ok=True)
    return workspace


__all__ = [
    "OperatorWorkspace",
    "default_operator_workspace",
    "ensure_operator_workspace",
]
