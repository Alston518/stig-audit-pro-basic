# -*- mode: python ; coding: utf-8 -*-
"""Customer-only one-folder build for STIG Audit Pro."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
datas = [
    (str(project_root / "data"), "data"),
    (str(project_root / "docs"), "docs"),
    (
        str(project_root / "stig_audit_pro" / "resources"),
        "stig_audit_pro/resources",
    ),
    *collect_data_files("customtkinter"),
]

a = Analysis(
    [str(project_root / "app.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        *collect_submodules("sqlalchemy.dialects.sqlite"),
        "openpyxl",
        "openpyxl.styles",
        "openpyxl.worksheet.table",
        "stig_audit_pro.application.run_service",
        "stig_audit_pro.application.preflight_service",
        "stig_audit_pro.application.support_bundle_service",
        "stig_audit_pro.application.backup_service",
        "stig_audit_pro.application.audit_package_service",
        "stig_audit_pro.application.check_fixture_service",
        "stig_audit_pro.application.stig_lifecycle_service",
        "stig_audit_pro.infrastructure.evidence.evidence_store",
        "stig_audit_pro.stig.cklb_writer",
        "stig_audit_pro.stig.stig_diff",
        "stig_audit_pro.stig.stig_repository",
        "stig_audit_pro.gui.audit_wizard",
        "stig_audit_pro.gui.administration_tab",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "tests", "tools", "tools.license_admin"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="STIGAuditPro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="STIGAuditPro",
)
