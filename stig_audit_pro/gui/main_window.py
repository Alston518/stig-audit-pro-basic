"""Main customtkinter window for STIG Audit Pro."""

from __future__ import annotations

import json
import os
import queue
import shutil
import threading
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, TypeVar

import customtkinter as ctk
import yaml
from pydantic import BaseModel, ValidationError

from stig_audit_pro.config import APP_VERSION, DEFAULT_PROFILE_NAME
from stig_audit_pro.application.report_service import ReportService
from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.application.preflight_service import PreflightService
from stig_audit_pro.application.error_presenter import explain_error
from stig_audit_pro.application.support_bundle_service import SupportBundleService
from stig_audit_pro.application.backup_service import BackupService, BackupSource
from stig_audit_pro.application.audit_package_service import AuditPackageService
from stig_audit_pro.application.check_fixture_service import CheckFixtureService
from stig_audit_pro.application.run_comparison import RunComparison, compare_runs
from stig_audit_pro.application.run_service import (
    OfflineEvidenceDevice,
    RunContext,
    RunService,
)
from stig_audit_pro.application.scan_orchestrator import ScanEventType
from stig_audit_pro.application.stig_lifecycle_service import StigLifecycleService
from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.ssh_runner import DeviceCredentials
from stig_audit_pro.core.models import (
    CheckDefinition,
    CheckLibrary,
    CollectionMode,
    SiteProfile,
)
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.yaml_loader import ConfigValidationError, deep_merge, load_check_library, load_profile, load_yaml_file
from stig_audit_pro.gui.checks_tab import ChecksTab
from stig_audit_pro.gui.audit_wizard import AuditWizard
from stig_audit_pro.gui.administration_tab import AdministrationTab
from stig_audit_pro.gui.evidence_tab import EvidenceTab
from stig_audit_pro.gui.history_tab import HistoryTab
from stig_audit_pro.gui.license_tab import LicenseTab
from stig_audit_pro.gui.overview_tab import OverviewTab
from stig_audit_pro.gui.profiles_tab import ProfilesTab
from stig_audit_pro.gui.reports_tab import ReportsTab
from stig_audit_pro.gui.results_tab import ResultsTab
from stig_audit_pro.gui.stig_tab import StigTab
from stig_audit_pro.gui.targets_tab import TargetsTab
from stig_audit_pro.gui.widgets import configure_treeview_style, confirm_action
from stig_audit_pro.licensing import (
    LicenseImportError,
    LicenseManager,
    LicensePolicyError,
    LicenseStatus,
)
from stig_audit_pro.licensing.paths import application_data_dir
from stig_audit_pro.licensing.paths import log_directory
from stig_audit_pro.infrastructure.persistence.migrations import get_schema_version
from stig_audit_pro.reports.audit_report import write_csv_report, write_text_report
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord
from stig_audit_pro.storage.application_data import bootstrap_writable_data
from stig_audit_pro.storage.operator_workspace import ensure_operator_workspace
from stig_audit_pro.storage.scan_presets import ReportOptions, ScanPreset, ScanPresetStore
from stig_audit_pro.stig.check_generator import build_manual_starter_library, write_manual_starter_library
from stig_audit_pro.stig.ckl_writer import (
    CklAsset,
    checklist_vuln_ids,
    safe_device_filename,
    write_completed_ckl,
)
from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.stig_comparator import (
    StigComparisonReport,
    compare_stig_sources as build_stig_comparison,
)
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata

ModelT = TypeVar("ModelT", bound=BaseModel)

COMMAND_FILES = {
    "show running-config": "show_running_config.txt",
    "show vtp status": "show_vtp_status.txt",
    "show interfaces status": "show_interfaces_status.txt",
    "show interfaces switchport | include Negotiation of Trunking": "show_interfaces_switchport_negotiation.txt",
    "show interfaces trunk": "show_interfaces_trunk.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
    "show ip dhcp snooping": "show_ip_dhcp_snooping.txt",
    "show ip arp inspection": "show_ip_arp_inspection.txt",
    "show snmp user": "show_snmp_user.txt",
    "show running-config | include ssh": "show_running_config_include_ssh.txt",
    "show version": "show_version.txt",
}

CHECKLIST_TEMPLATE_KEYS = ("IOSXE_L2", "IOSXE_NDM", "COMBINED")
SUPPORTED_CHECKLIST_FAMILIES = frozenset({"IOSXE_L2", "IOSXE_NDM"})
CHECKLIST_TEMPLATE_LABELS = {
    "IOSXE_L2": "L2",
    "IOSXE_NDM": "NDM",
    "COMBINED": "combined L2 and NDM",
}
CHECKLIST_FILE_LABELS = {
    "IOSXE_L2": "IOSXE_L2",
    "IOSXE_NDM": "IOSXE_NDM",
}


@dataclass(frozen=True, slots=True)
class ChecklistTemplateJob:
    families: frozenset[str]
    file_label: str
    template_path: Path


def _validate_checklist_template(
    template_path: Path,
    *,
    template_label: str,
    required_families: frozenset[str],
    family_vuln_ids: Mapping[str, set[str]],
) -> None:
    template_ids = checklist_vuln_ids(template_path)
    missing_family_ids = [
        family
        for family in sorted(required_families)
        if not (template_ids & family_vuln_ids[family])
    ]
    if missing_family_ids:
        family_names = ", ".join(
            family.replace("IOSXE_", "")
            for family in missing_family_ids
        )
        raise ValueError(
            f"The selected {template_label} CKL template does not contain "
            f"matching {family_names} vulnerability IDs."
        )


def _build_checklist_template_jobs(
    selected_families: set[str],
    ckl_paths: Mapping[str, Path | None],
    checks_by_family: Mapping[str, Sequence[CheckDefinition]],
) -> list[ChecklistTemplateJob]:
    family_vuln_ids = {
        family: {check.vuln_id for check in checks_by_family[family]}
        for family in SUPPORTED_CHECKLIST_FAMILIES
    }

    def make_job(
        template_key: str,
        families: frozenset[str],
        file_label: str,
    ) -> ChecklistTemplateJob:
        template_path = ckl_paths.get(template_key)
        if template_path is None:
            raise ValueError(
                f"Select the {CHECKLIST_TEMPLATE_LABELS[template_key]} "
                "CKL template before running."
            )
        _validate_checklist_template(
            template_path,
            template_label=CHECKLIST_TEMPLATE_LABELS[template_key],
            required_families=families,
            family_vuln_ids=family_vuln_ids,
        )
        return ChecklistTemplateJob(
            families=families,
            file_label=file_label,
            template_path=template_path,
        )

    selected = frozenset(
        family
        for family in selected_families
        if family in SUPPORTED_CHECKLIST_FAMILIES
    )
    if not selected:
        raise ValueError("Select L2, NDM, or both before starting the audit.")

    if selected == SUPPORTED_CHECKLIST_FAMILIES:
        combined_path = ckl_paths.get("COMBINED")
        separate_templates_available = all(
            ckl_paths.get(family) is not None
            for family in SUPPORTED_CHECKLIST_FAMILIES
        )
        if combined_path is not None:
            try:
                return [
                    make_job(
                        "COMBINED",
                        SUPPORTED_CHECKLIST_FAMILIES,
                        "IOSXE_L2_NDM",
                    )
                ]
            except ValueError:
                if not separate_templates_available:
                    raise
        if separate_templates_available:
            return [
                make_job(
                    "IOSXE_L2",
                    frozenset({"IOSXE_L2"}),
                    CHECKLIST_FILE_LABELS["IOSXE_L2"],
                ),
                make_job(
                    "IOSXE_NDM",
                    frozenset({"IOSXE_NDM"}),
                    CHECKLIST_FILE_LABELS["IOSXE_NDM"],
                ),
            ]
        raise ValueError(
            "For an L2 + NDM run, select either the combined L2 and NDM "
            "CKL template, or both separate L2 and NDM CKL templates."
        )

    if selected == frozenset({"IOSXE_NDM"}):
        return [
            make_job(
                "IOSXE_NDM",
                selected,
                CHECKLIST_FILE_LABELS["IOSXE_NDM"],
            )
        ]

    return [
        make_job(
            "IOSXE_L2",
            frozenset({"IOSXE_L2"}),
            CHECKLIST_FILE_LABELS["IOSXE_L2"],
        )
    ]


class StigAuditProApp(ctk.CTk):
    def __init__(self) -> None:
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        super().__init__()
        configure_treeview_style()

        self.root_dir = Path(__file__).resolve().parents[2]
        self.operator_workspace = ensure_operator_workspace()
        self.ui_state_path = application_data_dir() / "ui_state.json"
        self.data_dir = bootstrap_writable_data(self.root_dir / "data")
        self.sample_dir = self.root_dir / "tests" / "sample_outputs"
        self.device_group_store = DeviceGroupStore(self.data_dir / "device_groups")
        self.scan_preset_store = ScanPresetStore()
        self.stig_source_manager = StigSourceManager(self.data_dir / "stigs" / "cache")
        self.check_path = self.data_dir / "checks" / "iosxe_l2.yaml"
        self.ndm_check_path = self.data_dir / "checks" / "iosxe_ndm.yaml"
        self.check_library_paths: list[Path] = []
        self.check_source_paths: dict[str, Path] = {}
        self.profile_name = DEFAULT_PROFILE_NAME
        self.profile_path = self.data_dir / "profiles" / f"{DEFAULT_PROFILE_NAME}.yaml"
        self.checks = []
        self.profile: SiteProfile | None = None
        self.results: list[CheckResult] = []
        self.last_artifacts: list[Path] = []
        self.stig_metadata: list[StigBenchmarkMetadata] = []
        self._scan_cancel_event = threading.Event()
        self._scan_event_queue: queue.Queue = queue.Queue()
        self._ui_callback_queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._evidence_load_generation = 0
        self._scan_event_polling = False
        self.current_run_id: str | None = None
        self._scan_thread: threading.Thread | None = None
        self._scan_in_progress = False
        self._license_notice_dismissed = False
        self._loading_ui_state = False
        self.show_welcome = True
        self.license_manager = LicenseManager()
        self.license_manager.load()
        self.report_service = ReportService()
        self.audit_service = AuditService()
        self.preflight_service = PreflightService()
        self.run_service = RunService(audit_service=self.audit_service)
        self.stig_lifecycle_service = StigLifecycleService(
            checks_dir=self.data_dir / "checks"
        )

        self.title(f"STIG Audit Pro {APP_VERSION}")
        self.geometry("1280x820")
        self.minsize(1100, 720)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabs()
        # A saved preset/UI preference may replace this during _load_ui_state.
        self.set_checklist_output_dir(self.operator_workspace.completed_ckls)
        self._build_status_bar()
        self._load_ui_state()
        self.reload_from_disk()
        self.refresh_device_groups()
        self.refresh_scan_presets()
        self.refresh_stig_metadata()
        self.refresh_license_status(announce=False)
        self.refresh_audit_history(announce=False)
        self.after(50, self._poll_ui_callbacks)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=("#eef2f6", "#0f172a"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(header, text="STIG Audit Pro", font=ctk.CTkFont(size=24, weight="bold"))
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 2))
        subtitle = ctk.CTkLabel(header, text="Cisco IOS-XE switch audit workspace", text_color=("#344054", "#d0d5dd"))
        subtitle.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 12))
        self.version_label = ctk.CTkLabel(
            header,
            text=APP_VERSION,
            font=ctk.CTkFont(weight="bold"),
            corner_radius=8,
            fg_color=("#dbeafe", "#1e3a8a"),
            text_color=("#1e3a8a", "#eff6ff"),
            width=64,
            height=28,
        )
        self.version_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=18)
        self.license_badge = ctk.CTkLabel(
            header,
            text="Free",
            font=ctk.CTkFont(weight="bold"),
            corner_radius=8,
            fg_color=("#fef3c7", "#78350f"),
            text_color=("#92400e", "#fef3c7"),
            width=82,
            height=28,
        )
        self.license_badge.grid(row=0, column=2, rowspan=2, sticky="e", padx=(0, 18))
        ctk.CTkButton(
            header, text="Welcome / Help", width=112, height=28,
            fg_color="transparent", border_width=1,
            command=self.show_welcome_page,
        ).grid(row=0, column=3, rowspan=2, sticky="e", padx=(0, 18))

        self.license_notice_frame = ctk.CTkFrame(
            header,
            corner_radius=0,
            fg_color=("#fffaeb", "#451a03"),
            border_width=1,
            border_color=("#f79009", "#b45309"),
        )
        self.license_notice_frame.grid(
            row=2,
            column=0,
            columnspan=4,
            sticky="ew",
        )
        self.license_notice_frame.grid_columnconfigure(0, weight=1)
        self.license_notice_label = ctk.CTkLabel(
            self.license_notice_frame,
            text="",
            anchor="w",
            text_color=("#7a2e0e", "#fef3c7"),
        )
        self.license_notice_label.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(18, 10),
            pady=7,
        )
        ctk.CTkButton(
            self.license_notice_frame,
            text="Open License",
            width=100,
            height=26,
            command=lambda: self.show_tab("License"),
        ).grid(row=0, column=1, padx=(0, 8), pady=5)
        ctk.CTkButton(
            self.license_notice_frame,
            text="Dismiss",
            width=76,
            height=26,
            fg_color="transparent",
            border_width=1,
            text_color=("#7a2e0e", "#fef3c7"),
            command=self._dismiss_license_notice,
        ).grid(row=0, column=2, padx=(0, 18), pady=5)
        self.license_notice_frame.grid_remove()

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        tab_overview = self.tabs.add("Overview")
        tab_targets = self.tabs.add("Audit Run")
        tab_stig = self.tabs.add("STIG Update Center")
        tab_profiles = self.tabs.add("Profiles")
        tab_checks = self.tabs.add("Checks")
        tab_results = self.tabs.add("Results")
        tab_evidence = self.tabs.add("Evidence")
        tab_history = self.tabs.add("History")
        tab_reports = self.tabs.add("Reports")
        tab_license = self.tabs.add("License")
        tab_admin = self.tabs.add("Administration")
        for tab in (
            tab_overview,
            tab_targets,
            tab_stig,
            tab_profiles,
            tab_checks,
            tab_results,
            tab_evidence,
            tab_history,
            tab_reports,
            tab_license,
            tab_admin,
        ):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        self.overview_tab = OverviewTab(tab_overview, self)
        self.overview_tab.grid(row=0, column=0, sticky="nsew")
        self.targets_tab = TargetsTab(tab_targets, self)
        self.targets_tab.grid(row=0, column=0, sticky="nsew")
        self.stig_tab = StigTab(tab_stig, self)
        self.stig_tab.grid(row=0, column=0, sticky="nsew")
        self.profiles_tab = ProfilesTab(tab_profiles, self)
        self.profiles_tab.grid(row=0, column=0, sticky="nsew")
        self.checks_tab = ChecksTab(tab_checks, self)
        self.checks_tab.grid(row=0, column=0, sticky="nsew")
        self.results_tab = ResultsTab(tab_results, self)
        self.results_tab.grid(row=0, column=0, sticky="nsew")
        self.evidence_tab = EvidenceTab(tab_evidence, self)
        self.evidence_tab.grid(row=0, column=0, sticky="nsew")
        self.history_tab = HistoryTab(tab_history, self)
        self.history_tab.grid(row=0, column=0, sticky="nsew")
        self.reports_tab = ReportsTab(tab_reports, self)
        self.reports_tab.grid(row=0, column=0, sticky="nsew")
        self.license_tab = LicenseTab(tab_license, self)
        self.license_tab.grid(row=0, column=0, sticky="nsew")
        self.administration_tab = AdministrationTab(tab_admin, self)
        self.administration_tab.grid(row=0, column=0, sticky="nsew")

    def _build_status_bar(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=0)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        self.status_label = ctk.CTkLabel(footer, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=0, sticky="ew", padx=14, pady=6)

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def _post_to_ui(self, callback: Callable[[], None]) -> None:
        """Queue a widget callback without calling Tcl from a worker thread."""
        self._ui_callback_queue.put(callback)

    def _poll_ui_callbacks(self) -> None:
        """Run callbacks on Tk's owning thread and keep the dispatcher alive."""
        try:
            while True:
                try:
                    callback = self._ui_callback_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    callback()
                except Exception as exc:
                    self.set_status(f"A background UI update failed: {exc}")
        except queue.Empty:
            pass
        finally:
            self.after(50, self._poll_ui_callbacks)

    def show_tab(self, tab_name: str) -> None:
        aliases = {
            "Targets": "Audit Run",
            "Setup": "STIG Update Center",
            "STIG Source": "STIG Update Center",
            "STIG / CKL": "STIG Update Center",
            "STIG Library": "STIG Update Center",
        }
        self.tabs.set(aliases.get(tab_name, tab_name))

    def set_welcome_preference(self, show: bool) -> None:
        self.show_welcome = bool(show)
        self.overview_tab.set_welcome_visible(self.show_welcome)
        self._save_ui_state()

    def show_welcome_page(self) -> None:
        self.show_welcome = True
        self.overview_tab.set_welcome_visible(True)
        self.show_tab("Overview")

    def open_audit_wizard(self) -> None:
        AuditWizard(self, self)

    def build_preflight_result(self):
        settings = self.targets_tab.get_audit_run_settings()
        families = set(settings["families"])
        checks = [check for check in self.checks if check.stig_family in families]
        output_dir = self.stig_tab.selected_output_dir
        return self.preflight_service.validate(
            targets=self.targets_tab.get_targets("checked"), checks=checks,
            profile=self.profile, stig_families=families,
            database=self.run_service.database,
            evidence_root=self.run_service.evidence_store.root,
            report_directory=output_dir,
        )

    def application_health(self) -> list[tuple[str, str]]:
        try:
            database_health = "✓ Healthy" if self.run_service.database.foreign_keys_enabled() else "⚠ Foreign keys disabled"
        except Exception as exc:
            database_health = f"✕ Unavailable ({exc})"
        try:
            evidence_root = self.run_service.evidence_store.root
            evidence_root.mkdir(parents=True, exist_ok=True)
            free_gb = shutil.disk_usage(evidence_root).free / 1024 ** 3
            evidence_health = f"✓ Healthy ({free_gb:.1f} GB free)"
        except Exception as exc:
            evidence_health = f"✕ Unavailable ({exc})"
        return [
            ("Application", APP_VERSION),
            ("Database", database_health),
            ("Database schema", str(get_schema_version(self.run_service.database.engine))),
            ("Evidence Store", evidence_health),
            ("Check Libraries", f"✓ {len(self.checks)} checks loaded" if self.checks else "⚠ No checks loaded"),
            ("STIG Library", f"{len(self.stig_metadata)} installed release(s)"),
            ("Command Policy", "✓ Read-only allowlist active"),
        ]

    def create_support_bundle(self) -> None:
        destination = filedialog.asksaveasfilename(parent=self, title="Create Support Bundle", initialdir=str(self.operator_workspace.support_bundles), defaultextension=".zip", initialfile=f"stig-audit-pro-support-{datetime.now().strftime('%Y%m%d')}.zip", filetypes=[("ZIP archive", "*.zip")])
        if not destination:
            return
        try:
            service = SupportBundleService(self.run_service.database, log_paths=(log_directory() / "stig-audit-pro.log",))
            path = service.create(destination)
            self.set_status(f"Created sanitized support bundle: {path}")
        except Exception as exc:
            self._show_error(str(exc))

    def backup_application_data(self) -> None:
        destination = filedialog.asksaveasfilename(parent=self, title="Back Up STIG Audit Pro Data", initialdir=str(self.operator_workspace.backups), defaultextension=".zip", initialfile=f"stig-audit-pro-backup-{datetime.now().strftime('%Y%m%d')}.zip", filetypes=[("ZIP archive", "*.zip")])
        if not destination:
            return
        try:
            service = self._application_backup_service()
            path = service.create(destination, include_evidence=False)
            self.run_service.activity_log.record("BACKUP_CREATED", "application_backup", str(path), details={"includes_evidence": False})
            self.set_status(f"Backup created: {path}. Raw evidence was not included.")
        except Exception as exc:
            self._show_error(str(exc))

    def restore_application_data(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Restore STIG Audit Pro Data",
            initialdir=str(self.operator_workspace.backups),
            filetypes=[("STIG Audit Pro backup", "*.zip")],
        )
        if not selected:
            return
        service = self._application_backup_service()
        try:
            inspection = service.inspect(selected)
        except Exception as exc:
            self._show_error(str(exc), kind="validation")
            return
        evidence_text = (
            "Raw evidence in the backup will replace the current evidence store."
            if inspection.includes_evidence
            else "The backup does not replace raw evidence."
        )
        if not confirm_action(
            self,
            title="Restore Application Data?",
            message=(
                f"Restore the backup created {inspection.created_at}?\n\n"
                "The current database, profiles, device groups, checks, STIG "
                "library, and presets will be replaced. A safety backup is "
                f"created first. {evidence_text}\n\n"
                "STIG Audit Pro will close after restore."
            ),
            confirm_text="Restore and Close",
        ):
            return
        try:
            self.run_service.database.dispose()
            safety = service.restore_in_place(selected)
            self.run_service.activity_log.record(
                "RESTORE_PERFORMED",
                "application_backup",
                str(selected),
                details={"safety_backup": str(safety)},
            )
            messagebox.showinfo(
                "Restore Complete",
                "Application data was restored successfully. A safety backup "
                f"was saved at:\n{safety}\n\nReopen STIG Audit Pro to continue.",
                parent=self,
            )
            self.destroy()
        except Exception as exc:
            messagebox.showerror(
                "Restore Failed",
                f"The restore did not complete. Current data was rolled back "
                f"where necessary.\n\n{exc}\n\nClose and reopen STIG Audit Pro.",
                parent=self,
            )
            self.destroy()

    def _application_backup_service(self) -> BackupService:
        database_path = self.run_service.database.path
        if database_path is None:
            raise RuntimeError("The in-memory development database cannot be backed up.")
        return BackupService(
            database_path=database_path,
            sources=(
                BackupSource("profiles", self.data_dir / "profiles"),
                BackupSource("device-groups", self.data_dir / "device_groups"),
                BackupSource("checks", self.data_dir / "checks"),
                BackupSource("stig-library", self.data_dir / "stigs"),
                BackupSource("scan-presets", self.scan_preset_store.root),
            ),
            evidence_root=self.run_service.evidence_store.root,
        )

    def _open_local_folder(self, path: Path, label: str) -> None:
        """Open an operator-requested local folder in Windows Explorer."""

        try:
            path.mkdir(parents=True, exist_ok=True)
            os.startfile(str(path))  # type: ignore[attr-defined]
            self.set_status(f"Opened {label}: {path}")
        except (AttributeError, OSError) as exc:
            self._show_error(f"Could not open {label}.\n\n{path}\n\n{exc}")

    def open_operator_workspace(self) -> None:
        self._open_local_folder(self.operator_workspace.root, "operator workspace")

    def open_application_data_folder(self) -> None:
        self._open_local_folder(application_data_dir(), "application data")

    def open_checks_folder(self) -> None:
        self._open_local_folder(self.data_dir / "checks", "editable checks")

    def open_profiles_folder(self) -> None:
        self._open_local_folder(self.data_dir / "profiles", "Site Profiles")

    def show_result(self, result: CheckResult) -> None:
        """Open the Results tab with the requested result selected."""
        self.show_tab("Results")
        self.results_tab.select_result(result.ip, result.vuln_id)

    def show_disa_guidance(self, result: CheckResult, field: str) -> None:
        label = "DISA Check Text" if field == "check_text" else "DISA Fix Text"
        text = "This guidance is not available in the currently installed STIG releases."
        for benchmark in self.stig_metadata:
            for rule in benchmark.rules:
                if rule.vuln_id == result.vuln_id or (result.rule_id and rule.rule_id == result.rule_id):
                    text = getattr(rule, field, "") or text
                    break
        self._show_text_dialog(label, text)

    def open_manual_review(self, result: CheckResult) -> None:
        if not result.run_id:
            self._show_error("Run and persist the audit before recording a reviewer decision.", kind="validation")
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Manual Review — {result.vuln_id}")
        dialog.geometry("680x560")
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(4, weight=1)
        ctk.CTkLabel(dialog, text="Manual Review Required", font=ctk.CTkFont(size=20, weight="bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 4))
        ctk.CTkLabel(dialog, text="Choose a reviewer status. This decision is stored in the Audit Run and does not change the device.", anchor="w", justify="left", wraplength=640).grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        status = ctk.CTkComboBox(dialog, values=["Open", "Not a Finding", "Not Applicable", "Not Reviewed"], state="readonly")
        status.set({"NotAFinding": "Not a Finding", "Not_Applicable": "Not Applicable", "Not_Reviewed": "Not Reviewed"}.get(result.status, result.status))
        status.grid(row=2, column=0, sticky="ew", padx=16, pady=4)
        fields = ctk.CTkFrame(dialog, fg_color="transparent")
        fields.grid(row=4, column=0, sticky="nsew", padx=16, pady=8)
        fields.grid_columnconfigure(0, weight=1)
        fields.grid_rowconfigure((1, 3), weight=1)
        ctk.CTkLabel(fields, text="Finding Details", anchor="w").grid(row=0, column=0, sticky="ew")
        details = ctk.CTkTextbox(fields, wrap="word", height=130)
        details.grid(row=1, column=0, sticky="nsew", pady=(2, 8)); details.insert("1.0", result.finding_details)
        ctk.CTkLabel(fields, text="Comments", anchor="w").grid(row=2, column=0, sticky="ew")
        comments = ctk.CTkTextbox(fields, wrap="word", height=110)
        comments.grid(row=3, column=0, sticky="nsew", pady=(2, 8)); comments.insert("1.0", result.comments)
        def save() -> None:
            internal = {"Not a Finding": "NotAFinding", "Not Applicable": "Not_Applicable", "Not Reviewed": "Not_Reviewed"}.get(status.get(), status.get())
            try:
                self.results = self.run_service.save_manual_decision(result, status=internal, finding_details=details.get("1.0", "end").strip(), comments=comments.get("1.0", "end").strip())
                self.results_tab.refresh(self.results)
                self.update_report_summary(self.results)
                dialog.destroy()
                self.set_status(f"Saved manual reviewer decision for {result.vuln_id}.")
            except Exception as exc:
                self._show_error(str(exc))
        ctk.CTkButton(dialog, text="Save Reviewer Decision", command=save).grid(row=5, column=0, sticky="e", padx=16, pady=(0, 16))

    def show_result_evidence(self, result: CheckResult) -> list[Any]:
        """Open the immutable evidence linked to one result."""
        if not result.run_id:
            self.set_status("This result is not linked to a persisted audit run.")
            return []
        try:
            artifacts = self.run_service.evidence_for_result(result)
            self.evidence_tab.show_context(result.run_id, result, artifacts)
            self.show_tab("Evidence")
            self.set_status(
                f"Loaded {len(artifacts)} evidence artifact(s) for {result.vuln_id}."
            )
            return artifacts
        except Exception as exc:
            self.set_status("Could not load result evidence.")
            self._show_error(str(exc))
            return []

    def list_audit_runs(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        search: str = "",
    ) -> list[Any]:
        return list(
            self.run_service.list_history(
                limit=limit,
                offset=offset,
                search=search,
            )
        )

    def count_audit_runs(self, *, search: str = "") -> int:
        return self.run_service.count_history(search=search)

    def refresh_audit_history(self, *, announce: bool = True) -> list[Any]:
        try:
            rows = self.history_tab.refresh_from_controller(reset=True)
            if announce:
                self.set_status(f"Loaded {len(rows)} historical audit run(s).")
            return rows
        except Exception as exc:
            if announce:
                self.set_status("Could not refresh audit history.")
                self._show_error(str(exc))
            return []

    def open_historical_run(self, run_id: str) -> list[CheckResult]:
        try:
            results = self.run_service.load_results(run_id)
            artifacts = self.run_service.repository.list_evidence_artifacts(run_id)
            self.current_run_id = run_id
            self.results = results
            self.results_tab.refresh(results)
            self.update_report_summary(results)
            self.evidence_tab.show_context(run_id, None, artifacts)
            self.show_tab("Results")
            self.set_status(
                f"Opened historical run {run_id} with {len(results)} result(s)."
            )
            return results
        except Exception as exc:
            self.set_status(f"Could not open historical run {run_id}.")
            self._show_error(str(exc))
            return []

    def compare_historical_runs(
        self, previous_run_id: str, current_run_id: str
    ) -> RunComparison | None:
        try:
            history = {
                str(self._record_value(item, "id", "")): item
                for item in self.run_service.list_history()
            }
            selected = [previous_run_id, current_run_id]
            if all(run_id in history for run_id in selected):
                selected.sort(
                    key=lambda run_id: self._record_value(
                        history[run_id], "started_at", datetime.min
                    )
                )
                previous_run_id, current_run_id = selected
            comparison = compare_runs(
                self.run_service.load_results(previous_run_id),
                self.run_service.load_results(current_run_id),
                previous_run_id=previous_run_id,
                current_run_id=current_run_id,
            )
            summary = comparison.summary
            lines = [
                f"Previous run: {previous_run_id}",
                f"Current run:  {current_run_id}",
                "",
                f"New findings: {summary['new']}",
                f"Resolved findings: {summary['resolved']}",
                f"Persistent findings: {summary['persistent']}",
                f"Comparison errors: {summary['errors']}",
                "",
                "Device / Vuln ID / Change",
            ]
            lines.extend(
                f"{item.device} / {item.vuln_id} / {item.classification.value}"
                for item in comparison.items
            )
            self._show_text_dialog("Audit Run Comparison", "\n".join(lines))
            self.set_status(
                f"Compared {previous_run_id} with {current_run_id}: "
                f"{summary['new']} new, {summary['resolved']} resolved."
            )
            return comparison
        except Exception as exc:
            self.set_status("Could not compare the selected audit runs.")
            self._show_error(str(exc))
            return None

    def retry_failed_devices(self, run_id: str) -> None:
        """Create a linked retry run containing only previously failed devices."""
        failure_states = {"AUTH_FAILED", "CONNECT_FAILED", "COLLECTION_FAILED", "EVALUATION_FAILED"}
        devices = self.run_service.repository.list_devices(run_id)
        failed = [item for item in devices if item.status in failure_states]
        if not failed:
            self.set_status("The selected audit has no failed devices to retry.")
            return
        settings = self.targets_tab.get_scan_settings()
        if settings.get("mode") != "Live SSH":
            self.show_tab("Audit Run")
            self._show_error("Select Live SSH and enter session credentials before retrying failed devices.", title="Retry Needs Credentials", kind="validation")
            return
        targets = [DeviceTargetRecord(ip=item.target_ip, checked=True) for item in failed]
        self.targets_tab.set_targets(targets)
        self.run_service.activity_log.record("FAILED_DEVICES_RETRIED", "audit_run", run_id, details={"device_count": len(targets)})
        self._run_live_for_targets(targets, settings, f"retry of audit {run_id}", list(self.checks))

    def export_historical_run(
        self, run_id: str, output_dir: Path | None = None
    ) -> list[Path]:
        try:
            self.license_manager.require_feature("advanced_reporting")
            results = self.run_service.load_results(run_id)
            if not results:
                raise ValueError("The selected run has no results to export.")
            if output_dir is None:
                selected = filedialog.askdirectory(
                    parent=self,
                    title="Export historical audit reports",
                    initialdir=str(self.operator_workspace.reports),
                )
                if not selected:
                    return []
                output_dir = Path(selected)
            output_dir.mkdir(parents=True, exist_ok=True)
            stem = f"stig-audit-{run_id}"
            paths = [
                self.report_service.write_text(results, output_dir / f"{stem}.txt"),
                self.report_service.write_csv(results, output_dir / f"{stem}.csv"),
                self.report_service.write_json(results, output_dir / f"{stem}.json"),
                self.report_service.write_excel(results, output_dir / f"{stem}.xlsx"),
            ]
            self.set_status(
                f"Exported {len(paths)} report(s) for {run_id} to {output_dir}."
            )
            return paths
        except LicensePolicyError as exc:
            self.set_status("Historical report export is blocked by the current license.")
            self._show_error(str(exc), kind="license")
            return []
        except Exception as exc:
            self.set_status("Historical report export failed.")
            self._show_error(str(exc))
            return []

    def export_audit_package(self, run_id: str) -> Path | None:
        destination = filedialog.asksaveasfilename(parent=self, title="Export Audit Package", initialdir=str(self.operator_workspace.audit_packages), defaultextension=".zip", initialfile=f"STIG-Audit-Pro-Audit-{run_id}.zip", filetypes=[("Audit package", "*.zip")])
        if not destination:
            return None
        try:
            run_directory = self.run_service.evidence_store.root / run_id
            path = AuditPackageService().export(run_id=run_id, run_directory=run_directory, destination=destination, include_evidence=True)
            self.run_service.activity_log.record("AUDIT_PACKAGE_EXPORTED", "audit_run", run_id, details={"path": str(path), "includes_evidence": True})
            self.set_status(f"Exported verified audit package: {path}")
            return path
        except Exception as exc:
            self._show_error(str(exc))
            return None

    def import_audit_package(self) -> str | None:
        selected = filedialog.askopenfilename(
            parent=self,
            title="Import Historical Audit Package",
            initialdir=str(self.operator_workspace.audit_packages),
            filetypes=[("STIG Audit Pro package", "*.zip")],
        )
        if not selected:
            return None
        try:
            run_id = self.run_service.import_audit_package(selected)
            self.refresh_audit_history(announce=False)
            self.open_historical_run(run_id)
            message = (
                f"Imported historical audit {run_id}. Its original results and "
                "evidence are shown without rescanning any device."
            )
            self.history_tab.message.configure(text=message)
            self.set_status(message)
            return run_id
        except Exception as exc:
            self._show_error(str(exc), kind="validation")
            return None

    def verify_historical_evidence(self, run_id: str) -> Any | None:
        try:
            verification = self.run_service.verify_evidence(run_id)
            status = getattr(verification.aggregate, "value", verification.aggregate)
            message = (
                f"Evidence verification for {run_id}: {status} "
                f"({len(verification.artifacts)} artifact(s))."
            )
            self.history_tab.message.configure(text=message)
            self.set_status(message)
            if not verification.is_valid:
                details = "\n".join(
                    f"{item.status.value}: {item.relative_path}"
                    for item in verification.artifacts
                    if item.status.value != "VALID"
                )
                self._show_text_dialog("Evidence Verification", details or message)
            return verification
        except Exception as exc:
            self.set_status(f"Could not verify evidence for {run_id}.")
            self._show_error(str(exc))
            return None

    def purge_historical_evidence(self, run_id: str) -> int:
        if self._scan_in_progress and self.current_run_id == run_id:
            self.set_status("Raw evidence cannot be purged while that audit is running.")
            return 0
        try:
            removed = self.run_service.purge_raw_evidence(run_id)
            self.set_status(
                f"Purged {removed} raw evidence file(s) from audit run {run_id}."
            )
            return removed
        except Exception as exc:
            self.set_status(f"Could not purge evidence for {run_id}.")
            self._show_error(str(exc))
            return 0

    def delete_historical_run(self, run_id: str) -> bool:
        if self._scan_in_progress and self.current_run_id == run_id:
            self.set_status("The active audit run cannot be deleted.")
            return False
        try:
            deleted = self.run_service.delete_run(run_id)
            if deleted and self.current_run_id == run_id:
                self.current_run_id = None
                self.results = []
                self.results_tab.refresh([])
                self.update_report_summary([])
                self.evidence_tab.show_context(run_id, None, [])
            self.set_status(
                f"Deleted audit run {run_id}."
                if deleted
                else f"Audit run {run_id} was not found."
            )
            return deleted
        except Exception as exc:
            self.set_status(f"Could not delete audit run {run_id}.")
            self._show_error(str(exc))
            return False

    def import_offline_evidence(self) -> None:
        """Create a labeled audit run from operator-collected text outputs.

        Directory files must use the bundled sample/output names (for example
        ``show_running_config.txt``). This deliberately avoids accepting a
        user-supplied command name without passing it through the same command
        policy used by live SSH collection.
        """
        selected = filedialog.askdirectory(
            parent=self,
            title="Select offline command-output directory",
            initialdir=str(self.operator_workspace.offline_evidence),
        )
        if not selected:
            return
        prompt = ctk.CTkInputDialog(
            title="Offline Evidence Import",
            text="Device target IP or hostname:",
        )
        target_ip = (prompt.get_input() or "").strip()
        if not target_ip:
            self.set_status("Offline evidence import cancelled.")
            return
        source_dir = Path(selected)
        filenames = {filename: command for command, filename in COMMAND_FILES.items()}
        outputs: dict[str, str] = {}
        timestamps: list[float] = []
        try:
            for filename, command in filenames.items():
                path = source_dir / filename
                if not path.is_file():
                    continue
                outputs[command] = path.read_text(encoding="utf-8", errors="replace")
                timestamps.append(path.stat().st_mtime)
            if not outputs:
                expected = ", ".join(sorted(filenames))
                raise ValueError(
                    "No recognized command-output files were found. Expected "
                    f"filenames include: {expected}."
                )
            selected_checks = [
                check
                for check in self.checks
                if set(check.commands).issubset(outputs)
            ]
            if not selected_checks:
                raise ValueError(
                    "The imported evidence does not contain the complete command "
                    "set for any currently loaded check."
                )
            if self.profile is None:
                raise ValueError("No site profile is loaded.")
            collected_at = datetime.fromtimestamp(
                max(timestamps), timezone.utc
            )
            device = OfflineEvidenceDevice(
                target_ip=target_ip,
                source=str(source_dir),
                collected_at=collected_at,
                outputs=outputs,
            )
        except Exception as exc:
            self.set_status("Offline evidence import could not be prepared.")
            self._show_error(str(exc), kind="validation")
            return

        if not self._begin_scan(1, f"Importing offline evidence for {target_ip}..."):
            return

        def worker() -> None:
            try:
                context, result = self.run_service.import_offline(
                    devices=[device],
                    checks=selected_checks,
                    profile_provider=lambda _device: self.profile,
                    profile_snapshot=self.profile,
                    stig_families=sorted(
                        {check.stig_family for check in selected_checks}
                    ),
                    concurrency=1,
                    description=f"Offline evidence import: {source_dir.name}",
                )

                def complete() -> None:
                    self.current_run_id = context.run_id
                    self.results = result.results
                    self.results_tab.refresh(result.results)
                    self.update_report_summary(result.results)
                    self.refresh_audit_history(announce=False)
                    self.show_tab("Results")
                    self._finish_scan_ui(
                        completed=1,
                        total=1,
                        message=(
                            f"Imported offline evidence for {target_ip} as run "
                            f"{context.run_id}. No SSH connection was made."
                        ),
                    )

                self._post_to_ui(complete)
            except Exception as exc:
                message = str(exc)
                self._post_to_ui(
                    lambda: self._handle_background_scan_error(
                        message, 0, 1, checklist=False
                    )
                )

        self._scan_thread = threading.Thread(
            target=worker,
            daemon=True,
            name="stig-audit-offline-evidence-import",
        )
        self._scan_thread.start()

    def load_evidence_text_async(
        self, artifact: Any, callback: Callable[[str], None]
    ) -> threading.Thread:
        relative_path = str(self._record_value(artifact, "relative_path", ""))
        self._evidence_load_generation += 1
        generation = self._evidence_load_generation

        def worker() -> None:
            try:
                text = self.run_service.read_evidence(relative_path)
            except Exception as exc:
                text = f"Evidence could not be loaded: {exc}"

            def deliver(loaded: str = text) -> None:
                if generation == self._evidence_load_generation:
                    callback(loaded)

            self._post_to_ui(deliver)

        thread = threading.Thread(
            target=worker,
            daemon=True,
            name="stig-audit-evidence-reader",
        )
        thread.start()
        return thread

    def open_evidence_location(self, artifact: Any) -> Path | None:
        try:
            relative_path = str(self._record_value(artifact, "relative_path", ""))
            root = Path(self.run_service.evidence_store.root).resolve()
            path = (root / relative_path).resolve()
            if path == root or root not in path.parents:
                raise ValueError("Evidence path resolves outside the evidence root")
            location = path.parent
            if not location.is_dir():
                raise FileNotFoundError(location)
            if os.name == "nt":
                os.startfile(str(location))  # type: ignore[attr-defined]
            else:
                import subprocess
                import sys

                opener = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.Popen([opener, str(location)])
            self.set_status(f"Opened evidence location {location}.")
            return location
        except Exception as exc:
            self.set_status("Could not open the evidence file location.")
            self._show_error(str(exc))
            return None

    def verify_evidence_artifact(self, artifact: Any) -> Any | None:
        try:
            relative_path = str(self._record_value(artifact, "relative_path", ""))
            run_id = self.evidence_tab.run_id
            if not run_id:
                parts = Path(relative_path.replace("\\", "/")).parts
                run_id = parts[0] if parts else None
            if not run_id:
                raise ValueError("The selected artifact is not linked to an audit run.")
            artifact_id = self._record_value(
                artifact,
                "id",
                self._record_value(artifact, "artifact_id", None),
            )
            verification = self.run_service.verify_evidence(run_id)
            item = next(
                (
                    candidate
                    for candidate in verification.artifacts
                    if (
                        artifact_id is not None
                        and candidate.artifact_id == artifact_id
                    )
                    or candidate.relative_path == relative_path
                ),
                None,
            )
            if item is None:
                raise KeyError("The selected evidence artifact is not in the run manifest.")
            status = getattr(item.status, "value", item.status)
            self.set_status(f"Evidence hash {status}: {relative_path}.")
            if status != "VALID":
                self._show_text_dialog(
                    "Evidence Verification",
                    f"{status}: {relative_path}\n{item.error or ''}".rstrip(),
                )
            return item
        except Exception as exc:
            self.set_status("Could not verify the selected evidence artifact.")
            self._show_error(str(exc))
            return None

    @staticmethod
    def _record_value(record: Any, name: str, default: Any = None) -> Any:
        if isinstance(record, Mapping):
            return record.get(name, default)
        return getattr(record, name, default)

    def set_checklist_template(self, family_key: str, path: Path) -> None:
        self.stig_tab.set_ckl_template_path(family_key, path)
        self._save_ui_state()
        self._refresh_audit_preflight()

    def set_checklist_output_dir(self, path: Path) -> None:
        self.stig_tab.set_checklist_output_dir(path)
        self._save_ui_state()
        self._refresh_audit_preflight()

    def _set_checklist_status(self, message: str) -> None:
        self.targets_tab.set_checklist_status(message)
        self.stig_tab.set_checklist_status(message)

    def _remember_checklist_preferences(
        self,
        ckl_paths: Mapping[str, Path | None],
        output_dir: Path | None,
    ) -> None:
        for family_key in CHECKLIST_TEMPLATE_KEYS:
            path = ckl_paths.get(family_key)
            if path is not None:
                self.stig_tab.set_ckl_template_path(family_key, path)
        if output_dir is not None:
            self.stig_tab.set_checklist_output_dir(output_dir)
        self._save_ui_state()
        self._refresh_audit_preflight()

    def _load_ui_state(self) -> None:
        if not self.ui_state_path.is_file():
            return
        try:
            raw_state = json.loads(self.ui_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw_state, dict):
            return

        self._loading_ui_state = True
        try:
            templates = raw_state.get("ckl_templates")
            if isinstance(templates, dict):
                for family_key in CHECKLIST_TEMPLATE_KEYS:
                    path_text = templates.get(family_key)
                    if isinstance(path_text, str) and path_text.strip():
                        self.set_checklist_template(family_key, Path(path_text))

            output_text = raw_state.get("checklist_output_dir") or raw_state.get("output_dir")
            if isinstance(output_text, str) and output_text.strip():
                self.set_checklist_output_dir(Path(output_text))
            self.show_welcome = bool(raw_state.get("show_welcome", True))
            self.overview_tab.set_welcome_visible(self.show_welcome)
        finally:
            self._loading_ui_state = False

    def _save_ui_state(self) -> None:
        if self._loading_ui_state:
            return
        templates = {
            family_key: str(path)
            for family_key in CHECKLIST_TEMPLATE_KEYS
            if (path := self.stig_tab.selected_ckl_paths.get(family_key))
            is not None
        }
        state = {
            "show_welcome": self.show_welcome,
            "ckl_templates": templates,
            "checklist_output_dir": (
                str(self.stig_tab.selected_output_dir)
                if self.stig_tab.selected_output_dir is not None
                else ""
            ),
        }
        try:
            self.ui_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.ui_state_path.write_text(
                json.dumps(state, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            return

    def refresh_license_status(self, announce: bool = True) -> None:
        self.license_manager.reload()
        self.license_tab.refresh(self.license_manager)
        self.license_badge.configure(
            text=self.license_manager.edition,
            fg_color=(
                ("#dcfce7", "#14532d")
                if self.license_manager.is_valid
                else ("#fef3c7", "#78350f")
            ),
            text_color=(
                ("#166534", "#dcfce7")
                if self.license_manager.is_valid
                else ("#92400e", "#fef3c7")
            ),
        )
        self._update_license_notice()
        if announce:
            self.set_status(
                f"License status: {self.license_manager.mode_summary}."
            )
        self._refresh_audit_preflight()

    def _refresh_audit_preflight(self) -> None:
        if not hasattr(self, "targets_tab") or not hasattr(self, "stig_tab"):
            return
        checklist_settings = self.stig_tab.get_checklist_settings()
        self.targets_tab.set_audit_settings(
            ckl_paths=checklist_settings["ckl_paths"],
            output_dir=checklist_settings["output_dir"],
        )
        counts = {
            family: sum(
                1 for check in self.checks if check.stig_family == family
            )
            for family in SUPPORTED_CHECKLIST_FAMILIES
        }
        license_summary = (
            f"Valid - {self.license_manager.edition}"
            if self.license_manager.is_valid
            else f"{self.license_manager.status.value.title()} - Free mode"
        )
        self.targets_tab.refresh_preflight(
            checks_loaded=len(self.checks),
            checks_by_family=counts,
            license_valid=self.license_manager.is_valid,
            license_summary=license_summary,
        )

    def refresh_audit_preflight(self) -> None:
        self._refresh_audit_preflight()

    def run_configured_checklist_audit(self) -> None:
        readiness = self.build_preflight_result()
        if not readiness.ready:
            lines = ["The audit did not start because readiness checks found:", ""]
            for issue in readiness.blocking_issues:
                lines.extend((f"• {issue.message}", f"  {issue.guidance}"))
            self._show_error("\n".join(lines), title="Audit Not Ready", kind="validation")
            return
        setup_settings = self.stig_tab.get_checklist_settings()
        run_settings = self.targets_tab.get_audit_run_settings()
        self.run_checklist_audit(
            families=set(run_settings["families"]),
            ckl_paths=setup_settings["ckl_paths"],
            output_dir=setup_settings["output_dir"],
            create_ckl=bool(run_settings["create_ckl"]),
            create_text=bool(run_settings["create_text"]),
            append_comments=bool(run_settings["append_comments"]),
        )

    def _update_license_notice(self) -> None:
        if self.license_manager.is_valid or self._license_notice_dismissed:
            self.license_notice_frame.grid_remove()
            return
        messages = {
            LicenseStatus.INVALID: (
                "The installed license is invalid. STIG Audit Pro is running "
                "in Free mode."
            ),
            LicenseStatus.EXPIRED: (
                "The installed license has expired. STIG Audit Pro is running "
                "in Free mode."
            ),
            LicenseStatus.MISSING: (
                "No license is installed. STIG Audit Pro is running in Free mode."
            ),
            LicenseStatus.FREE: "STIG Audit Pro is running in Free mode.",
        }
        self.license_notice_label.configure(
            text=messages.get(
                self.license_manager.status,
                "STIG Audit Pro is running in Free mode.",
            )
        )
        self.license_notice_frame.grid()

    def _dismiss_license_notice(self) -> None:
        self._license_notice_dismissed = True
        self.license_notice_frame.grid_remove()

    def import_license_file(self, path: Path) -> None:
        try:
            destination = self.license_manager.import_license(path)
            self.refresh_license_status(announce=False)
            self.license_tab.set_message(
                f"License imported and verified. Installed at {destination}."
            )
            self.tabs.set("License")
            self.set_status(
                f"License {self.license_manager.license_id} imported successfully."
            )
        except LicenseImportError as exc:
            self.refresh_license_status(announce=False)
            self.tabs.set("License")
            self.set_status("License import failed; Free mode remains active.")
            self._show_error(str(exc), kind="license")

    def reload_from_disk(self) -> None:
        try:
            self.check_library_paths = self._check_library_paths()
            libraries = [load_check_library(path) for path in self.check_library_paths]
            checks = [check for library in libraries for check in library.checks]
            self._raise_on_duplicate_checks(checks)
            self.checks = checks
            self.check_source_paths = {
                check.vuln_id: path
                for path, library in zip(self.check_library_paths, libraries)
                for check in library.checks
            }
            self._set_active_profile(self.profile_name, announce=False)
            self.checks_tab.refresh(self.checks, self.check_library_paths)
            self.overview_tab.refresh_inventory(self.checks, self.profile)
            self.refresh_device_groups()
            self._refresh_audit_preflight()
            self.set_status(f"Loaded {len(self.checks)} checks using profile {self.profile.profile_name if self.profile else self.profile_name}.")
        except ConfigValidationError as exc:
            self.set_status("YAML validation failed.")
            self._show_error(str(exc), kind="validation")
        except ValueError as exc:
            self.set_status("Check library validation failed.")
            self._show_error(str(exc), kind="validation")

    def available_profile_names(self) -> list[str]:
        return sorted(path.stem for path in (self.data_dir / "profiles").glob("*.yaml"))

    def _profile_path_for_name(self, profile_name: str) -> Path:
        name = profile_name.strip()
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        if not name:
            raise ValueError("Enter a profile name.")
        if any(character not in allowed for character in name):
            raise ValueError(
                "Profile names can use letters, numbers, underscores, and hyphens."
            )
        return self.data_dir / "profiles" / f"{name}.yaml"

    def create_profile(self, profile_name: str) -> tuple[bool, str]:
        try:
            path = self._profile_path_for_name(profile_name)
            if path.exists():
                raise ValueError(f"Profile {path.stem} already exists.")
            profile_data = {
                "profile_name": path.stem,
                "inherits": DEFAULT_PROFILE_NAME,
                "variables": {
                    "site_label": path.stem.replace("_", " "),
                },
            }
            text = yaml.safe_dump(profile_data, sort_keys=False)
            ok, message = self.validate_profile_yaml(text)
            if not ok:
                return False, message
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            self.profile_name = path.stem
            self.reload_from_disk()
            self.refresh_device_groups()
            self.set_status(f"Created profile {path.stem}.")
            return True, f"Created {path.name}"
        except (OSError, ValueError, yaml.YAMLError) as exc:
            message = self._short_error(exc)
            self.set_status("Could not create profile.")
            return False, message

    def delete_profile(self, profile_name: str) -> tuple[bool, str]:
        try:
            path = self._profile_path_for_name(profile_name)
            if path.stem == DEFAULT_PROFILE_NAME:
                raise ValueError("The base profile cannot be deleted.")
            if not path.is_file():
                raise ValueError(f"Profile {path.stem} was not found.")
            path.unlink()
            if self.profile_name == path.stem:
                self.profile_name = DEFAULT_PROFILE_NAME
            self.reload_from_disk()
            self.refresh_device_groups()
            self.set_status(f"Deleted profile {path.stem}.")
            return True, f"Deleted {path.name}"
        except (OSError, ValueError) as exc:
            message = self._short_error(exc)
            self.set_status("Could not delete profile.")
            return False, message

    def _check_library_paths(self) -> list[Path]:
        return sorted((self.data_dir / "checks").glob("*.yaml"))

    def _raise_on_duplicate_checks(self, checks: list[CheckDefinition]) -> None:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for check in checks:
            if check.vuln_id in seen:
                duplicates.add(check.vuln_id)
            seen.add(check.vuln_id)
        if duplicates:
            raise ValueError(f"Duplicate check IDs across check libraries: {', '.join(sorted(duplicates))}")

    def refresh_device_groups(self) -> None:
        self.targets_tab.refresh_groups(
            self.device_group_store.list_groups(),
            self.available_profile_names(),
        )

    def refresh_stig_metadata(self) -> None:
        self.stig_metadata = self.stig_source_manager.load_cached_metadata()
        self.stig_tab.refresh_metadata(self.stig_metadata)
        self.stig_tab.refresh_library(
            self.stig_lifecycle_service.installed_releases()
        )

    def _install_stig_release(
        self, metadata: StigBenchmarkMetadata
    ) -> None:
        """Add a cached import to the immutable, versioned STIG library."""
        source = Path(metadata.source_path)
        if not source.is_file():
            raise ValueError("The imported STIG source is no longer available.")
        self.stig_lifecycle_service.import_release(source, metadata.family)

    def _stig_release_summary(self, metadata: StigBenchmarkMetadata) -> str:
        release_date = metadata.benchmark_release_date or "unknown benchmark date"
        version = f" {metadata.version}" if metadata.version else ""
        return f"{metadata.family}{version} benchmark date {release_date}"

    def download_latest_stig(self, family: str) -> None:
        try:
            self.set_status(f"Finding latest {family} STIG metadata from Cyber Exchange...")
            self.update_idletasks()
            metadata = self.stig_source_manager.download_latest(family)
            self._install_stig_release(metadata)
            self.refresh_stig_metadata()
            release_summary = self._stig_release_summary(metadata)
            self.stig_tab.set_status(
                f"Downloaded {metadata.display_name}: {release_summary}, "
                f"{metadata.rule_count} rule(s)."
            )
            self.set_status(f"Downloaded {release_summary}.")
        except Exception as exc:
            self.stig_tab.set_status("Automatic lookup failed. Paste a direct ZIP/XML URL or import the downloaded file.")
            self.set_status("STIG lookup failed.")
            self._show_error(str(exc))

    def download_core_stigs(self) -> None:
        try:
            downloaded: list[StigBenchmarkMetadata] = []
            for family in ("IOSXE_L2", "IOSXE_NDM"):
                self.set_status(f"Finding latest {family} STIG metadata from Cyber Exchange...")
                self.update_idletasks()
                downloaded.append(self.stig_source_manager.download_latest(family))
                self._install_stig_release(downloaded[-1])
            self.refresh_stig_metadata()
            summary = ", ".join(self._stig_release_summary(item) for item in downloaded)
            self.stig_tab.set_status(f"Downloaded {summary}.")
            self.set_status(f"Downloaded {summary}.")
        except Exception as exc:
            self.stig_tab.set_status("Automatic L2/NDM lookup failed. Paste a direct ZIP/XML URL or import the downloaded file.")
            self.set_status("STIG lookup failed.")
            self._show_error(str(exc))

    def download_stig_from_url(self, url: str, family: str) -> None:
        try:
            self.set_status(f"Downloading {family} STIG package from direct URL...")
            self.update_idletasks()
            metadata = self.stig_source_manager.download_from_url(url, family=family)
            self._install_stig_release(metadata)
            self.refresh_stig_metadata()
            release_summary = self._stig_release_summary(metadata)
            self.stig_tab.set_status(
                f"Downloaded {metadata.display_name}: {release_summary}, "
                f"{metadata.rule_count} rule(s)."
            )
            self.set_status(f"Downloaded {release_summary}.")
        except Exception as exc:
            self.stig_tab.set_status("Direct URL download failed. Import the ZIP/XML file if the link is protected.")
            self.set_status("STIG URL download failed.")
            self._show_error(str(exc))

    def import_stig_source(self, path: Path, family: str) -> None:
        try:
            metadata = self.stig_source_manager.import_source(path, family=family)
            import_result = self.stig_lifecycle_service.import_release(
                metadata.source_path, metadata.family
            )
            self.refresh_stig_metadata()
            release_summary = self._stig_release_summary(metadata)
            library_note = (
                "Baseline stored in the local release library."
                if import_result.baseline
                else (
                    "Compared with the previous local release: "
                    f"{import_result.diff.summary['changed']} changed, "
                    f"{import_result.diff.summary['added']} added."
                )
            )
            self.stig_tab.set_status(
                f"Imported {metadata.display_name}: {release_summary}, "
                f"{metadata.rule_count} rule(s). {library_note}"
            )
            self.set_status(f"Imported {release_summary}.")
            self.run_service.activity_log.record("STIG_IMPORTED", "stig_release", str(import_result.benchmark.database_id or ""), details={"family": metadata.family, "version": metadata.version, "release": metadata.release})
        except Exception as exc:
            self.stig_tab.set_status("STIG import failed.")
            self.set_status("STIG import failed.")
            self._show_error(str(exc))

    def compare_installed_stig_to_previous(self, benchmark_id: int):
        try:
            diff = self.stig_lifecycle_service.compare_to_previous(benchmark_id)
            self.stig_tab.show_library_diff(diff)
            self.set_status("STIG release comparison complete.")
            self.run_service.activity_log.record("STIG_RELEASE_COMPARED", "stig_release", str(benchmark_id), details={"comparison": "previous"})
            return diff
        except Exception as exc:
            self.set_status("STIG release comparison failed.")
            self._show_error(str(exc))
            return None

    def compare_installed_stigs(self, previous_id: int, current_id: int):
        try:
            diff = self.stig_lifecycle_service.compare(previous_id, current_id)
            self.stig_tab.show_library_diff(diff)
            self.set_status("STIG release comparison complete.")
            self.run_service.activity_log.record("STIG_RELEASE_COMPARED", "stig_release", str(current_id), details={"previous_id": previous_id})
            return diff
        except Exception as exc:
            self.set_status("STIG release comparison failed.")
            self._show_error(str(exc))
            return None

    def installed_stig_coverage(self, benchmark_id: int):
        return self.stig_lifecycle_service.coverage(benchmark_id)

    def export_installed_stig_diff(self, diff: Any, path: Path) -> Path:
        return self.stig_lifecycle_service.export_diff(diff, path)

    def generate_installed_stig_starters(self, benchmark_id: int) -> Path:
        destination = self.data_dir / "checks" / "generated_stig_manual.yaml"
        path = self.stig_lifecycle_service.build_missing_starters(
            benchmark_id, self.checks, destination
        )
        self.reload_from_disk()
        return path

    def mark_installed_stig_automation_reviewed(
        self, benchmark_id: int, vuln_id: str
    ) -> None:
        repository = self.stig_lifecycle_service.repository
        repository.sync_check_mappings(
            benchmark_id, checks_dir=self.data_dir / "checks"
        )
        benchmark = repository.get_benchmark(benchmark_id)
        if benchmark is None:
            raise KeyError("The selected STIG release no longer exists.")
        rule = benchmark.rule_by_vuln(vuln_id)
        if rule is None or rule.database_id is None:
            raise KeyError(f"{vuln_id} is not in the selected STIG release.")
        mappings = repository.persistence.list_mappings(
            vuln_id=vuln_id, stig_rule_id=rule.database_id
        )
        if len(mappings) != 1:
            raise ValueError(
                "Exactly one local YAML mapping is required before this rule can "
                "be marked reviewed. Resolve missing or ambiguous mappings first."
            )
        self.stig_lifecycle_service.mark_automation_reviewed(
            mappings[0].id, benchmark_id, vuln_id
        )
        self.run_service.activity_log.record("AUTOMATION_REVIEWED", "stig_rule", vuln_id, details={"benchmark_id": benchmark_id, "mapping_id": mappings[0].id})

    def compare_stig_sources(
        self,
        old_path: Path,
        new_path: Path,
        family: str | None = None,
    ) -> StigComparisonReport | None:
        try:
            family_text = family or "all benchmarks"
            self.stig_tab.set_comparison_status(f"Comparing {family_text}...")
            self.set_status(f"Comparing old and new STIG sources for {family_text}...")
            self.update_idletasks()
            report = build_stig_comparison(
                old_path,
                new_path,
                family=family,
                checks=self.checks,
                check_sources=self.check_source_paths,
                profiles_dir=self.data_dir / "profiles",
                workspace_root=self.root_dir,
            )
            self.set_status(f"STIG comparison complete: {report.summary}.")
            return report
        except Exception as exc:
            self.stig_tab.set_comparison_status("STIG comparison failed. Check both source files and the selected benchmark.")
            self.set_status("STIG comparison failed.")
            self._show_error(str(exc))
            return None

    def generate_starter_checks_from_stigs(self) -> None:
        try:
            self.refresh_stig_metadata()
            if not self.stig_metadata:
                raise ValueError("Import the current L2/NDM STIG ZIP/XML first, then build starter checks.")
            starter_library = build_manual_starter_library(self.stig_metadata, self.checks)
            destination = self.data_dir / "checks" / "generated_stig_manual.yaml"
            write_manual_starter_library(starter_library, destination)
            self.reload_from_disk()
            self.stig_tab.set_status(
                f"Generated {len(starter_library.checks)} starter manual review check(s) in {destination.name}."
            )
            self.set_status(f"Generated {len(starter_library.checks)} starter check(s).")
        except Exception as exc:
            self.stig_tab.set_status("Starter check generation failed.")
            self.set_status("Starter check generation failed.")
            self._show_error(str(exc))

    def load_device_group(self, group_name: str) -> None:
        try:
            group = self.device_group_store.load_group(group_name)
            if group.profile_name:
                self._set_active_profile(group.profile_name, announce=False)
            self.targets_tab.set_targets(group.targets, group.group_name, group.profile_name)
            profile_text = group.profile_name or (self.profile.profile_name if self.profile else self.profile_name)
            self.set_status(
                f"Loaded {group.group_name}: {len(group.targets)} target(s), profile {profile_text}."
            )
        except Exception as exc:
            self.set_status("Could not load device group.")
            self._show_error(str(exc))

    def save_device_group(
        self,
        group_name: str,
        targets: list[DeviceTargetRecord],
        profile_name: str | None = None,
    ) -> None:
        try:
            self.license_manager.require_feature("saved_presets")
            resolved_profile = profile_name or (self.profile.profile_name if self.profile else self.profile_name)
            group = DeviceGroup(
                group_name=group_name,
                profile_name=resolved_profile,
                targets=targets,
            )
            path = self.device_group_store.save_group(group)
            self.refresh_device_groups()
            self.targets_tab.group_select.set(group.group_name)
            self.targets_tab.group_profile.set(group.profile_name or "Use selected profile")
            self.set_status(
                f"Saved {len(targets)} target(s) to {path.name} with profile {resolved_profile}."
            )
        except Exception as exc:
            self.set_status("Could not save device group.")
            self._show_error(str(exc))

    def select_profile(self, profile_name: str) -> None:
        try:
            self._set_active_profile(profile_name)
            self.refresh_device_groups()
        except Exception as exc:
            self.set_status("Could not load profile.")
            self._show_error(str(exc), kind="validation")

    def _begin_persistent_run(
        self,
        targets: Sequence[DeviceTargetRecord],
        checks: Sequence[CheckDefinition],
        *,
        description: str,
        collection_mode: CollectionMode,
        commands: Sequence[str] | None = None,
    ) -> RunContext:
        """Create the durable run boundary without including session secrets."""
        if self.profile is None:
            raise ValueError("No site profile is loaded.")
        selected_commands = list(commands or plan_commands(list(checks), run_all=False))
        families = sorted({check.stig_family for check in checks})
        metadata = [
            item for item in self.stig_metadata if item.family in set(families)
        ]

        def joined(name: str) -> str | None:
            values = list(
                dict.fromkeys(
                    str(getattr(item, name, "") or "").strip()
                    for item in metadata
                    if str(getattr(item, name, "") or "").strip()
                )
            )
            return ", ".join(values) or None

        preset_name: str | None = None
        if hasattr(self.targets_tab, "preset_select"):
            selected_preset = self.targets_tab.preset_select.get().strip()
            preset_name = selected_preset or None
        context = self.run_service.begin_run(
            targets=list(targets),
            checks=list(checks),
            profile=self.profile,
            stig_families=families,
            commands_requested=selected_commands,
            description=description,
            preset_name=preset_name,
            collection_mode=collection_mode,
            stig_benchmark=joined("benchmark_id"),
            stig_version=joined("version"),
            stig_release=joined("release"),
        )
        self.current_run_id = context.run_id
        return context

    def _persist_service_result(
        self,
        context: RunContext,
        service_result: Any,
        commands: Sequence[str],
    ) -> list[CheckResult]:
        """Persist device failures as visible results before finalizing a run."""
        result_keys = {(result.ip, result.vuln_id) for result in service_result.results}
        for outcome in service_result.summary.outcomes:
            status = getattr(outcome.status, "value", outcome.status)
            key = (outcome.target_ip, "DEVICE-SCAN")
            if status != "COMPLETE" and key not in result_keys:
                reason = outcome.error_message or str(status).replace("_", " ").title()
                service_result.results.append(
                    self._skipped_result(
                        outcome.target_ip,
                        reason,
                        list(commands),
                    ).model_copy(update={"run_id": context.run_id})
                )
                result_keys.add(key)
        persisted = self.run_service.persist_result(context, service_result)
        service_result.results[:] = persisted
        return list(persisted)

    def _abort_persistent_run(
        self,
        context: RunContext | None,
        error_message: str,
        *,
        cancelled: bool = False,
    ) -> None:
        if context is None:
            return
        try:
            self.run_service.abort_run(
                context,
                error_message,
                cancelled=cancelled,
            )
        except Exception:
            # Preserve the original scan exception for the operator. The
            # persistence service logs any abort/finalization failure.
            return

    def _begin_scan(self, total: int, message: str) -> bool:
        if self._scan_in_progress:
            self.set_status(
                "A scan is already running. Cancel it or wait for it to finish."
            )
            return False
        self._scan_cancel_event.clear()
        while not self._scan_event_queue.empty():
            try:
                self._scan_event_queue.get_nowait()
            except queue.Empty:
                break
        self._scan_in_progress = True
        self.targets_tab.set_scan_state(
            running=True,
            completed=0,
            total=total,
            message=f"0/{total} devices",
        )
        self.stig_tab.set_scan_running(True)
        self.set_status(message)
        if not self._scan_event_polling:
            self._scan_event_polling = True
            self.after(75, self._poll_scan_events)
        return True

    def refresh_scan_presets(self) -> None:
        self.targets_tab.refresh_presets(self.scan_preset_store.list_presets())

    def save_scan_preset(self, name: str) -> None:
        try:
            settings = self.targets_tab.get_scan_settings()
            audit = self.targets_tab.get_audit_run_settings()
            group_name = self.targets_tab.group_select.get().strip()
            preset = ScanPreset(
                preset_name=name,
                device_group=None if group_name == "Session targets" else group_name,
                target_ips=[target.ip for target in self.targets_tab.get_targets("checked")],
                stig_families=sorted(audit.get("families", set())),
                profile_name=self.profile_name,
                concurrency=int(settings.get("concurrency") or 5),
                connect_timeout=int(settings.get("timeout") or 30),
                command_timeout=int(settings.get("command_timeout") or 30),
                report_options=ReportOptions(
                    text=bool(audit.get("create_text")),
                    ckl=bool(audit.get("create_ckl")),
                ),
            )
            path = self.scan_preset_store.save(preset)
            self.refresh_scan_presets()
            self.targets_tab.preset_select.set(preset.preset_name)
            self.set_status(f"Saved credential-free scan preset to {path}.")
        except Exception as exc:
            self._show_error(str(exc), kind="validation")

    def load_scan_preset(self, name: str) -> None:
        try:
            preset = self.scan_preset_store.load(name)
            self.select_profile(preset.profile_name)
            if preset.device_group:
                self.load_device_group(preset.device_group)
            elif preset.target_ips:
                self.targets_tab.set_targets([
                    DeviceTargetRecord(ip=ip, checked=True) for ip in preset.target_ips
                ])
            self.targets_tab.apply_scan_preset(preset)
            self.set_status(f"Loaded scan preset {preset.preset_name}; enter session credentials before Live SSH.")
        except Exception as exc:
            self._show_error(str(exc), kind="validation")

    def delete_scan_preset(self, name: str) -> None:
        try:
            if self.scan_preset_store.delete(name):
                self.refresh_scan_presets()
                self.set_status(f"Deleted scan preset {name}.")
        except Exception as exc:
            self._show_error(str(exc), kind="validation")

    def _poll_scan_events(self) -> None:
        """Consume worker events only on Tk's main thread."""
        try:
            while True:
                event = self._scan_event_queue.get_nowait()
                if event.event_type == ScanEventType.DEVICE_STATUS:
                    if event.target_ip:
                        self.targets_tab.set_device_status(
                            event.target_ip, event.status, event.message
                        )
                elif event.event_type == ScanEventType.PROGRESS:
                    self.targets_tab.set_scan_state(
                        running=True,
                        completed=event.completed,
                        total=event.total,
                    )
        except queue.Empty:
            pass
        if self._scan_in_progress:
            self.after(75, self._poll_scan_events)
        else:
            self._scan_event_polling = False

    def _queue_scan_progress(
        self,
        completed: int,
        total: int,
        message: str,
        *,
        checklist: bool = False,
    ) -> None:
        self._post_to_ui(
            lambda: self._update_scan_progress(
                completed,
                total,
                message,
                checklist=checklist,
            )
        )

    def _update_scan_progress(
        self,
        completed: int,
        total: int,
        message: str,
        *,
        checklist: bool = False,
    ) -> None:
        self.targets_tab.set_scan_state(
            running=True,
            completed=completed,
            total=total,
        )
        self.set_status(message)
        if checklist:
            self._set_checklist_status(message)

    def _finish_scan_ui(
        self,
        *,
        completed: int,
        total: int,
        message: str,
    ) -> None:
        self._scan_in_progress = False
        self._scan_thread = None
        self.targets_tab.set_scan_state(
            running=False,
            completed=completed,
            total=total,
        )
        self.stig_tab.set_scan_running(False)
        self.targets_tab.clear_session_credentials()
        self.set_status(message)

    def cancel_scan(self) -> None:
        if not self._scan_in_progress:
            self.set_status("No scan is currently running.")
            return
        self._scan_cancel_event.set()
        message = (
            "Cancel requested. Active workers will stop between commands and "
            "queued targets will be cancelled."
        )
        self.set_status(message)
        self._set_checklist_status(message)

    def run_target_scope(self, scope: str) -> None:
        targets = self.targets_tab.get_targets(scope)
        if not targets:
            self.set_status(f"No targets available for {scope} run.")
            return
        try:
            targets = self._licensed_targets(targets)
            checks = self._licensed_checks(self.checks)
            settings = self.targets_tab.get_scan_settings()
            if settings.get("mode") == "Live SSH":
                self._run_live_for_targets(targets, settings, scope, checks)
            else:
                self._run_sample_for_targets(targets, scope, checks)
        except LicensePolicyError as exc:
            self.refresh_license_status(announce=False)
            self.set_status("Scan blocked by the current license.")
            self._show_error(str(exc), kind="license")

    def run_sample_audit(self, sample_name: str) -> None:
        ip = "10.50.10.25" if sample_name == "compliant" else "10.50.10.26"
        target = DeviceTargetRecord(ip=ip, checked=True)
        try:
            targets = self._licensed_targets([target])
            checks = self._licensed_checks(self.checks)
            self._run_sample_for_targets(targets, sample_name, checks)
        except LicensePolicyError as exc:
            self.refresh_license_status(announce=False)
            self.set_status("Demo scan blocked by the current license.")
            self._show_error(str(exc), kind="license")

    def update_report_summary(self, results: list[CheckResult]) -> None:
        self.reports_tab.refresh(results)
        self.overview_tab.refresh_results(results)

    def export_text_report(self, path: Path) -> None:
        try:
            self.license_manager.require_feature("advanced_reporting")
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_text_report(self.results, path)
            self.set_status(f"Saved TXT report to {destination}.")
            self.reports_tab.set_export_status(f"Saved TXT report: {destination}")
        except LicensePolicyError as exc:
            self.set_status("TXT report export blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except ValueError as exc:
            self.set_status("TXT report export needs more information.")
            self._show_error(str(exc), kind="validation")
        except Exception as exc:
            self.set_status("TXT report export failed.")
            self._show_error(str(exc))

    def export_csv_report(self, path: Path) -> None:
        try:
            self.license_manager.require_feature("advanced_reporting")
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_csv_report(self.results, path)
            self.set_status(f"Saved CSV report to {destination}.")
            self.reports_tab.set_export_status(f"Saved CSV report: {destination}")
        except LicensePolicyError as exc:
            self.set_status("CSV report export blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except ValueError as exc:
            self.set_status("CSV report export needs more information.")
            self._show_error(str(exc), kind="validation")
        except Exception as exc:
            self.set_status("CSV report export failed.")
            self._show_error(str(exc))

    def export_json_report(self, path: Path) -> None:
        self._export_modern_report(path, "JSON", self.report_service.write_json)

    def export_excel_report(self, path: Path) -> None:
        self._export_modern_report(path, "Excel", self.report_service.write_excel)

    def _export_modern_report(
        self,
        path: Path,
        label: str,
        writer: Callable[..., Path],
    ) -> None:
        try:
            self.license_manager.require_feature("advanced_reporting")
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = writer(self.results, path)
            self.set_status(f"Saved {label} report to {destination}.")
            self.reports_tab.set_export_status(f"Saved {label} report: {destination}")
        except LicensePolicyError as exc:
            self.set_status(f"{label} report export blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except ValueError as exc:
            self.set_status(f"{label} report export needs more information.")
            self._show_error(str(exc), kind="validation")
        except Exception as exc:
            self.set_status(f"{label} report export failed.")
            self._show_error(str(exc))

    def run_checklist_audit(
        self,
        *,
        families: set[str],
        ckl_paths: dict[str, Path | None],
        output_dir: Path | None,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
    ) -> None:
        """Run L2, NDM, or a combined audit and create the selected artifacts."""

        scan_started = False
        context: RunContext | None = None
        try:
            supported_families = set(SUPPORTED_CHECKLIST_FAMILIES)
            selected_families = families & supported_families
            if not selected_families:
                raise ValueError("Select L2, NDM, or both before starting the audit.")

            self.license_manager.reload()
            if "IOSXE_L2" in selected_families:
                self.license_manager.require_feature("l2_checks", refresh=False)
            if "IOSXE_NDM" in selected_families:
                self.license_manager.require_feature("ndm_checks", refresh=False)
            if create_ckl:
                self.license_manager.require_feature("ckl_export", refresh=False)
            if create_text:
                self.license_manager.require_feature(
                    "advanced_reporting",
                    refresh=False,
                )
            if not create_ckl and not create_text:
                raise ValueError("Select Fill CKL, Create text report, or both.")
            if output_dir is None:
                raise ValueError(
                    "Select a destination folder for the completed files."
                )
            output_dir.mkdir(parents=True, exist_ok=True)
            self._remember_checklist_preferences(ckl_paths, output_dir)

            checks_by_family = {
                family: [
                    check for check in self.checks if check.stig_family == family
                ]
                for family in supported_families
            }
            for family in selected_families:
                if not checks_by_family[family]:
                    raise ValueError(f"No {family} checks are loaded.")

            selected_checks = [
                check
                for check in self.checks
                if check.stig_family in selected_families
            ]
            if selected_families == supported_families:
                scan_label = "L2 + NDM"
                report_file_label = "IOSXE_L2_NDM"
            elif selected_families == {"IOSXE_NDM"}:
                scan_label = "NDM"
                report_file_label = "IOSXE_NDM"
            else:
                scan_label = "L2"
                report_file_label = "IOSXE_L2"

            ckl_jobs = (
                _build_checklist_template_jobs(
                    selected_families,
                    ckl_paths,
                    checks_by_family,
                )
                if create_ckl
                else []
            )

            targets = self.targets_tab.get_targets("checked")
            if not targets:
                raise ValueError("Check at least one target on the Audit Run tab.")
            targets = self._licensed_targets(targets, refresh=False)
            settings = self.targets_tab.get_scan_settings()
            if settings.get("mode") != "Live SSH":
                raise ValueError(
                    "The CKL workflow requires Live SSH. On the Audit Run tab, "
                    "change Scan Mode from Sample outputs to Live SSH."
                )
            username = str(settings.get("username") or "")
            password = str(settings.get("password") or "")
            if not username or not password:
                raise ValueError(
                    "Live SSH requires a username and password on the Audit Run tab."
                )
            credentials = DeviceCredentials(
                username=username,
                password=password,
                secret=(
                    settings.get("secret")
                    if isinstance(settings.get("secret"), str)
                    else None
                ),
            )
            runtime_settings = {
                "mode": "Live SSH",
                "timeout": int(settings.get("timeout") or 30),
                "concurrency": int(settings.get("concurrency") or 5),
                "command_timeout": int(
                    settings.get("command_timeout") or settings.get("timeout") or 30
                ),
            }
            commands = plan_commands(selected_checks, run_all=False)
            if not self._begin_scan(
                len(targets),
                f"Starting {scan_label} checklist audit for "
                f"{len(targets)} target(s)...",
            ):
                return
            scan_started = True
            context = self._begin_persistent_run(
                targets,
                selected_checks,
                description=f"{scan_label} checklist audit",
                collection_mode=CollectionMode.LIVE_SSH,
                commands=commands,
            )
            self._scan_thread = threading.Thread(
                target=self._checklist_scan_worker,
                args=(
                    list(targets),
                    runtime_settings,
                    credentials,
                    list(selected_checks),
                    scan_label,
                    report_file_label,
                    ckl_jobs,
                    output_dir,
                    create_ckl,
                    create_text,
                    append_comments,
                    context,
                ),
                daemon=True,
                name="stig-audit-checklist-scan",
            )
            self._scan_thread.start()
        except LicensePolicyError as exc:
            self._abort_persistent_run(context, str(exc))
            if scan_started:
                self._finish_scan_ui(
                    completed=0,
                    total=len(targets) if "targets" in locals() else 0,
                    message="Checklist audit could not be started.",
                )
            self.refresh_license_status(announce=False)
            self._set_checklist_status(
                f"Checklist audit blocked by license: {exc}"
            )
            self.set_status("Checklist audit blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except Exception as exc:
            self._abort_persistent_run(context, str(exc))
            if scan_started:
                self._finish_scan_ui(
                    completed=0,
                    total=len(targets) if "targets" in locals() else 0,
                    message="Checklist audit could not be started.",
                )
            self._set_checklist_status(
                f"Checklist audit failed: {exc}"
            )
            self.set_status("Checklist audit failed.")
            self._show_error(str(exc), kind="validation")

    def _checklist_scan_worker(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        credentials: DeviceCredentials,
        checks: list[CheckDefinition],
        scan_label: str,
        report_file_label: str,
        ckl_jobs: list[ChecklistTemplateJob],
        output_dir: Path,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
        context: RunContext,
    ) -> None:
        progress = {"completed": 0}
        total = len(targets)

        def progress_callback(
            completed: int,
            progress_total: int,
            message: str,
        ) -> None:
            progress["completed"] = completed
            self._queue_scan_progress(
                completed,
                progress_total,
                message,
                checklist=True,
            )

        run_finalized = False
        try:
            results, assets = self._run_l2_targets(
                targets,
                settings,
                checks,
                audit_label=scan_label,
                cancel_event=self._scan_cancel_event,
                progress_callback=progress_callback,
                credentials=credentials,
                run_context=context,
            )
            # _run_l2_targets persists and finalizes the immutable audit run.
            # Subsequent CKL/TXT export failures must not relabel that completed
            # assessment as a failed collection.
            run_finalized = True

            artifacts: list[Path] = []
            unmatched_count = 0
            if create_ckl and ckl_jobs:
                for target in targets:
                    asset = assets.get(target.ip)
                    if asset is None:
                        continue
                    for job in ckl_jobs:
                        device_results = [
                            result
                            for result in results
                            if result.ip == target.ip
                            and result.stig_family in job.families
                        ]
                        if not device_results:
                            continue
                        filename = (
                            f"{safe_device_filename(asset.hostname)}_"
                            f"{safe_device_filename(target.ip)}_"
                            f"{job.file_label}_completed.ckl"
                        )
                        summary = write_completed_ckl(
                            job.template_path,
                            output_dir / filename,
                            device_results,
                            asset,
                            append_comments=append_comments,
                        )
                        artifacts.append(summary.path)
                        unmatched_count += len(summary.unmatched_result_ids)

            if create_text and results:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = (
                    output_dir / f"{report_file_label}_audit_{timestamp}.txt"
                )
                artifacts.append(write_text_report(results, report_path))

            cancelled = self._scan_cancel_event.is_set()
            completed = progress["completed"]
            self._post_to_ui(
                lambda: self._complete_checklist_scan(
                    results,
                    artifacts,
                    unmatched_count,
                    scan_label,
                    output_dir,
                    completed,
                    total,
                    cancelled,
                )
            )
        except Exception as exc:
            message = str(exc)
            if not run_finalized:
                self._abort_persistent_run(
                    context,
                    message,
                    cancelled=self._scan_cancel_event.is_set(),
                )
            completed = progress["completed"]
            self._post_to_ui(
                lambda: self._handle_background_scan_error(
                    message,
                    completed,
                    total,
                    checklist=True,
                )
            )

    def _complete_checklist_scan(
        self,
        results: list[CheckResult],
        artifacts: list[Path],
        unmatched_count: int,
        scan_label: str,
        output_dir: Path,
        completed: int,
        total: int,
        cancelled: bool,
    ) -> None:
        self.last_artifacts = artifacts
        self.results = results
        self.results_tab.refresh(results)
        self.update_report_summary(results)
        self.refresh_audit_history(announce=False)
        if results:
            self.tabs.set("Results")
        open_count = sum(result.status == "Open" for result in results)
        pass_count = sum(result.status == "NotAFinding" for result in results)
        prefix = (
            f"{scan_label} audit cancelled after {completed}/{total} target(s)"
            if cancelled
            else f"{scan_label} audit complete for {completed} target(s)"
        )
        message = (
            f"{prefix}: {pass_count} NotAFinding, {open_count} Open; "
            f"created {len(artifacts)} file(s) in {output_dir}."
        )
        if unmatched_count:
            message += (
                f" {unmatched_count} result(s) had no matching CKL "
                "vulnerability."
            )
        self._set_checklist_status(message)
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=message,
        )

    def run_l2_checklist_audit(
        self,
        *,
        ckl_path: Path | None,
        output_dir: Path | None,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
    ) -> None:
        """Compatibility entry point for the unified persistent checklist flow."""
        self.run_checklist_audit(
            families={"IOSXE_L2"},
            ckl_paths={
                "IOSXE_L2": ckl_path,
                "IOSXE_NDM": None,
                "COMBINED": None,
            },
            output_dir=output_dir,
            create_ckl=create_ckl,
            create_text=create_text,
            append_comments=append_comments,
        )

    def _run_l2_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        checks: list[CheckDefinition],
        audit_label: str = "L2",
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
        credentials: DeviceCredentials | None = None,
        run_context: RunContext | None = None,
    ) -> tuple[list[CheckResult], dict[str, CklAsset]]:
        return self._run_service_targets(
            targets,
            settings,
            checks,
            audit_label=audit_label,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
            credentials=credentials,
            run_context=run_context,
        )

    def _run_service_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        checks: list[CheckDefinition],
        *,
        audit_label: str = "Audit",
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
        credentials: DeviceCredentials | None = None,
        run_context: RunContext | None = None,
    ) -> tuple[list[CheckResult], dict[str, CklAsset]]:
        mode = str(settings.get("mode") or "Sample outputs")
        commands = plan_commands(checks, run_all=False)
        collection_mode = (
            CollectionMode.LIVE_SSH
            if mode == "Live SSH"
            else CollectionMode.SAMPLE
        )
        context = run_context or self._begin_persistent_run(
            targets,
            checks,
            description=f"{audit_label} audit",
            collection_mode=collection_mode,
            commands=commands,
        )
        cancellation = cancel_event or self._scan_cancel_event
        finalized = False
        try:
            if mode == "Live SSH":
                if credentials is None:
                    username = str(settings.get("username") or "")
                    password = str(settings.get("password") or "")
                    if not username or not password:
                        raise ValueError(
                            "Live SSH requires a username and password on the Audit Run tab."
                        )
                    credentials = DeviceCredentials(
                        username=username,
                        password=password,
                        secret=(
                            settings.get("secret")
                            if isinstance(settings.get("secret"), str)
                            else None
                        ),
                    )
                service_result = self.audit_service.run_live(
                    run_id=context.run_id,
                    targets=targets,
                    credentials=credentials,
                    checks=checks,
                    profile_provider=self._profile_for_target,
                    concurrency=int(settings.get("concurrency") or 5),
                    connect_timeout=int(settings.get("timeout") or 30),
                    command_timeout=int(settings.get("command_timeout") or settings.get("timeout") or 30),
                    cancel_event=cancellation,
                    event_queue=self._scan_event_queue,
                    evidence_sink=self.run_service.evidence_sink(context),
                )
            else:
                service_result = self.audit_service.run_offline(
                    run_id=context.run_id,
                    targets=targets,
                    checks=checks,
                    profile_provider=self._profile_for_target,
                    output_loader=lambda target: self._load_sample_outputs(
                        self._sample_name_for_target(target)
                    ),
                    concurrency=int(settings.get("concurrency") or 5),
                    cancel_event=cancellation,
                    event_queue=self._scan_event_queue,
                    evidence_sink=self.run_service.evidence_sink(context),
                )
            results = self._persist_service_result(context, service_result, commands)
            finalized = True
        except Exception as exc:
            if not finalized:
                self._abort_persistent_run(
                    context,
                    str(exc),
                    cancelled=cancellation.is_set(),
                )
            raise
        if progress_callback is not None:
            progress_callback(
                len(service_result.summary.outcomes),
                len(targets),
                f"{audit_label} collection complete.",
            )
        return results, service_result.assets

    def validate_check_yaml(self, text: str) -> tuple[bool, str]:
        try:
            data = yaml.safe_load(text) or {}
            library = self._validate_model(CheckLibrary, data)
            return True, f"{len(library.checks)} checks valid"
        except (ValidationError, yaml.YAMLError, ValueError) as exc:
            return False, self._short_error(exc)

    def validate_check_simple(
        self, vuln_id: str, updates: dict[str, list[object]]
    ) -> tuple[bool, str]:
        try:
            check = next(item for item in self.checks if item.vuln_id == vuln_id)
            conditions = dict(check.conditions)
            for key, value in updates.items():
                if value:
                    conditions[key] = value
                else:
                    conditions.pop(key, None)
            CheckDefinition.model_validate(
                {**check.model_dump(mode="python"), "conditions": conditions}
            )
            return True, f"{vuln_id} string and pattern values are valid"
        except (StopIteration, ValidationError, ValueError) as exc:
            return False, self._short_error(exc)

    def save_check_simple(
        self, path: Path, vuln_id: str, updates: dict[str, list[object]]
    ) -> tuple[bool, str]:
        try:
            data = load_yaml_file(path)
            raw_checks = data.get("checks")
            if not isinstance(raw_checks, list):
                raise ValueError("Check library does not contain a checks list")
            raw_check = next(
                item for item in raw_checks
                if isinstance(item, dict) and str(item.get("vuln_id")) == vuln_id
            )
            conditions = raw_check.setdefault("conditions", {})
            if not isinstance(conditions, dict):
                raise ValueError(f"{vuln_id} conditions must be a mapping")
            for key, value in updates.items():
                if value:
                    conditions[key] = value
                else:
                    conditions.pop(key, None)
            text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
            return self.save_check_yaml(path, text)
        except (OSError, StopIteration, ValueError, yaml.YAMLError) as exc:
            return False, self._short_error(exc)

    def save_check_yaml(self, path: Path, text: str) -> tuple[bool, str]:
        try:
            ok, message = self.validate_check_yaml(text)
            if not ok:
                return False, message
            backup_dir = application_data_dir() / "check_backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            if path.is_file():
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                shutil.copy2(path, backup_dir / f"{path.stem}-{stamp}{path.suffix}.bak")
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_name, path)
            except Exception:
                Path(temporary_name).unlink(missing_ok=True)
                raise
            self.reload_from_disk()
            self.run_service.activity_log.record("CHECK_MODIFIED", "check_library", path.name, details={"backup_created": True})
            return True, f"Saved {path.name}"
        except OSError as exc:
            return False, self._short_error(exc)

    def run_check_fixture_tests(self, check: CheckDefinition):
        if self.profile is None:
            raise ValueError("Load a Site Profile before running check tests")
        return CheckFixtureService(self.root_dir / "tests" / "check_fixtures").run_check(check, self.profile)

    def validate_profile_yaml(self, text: str) -> tuple[bool, str]:
        try:
            data = yaml.safe_load(text) or {}
            if not isinstance(data, dict):
                raise ValueError("Profile YAML must be a mapping")
            inherits = data.get("inherits")
            if inherits:
                base_path = self.data_dir / "profiles" / f"{inherits}.yaml"
                data = deep_merge(load_yaml_file(base_path), data)
            profile = self._validate_model(SiteProfile, data)
            return True, f"{profile.profile_name} valid"
        except (ValidationError, yaml.YAMLError, ValueError) as exc:
            return False, self._short_error(exc)

    def validate_profile_values(self, values: dict[str, str]) -> tuple[bool, str]:
        try:
            self._profile_overlay_from_values(values)
            return True, "Profile values are valid"
        except (ValueError, yaml.YAMLError) as exc:
            return False, self._short_error(exc)

    def save_profile_values(
        self, path: Path, values: dict[str, str]
    ) -> tuple[bool, str]:
        try:
            data = load_yaml_file(path)
            overlay = self._profile_overlay_from_values(values)
            updated = deep_merge(data, overlay)
            text = yaml.safe_dump(updated, sort_keys=False, allow_unicode=True)
            return self.save_profile_yaml(path, text)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return False, self._short_error(exc)

    def _profile_overlay_from_values(self, values: dict[str, str]) -> dict[str, Any]:
        def vlan(name: str) -> int:
            raw = values.get(name, "").strip()
            if not raw.isdigit() or not 1 <= int(raw) <= 4094:
                raise ValueError(f"{name.replace('_', ' ').title()} must be a VLAN from 1 through 4094")
            return int(raw)

        def integers(name: str) -> list[int]:
            output: list[int] = []
            for token in values.get(name, "").replace(";", ",").split(","):
                token = token.strip()
                if not token:
                    continue
                if not token.isdigit() or not 1 <= int(token) <= 4094:
                    raise ValueError(f"{name.replace('_', ' ').title()} contains an invalid VLAN: {token}")
                if int(token) not in output:
                    output.append(int(token))
            return output

        def strings(name: str) -> list[str]:
            return list(dict.fromkeys(
                token.strip()
                for token in values.get(name, "").replace("\n", ",").replace(";", ",").split(",")
                if token.strip()
            ))

        networks: list[dict[str, str]] = []
        network_text = values.get("management_networks", "")
        for line in network_text.replace(";", "\n").splitlines():
            clean = line.strip()
            if not clean:
                continue
            parts = clean.split()
            if len(parts) != 2:
                raise ValueError("Management networks require one 'network_address subnet_mask' pair per line")
            networks.append({"network_address": parts[0], "subnet_mask": parts[1]})
        variables = yaml.safe_load(values.get("variables_yaml", "") or "{}")
        if not isinstance(variables, dict):
            raise ValueError("Additional profile variables must be a YAML mapping")
        overlay: dict[str, Any] = {
            "unused_vlan": vlan("unused_vlan"),
            "native_vlan": vlan("native_vlan"),
            "management_vlan": vlan("management_vlan"),
            "dhcp_snooping": {"vlans": integers("dhcp_vlans")},
            "arp_inspection": {"vlans": integers("arp_vlans")},
            "trunk_policy": {"additional_pruned_vlans": integers("additional_pruned_vlans")},
            "management_access": {"networks": networks},
            "endpoint_authentication": {"radius_servers": strings("radius_servers")},
            "root_guard": {"upstream_switches": strings("root_guard_upstream")},
            "variables": variables,
        }
        # Validate the edited portion using the active profile as a complete
        # base; the actual file is also revalidated before its atomic save.
        if self.profile is not None:
            SiteProfile.model_validate(deep_merge(self.profile.model_dump(mode="python"), overlay))
        return overlay

    def save_profile_yaml(
        self,
        path: Path,
        text: str,
        *,
        activate: bool = True,
    ) -> tuple[bool, str]:
        try:
            ok, message = self.validate_profile_yaml(text)
            if not ok:
                return False, message
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file():
                backup_dir = application_data_dir() / "profile_backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                shutil.copy2(path, backup_dir / f"{path.stem}-{stamp}{path.suffix}.bak")
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_name, path)
            except Exception:
                Path(temporary_name).unlink(missing_ok=True)
                raise
            if activate:
                self.profile_name = path.stem
            self.reload_from_disk()
            self.run_service.activity_log.record("PROFILE_MODIFIED", "site_profile", path.stem, details={"backup_created": True})
            return True, f"Saved {path.name}"
        except (OSError, yaml.YAMLError) as exc:
            return False, self._short_error(exc)

    def _set_active_profile(self, profile_name: str, announce: bool = True) -> None:
        self.profile_name = profile_name
        self.profile_path = self.data_dir / "profiles" / f"{profile_name}.yaml"
        self.profile = load_profile(self.profile_path)
        self.stig_tab.refresh_profile(
            self.profile,
            self.profile_path,
            self.data_dir / "profiles" / f"{DEFAULT_PROFILE_NAME}.yaml",
        )
        self.profiles_tab.refresh(self.profile, self.profile_path)
        self.targets_tab.set_active_profile(self.profile.profile_name, self.profile_path)
        self._refresh_audit_preflight()
        if announce:
            self.set_status(f"Selected site profile {self.profile.profile_name}.")

    def _run_sample_for_targets(
        self,
        targets: list[DeviceTargetRecord],
        label: str,
        checks: list[CheckDefinition],
    ) -> None:
        if self.profile is None:
            self.reload_from_disk()
        if self.profile is None:
            return
        context: RunContext | None = None
        run_finalized = False
        try:
            commands = plan_commands(checks, run_all=False)
            context = self._begin_persistent_run(
                targets,
                checks,
                description=f"{label.title()} sample audit",
                collection_mode=CollectionMode.SAMPLE,
                commands=commands,
            )
            service_result = self.audit_service.run_offline(
                run_id=context.run_id,
                targets=targets,
                checks=checks,
                profile_provider=self._profile_for_target,
                output_loader=lambda target: self._load_sample_outputs(
                    self._sample_name_for_target(target)
                ),
                concurrency=min(5, max(1, len(targets))),
                evidence_sink=self.run_service.evidence_sink(context),
            )
            results = self._persist_service_result(context, service_result, commands)
            run_finalized = True
            self.results = results
            self.results_tab.refresh(self.results)
            self.update_report_summary(self.results)
            self.refresh_audit_history(announce=False)
            open_count = sum(1 for result in self.results if result.status == "Open")
            pass_count = sum(1 for result in self.results if result.status == "NotAFinding")
            self.tabs.set("Results")
            self.set_status(
                f"{label.title()} run complete for {len(targets)} target(s): "
                f"{pass_count} NotAFinding, {open_count} Open."
            )
        except Exception as exc:
            if not run_finalized:
                self._abort_persistent_run(context, str(exc))
            self.refresh_audit_history(announce=False)
            self.set_status("Sample target run failed.")
            self._show_error(str(exc))

    def _run_live_for_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        label: str,
        checks: list[CheckDefinition],
    ) -> None:
        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        if not username or not password:
            self.set_status("Live SSH requires a username and password.")
            self._show_error(
                "Enter both an SSH username and password on the Audit Run tab.",
                kind="validation",
            )
            return
        if not self._begin_scan(
            len(targets),
            f"Starting {label} SSH scan for {len(targets)} target(s)...",
        ):
            return

        context: RunContext | None = None
        try:
            timeout = int(settings.get("timeout") or 30)
            concurrency = int(settings.get("concurrency") or 5)
            command_timeout = int(settings.get("command_timeout") or timeout)
            credentials = DeviceCredentials(
                username=username,
                password=password,
                secret=settings.get("secret") if isinstance(settings.get("secret"), str) else None,
            )
            commands = plan_commands(checks, run_all=False)
            context = self._begin_persistent_run(
                targets,
                checks,
                description=f"{label.title()} live SSH audit",
                collection_mode=CollectionMode.LIVE_SSH,
                commands=commands,
            )
            self._scan_thread = threading.Thread(
                target=self._live_scan_worker,
                args=(
                    list(targets),
                    credentials,
                    timeout,
                    command_timeout,
                    concurrency,
                    label,
                    list(checks),
                    commands,
                    context,
                ),
                daemon=True,
                name="stig-audit-live-scan",
            )
            self._scan_thread.start()
        except Exception as exc:
            self._abort_persistent_run(context, str(exc))
            self.refresh_audit_history(announce=False)
            self._finish_scan_ui(
                completed=0,
                total=len(targets),
                message="Live SSH scan could not be started.",
            )
            self._show_error(str(exc), kind="connection")

    def _live_scan_worker(
        self,
        targets: list[DeviceTargetRecord],
        credentials: DeviceCredentials,
        timeout: int,
        command_timeout: int,
        concurrency: int,
        label: str,
        checks: list[CheckDefinition],
        commands: list[str],
        context: RunContext,
    ) -> None:
        total = len(targets)
        run_finalized = False
        try:
            service_result = self.audit_service.run_live(
                run_id=context.run_id,
                targets=targets,
                credentials=credentials,
                checks=checks,
                profile_provider=self._profile_for_target,
                concurrency=concurrency,
                connect_timeout=timeout,
                command_timeout=command_timeout,
                cancel_event=self._scan_cancel_event,
                event_queue=self._scan_event_queue,
                evidence_sink=self.run_service.evidence_sink(context),
            )
            results = self._persist_service_result(context, service_result, commands)
            run_finalized = True
            completed = len(service_result.summary.outcomes)
            cancelled = (
                service_result.summary.status.value == "CANCELLED"
                or self._scan_cancel_event.is_set()
            )
            self._post_to_ui(
                lambda: self._complete_live_scan(
                    results,
                    label,
                    completed,
                    total,
                    cancelled,
                )
            )
        except Exception as exc:
            message = str(exc)
            if not run_finalized:
                self._abort_persistent_run(
                    context,
                    message,
                    cancelled=self._scan_cancel_event.is_set(),
                )
            self._post_to_ui(
                lambda: self._handle_background_scan_error(
                    message,
                    0,
                    total,
                )
            )

    def _complete_live_scan(
        self,
        results: list[CheckResult],
        label: str,
        completed: int,
        total: int,
        cancelled: bool,
    ) -> None:
        self.results = results
        self.results_tab.refresh(self.results)
        self.update_report_summary(self.results)
        self.refresh_audit_history(announce=False)
        skipped = sum(1 for result in self.results if result.status == "Skipped")
        open_count = sum(1 for result in self.results if result.status == "Open")
        pass_count = sum(1 for result in self.results if result.status == "NotAFinding")
        if results:
            self.tabs.set("Results")
        prefix = (
            f"{label.title()} SSH run cancelled after {completed}/{total} target(s)"
            if cancelled
            else f"{label.title()} SSH run complete for {completed} target(s)"
        )
        message = (
            f"{prefix}: "
            f"{pass_count} NotAFinding, {open_count} Open, {skipped} Skipped."
        )
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=message,
        )

    def _handle_background_scan_error(
        self,
        message: str,
        completed: int,
        total: int,
        *,
        checklist: bool = False,
    ) -> None:
        status_message = (
            f"Scan failed after {completed}/{total} target(s)."
        )
        if checklist:
            self._set_checklist_status(
                f"Checklist audit failed: {message}"
            )
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=status_message,
        )
        self._show_error(message, kind="connection")

    def _skipped_result(self, ip: str, reason: str, commands: list[str]) -> CheckResult:
        return CheckResult(
            ip=ip,
            hostname="unknown",
            vuln_id="DEVICE-SCAN",
            stig_family="SCAN",
            title="Device skipped",
            severity="info",
            status="Skipped",
            failed_objects=[],
            passed_objects=[],
            finding_details=reason,
            comments=reason,
            commands_used=commands,
            error_message=reason,
        )

    def _profile_for_target(self, target: DeviceTargetRecord) -> SiteProfile:
        if target.profile_override:
            profile_path = self.data_dir / "profiles" / f"{target.profile_override}.yaml"
            return load_profile(profile_path)
        if self.profile is None:
            raise ValueError("No site profile loaded")
        return self.profile

    def _licensed_targets(
        self,
        targets: list[DeviceTargetRecord],
        *,
        refresh: bool = True,
    ) -> list[DeviceTargetRecord]:
        normalized = self.license_manager.require_scan_targets(
            (target.ip for target in targets),
            refresh=refresh,
        )
        first_by_ip: dict[str, DeviceTargetRecord] = {}
        for target in targets:
            target_ip = self.license_manager.normalize_unique_targets([target.ip])[0]
            if target_ip not in first_by_ip:
                if hasattr(target, "model_copy"):
                    normalized_target = target.model_copy(update={"ip": target_ip})
                else:
                    normalized_target = target.copy(update={"ip": target_ip})
                first_by_ip[target_ip] = normalized_target
        return [first_by_ip[ip] for ip in normalized]

    def _licensed_checks(
        self, checks: list[CheckDefinition]
    ) -> list[CheckDefinition]:
        allowed: list[CheckDefinition] = []
        for check in checks:
            if check.stig_family == "IOSXE_L2":
                if self.license_manager.feature_enabled("l2_checks"):
                    allowed.append(check)
            elif check.stig_family == "IOSXE_NDM":
                if self.license_manager.feature_enabled("ndm_checks"):
                    allowed.append(check)
            else:
                allowed.append(check)
        if not allowed:
            raise LicensePolicyError(
                "The current license does not enable any of the selected L2 or NDM checks."
            )
        return allowed

    def _sample_name_for_target(self, target: DeviceTargetRecord) -> str:
        return "noncompliant" if target.ip.endswith(".26") else "compliant"

    def _load_sample_outputs(self, sample_name: str) -> dict[str, str]:
        base = self.sample_dir / sample_name
        return {
            command: (base / filename).read_text(encoding="utf-8")
            for command, filename in COMMAND_FILES.items()
        }

    def _validate_model(self, model_type: type[ModelT], data: Any) -> ModelT:
        if hasattr(model_type, "model_validate"):
            return model_type.model_validate(data)  # type: ignore[attr-defined]
        return model_type.parse_obj(data)

    def _show_text_dialog(self, title: str, message: str) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("760x520")
        dialog.transient(self)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        text = ctk.CTkTextbox(dialog, wrap="none")
        text.grid(row=0, column=0, sticky="nsew", padx=14, pady=(14, 8))
        text.insert("1.0", message)
        text.configure(state="disabled")
        ctk.CTkButton(
            dialog,
            text="Close",
            width=90,
            command=dialog.destroy,
        ).grid(row=1, column=0, sticky="e", padx=14, pady=(0, 14))

    def _show_error(
        self,
        message: str,
        title: str | None = None,
        kind: str = "generic",
    ) -> None:
        dialog_titles = {
            "connection": "Connection Failed",
            "license": "License Issue",
            "validation": "Invalid Input",
            "generic": "Error",
        }
        if kind == "connection":
            presented = explain_error(message)
            title = title or presented.title
            message = f"{presented.message}\n\nRecommended action\n{presented.guidance}\n\nTechnical details\n{presented.technical_details}"
        dialog = ctk.CTkToplevel(self)
        dialog.title(title or dialog_titles.get(kind, dialog_titles["generic"]))
        dialog.geometry("620x260")
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        text = ctk.CTkTextbox(dialog, wrap="word")
        text.grid(row=0, column=0, sticky="nsew", padx=14, pady=(14, 8))
        text.insert("1.0", message)
        text.configure(state="disabled")

        buttons = ctk.CTkFrame(dialog, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        buttons.grid_columnconfigure(0, weight=1)

        def copy_details() -> None:
            self.clipboard_clear()
            self.clipboard_append(message)
            self.update_idletasks()
            copy_button.configure(text="Copied")

        copy_button = ctk.CTkButton(
            buttons,
            text="Copy Details",
            width=110,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90"),
            command=copy_details,
        )
        copy_button.grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            buttons,
            text="OK",
            width=90,
            command=dialog.destroy,
        ).grid(row=0, column=1, sticky="e")

    def _short_error(self, exc: Exception) -> str:
        text = str(exc).replace("\n", " ")
        return text[:120] + ("..." if len(text) > 120 else "")


def run_gui() -> None:
    app = StigAuditProApp()
    app.mainloop()
