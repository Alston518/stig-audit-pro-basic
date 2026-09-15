"""Targets tab with a persistent device-list workbench."""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from stig_audit_pro.config import DEFAULT_PROFILE_NAME
from stig_audit_pro.gui.widgets import (
    BORDER_DARK,
    BORDER_LIGHT,
    DANGER,
    NEUTRAL,
    PANEL_DARK,
    PANEL_LIGHT,
    PageFrame,
    Panel,
    PRIMARY,
    PRIMARY_HOVER,
    SUCCESS,
    TEXT_MUTED,
    WARNING,
    confirm_action,
)
from stig_audit_pro.storage.device_groups import DeviceTargetRecord

USE_DEFAULT_PROFILE = "Use scan default"
USE_SELECTED_PROFILE = "Use selected profile"
PREFLIGHT_ITEMS = (
    ("license", "License"),
    ("targets", "Targets"),
    ("profile", "Site Profile"),
    ("mode", "Mode"),
    ("credentials", "Credentials"),
    ("families", "Families"),
    ("outputs", "Outputs"),
    ("templates", "CKL Templates"),
    ("destination", "Destination"),
    ("checks", "Checks Loaded"),
)
PREFLIGHT_COLORS = {
    "ok": (SUCCESS, "#6ce9a6"),
    "warn": (WARNING, "#fdb022"),
    "block": (DANGER, "#f97066"),
    "info": (NEUTRAL, "#98a2b3"),
}


class TargetsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.targets: list[DeviceTargetRecord] = []
        self.selected_index: int | None = None
        self.profile_values = [USE_DEFAULT_PROFILE]
        self.row_checks: dict[int, ctk.CTkCheckBox] = {}
        self.row_profiles: dict[int, ctk.CTkComboBox] = {}
        self.device_statuses: dict[str, tuple[str, str]] = {}
        self.selected_ckl_paths: dict[str, Path | None] = {
            "IOSXE_L2": None,
            "IOSXE_NDM": None,
            "COMBINED": None,
        }
        self.selected_output_dir: Path | None = None
        self.preflight_badges: dict[str, ctk.CTkLabel] = {}
        self.preflight_details: dict[str, ctk.CTkLabel] = {}
        self.preflight_checks_loaded = 0
        self.preflight_checks_by_family: dict[str, int] = {
            "IOSXE_L2": 0,
            "IOSXE_NDM": 0,
        }
        self.preflight_license_valid = False
        self.preflight_license_summary = "Checking license"
        self.active_profile_name = DEFAULT_PROFILE_NAME
        self.active_profile_path: Path | None = None
        self.audit_families: set[str] = {"IOSXE_L2"}
        self.audit_create_ckl = True
        self.audit_create_text = True
        self.audit_append_comments = True
        self.audit_option_checkboxes: list[ctk.CTkCheckBox] = []

        self.grid_columnconfigure(0, weight=0, minsize=360)
        self.grid_columnconfigure(1, weight=1, minsize=720)
        self.grid_rowconfigure(0, weight=1)

        self._build_input_panel()
        self._build_table_panel()

    def _build_input_panel(self) -> None:
        panel = Panel(self, "Targets & Connection")
        panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        content = ctk.CTkFrame(panel, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))
        content.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            content,
            text="1. Targets",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(4, 2))
        single_row = ctk.CTkFrame(content, fg_color="transparent")
        single_row.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        single_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(single_row, text="Single IP", width=68, anchor="w").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.single_ip = ctk.CTkEntry(single_row, placeholder_text="10.50.10.25", height=28)
        self.single_ip.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        self.single_ip.bind("<Return>", lambda _event: self.add_single_ip())
        ctk.CTkButton(single_row, text="Add", width=72, height=28, command=self.add_single_ip).grid(row=0, column=2)

        ctk.CTkLabel(content, text="Paste IPs").grid(row=2, column=0, sticky="w", padx=10, pady=(0, 2))
        self.ip_list = ctk.CTkTextbox(content, height=52)
        self.ip_list.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 5))

        add_row = ctk.CTkFrame(content, fg_color="transparent")
        add_row.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 7))
        add_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(add_row, text="Add Pasted", height=28, command=self.add_pasted_ips).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(add_row, text="Import CSV", height=28, command=self.import_targets).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        group_panel = ctk.CTkFrame(content, corner_radius=8, border_width=1)
        group_panel.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 7))
        group_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(group_panel, text="Saved Target Groups", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(5, 1))
        ctk.CTkLabel(group_panel, text="Group", width=72, anchor="w").grid(row=1, column=0, sticky="w", padx=(8, 4), pady=1)
        self.group_select = ctk.CTkComboBox(group_panel, values=["Session targets"], state="readonly", height=28)
        self.group_select.set("Session targets")
        self.group_select.grid(row=1, column=1, sticky="ew", padx=(4, 8), pady=1)

        ctk.CTkLabel(group_panel, text="Profile", width=72, anchor="w").grid(row=2, column=0, sticky="w", padx=(8, 4), pady=1)
        self.group_profile = ctk.CTkComboBox(group_panel, values=[USE_SELECTED_PROFILE], state="readonly", height=28)
        self.group_profile.set(USE_SELECTED_PROFILE)
        self.group_profile.grid(row=2, column=1, sticky="ew", padx=(4, 8), pady=1)

        group_buttons = ctk.CTkFrame(group_panel, fg_color="transparent")
        group_buttons.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=(3, 5))
        group_buttons.grid_columnconfigure((0, 1), weight=1)
        group_buttons.grid_columnconfigure(2, weight=2)
        ctk.CTkButton(group_buttons, text="Load", height=28, command=self.load_selected_group).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ctk.CTkButton(group_buttons, text="Save", height=28, command=self.save_current_group).grid(row=0, column=1, sticky="ew", padx=5)
        self.group_name = ctk.CTkEntry(group_buttons, placeholder_text="Group name", height=28)
        self.group_name.grid(row=0, column=2, sticky="ew", padx=(5, 0))

        scan_panel = ctk.CTkFrame(content, corner_radius=8, border_width=1)
        scan_panel.grid(row=6, column=0, sticky="ew", padx=10, pady=(0, 3))
        scan_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(scan_panel, text="2. Connection", font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=(6, 2))
        ctk.CTkLabel(scan_panel, text="Mode").grid(row=1, column=0, sticky="w", padx=8, pady=2)
        self.scan_mode = ctk.CTkComboBox(
            scan_panel,
            values=["Sample outputs", "Live SSH"],
            state="readonly",
            command=self.refresh_preflight,
            height=28,
        )
        self.scan_mode.set("Sample outputs")
        self.scan_mode.grid(row=1, column=1, columnspan=2, sticky="ew", padx=8, pady=2)
        ctk.CTkLabel(scan_panel, text="Username").grid(row=2, column=0, sticky="w", padx=8, pady=2)
        self.ssh_username = ctk.CTkEntry(scan_panel, placeholder_text="TACACS or local username", height=28)
        self.ssh_username.grid(row=2, column=1, columnspan=2, sticky="ew", padx=8, pady=2)
        ctk.CTkLabel(scan_panel, text="Password").grid(row=3, column=0, sticky="w", padx=8, pady=2)
        self.ssh_password = ctk.CTkEntry(scan_panel, show="*", height=28)
        self.ssh_password.grid(row=3, column=1, sticky="ew", padx=(8, 4), pady=2)
        self.password_toggle = ctk.CTkButton(
            scan_panel,
            text="Show",
            width=52,
            height=28,
            command=lambda: self._toggle_secret_visibility(self.ssh_password, self.password_toggle),
        )
        self.password_toggle.grid(row=3, column=2, sticky="e", padx=(0, 8), pady=2)
        ctk.CTkLabel(scan_panel, text="Enable Secret").grid(row=4, column=0, sticky="w", padx=8, pady=2)
        self.enable_secret = ctk.CTkEntry(scan_panel, show="*", height=28)
        self.enable_secret.grid(row=4, column=1, sticky="ew", padx=(8, 4), pady=2)
        self.secret_toggle = ctk.CTkButton(
            scan_panel,
            text="Show",
            width=52,
            height=28,
            command=lambda: self._toggle_secret_visibility(self.enable_secret, self.secret_toggle),
        )
        self.secret_toggle.grid(row=4, column=2, sticky="e", padx=(0, 8), pady=2)
        ctk.CTkLabel(scan_panel, text="Timeout").grid(row=5, column=0, sticky="w", padx=8, pady=(2, 6))
        self.ssh_timeout = ctk.CTkEntry(scan_panel, height=28)
        self.ssh_timeout.insert(0, "30")
        self.ssh_timeout.grid(row=5, column=1, columnspan=2, sticky="ew", padx=8, pady=(2, 6))
        ctk.CTkLabel(scan_panel, text="Concurrency").grid(row=6, column=0, sticky="w", padx=8, pady=2)
        self.scan_concurrency = ctk.CTkEntry(scan_panel, height=28)
        self.scan_concurrency.insert(0, "5")
        self.scan_concurrency.grid(row=6, column=1, columnspan=2, sticky="ew", padx=8, pady=2)
        ctk.CTkLabel(scan_panel, text="Command timeout").grid(row=7, column=0, sticky="w", padx=8, pady=(2, 6))
        self.command_timeout = ctk.CTkEntry(scan_panel, height=28)
        self.command_timeout.insert(0, "30")
        self.command_timeout.grid(row=7, column=1, columnspan=2, sticky="ew", padx=8, pady=(2, 6))
        for entry in (
            self.ssh_username,
            self.ssh_password,
            self.enable_secret,
            self.ssh_timeout,
            self.scan_concurrency,
            self.command_timeout,
        ):
            self._bind_preflight_refresh(entry)

        preset_row = ctk.CTkFrame(scan_panel, fg_color="transparent")
        preset_row.grid(row=8, column=0, columnspan=3, sticky="ew", padx=8, pady=(4, 7))
        preset_row.grid_columnconfigure(0, weight=1)
        self.preset_select = ctk.CTkComboBox(
            preset_row, values=[], state="normal", height=28
        )
        self.preset_select.set("")
        self.preset_select.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ctk.CTkButton(preset_row, text="Save Preset", width=88, height=28, command=self._save_preset).grid(row=0, column=1, padx=3)
        ctk.CTkButton(preset_row, text="Load", width=58, height=28, command=self._load_preset).grid(row=0, column=2, padx=3)
        ctk.CTkButton(preset_row, text="Delete", width=62, height=28, command=self._delete_preset).grid(row=0, column=3, padx=(3, 0))

        self.status = ctk.CTkLabel(content, text="No targets loaded.", anchor="w", height=18, text_color=TEXT_MUTED)
        self.status.grid(row=7, column=0, sticky="ew", padx=10, pady=(0, 0))

    def _build_table_panel(self) -> None:
        panel = Panel(self, "Audit Run")
        panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)

        workspace = ctk.CTkFrame(panel, fg_color="transparent")
        workspace.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        workspace.grid_columnconfigure(0, weight=3, uniform="audit_run")
        workspace.grid_columnconfigure(1, weight=2, uniform="audit_run")
        workspace.grid_rowconfigure(0, weight=1)

        ip_column = ctk.CTkFrame(workspace, fg_color="transparent")
        ip_column.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ip_column.grid_columnconfigure(0, weight=1)
        ip_column.grid_rowconfigure(1, weight=1)

        run_column = ctk.CTkFrame(workspace, fg_color="transparent")
        run_column.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        run_column.grid_columnconfigure(0, weight=1)

        toolbar = ctk.CTkFrame(ip_column, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        toolbar.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkButton(toolbar, text="Use All", command=self.check_all).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(toolbar, text="Use None", command=self.uncheck_all).grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(toolbar, text="Remove", command=self.remove_selected).grid(row=0, column=2, sticky="ew", padx=4)
        ctk.CTkButton(toolbar, text="Clear", command=self.clear_targets).grid(row=0, column=3, sticky="ew", padx=(4, 0))

        self.table = ctk.CTkScrollableFrame(ip_column)
        self.table.grid(row=1, column=0, sticky="nsew")
        self.table.grid_columnconfigure(1, weight=1)

        self._build_run_options_panel(run_column, row=0)
        self._build_preflight_panel(run_column, row=1)

        run_row = ctk.CTkFrame(run_column, fg_color="transparent")
        run_row.grid(row=2, column=0, sticky="ew", pady=(4, 12))
        run_row.grid_columnconfigure((0, 1), weight=1)
        self.audit_run_button = ctk.CTkButton(
            run_row,
            text="Run Checked Audit",
            command=self._run_checklist_audit,
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
        )
        self.audit_run_button.grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(0, 8),
        )
        self.run_buttons = [
            ctk.CTkButton(
                run_row,
                text="Scan Checked",
                command=lambda: self.app_controller.run_target_scope("checked"),
            ),
            ctk.CTkButton(
                run_row,
                text="Scan All",
                command=lambda: self.app_controller.run_target_scope("all"),
            ),
        ]
        self.run_buttons[0].grid(
            row=1,
            column=0,
            sticky="ew",
            padx=(0, 6),
        )
        self.run_buttons[1].grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(6, 0),
        )
        self.cancel_scan_button = ctk.CTkButton(
            run_row,
            text="Cancel Scan",
            command=self.app_controller.cancel_scan,
            state="disabled",
            fg_color="#b42318",
            hover_color="#912018",
        )
        self.cancel_scan_button.grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 0),
        )

        progress_row = ctk.CTkFrame(run_column, fg_color="transparent")
        progress_row.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        progress_row.grid_columnconfigure(0, weight=1)
        self.scan_progress = ctk.CTkProgressBar(progress_row)
        self.scan_progress.set(0)
        self.scan_progress.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(0, 10),
        )
        self.scan_progress_label = ctk.CTkLabel(
            progress_row,
            text="Idle",
            width=120,
            anchor="e",
            text_color=("#475467", "#d0d5dd"),
        )
        self.scan_progress_label.grid(row=0, column=1, sticky="e")

        self.audit_status = ctk.CTkLabel(
            run_column,
            text="Setup details live on the Setup tab. Confirm readiness here before you run.",
            anchor="w",
            text_color=TEXT_MUTED,
            wraplength=720,
            justify="left",
        )
        self.audit_status.grid(row=4, column=0, sticky="ew", pady=(0, 12))

        self._render_rows()

    def _build_run_options_panel(self, panel: ctk.CTkBaseClass, *, row: int) -> None:
        options_panel = ctk.CTkFrame(
            panel,
            corner_radius=8,
            border_width=1,
            fg_color=(PANEL_LIGHT, PANEL_DARK),
            border_color=(BORDER_LIGHT, BORDER_DARK),
        )
        options_panel.grid(row=row, column=0, sticky="ew", padx=12, pady=(0, 8))
        options_panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            options_panel,
            text="Run Options",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 4))

        ctk.CTkLabel(options_panel, text="Scan").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        family_row = ctk.CTkFrame(options_panel, fg_color="transparent")
        family_row.grid(row=1, column=1, sticky="w", padx=10, pady=4)
        self.audit_l2 = ctk.CTkCheckBox(family_row, text="L2", command=self._run_options_changed)
        self.audit_l2.select()
        self.audit_l2.grid(row=0, column=0, sticky="w", padx=(0, 18))
        self.audit_ndm = ctk.CTkCheckBox(family_row, text="NDM", command=self._run_options_changed)
        self.audit_ndm.grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(options_panel, text="Output").grid(row=2, column=0, sticky="w", padx=10, pady=4)
        output_row = ctk.CTkFrame(options_panel, fg_color="transparent")
        output_row.grid(row=2, column=1, sticky="w", padx=10, pady=4)
        self.audit_write_ckl = ctk.CTkCheckBox(output_row, text="Fill CKL", command=self._run_options_changed)
        self.audit_write_ckl.select()
        self.audit_write_ckl.grid(row=0, column=0, sticky="w", padx=(0, 18))
        self.audit_write_text = ctk.CTkCheckBox(output_row, text="Text report", command=self._run_options_changed)
        self.audit_write_text.select()
        self.audit_write_text.grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(options_panel, text="CKL comments").grid(row=3, column=0, sticky="w", padx=10, pady=(4, 10))
        self.audit_comment_mode = ctk.CTkComboBox(
            options_panel,
            values=["Append generated comments", "Replace comments"],
            state="readonly",
            command=self._run_options_changed,
        )
        self.audit_comment_mode.set("Append generated comments")
        self.audit_comment_mode.grid(row=3, column=1, sticky="ew", padx=10, pady=(4, 10))

        self.audit_option_checkboxes = [
            self.audit_l2,
            self.audit_ndm,
            self.audit_write_ckl,
            self.audit_write_text,
        ]

    def _build_preflight_panel(self, panel: ctk.CTkBaseClass, *, row: int) -> None:
        preflight = ctk.CTkFrame(panel, fg_color="transparent")
        preflight.grid(
            row=row,
            column=0,
            columnspan=3,
            sticky="ew",
            padx=10,
            pady=(8, 2),
        )
        preflight.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(preflight, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Readiness Checklist",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        self.preflight_summary = ctk.CTkLabel(
            header,
            text="Checking setup",
            anchor="e",
            width=170,
            text_color=TEXT_MUTED,
        )
        self.preflight_summary.grid(row=0, column=1, sticky="e")

        for index, (key, label) in enumerate(PREFLIGHT_ITEMS, start=1):
            item = ctk.CTkFrame(preflight, fg_color="transparent")
            item.grid(row=index, column=0, sticky="ew", pady=1)
            item.grid_columnconfigure(2, weight=1)

            badge = ctk.CTkLabel(
                item,
                text="WAIT",
                width=54,
                anchor="w",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=PREFLIGHT_COLORS["info"],
            )
            badge.grid(row=0, column=0, sticky="w", padx=(0, 8))
            ctk.CTkLabel(
                item,
                text=label,
                width=100,
                anchor="w",
            ).grid(row=0, column=1, sticky="w", padx=(0, 8))
            detail = ctk.CTkLabel(
                item,
                text="Waiting for setup",
                anchor="w",
                text_color=TEXT_MUTED,
                wraplength=500,
                justify="left",
            )
            detail.grid(row=0, column=2, sticky="ew")

            self.preflight_badges[key] = badge
            self.preflight_details[key] = detail

    def refresh_preflight(
        self,
        *_unused: object,
        checks_loaded: int | None = None,
        checks_by_family: dict[str, int] | None = None,
        license_valid: bool | None = None,
        license_summary: str | None = None,
    ) -> None:
        if checks_loaded is not None:
            self.preflight_checks_loaded = checks_loaded
        if checks_by_family is not None:
            self.preflight_checks_by_family = dict(checks_by_family)
        if license_valid is not None:
            self.preflight_license_valid = license_valid
        if license_summary is not None:
            self.preflight_license_summary = license_summary
        if not hasattr(self, "preflight_summary") or not self.preflight_badges:
            return

        self._sync_row_state()
        self._sync_audit_run_options()
        families = set(self.audit_families)
        ckl_paths = self._audit_entry_paths()
        output_dir = self._audit_output_path()
        checked_count = sum(1 for target in self.targets if target.checked)
        selected_outputs = self._selected_outputs()

        row_states: dict[str, str] = {}

        license_state = "ok" if self.preflight_license_valid else "block"
        license_detail = self.preflight_license_summary
        if not self.preflight_license_valid:
            license_detail = f"{license_detail}; checklist output needs a valid license"
        self._set_preflight_row("license", license_state, license_detail)
        row_states["license"] = license_state

        target_state = "ok" if checked_count else "block"
        target_detail = (
            f"{checked_count} of {len(self.targets)} target(s) checked"
            if self.targets
            else "Add at least one switch IP"
        )
        self._set_preflight_row("targets", target_state, target_detail)
        row_states["targets"] = target_state

        profile_state = "ok" if self.active_profile_name else "block"
        profile_detail = self.active_profile_name or "Select a site profile"
        if self.active_profile_path is not None:
            profile_detail = f"{profile_detail} ({self.active_profile_path.name})"
        self._set_preflight_row("profile", profile_state, profile_detail)
        row_states["profile"] = profile_state

        mode = self.scan_mode.get()
        mode_state = "ok" if mode == "Live SSH" else "block"
        mode_detail = (
            "Live SSH selected"
            if mode == "Live SSH"
            else "Select Live SSH before creating CKL output"
        )
        self._set_preflight_row("mode", mode_state, mode_detail)
        row_states["mode"] = mode_state

        username = self.ssh_username.get().strip()
        password = self.ssh_password.get()
        if mode == "Live SSH":
            credential_state = "ok" if username and password else "block"
            credential_detail = (
                "Username and password entered"
                if credential_state == "ok"
                else "Enter SSH username and password"
            )
        else:
            credential_state = "info"
            credential_detail = "Needed after Live SSH is selected"
        self._set_preflight_row(
            "credentials",
            credential_state,
            credential_detail,
        )
        row_states["credentials"] = credential_state

        family_state = "ok" if families else "block"
        family_detail = self._family_label(families) if families else "Select L2, NDM, or both"
        self._set_preflight_row("families", family_state, family_detail)
        row_states["families"] = family_state

        output_state = "ok" if selected_outputs else "block"
        output_detail = " and ".join(selected_outputs) if selected_outputs else "Select Fill CKL, Text report, or both"
        self._set_preflight_row("outputs", output_state, output_detail)
        row_states["outputs"] = output_state

        template_state, template_detail = self._preflight_template_status(
            families,
            ckl_paths,
        )
        if not self.audit_create_ckl:
            template_state = "info"
            template_detail = "Skipped because Fill CKL is off"
        self._set_preflight_row("templates", template_state, template_detail)
        row_states["templates"] = template_state

        destination_state = "ok" if output_dir else "block"
        destination_detail = str(output_dir) if output_dir else "Select where completed files will be saved"
        self._set_preflight_row(
            "destination",
            destination_state,
            destination_detail,
        )
        row_states["destination"] = destination_state

        checks_state, checks_detail = self._preflight_checks_status(families)
        self._set_preflight_row("checks", checks_state, checks_detail)
        row_states["checks"] = checks_state

        blocking_count = sum(1 for state in row_states.values() if state == "block")
        warning_count = sum(1 for state in row_states.values() if state == "warn")
        if blocking_count:
            summary = f"{blocking_count} item(s) need attention"
            summary_color = PREFLIGHT_COLORS["block"]
        elif warning_count:
            summary = f"{warning_count} warning(s)"
            summary_color = PREFLIGHT_COLORS["warn"]
        else:
            summary = "Ready to run"
            summary_color = PREFLIGHT_COLORS["ok"]
        self.preflight_summary.configure(text=summary, text_color=summary_color)

    def _bind_preflight_refresh(self, entry: ctk.CTkEntry) -> None:
        entry.bind("<KeyRelease>", lambda _event: self.after_idle(self.refresh_preflight))
        entry.bind("<FocusOut>", lambda _event: self.after_idle(self.refresh_preflight))

    def _audit_entry_paths(self) -> dict[str, Path | None]:
        return dict(self.selected_ckl_paths)

    def _audit_output_path(self) -> Path | None:
        return self.selected_output_dir

    def _selected_outputs(self) -> list[str]:
        outputs: list[str] = []
        if self.audit_create_ckl:
            outputs.append("Fill CKL")
        if self.audit_create_text:
            outputs.append("Text report")
        return outputs

    def _preflight_template_status(
        self,
        families: set[str],
        ckl_paths: dict[str, Path | None],
    ) -> tuple[str, str]:
        if not families:
            return "block", "Select a family first"
        if families == {"IOSXE_L2", "IOSXE_NDM"}:
            combined = ckl_paths["COMBINED"]
            l2 = ckl_paths["IOSXE_L2"]
            ndm = ckl_paths["IOSXE_NDM"]
            if combined is not None and combined.is_file():
                return "ok", f"Combined template: {combined.name}"
            if l2 is not None and l2.is_file() and ndm is not None and ndm.is_file():
                return "ok", "Separate L2 and NDM templates selected"
            if combined is not None or l2 is not None or ndm is not None:
                return "block", "Use one combined template or both separate templates"
            return "block", "Select a combined template or both separate templates"
        if "IOSXE_L2" in families:
            return self._single_template_status(ckl_paths["IOSXE_L2"], "L2")
        return self._single_template_status(ckl_paths["IOSXE_NDM"], "NDM")

    @staticmethod
    def _single_template_status(path: Path | None, label: str) -> tuple[str, str]:
        if path is None:
            return "block", f"Select the {label} CKL template"
        if not path.is_file():
            return "block", f"{label} template file was not found"
        return "ok", f"{label} template: {path.name}"

    def _preflight_checks_status(self, families: set[str]) -> tuple[str, str]:
        if not families:
            return "block", "Select a family first"
        missing = [
            self._short_family_name(family)
            for family in sorted(families)
            if self.preflight_checks_by_family.get(family, 0) == 0
        ]
        if missing:
            return "block", f"No {'/'.join(missing)} checks loaded"
        selected_count = sum(
            self.preflight_checks_by_family.get(family, 0)
            for family in families
        )
        return "ok", f"{selected_count} selected-family check(s) loaded"

    def _set_preflight_row(self, key: str, state: str, detail: str) -> None:
        badge_text = {
            "ok": "OK",
            "warn": "WARN",
            "block": "FIX",
            "info": "WAIT",
        }[state]
        color = PREFLIGHT_COLORS[state]
        self.preflight_badges[key].configure(text=badge_text, text_color=color)
        self.preflight_details[key].configure(text=detail)

    @staticmethod
    def _short_family_name(family: str) -> str:
        if family == "IOSXE_L2":
            return "L2"
        if family == "IOSXE_NDM":
            return "NDM"
        return family

    def _family_label(self, families: set[str]) -> str:
        if families == {"IOSXE_L2", "IOSXE_NDM"}:
            return "L2 + NDM"
        if families == {"IOSXE_NDM"}:
            return "NDM"
        if families == {"IOSXE_L2"}:
            return "L2"
        return "Select L2 and/or NDM"

    def _run_options_changed(self, *_unused: object) -> None:
        self._sync_audit_run_options()
        self.refresh_preflight()

    def _sync_audit_run_options(self) -> None:
        if not hasattr(self, "audit_l2"):
            return
        families: set[str] = set()
        if self.audit_l2.get():
            families.add("IOSXE_L2")
        if self.audit_ndm.get():
            families.add("IOSXE_NDM")
        self.audit_families = families
        self.audit_create_ckl = bool(self.audit_write_ckl.get())
        self.audit_create_text = bool(self.audit_write_text.get())
        self.audit_append_comments = (
            self.audit_comment_mode.get() == "Append generated comments"
        )
        if hasattr(self, "audit_run_button"):
            self.audit_run_button.configure(
                text=f"Run Checked Audit - {self._family_label(self.audit_families)}"
            )

    @staticmethod
    def _set_checkbox_value(control: ctk.CTkCheckBox, selected: bool) -> None:
        if selected:
            control.select()
        else:
            control.deselect()

    def get_audit_run_settings(self) -> dict[str, object]:
        self._sync_audit_run_options()
        return {
            "families": set(self.audit_families),
            "create_ckl": self.audit_create_ckl,
            "create_text": self.audit_create_text,
            "append_comments": self.audit_append_comments,
        }

    def refresh_groups(self, group_names: list[str], profile_names: list[str] | None = None) -> None:
        group_values = ["Session targets", *group_names]
        self.group_select.configure(values=group_values)
        if self.group_select.get() not in group_values:
            self.group_select.set("Session targets")

        if profile_names is not None:
            self.profile_values = [USE_DEFAULT_PROFILE, *profile_names]
            group_profile_values = [USE_SELECTED_PROFILE, *profile_names]
            current_group_profile = self.group_profile.get()
            self.group_profile.configure(values=group_profile_values)
            if current_group_profile not in group_profile_values:
                self.group_profile.set(USE_SELECTED_PROFILE)
            self._refresh_row_profile_values()
        self.refresh_preflight()

    def set_active_profile(self, profile_name: str, profile_path: Path | None = None) -> None:
        self.active_profile_name = profile_name
        self.active_profile_path = profile_path
        self.refresh_preflight()

    def set_targets(
        self,
        targets: list[DeviceTargetRecord],
        group_name: str | None = None,
        group_profile: str | None = None,
    ) -> None:
        self.targets = [target.copy() for target in targets]
        self.selected_index = 0 if self.targets else None
        if group_name:
            self.group_select.set(group_name)
            self.group_name.delete(0, "end")
            self.group_name.insert(0, group_name)
        self.group_profile.set(group_profile or USE_SELECTED_PROFILE)
        self._render_rows(sync=False)
        self._set_status(f"Loaded {len(self.targets)} target(s).")

    def get_targets(self, scope: str = "all") -> list[DeviceTargetRecord]:
        self._sync_row_state()
        if scope == "selected":
            if self.selected_index is None or self.selected_index >= len(self.targets):
                return []
            return [self.targets[self.selected_index]]
        if scope == "checked":
            return [target for target in self.targets if target.checked]
        return list(self.targets)

    def get_scan_settings(self) -> dict[str, object]:
        timeout_text = self.ssh_timeout.get().strip()
        timeout = int(timeout_text) if timeout_text.isdigit() else 30
        concurrency_text = self.scan_concurrency.get().strip()
        concurrency = int(concurrency_text) if concurrency_text.isdigit() else 5
        command_timeout_text = self.command_timeout.get().strip()
        command_timeout = int(command_timeout_text) if command_timeout_text.isdigit() else 30
        return {
            "mode": self.scan_mode.get(),
            "username": self.ssh_username.get().strip(),
            "password": self.ssh_password.get(),
            "secret": self.enable_secret.get() or None,
            "timeout": timeout,
            "concurrency": max(1, min(20, concurrency)),
            "command_timeout": max(1, min(3600, command_timeout)),
        }

    def clear_session_credentials(self) -> None:
        """Discard password and enable-secret values after a scan finishes."""
        self.ssh_password.delete(0, "end")
        self.enable_secret.delete(0, "end")
        self.refresh_preflight()

    def refresh_presets(self, names: list[str]) -> None:
        self.preset_select.configure(values=names)
        if self.preset_select.get() not in names:
            self.preset_select.set(names[0] if names else "")

    def apply_scan_preset(self, preset: object) -> None:
        def replace(entry: ctk.CTkEntry, value: object) -> None:
            entry.delete(0, "end")
            entry.insert(0, str(value))

        replace(self.scan_concurrency, getattr(preset, "concurrency", 5))
        replace(self.ssh_timeout, getattr(preset, "connect_timeout", 30))
        replace(self.command_timeout, getattr(preset, "command_timeout", 30))
        families = set(getattr(preset, "stig_families", []))
        self.set_audit_settings(
            ckl_paths=self.selected_ckl_paths,
            output_dir=self.selected_output_dir,
            families=families,
            create_ckl=bool(getattr(getattr(preset, "report_options", None), "ckl", False)),
            create_text=bool(getattr(getattr(preset, "report_options", None), "text", True)),
        )
        self.refresh_preflight()

    def _save_preset(self) -> None:
        name = self.preset_select.get().strip()
        if not name:
            self._set_status("Enter a preset name first.")
            return
        self.app_controller.save_scan_preset(name)

    def _load_preset(self) -> None:
        name = self.preset_select.get().strip()
        if name:
            self.app_controller.load_scan_preset(name)

    def _delete_preset(self) -> None:
        name = self.preset_select.get().strip()
        if not name:
            return
        if confirm_action(
            self, title="Delete Scan Preset",
            message=f"Delete scan preset {name}? Credentials are not part of presets.",
            confirm_text="Delete",
        ):
            self.app_controller.delete_scan_preset(name)

    def set_device_status(self, ip: str, status: str, detail: str = "") -> None:
        self.device_statuses[ip] = (status, detail)
        for index, target in enumerate(self.targets):
            if target.ip == ip:
                self._render_rows(sync=True)
                break

    @staticmethod
    def _toggle_secret_visibility(entry: ctk.CTkEntry, button: ctk.CTkButton) -> None:
        visible = entry.cget("show") == ""
        entry.configure(show="*" if visible else "")
        button.configure(text="Show" if visible else "Hide")

    def set_scan_state(
        self,
        *,
        running: bool,
        completed: int = 0,
        total: int = 0,
        message: str | None = None,
    ) -> None:
        state = "disabled" if running else "normal"
        for button in self.run_buttons:
            button.configure(state=state)
        self.audit_run_button.configure(state=state)
        for checkbox in self.audit_option_checkboxes:
            checkbox.configure(state=state)
        if hasattr(self, "audit_comment_mode"):
            self.audit_comment_mode.configure(
                state="disabled" if running else "readonly"
            )
        self.cancel_scan_button.configure(
            state="normal" if running else "disabled"
        )
        progress = completed / total if total else 0
        self.scan_progress.set(max(0.0, min(1.0, progress)))
        if message:
            label = message
        elif running:
            label = f"{completed}/{total} devices"
        elif total:
            label = f"{completed}/{total} complete"
        else:
            label = "Idle"
        self.scan_progress_label.configure(text=label)

    def set_ckl_template_path(self, family_key: str, path: Path) -> None:
        if family_key not in self.selected_ckl_paths:
            return
        self.selected_ckl_paths[family_key] = path
        self.refresh_preflight()

    def set_checklist_output_dir(self, path: Path) -> None:
        self.selected_output_dir = path
        self.refresh_preflight()

    def set_audit_settings(
        self,
        *,
        ckl_paths: dict[str, Path | None],
        output_dir: Path | None,
        families: set[str] | None = None,
        create_ckl: bool | None = None,
        create_text: bool | None = None,
        append_comments: bool | None = None,
    ) -> None:
        self.selected_ckl_paths = dict(ckl_paths)
        self.selected_output_dir = output_dir
        if families is not None:
            self.audit_families = set(families)
            if hasattr(self, "audit_l2"):
                self._set_checkbox_value(self.audit_l2, "IOSXE_L2" in families)
                self._set_checkbox_value(self.audit_ndm, "IOSXE_NDM" in families)
        if create_ckl is not None:
            self.audit_create_ckl = create_ckl
            if hasattr(self, "audit_write_ckl"):
                self._set_checkbox_value(self.audit_write_ckl, create_ckl)
        if create_text is not None:
            self.audit_create_text = create_text
            if hasattr(self, "audit_write_text"):
                self._set_checkbox_value(self.audit_write_text, create_text)
        if append_comments is not None:
            self.audit_append_comments = append_comments
            if hasattr(self, "audit_comment_mode"):
                self.audit_comment_mode.set(
                    "Append generated comments"
                    if append_comments
                    else "Replace comments"
                )
        self._sync_audit_run_options()
        self.refresh_preflight()

    def set_checklist_status(self, message: str) -> None:
        if hasattr(self, "audit_status"):
            self.audit_status.configure(text=message)
            return
        self.preflight_summary.configure(text=message)

    def _run_checklist_audit(self) -> None:
        self.refresh_preflight()
        self.set_checklist_status("Validating audit settings...")
        self.app_controller.run_configured_checklist_audit()

    def add_single_ip(self) -> None:
        text = self.single_ip.get().strip()
        added, skipped = self._add_targets_from_text(text)
        if added:
            self.single_ip.delete(0, "end")
        self._set_add_status(added, skipped)

    def add_pasted_ips(self) -> None:
        text = self.ip_list.get("1.0", "end")
        added, skipped = self._add_targets_from_text(text)
        if added:
            self.ip_list.delete("1.0", "end")
        self._set_add_status(added, skipped)

    def import_targets(self) -> None:
        path = filedialog.askopenfilename(
            title="Import targets",
            initialdir=str(self.app_controller.operator_workspace.device_imports),
            filetypes=[("Target files", "*.csv *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            imported_text = self._read_import_file(Path(path))
            values, invalid = self._extract_ips(imported_text)
            existing = {target.ip for target in self.targets}
            valid: list[str] = []
            duplicates = 0
            seen = set(existing)
            for value in values:
                if value in seen:
                    duplicates += 1
                else:
                    valid.append(value)
                    seen.add(value)
            message = (
                f"{len(values) + invalid} address value(s) detected\n"
                f"{len(valid)} valid new device(s)\n"
                f"{duplicates} duplicate(s)\n{invalid} invalid value(s)\n\n"
                "Only valid, non-duplicate devices will be imported. Bad rows are never silently accepted."
            )
            if not valid:
                self._set_status(message.replace("\n", " · "))
                return
            if not confirm_action(self, title="Review CSV Import", message=message, confirm_text=f"Import {len(valid)} Valid Devices"):
                return
            for value in valid:
                self.targets.append(DeviceTargetRecord(ip=value, checked=True))
            if self.selected_index is None:
                self.selected_index = 0
            self._render_rows()
            self._set_add_status(len(valid), duplicates + invalid)
        except (OSError, UnicodeError, ValueError, csv.Error) as exc:
            self._set_status(f"Import failed: {exc}")

    def save_current_group(self) -> None:
        self._sync_row_state()
        name = self.group_name.get().strip() or self.group_select.get().strip()
        if not name or name == "Session targets":
            name = "session_targets"
        group_profile = self.group_profile.get()
        if group_profile == USE_SELECTED_PROFILE:
            group_profile = None
        self.app_controller.save_device_group(name, self.targets, group_profile)

    def load_selected_group(self) -> None:
        group_name = self.group_select.get()
        if group_name == "Session targets":
            self._set_status("Choose a saved group to load.")
            return
        self.app_controller.load_device_group(group_name)

    def check_all(self) -> None:
        for target in self.targets:
            target.checked = True
        self._render_rows(sync=False)

    def uncheck_all(self) -> None:
        for target in self.targets:
            target.checked = False
        self._render_rows(sync=False)

    def remove_selected(self) -> None:
        if self.selected_index is None or self.selected_index >= len(self.targets):
            self._set_status("Select a target row first.")
            return
        target = self.targets[self.selected_index]
        if not confirm_action(
            self,
            title="Remove Target",
            message=f"Remove {target.ip} from the target list?",
            confirm_text="Remove",
        ):
            return
        removed = self.targets.pop(self.selected_index)
        if not self.targets:
            self.selected_index = None
        else:
            self.selected_index = min(self.selected_index, len(self.targets) - 1)
        self._render_rows()
        self._set_status(f"Removed {removed.ip}.")

    def clear_targets(self) -> None:
        if not self.targets:
            self._set_status("Target list is already empty.")
            return
        if not confirm_action(
            self,
            title="Clear Targets",
            message=f"Remove all {len(self.targets)} targets from the workbench?",
            confirm_text="Clear All",
        ):
            return
        self.targets = []
        self.selected_index = None
        self._render_rows()
        self._set_status("Cleared target list.")

    def _add_targets_from_text(self, text: str) -> tuple[int, int]:
        ips, skipped = self._extract_ips(text)
        existing = {target.ip for target in self.targets}
        added = 0
        for ip in ips:
            if ip in existing:
                skipped += 1
                continue
            self.targets.append(DeviceTargetRecord(ip=ip, checked=True))
            existing.add(ip)
            added += 1
        if added and self.selected_index is None:
            self.selected_index = 0
        self._render_rows()
        return added, skipped

    def _extract_ips(self, text: str) -> tuple[list[str], int]:
        values: list[str] = []
        skipped = 0
        for token in re.split(r"[\s,;]+", text):
            cleaned = token.strip().strip('"\'')
            if not cleaned or cleaned.lower() in {"ip", "address", "hostname"}:
                continue
            try:
                values.append(str(ipaddress.ip_address(cleaned)))
            except ValueError:
                skipped += 1
        return values, skipped

    def _read_import_file(self, path: Path) -> str:
        if path.suffix.lower() not in {".csv", ".txt"}:
            raise ValueError("Choose a CSV or text target file")
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("Target file is missing or exceeds the supported 5 MB limit")
        if path.suffix.lower() == ".csv":
            values: list[str] = []
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle)
                for index, row in enumerate(reader):
                    if index >= 10_000:
                        raise ValueError("CSV contains more than 10,000 rows")
                    values.extend(row)
            return "\n".join(values)
        return path.read_text(encoding="utf-8-sig")

    def _render_rows(self, sync: bool = True) -> None:
        if sync:
            self._sync_row_state()
        for child in self.table.winfo_children():
            child.destroy()
        self.row_checks = {}
        self.row_profiles = {}

        headers = ["Use", "IP Address", "Override", "Status", "Row"]
        for column, header in enumerate(headers):
            ctk.CTkLabel(self.table, text=header, font=ctk.CTkFont(weight="bold")).grid(row=0, column=column, sticky="w", padx=8, pady=(0, 6))

        if not self.targets:
            ctk.CTkLabel(self.table, text="No targets yet. Add or import switches on the left.", text_color=TEXT_MUTED).grid(row=1, column=0, columnspan=5, sticky="ew", padx=8, pady=18)
            self.refresh_preflight()
            return

        for index, target in enumerate(self.targets, start=1):
            actual_index = index - 1
            selected = actual_index == self.selected_index
            row_color = ("#eaf2ff", "#102a43") if selected else "transparent"
            row = ctk.CTkFrame(self.table, fg_color=row_color, corner_radius=6)
            row.grid(row=index, column=0, columnspan=5, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            check = ctk.CTkCheckBox(
                row,
                text="",
                width=28,
                command=self.refresh_preflight,
            )
            if target.checked:
                check.select()
            else:
                check.deselect()
            check.grid(row=0, column=0, padx=(8, 4), pady=6)
            self.row_checks[actual_index] = check

            ip_button = ctk.CTkButton(row, text=target.ip, anchor="w", fg_color="transparent", text_color=("#101828", "#f2f4f7"), hover_color=("#d0e2ff", "#1f2937"), command=lambda i=actual_index: self._select_row(i))
            ip_button.grid(row=0, column=1, sticky="ew", padx=4, pady=6)

            combo = ctk.CTkComboBox(row, values=self.profile_values, width=150)
            combo.set(target.profile_override or USE_DEFAULT_PROFILE)
            combo.grid(row=0, column=2, sticky="ew", padx=4, pady=6)
            self.row_profiles[actual_index] = combo

            state, detail = self.device_statuses.get(target.ip, ("QUEUED", ""))
            status_label = ctk.CTkLabel(
                row, text=state.replace("_", " ").title(), width=105,
                anchor="w", text_color=TEXT_MUTED,
            )
            status_label.grid(row=0, column=3, padx=4, pady=6)
            if detail:
                status_label.bind("<Enter>", lambda _event, text=detail: self._set_status(text))

            remove_button = ctk.CTkButton(row, text="Remove", width=78, command=lambda i=actual_index: self._remove_row(i))
            remove_button.grid(row=0, column=4, padx=(4, 8), pady=6)
        self.refresh_preflight()

    def _refresh_row_profile_values(self) -> None:
        for combo in self.row_profiles.values():
            current = combo.get()
            combo.configure(values=self.profile_values)
            if current not in self.profile_values:
                combo.set(USE_DEFAULT_PROFILE)

    def _select_row(self, index: int) -> None:
        self._sync_row_state()
        self.selected_index = index
        self._render_rows()
        self._set_status(f"Selected {self.targets[index].ip}.")

    def _remove_row(self, index: int) -> None:
        self._sync_row_state()
        removed = self.targets.pop(index)
        if not self.targets:
            self.selected_index = None
        else:
            self.selected_index = min(index, len(self.targets) - 1)
        self._render_rows()
        self._set_status(f"Removed {removed.ip}.")

    def _sync_row_state(self) -> None:
        for index, target in enumerate(self.targets):
            check = self.row_checks.get(index)
            if check is not None:
                target.checked = bool(check.get())
            combo = self.row_profiles.get(index)
            if combo is not None:
                value = combo.get()
                target.profile_override = None if value == USE_DEFAULT_PROFILE else value

    def _set_add_status(self, added: int, skipped: int) -> None:
        self._set_status(f"Added {added} target(s), skipped {skipped}.")

    def _set_status(self, message: str) -> None:
        self.status.configure(text=message)
        self.app_controller.set_status(message)

