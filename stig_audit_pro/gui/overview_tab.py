"""Overview dashboard for the desktop GUI."""

from __future__ import annotations

import tkinter as tk
from collections import Counter
from tkinter import ttk
from typing import Any

import customtkinter as ctk

from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import (
    DANGER,
    DANGER_HOVER,
    Metric,
    PageFrame,
    Panel,
    PRIMARY,
    STATUS_COLORS,
    SUCCESS,
    WARNING,
)


class OverviewTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.open_results: list[CheckResult] = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.welcome = Panel(self, "Welcome to STIG Audit Pro")
        self.welcome.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        self.welcome.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkLabel(
            self.welcome,
            text="Cisco IOS-XE STIG Assessment\nChoose a task to get started.",
            justify="left",
            anchor="w",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=1, column=0, columnspan=4, sticky="ew", padx=12, pady=(10, 8))
        actions = (
            ("Run an Audit", "__wizard__"),
            ("Import a DISA STIG", "STIG Update Center"),
            ("Review Previous Audits", "History"),
            ("Manage STIG Automation", "Checks"),
        )
        for column, (label, tab) in enumerate(actions):
            action = app_controller.open_audit_wizard if tab == "__wizard__" else lambda name=tab: app_controller.show_tab(name)
            ctk.CTkButton(self.welcome, text=label, command=action).grid(
                row=2, column=column, sticky="ew", padx=6, pady=4
            )
        ctk.CTkLabel(
            self.welcome,
            text="Getting started:  1. Add switches   2. Import or select a STIG   3. Review your Site Profile   4. Run the assessment",
            anchor="w",
            justify="left",
        ).grid(row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(6, 10))
        self.hide_welcome = ctk.CTkCheckBox(
            self.welcome, text="Don't show this welcome page again",
            command=lambda: app_controller.set_welcome_preference(not bool(self.hide_welcome.get())),
        )
        self.hide_welcome.grid(row=3, column=3, sticky="e", padx=12, pady=(6, 10))

        metrics = ctk.CTkFrame(self, fg_color="transparent")
        metrics.grid(row=1, column=0, sticky="ew", padx=12, pady=6)
        metrics.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.metrics = {
            "checks": Metric(metrics, "Checks", accent=PRIMARY),
            "automated": Metric(metrics, "Automated", accent=SUCCESS),
            "tailoring": Metric(metrics, "String Slots", accent=WARNING),
            "l2": Metric(metrics, "L2", accent=PRIMARY),
            "ndm": Metric(metrics, "NDM", accent=PRIMARY),
            "profile": Metric(metrics, "Profile", "-", accent=SUCCESS),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=12, pady=(6, 12))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        run_panel = Panel(body, "Assessment Workspace")
        run_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        run_panel.grid_columnconfigure((0, 1, 2), weight=1)
        run_panel.grid_rowconfigure(3, weight=1)

        ctk.CTkButton(
            run_panel,
            text="Start an Assessment",
            command=app_controller.open_audit_wizard,
        ).grid(row=1, column=0, sticky="ew", padx=(12, 6), pady=(10, 8))
        ctk.CTkButton(
            run_panel,
            text="Run Compliant Demo",
            command=lambda: app_controller.run_sample_audit("compliant"),
            fg_color=SUCCESS,
            hover_color="#0f6b30",
        ).grid(row=1, column=1, sticky="ew", padx=6, pady=(10, 8))
        ctk.CTkButton(
            run_panel,
            text="Run Noncompliant Demo",
            command=lambda: app_controller.run_sample_audit("noncompliant"),
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
        ).grid(row=1, column=2, sticky="ew", padx=(6, 12), pady=(10, 8))

        quick_row = ctk.CTkFrame(run_panel, fg_color="transparent")
        quick_row.grid(row=2, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 10))
        quick_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(quick_row, text="Checks", command=lambda: app_controller.show_tab("Checks")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(quick_row, text="STIG Updates", command=lambda: app_controller.show_tab("STIG Update Center")).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(quick_row, text="Reports", command=lambda: app_controller.show_tab("Reports")).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        results_frame = ctk.CTkFrame(run_panel, fg_color="transparent")
        results_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=12, pady=(0, 12))
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(2, weight=1)

        self.run_summary = ctk.CTkTextbox(results_frame, wrap="word", height=132)
        self.run_summary.grid(row=0, column=0, sticky="ew")
        self._set_run_summary("No scan results loaded.")

        ctk.CTkLabel(
            results_frame,
            text="Open Findings — select a row to view details",
            anchor="w",
            font=ctk.CTkFont(weight="bold"),
        ).grid(row=1, column=0, sticky="ew", pady=(10, 4))

        findings_frame = ctk.CTkFrame(results_frame, corner_radius=6, border_width=1)
        findings_frame.grid(row=2, column=0, sticky="nsew")
        findings_frame.grid_columnconfigure(0, weight=1)
        findings_frame.grid_rowconfigure(0, weight=1)
        self.open_tree = ttk.Treeview(
            findings_frame,
            columns=("ip", "vuln", "title"),
            show="headings",
            selectmode="browse",
            height=7,
        )
        self.open_tree.heading("ip", text="IP")
        self.open_tree.heading("vuln", text="Vuln ID")
        self.open_tree.heading("title", text="Finding")
        self.open_tree.column("ip", width=110, anchor="w", stretch=False)
        self.open_tree.column("vuln", width=100, anchor="w", stretch=False)
        self.open_tree.column("title", width=360, anchor="w")
        self.open_tree.tag_configure(
            "Open",
            background=STATUS_COLORS["Open"][0],
            foreground=STATUS_COLORS["Open"][1],
        )
        self.open_tree.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        scrollbar = ttk.Scrollbar(findings_frame, orient="vertical", command=self.open_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=8)
        self.open_tree.configure(yscrollcommand=scrollbar.set)
        self.open_tree.bind("<<TreeviewSelect>>", self._open_finding_selected)

        ops_panel = Panel(body, "Library Status")
        ops_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ops_panel.grid_columnconfigure(0, weight=1)
        ops_panel.grid_rowconfigure(1, weight=1)
        self.library_status = ctk.CTkTextbox(ops_panel, wrap="word", height=320)
        self.library_status.grid(row=1, column=0, sticky="nsew", padx=12, pady=(10, 12))
        self._set_library_status("Loading check libraries.")

    def refresh_inventory(self, checks: list[CheckDefinition], profile: SiteProfile | None) -> None:
        family_counts = Counter(check.stig_family for check in checks)
        automated = sum(1 for check in checks if check.automated and check.check_type != "manual_review")
        string_slots = sum(self._blank_string_slots(check.conditions) for check in checks)
        self.metrics["checks"].set(len(checks))
        self.metrics["automated"].set(automated)
        self.metrics["tailoring"].set(string_slots)
        self.metrics["l2"].set(family_counts.get("IOSXE_L2", 0))
        self.metrics["ndm"].set(family_counts.get("IOSXE_NDM", 0))
        self.metrics["profile"].set(profile.profile_name if profile else "-")

        lines = [
            f"Loaded checks: {len(checks)}",
            f"Automated checks: {automated}",
            f"Manual or placeholder checks: {len(checks) - automated}",
            f"Editable blank string slots: {string_slots}",
            f"Active profile: {profile.profile_name if profile else '-'}",
            "",
            "Families:",
        ]
        for family, count in sorted(family_counts.items()):
            lines.append(f"- {family}: {count}")
        self._set_library_status("\n".join(lines))

    def set_welcome_visible(self, visible: bool) -> None:
        if visible:
            self.welcome.grid()
            self.hide_welcome.deselect()
        else:
            self.welcome.grid_remove()

    def refresh_results(self, results: list[CheckResult]) -> None:
        for item in self.open_tree.get_children():
            self.open_tree.delete(item)
        self.open_results = []
        if not results:
            self._set_run_summary("No scan results loaded.")
            return
        counts = Counter(result.status for result in results)
        devices = sorted({result.ip for result in results})
        self.open_results = [result for result in results if result.status == "Open"]
        lines = [
            f"Devices scanned: {len(devices)}",
            f"Total results: {len(results)}",
            f"NotAFinding: {counts.get('NotAFinding', 0)}",
            f"Open: {counts.get('Open', 0)}",
            f"NotReviewed: {counts.get('Not_Reviewed', 0)}",
            f"NotApplicable: {counts.get('Not_Applicable', 0)}",
            f"Error: {counts.get('Error', 0)}",
            f"Skipped: {counts.get('Skipped', 0)}",
        ]
        self._set_run_summary("\n".join(lines))
        for index, result in enumerate(self.open_results):
            self.open_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(result.ip, result.vuln_id, result.title),
                tags=("Open",),
            )

    def _blank_string_slots(self, value: Any) -> int:
        if isinstance(value, dict):
            count = 0
            for key, child in value.items():
                if key in {"strings", "required_strings", "forbidden_strings"} and child == []:
                    count += 1
                else:
                    count += self._blank_string_slots(child)
            return count
        if isinstance(value, list):
            return sum(self._blank_string_slots(item) for item in value)
        return 0

    def _set_run_summary(self, text: str) -> None:
        self.run_summary.configure(state="normal")
        self.run_summary.delete("1.0", "end")
        self.run_summary.insert("1.0", text)
        self.run_summary.configure(state="disabled")

    def _open_finding_selected(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.open_tree.selection()
        if not selected:
            return
        index = int(selected[0])
        if index >= len(self.open_results):
            return
        self.app_controller.show_result(self.open_results[index])

    def _set_library_status(self, text: str) -> None:
        self.library_status.configure(state="normal")
        self.library_status.delete("1.0", "end")
        self.library_status.insert("1.0", text)
        self.library_status.configure(state="disabled")
