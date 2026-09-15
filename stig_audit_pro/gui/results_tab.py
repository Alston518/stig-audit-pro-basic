"""Results tab for check outcomes and finding detail."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import (
    DANGER,
    Metric,
    PageFrame,
    PRIMARY,
    STATUS_COLORS,
    SUCCESS,
    WARNING,
    confirm_action,
)


class ResultsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.results: list[CheckResult] = []
        self.filtered_results: list[CheckResult] = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        actions.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        self.metrics = {
            "total": Metric(actions, "Total", accent=PRIMARY),
            "NotAFinding": Metric(actions, "NotAFinding", accent=SUCCESS),
            "Open": Metric(actions, "Open", accent=DANGER),
            "Not_Applicable": Metric(actions, "NotApplicable", accent="#667085"),
            "Error": Metric(actions, "Error", accent="#c2410c"),
            "Skipped": Metric(actions, "Skipped", accent="#667085"),
            "Not_Reviewed": Metric(actions, "NotReviewed", accent=WARNING),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        run_row = ctk.CTkFrame(self, fg_color="transparent")
        run_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        run_row.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkButton(run_row, text="Run Compliant Sample", command=lambda: app_controller.run_sample_audit("compliant")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(run_row, text="Run Noncompliant Sample", command=lambda: app_controller.run_sample_audit("noncompliant"), fg_color="#9f1d1d", hover_color="#7f1d1d").grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="View Evidence", command=self._view_evidence).grid(row=0, column=2, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="Clear", command=self.clear).grid(row=0, column=3, sticky="ew", padx=(6, 0))

        filter_row = ctk.CTkFrame(self, fg_color="transparent")
        filter_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        filter_row.grid_columnconfigure(1, weight=1)
        self.status_filter = ctk.CTkComboBox(
            filter_row,
            values=["All findings", "CAT I", "CAT II", "CAT III", "Open", "Not a Finding", "Manual Review", "Not Applicable", "Errors"],
            command=lambda _value: self._render_tree(),
            state="readonly",
            width=160,
        )
        self.status_filter.set("All findings")
        self.status_filter.grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.search = ctk.CTkEntry(filter_row, placeholder_text="Search hostname, IP, Vuln ID, Rule ID, or title")
        self.search.grid(row=0, column=1, sticky="ew")
        self.search.bind("<KeyRelease>", lambda _event: self._render_tree())

        content = ctk.CTkFrame(self, corner_radius=8, border_width=1)
        content.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        content.grid_columnconfigure(0, weight=3)
        content.grid_columnconfigure(1, weight=2)
        content.grid_rowconfigure(0, weight=1)

        columns = ("ip", "vuln", "family", "severity", "status", "failed")
        self.tree = ttk.Treeview(content, columns=columns, show="headings", selectmode="browse")
        headings = {
            "ip": "IP",
            "vuln": "Vuln ID",
            "family": "Family",
            "severity": "Severity",
            "status": "Status",
            "failed": "Failed Objects",
        }
        widths = {"ip": 110, "vuln": 180, "family": 100, "severity": 80, "status": 120, "failed": 260}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        for status, colors in STATUS_COLORS.items():
            self.tree.tag_configure(status, background=colors[0], foreground=colors[1])
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)

        self.details = ctk.CTkTextbox(content, wrap="word")
        self.details.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        self.details.insert("1.0", "Run a sample audit to populate results.")
        self.details.configure(state="disabled")

        detail_actions = ctk.CTkFrame(content, fg_color="transparent")
        detail_actions.grid(row=1, column=1, sticky="ew", padx=(6, 10), pady=(0, 10))
        for column, (label, command) in enumerate((
            ("View Evidence", self._view_evidence),
            ("DISA Check Text", lambda: self._view_stig_text("check_text")),
            ("DISA Fix Text", lambda: self._view_stig_text("fix_text")),
            ("Copy Finding", self._copy_finding),
            ("Record Manual Review", self._manual_review),
        )):
            ctk.CTkButton(detail_actions, text=label, height=28, command=command).grid(row=0, column=column, sticky="ew", padx=3)
            detail_actions.grid_columnconfigure(column, weight=1)

    def refresh(self, results: list[CheckResult]) -> None:
        self.results = results
        self._update_metrics()
        self._render_tree()

    def _render_tree(self, selected_result: tuple[str, str] | None = None) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Bound widget creation for enterprise-size histories. Search/filtering
        # narrows the full in-memory result set before this display window.
        self.filtered_results = self._filtered_results()[:1000]
        selected_iid: str | None = None
        for index, result in enumerate(self.filtered_results):
            failed = ", ".join(obj.object_name for obj in result.failed_objects)
            iid = str(index)
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(result.ip, result.vuln_id, result.stig_family, result.severity, result.status, failed),
                tags=(result.status,),
            )
            if selected_result == (result.ip, result.vuln_id):
                selected_iid = iid
        if self.filtered_results:
            selected_iid = selected_iid or "0"
            self.tree.selection_set(selected_iid)
            self.tree.focus(selected_iid)
            self.tree.see(selected_iid)
            self._show_result(self.filtered_results[int(selected_iid)])
        elif self.results:
            self._set_details("No results match the current filter.")
        else:
            self._set_details("No results.")

    def select_result(self, ip: str, vuln_id: str) -> None:
        """Reveal and select a result, clearing filters that would otherwise hide it."""
        self.status_filter.set("All findings")
        self.search.delete(0, "end")
        self._render_tree((ip, vuln_id))

    def _filtered_results(self) -> list[CheckResult]:
        selected_filter = self.status_filter.get()
        status_map = {"Not a Finding": "NotAFinding", "Manual Review": "Not_Reviewed", "Not Applicable": "Not_Applicable"}
        query = self.search.get().strip().lower()
        filtered: list[CheckResult] = []
        for result in self.results:
            if selected_filter in {"CAT I", "CAT II", "CAT III"} and self._cat(result.severity) != selected_filter:
                continue
            wanted_status = status_map.get(selected_filter, selected_filter)
            if selected_filter == "Errors" and result.status not in {"Error", "Skipped"}:
                continue
            if selected_filter not in {"All findings", "CAT I", "CAT II", "CAT III", "Errors"} and result.status != wanted_status:
                continue
            haystack = f"{result.ip} {result.hostname} {result.vuln_id} {result.rule_id or ''} {result.stig_id or ''} {result.title} {result.stig_family} {result.severity} {result.status}".lower()
            if query and query not in haystack:
                continue
            filtered.append(result)
        return filtered

    def clear(self) -> None:
        if not self.results:
            return
        if not confirm_action(
            self,
            title="Clear Results",
            message=f"Clear all {len(self.results)} scan results from the current session?",
            confirm_text="Clear Results",
        ):
            return
        self.refresh([])
        self.app_controller.update_report_summary([])

    def _update_metrics(self) -> None:
        counts = {
            "total": len(self.results),
            "NotAFinding": 0,
            "Open": 0,
            "Not_Applicable": 0,
            "Error": 0,
            "Skipped": 0,
            "Not_Reviewed": 0,
        }
        for result in self.results:
            if result.status in counts:
                counts[result.status] += 1
        for key, value in counts.items():
            self.metrics[key].set(value)

    def _selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        self._show_result(self.filtered_results[index])

    def _selected_result(self) -> CheckResult | None:
        selected = self.tree.selection()
        if not selected:
            return None
        index = int(selected[0])
        if index >= len(self.filtered_results):
            return None
        return self.filtered_results[index]

    def _view_evidence(self) -> None:
        result = self._selected_result()
        if result is not None:
            self.app_controller.show_result_evidence(result)

    def _show_result(self, result: CheckResult) -> None:
        failed = "\n".join(f"- {obj.object_type}: {obj.object_name} ({obj.details})" for obj in result.failed_objects) or "None"
        passed = "\n".join(f"- {obj.object_type}: {obj.object_name}" for obj in result.passed_objects) or "None"
        commands = "\n".join(f"- {command}" for command in result.commands_used) or "None"
        warnings = "\n".join(f"- {warning}" for warning in result.parser_warnings) or "None"
        artifacts = ", ".join(str(item) for item in result.evidence_artifact_ids) or "None"
        status = {"NotAFinding": "NOT A FINDING", "Not_Reviewed": "MANUAL REVIEW REQUIRED", "Not_Applicable": "NOT APPLICABLE"}.get(result.status, result.status.upper())
        explanation = result.evaluation_reason or result.finding_details or result.comments or "No automated explanation was recorded."
        if result.status == "Not_Reviewed":
            explanation = "STIG Audit Pro cannot reliably determine this requirement from the available Cisco CLI evidence. A reviewer decision is required.\n\n" + explanation
        text = (
            f"{result.vuln_id}   {self._cat(result.severity) or result.severity.upper()}   {status}\n{result.title}\n\n"
            f"WHY STIG AUDIT PRO CHOSE THIS RESULT\n{'─' * 38}\n{explanation}\n\n"
            f"WHAT WAS FOUND\n{'─' * 18}\n{result.finding_details or failed}\n\n"
            f"DEVICE\n{'─' * 10}\n{result.hostname or 'Unknown hostname'}\n{result.ip}\n\n"
            f"EVIDENCE USED\n{'─' * 18}\n{commands}\nFiles: {artifacts}\n\n"
            f"SITE SETTINGS USED\n{'─' * 22}\n{result.profile_values_used or 'None'}\n\n"
            f"Rule ID: {result.rule_id or '-'}\nSTIG ID: {result.stig_id or '-'}\nAudit Run: {result.run_id or '-'}\n"
            f"Parser warnings: {warnings}\nPassed objects: {passed}\nComments: {result.comments or '-'}"
        )
        self._set_details(text)

    @staticmethod
    def _cat(severity: str) -> str:
        value = severity.lower().replace(" ", "")
        return {"high": "CAT I", "cat1": "CAT I", "cati": "CAT I", "medium": "CAT II", "cat2": "CAT II", "catii": "CAT II", "low": "CAT III", "cat3": "CAT III", "catiii": "CAT III"}.get(value, "")

    def _view_stig_text(self, field: str) -> None:
        if result := self._selected_result():
            self.app_controller.show_disa_guidance(result, field)

    def _copy_finding(self) -> None:
        result = self._selected_result()
        if result is None:
            return
        self.clipboard_clear()
        self.clipboard_append(f"{result.vuln_id} | {result.status} | {result.hostname} ({result.ip})\n{result.title}\n{result.evaluation_reason or result.finding_details}")
        self.update_idletasks()

    def _manual_review(self) -> None:
        result = self._selected_result()
        if result is not None:
            self.app_controller.open_manual_review(result)

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")
