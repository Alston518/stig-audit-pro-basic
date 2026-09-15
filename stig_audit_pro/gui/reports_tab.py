"""Reports tab with summary and export actions."""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import DANGER, Metric, PageFrame, Panel, PRIMARY, SUCCESS, WARNING


class ReportsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.results: list[CheckResult] = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        metrics = ctk.CTkFrame(self, fg_color="transparent")
        metrics.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        metrics.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        self.metrics = {
            "compliance": Metric(metrics, "Compliance", "0%", accent=PRIMARY),
            "open": Metric(metrics, "Open", accent=DANGER),
            "not_a_finding": Metric(metrics, "NotAFinding", accent=SUCCESS),
            "not_applicable": Metric(metrics, "NotApplicable", accent="#667085"),
            "error": Metric(metrics, "Error", accent="#c2410c"),
            "skipped": Metric(metrics, "Skipped", accent="#667085"),
            "not_reviewed": Metric(metrics, "NotReviewed", accent=WARNING),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        panel = Panel(self, "Report Output")
        panel.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        panel.grid_columnconfigure((0, 1), weight=1)
        self.txt_button = ctk.CTkButton(panel, text="Save TXT Summary", command=self._save_txt_report, state="disabled")
        self.txt_button.grid(row=1, column=0, sticky="ew", padx=(12, 6), pady=(14, 8))
        self.csv_button = ctk.CTkButton(panel, text="Save CSV Details", command=self._save_csv_report, state="disabled")
        self.csv_button.grid(row=1, column=1, sticky="ew", padx=(6, 12), pady=(14, 8))
        self.json_button = ctk.CTkButton(panel, text="Save JSON Report", command=self._save_json_report, state="disabled")
        self.json_button.grid(row=2, column=0, sticky="ew", padx=(12, 6), pady=(0, 8))
        self.xlsx_button = ctk.CTkButton(panel, text="Save Excel Report", command=self._save_excel_report, state="disabled")
        self.xlsx_button.grid(row=2, column=1, sticky="ew", padx=(6, 12), pady=(0, 8))
        self.summary = ctk.CTkTextbox(panel, height=260)
        self.summary.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=12, pady=(4, 8))
        panel.grid_rowconfigure(3, weight=1)
        self.summary.insert("1.0", "No audit results loaded.")
        self.summary.configure(state="disabled")
        self.export_status = ctk.CTkLabel(panel, text="Run a scan to enable report export.", anchor="w", text_color=("#475467", "#d0d5dd"))
        self.export_status.grid(row=4, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))

    def refresh(self, results: list[CheckResult]) -> None:
        self.results = results
        total = len(results)
        open_count = sum(1 for result in results if result.status == "Open")
        pass_count = sum(1 for result in results if result.status == "NotAFinding")
        not_applicable_count = sum(1 for result in results if result.status == "Not_Applicable")
        error_count = sum(1 for result in results if result.status == "Error")
        skipped_count = sum(1 for result in results if result.status == "Skipped")
        not_reviewed_count = sum(1 for result in results if result.status == "Not_Reviewed")
        scorable = pass_count + open_count + error_count
        compliance = round((pass_count / scorable) * 100) if scorable else 0
        self.metrics["compliance"].set(f"{compliance}%")
        self.metrics["open"].set(open_count)
        self.metrics["not_a_finding"].set(pass_count)
        self.metrics["not_applicable"].set(not_applicable_count)
        self.metrics["error"].set(error_count)
        self.metrics["skipped"].set(skipped_count)
        self.metrics["not_reviewed"].set(not_reviewed_count)
        self.set_export_status("Reports are ready to export." if total else "Run a scan to enable report export.")
        button_state = "normal" if total else "disabled"
        self.txt_button.configure(state=button_state)
        self.csv_button.configure(state=button_state)
        self.json_button.configure(state=button_state)
        self.xlsx_button.configure(state=button_state)
        devices = sorted({result.ip for result in results})
        lines = [
            f"Devices: {len(devices)}",
            f"Total results: {total}",
            f"Compliance: {compliance}%",
            f"NotAFinding: {pass_count}",
            f"Open: {open_count}",
            f"NotApplicable: {not_applicable_count}",
            f"Error: {error_count}",
            f"Skipped: {skipped_count}",
            f"NotReviewed: {not_reviewed_count}",
            "",
            "Open findings:",
        ]
        lines.extend(
            f"- {result.ip} {result.vuln_id}: {result.title}"
            for result in results
            if result.status == "Open"
        )
        if open_count == 0:
            lines.append("None")
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("1.0", "\n".join(lines))
        self.summary.configure(state="disabled")

    def set_export_status(self, message: str) -> None:
        self.export_status.configure(text=message)

    def _save_txt_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save TXT report",
            initialdir=str(self.app_controller.operator_workspace.reports),
            defaultextension=".txt",
            initialfile="stig-audit-report.txt",
            filetypes=[("Text report", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.export_text_report(Path(path))

    def _save_csv_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save CSV report",
            initialdir=str(self.app_controller.operator_workspace.reports),
            defaultextension=".csv",
            initialfile="stig-audit-results.csv",
            filetypes=[("CSV report", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.export_csv_report(Path(path))

    def _save_json_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save JSON report",
            initialdir=str(self.app_controller.operator_workspace.reports),
            defaultextension=".json",
            initialfile="stig-audit-report.json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.export_json_report(Path(path))

    def _save_excel_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save Excel report",
            initialdir=str(self.app_controller.operator_workspace.reports),
            defaultextension=".xlsx",
            initialfile="stig-audit-report.xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.export_excel_report(Path(path))
