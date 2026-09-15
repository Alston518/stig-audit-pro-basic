"""Evidence traceability, raw-output search, and integrity controls."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Iterable

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import PageFrame


def _value(item: Any, name: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


class EvidenceTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.run_id: str | None = None
        self.result: CheckResult | None = None
        self.artifacts: list[Any] = []
        self._loaded_text = ""
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        header.grid_columnconfigure(0, weight=1)
        self.context = ctk.CTkLabel(
            header,
            text="Select a result or historical run to inspect evidence.",
            anchor="w",
            justify="left",
        )
        self.context.grid(row=0, column=0, sticky="ew")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        actions.grid_columnconfigure(0, weight=1)
        self.search = ctk.CTkEntry(actions, placeholder_text="Search raw evidence")
        self.search.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.search.bind("<Return>", lambda _event: self.find_next())
        ctk.CTkButton(actions, text="Find Next", width=90, command=self.find_next).grid(
            row=0, column=1, padx=3
        )
        ctk.CTkButton(actions, text="Copy Evidence", width=110, command=self.copy).grid(
            row=0, column=2, padx=3
        )
        ctk.CTkButton(actions, text="Open File Location", width=130, command=self.open_location).grid(
            row=0, column=3, padx=3
        )
        ctk.CTkButton(actions, text="Verify Hash", width=100, command=self.verify).grid(
            row=0, column=4, padx=(3, 0)
        )
        ctk.CTkButton(
            actions,
            text="Import Offline Evidence",
            width=155,
            command=self.app_controller.import_offline_evidence,
        ).grid(row=0, column=5, padx=(6, 0))

        content = ctk.CTkFrame(self, corner_radius=8, border_width=1)
        content.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        content.grid_columnconfigure(0, weight=2)
        content.grid_columnconfigure(1, weight=3)
        content.grid_rowconfigure(0, weight=1)

        columns = ("command", "path", "sha256", "bytes")
        self.tree = ttk.Treeview(content, columns=columns, show="headings", selectmode="browse")
        for column, label, width in (
            ("command", "Command", 220), ("path", "Evidence File", 230),
            ("sha256", "SHA-256", 180), ("bytes", "Bytes", 65),
        ):
            self.tree.heading(column, text=label)
            self.tree.column(column, width=width, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)

        self.raw = ctk.CTkTextbox(content, wrap="none")
        self.raw.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        self._set_raw("No evidence selected.")

    def show_context(
        self,
        run_id: str,
        result: CheckResult | None,
        artifacts: Iterable[Any],
    ) -> None:
        self.run_id = run_id
        self.result = result
        self.artifacts = list(artifacts)
        self._loaded_text = ""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for index, artifact in enumerate(self.artifacts):
            self.tree.insert("", "end", iid=str(index), values=(
                _value(artifact, "command"),
                _value(artifact, "relative_path"),
                _value(artifact, "sha256"),
                _value(artifact, "byte_length", 0),
            ))
        if result is None:
            detail = f"Audit Run: {run_id}"
        else:
            detail = (
                f"Audit Run: {run_id}   Device: {result.hostname or result.ip} "
                f"({result.ip})   Vuln ID: {result.vuln_id}   Rule ID: "
                f"{result.rule_id or '-'}   Severity: {result.severity}   "
                f"Status: {result.status}\nEvaluation: "
                f"{result.evaluation_reason or result.finding_details or '-'}   "
                f"Profile inputs: {result.profile_values_used or '{}'}"
            )
        self.context.configure(text=detail)
        if self.artifacts:
            self.tree.selection_set("0")
            self.tree.focus("0")
            self._load_selected_async()
        else:
            self._set_raw("No linked evidence is available for this selection.")

    def _selected(self) -> Any | None:
        selection = self.tree.selection()
        return self.artifacts[int(selection[0])] if selection else None

    def _selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        self._load_selected_async()

    def _load_selected_async(self) -> None:
        artifact = self._selected()
        if artifact is None:
            return
        self._set_raw("Loading evidence...")
        self.app_controller.load_evidence_text_async(artifact, self._evidence_loaded)

    def _evidence_loaded(self, text: str) -> None:
        self._loaded_text = text
        self._set_raw(text)

    def _set_raw(self, text: str) -> None:
        self.raw.configure(state="normal")
        self.raw.delete("1.0", "end")
        self.raw.insert("1.0", text)
        self.raw.configure(state="disabled")

    def find_next(self) -> None:
        needle = self.search.get().strip()
        if not needle or not self._loaded_text:
            return
        self.raw.configure(state="normal")
        start = self.raw.index("insert + 1 char")
        position = self.raw.search(needle, start, stopindex="end", nocase=True)
        if not position:
            position = self.raw.search(needle, "1.0", stopindex=start, nocase=True)
        self.raw.tag_remove("evidence_match", "1.0", "end")
        if position:
            end = f"{position}+{len(needle)}c"
            self.raw.tag_add("evidence_match", position, end)
            self.raw.tag_config("evidence_match", background="#facc15", foreground="#111827")
            self.raw.mark_set("insert", end)
            self.raw.see(position)
        self.raw.configure(state="disabled")

    def copy(self) -> None:
        if not self._loaded_text:
            return
        self.clipboard_clear()
        self.clipboard_append(self._loaded_text)

    def open_location(self) -> None:
        if artifact := self._selected():
            self.app_controller.open_evidence_location(artifact)

    def verify(self) -> None:
        if artifact := self._selected():
            self.app_controller.verify_evidence_artifact(artifact)


__all__ = ["EvidenceTab"]
