"""Historical audit-run browser and actions."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Iterable

import customtkinter as ctk

from stig_audit_pro.gui.widgets import PageFrame, confirm_action


def _value(row: Any, name: str, default: Any = "") -> Any:
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


class HistoryTab(PageFrame):
    """Render persistent runs without coupling the UI to SQLAlchemy."""

    PAGE_SIZE = 100

    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.rows: list[Any] = []
        self.offset = 0
        self.total_rows = 0
        self.grid_rowconfigure(3, weight=1)

        heading = ctk.CTkFrame(self, fg_color="transparent")
        heading.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        heading.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            heading,
            text="Audit History",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        self.message = ctk.CTkLabel(
            heading,
            text="Historical runs remain until explicitly deleted.",
            anchor="e",
        )
        self.message.grid(row=0, column=1, sticky="e")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        for column in range(10):
            actions.grid_columnconfigure(column, weight=1)
        buttons = (
            ("Refresh", self.refresh_from_controller),
            ("Open Run", self._open),
            ("Compare Runs", self._compare),
            ("Export Reports", self._export),
            ("Export Package", self._export_package),
            ("Import Package", self._import_package),
            ("Verify Evidence", self._verify),
            ("Retry Failed", self._retry),
            ("Purge Raw Evidence", self._purge),
            ("Delete Run", self._delete),
        )
        for column, (label, command) in enumerate(buttons):
            kwargs: dict[str, object] = {}
            if label in {"Purge Raw Evidence", "Delete Run"}:
                kwargs["fg_color"] = "#b42318"
                kwargs["hover_color"] = "#912018"
            ctk.CTkButton(actions, text=label, command=command, **kwargs).grid(
                row=0, column=column, sticky="ew", padx=3
            )

        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        search_row.grid_columnconfigure(0, weight=1)
        self.search = ctk.CTkEntry(search_row, placeholder_text="Search date, run ID, description, STIG, profile, or status")
        self.search.grid(row=0, column=0, sticky="ew")
        self.search.bind("<KeyRelease>", lambda _event: self.refresh_from_controller(reset=True))
        self.previous_button = ctk.CTkButton(search_row, text="Previous", width=88, command=self._previous_page)
        self.previous_button.grid(row=0, column=1, padx=(10, 4))
        self.page_label = ctk.CTkLabel(search_row, text="0 audits", width=130)
        self.page_label.grid(row=0, column=2, padx=4)
        self.next_button = ctk.CTkButton(search_row, text="Next", width=88, command=self._next_page)
        self.next_button.grid(row=0, column=3, padx=(4, 0))

        columns = (
            "time", "run_id", "description", "families", "stig", "profile",
            "devices", "open", "pass", "errors", "status",
        )
        self.tree = ttk.Treeview(
            self, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "time": "Date / Time (UTC)", "run_id": "Run ID",
            "description": "Description / Preset", "families": "STIG Families",
            "stig": "STIG Version / Release", "profile": "Profile",
            "devices": "Devices", "open": "Open", "pass": "Pass",
            "errors": "Errors", "status": "Status",
        }
        widths = {
            "time": 155, "run_id": 235, "description": 170, "families": 130,
            "stig": 135, "profile": 130, "devices": 65, "open": 55,
            "pass": 55, "errors": 55, "status": 90,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        self.tree.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.tree.bind("<Double-1>", lambda _event: self._open())

    def refresh(self, rows: Iterable[Any], *, total: int | None = None) -> None:
        self.rows = list(rows)
        self.total_rows = len(self.rows) if total is None else max(0, int(total))
        self._render()

    def _render(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        query = self.search.get().strip().casefold() if hasattr(self, "search") else ""
        visible = 0
        for index, row in enumerate(self.rows):
            started = _value(row, "started_at", "")
            if hasattr(started, "isoformat"):
                started = started.isoformat(timespec="seconds")
            families = _value(row, "stig_families", []) or []
            if isinstance(families, (list, tuple, set)):
                families = ", ".join(str(item) for item in families)
            version = " / ".join(
                str(value) for value in (
                    _value(row, "stig_version", ""),
                    _value(row, "stig_release", ""),
                ) if value
            )
            description = (
                _value(row, "description", "")
                or _value(row, "preset_name", "")
                or _value(row, "collection_mode", "")
            )
            haystack = f"{started} {_value(row, 'id', _value(row, 'run_id', ''))} {description} {families} {version} {_value(row, 'profile_name', '')} {_value(row, 'status', '')}".casefold()
            if query and query not in haystack:
                continue
            self.tree.insert("", "end", iid=str(index), values=(
                started,
                _value(row, "id", _value(row, "run_id", "")),
                description,
                families,
                version,
                _value(row, "profile_name", ""),
                _value(row, "device_count", 0),
                _value(row, "open_count", 0),
                _value(row, "pass_count", 0),
                _value(row, "error_count", _value(row, "failure_count", 0)),
                _value(row, "status", ""),
            ))
            visible += 1
        first = self.offset + 1 if visible else 0
        last = self.offset + visible
        self.message.configure(text=f"Showing {first}–{last} of {self.total_rows} historical audit(s).")
        self.page_label.configure(text=f"{first}–{last} of {self.total_rows}")
        self.previous_button.configure(state="normal" if self.offset else "disabled")
        self.next_button.configure(
            state="normal" if self.offset + len(self.rows) < self.total_rows else "disabled"
        )

    def refresh_from_controller(self, *, reset: bool = False) -> list[Any]:
        if reset:
            self.offset = 0
        query = self.search.get().strip()
        total = self.app_controller.count_audit_runs(search=query)
        if self.offset >= total and self.offset:
            self.offset = max(0, ((max(total, 1) - 1) // self.PAGE_SIZE) * self.PAGE_SIZE)
        rows = self.app_controller.list_audit_runs(
            limit=self.PAGE_SIZE,
            offset=self.offset,
            search=query,
        )
        self.refresh(rows, total=total)
        return rows

    def _previous_page(self) -> None:
        self.offset = max(0, self.offset - self.PAGE_SIZE)
        self.refresh_from_controller()

    def _next_page(self) -> None:
        if self.offset + len(self.rows) < self.total_rows:
            self.offset += self.PAGE_SIZE
            self.refresh_from_controller()

    def _selected_ids(self) -> list[str]:
        selected: list[str] = []
        for iid in self.tree.selection():
            row = self.rows[int(iid)]
            selected.append(str(_value(row, "id", _value(row, "run_id", ""))))
        return [run_id for run_id in selected if run_id]

    def _require_one(self) -> str | None:
        ids = self._selected_ids()
        if len(ids) != 1:
            self.message.configure(text="Select exactly one audit run.")
            return None
        return ids[0]

    def _open(self) -> None:
        if run_id := self._require_one():
            self.app_controller.open_historical_run(run_id)

    def _compare(self) -> None:
        run_ids = self._selected_ids()
        if len(run_ids) != 2:
            self.message.configure(text="Select exactly two compatible audit runs.")
            return
        self.app_controller.compare_historical_runs(run_ids[0], run_ids[1])

    def _export(self) -> None:
        if run_id := self._require_one():
            self.app_controller.export_historical_run(run_id)

    def _export_package(self) -> None:
        if run_id := self._require_one():
            self.app_controller.export_audit_package(run_id)

    def _import_package(self) -> None:
        self.app_controller.import_audit_package()

    def _verify(self) -> None:
        if run_id := self._require_one():
            self.app_controller.verify_historical_evidence(run_id)

    def _retry(self) -> None:
        if run_id := self._require_one():
            self.app_controller.retry_failed_devices(run_id)

    def _purge(self) -> None:
        run_id = self._require_one()
        if run_id and confirm_action(
            self,
            title="Purge Raw Evidence",
            message=(
                "Purge raw evidence for this run? Structured results and audit "
                "metadata will remain, but the command output cannot be recovered."
            ),
            confirm_text="Purge Evidence",
        ):
            self.app_controller.purge_historical_evidence(run_id)
            self.refresh_from_controller()

    def _delete(self) -> None:
        run_id = self._require_one()
        if run_id and confirm_action(
            self,
            title="Delete Audit Run",
            message="Delete this audit run and its local evidence? This cannot be undone.",
            confirm_text="Delete Run",
        ):
            self.app_controller.delete_historical_run(run_id)
            self.refresh_from_controller()


__all__ = ["HistoryTab"]
