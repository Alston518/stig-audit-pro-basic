"""Checks tab showing YAML-backed check definitions."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk
import yaml

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.gui.widgets import PageFrame, Panel
from stig_audit_pro.gui.yaml_editor import YamlEditor


class ChecksTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.checks: list[CheckDefinition] = []
        self.yaml_paths: list[Path] = []
        self.current_yaml_path: Path | None = None
        self.selected_check: CheckDefinition | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        list_panel = Panel(self, "Checks")
        list_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        list_panel.grid_columnconfigure(0, weight=1)
        list_panel.grid_rowconfigure(3, weight=1)

        self.search = ctk.CTkEntry(list_panel, placeholder_text="Filter by Vuln ID, title, severity")
        self.search.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 6))
        self.search.bind("<KeyRelease>", lambda _event: self._render_check_rows())

        filter_row = ctk.CTkFrame(list_panel, fg_color="transparent")
        filter_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(2, 8))
        filter_row.grid_columnconfigure((0, 1), weight=1)
        self.family_filter = ctk.CTkComboBox(filter_row, values=["All families", "IOSXE_L2", "IOSXE_NDM"], command=lambda _value: self._render_check_rows(), state="readonly")
        self.family_filter.set("All families")
        self.family_filter.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.severity_filter = ctk.CTkComboBox(filter_row, values=["All severities", "cat1", "cat2", "cat3"], command=lambda _value: self._render_check_rows(), state="readonly")
        self.severity_filter.set("All severities")
        self.severity_filter.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.scroll = ctk.CTkScrollableFrame(list_panel)
        self.scroll.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.scroll.grid_columnconfigure(0, weight=1)

        editor_panel = ctk.CTkFrame(self, fg_color="transparent")
        editor_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        editor_panel.grid_columnconfigure(0, weight=1)
        editor_panel.grid_rowconfigure(1, weight=1)

        library_row = ctk.CTkFrame(editor_panel, fg_color="transparent")
        library_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        library_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(library_row, text="Library").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.library_select = ctk.CTkComboBox(
            library_row,
            values=[],
            command=lambda _value: self._load_selected_yaml(),
            state="readonly",
        )
        self.library_select.grid(row=0, column=1, sticky="ew")

        self.edit_tabs = ctk.CTkTabview(editor_panel)
        self.edit_tabs.grid(row=1, column=0, sticky="nsew")
        simple_page = self.edit_tabs.add("Simple Editor")
        advanced_page = self.edit_tabs.add("Advanced YAML")
        for page in (simple_page, advanced_page):
            page.grid_columnconfigure(0, weight=1)
            page.grid_rowconfigure(0, weight=1)
        simple = ctk.CTkScrollableFrame(simple_page)
        simple.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        simple.grid_columnconfigure(1, weight=1)
        self.simple_labels: dict[str, ctk.CTkLabel] = {}
        for row, (key, label) in enumerate((
            ("vuln_id", "Vuln ID"), ("title", "Title"), ("family", "STIG family"),
            ("severity", "Severity"), ("check_type", "Check type"),
            ("automation", "Automation"), ("source", "Source release"),
            ("commands", "Approved commands"),
        )):
            ctk.CTkLabel(simple, text=label, anchor="w").grid(row=row, column=0, sticky="nw", padx=10, pady=4)
            value = ctk.CTkLabel(simple, text="-", anchor="w", justify="left", wraplength=560)
            value.grid(row=row, column=1, sticky="ew", padx=10, pady=4)
            self.simple_labels[key] = value
        self.simple_fields: dict[str, ctk.CTkTextbox] = {}
        start = len(self.simple_labels)
        for offset, (key, label) in enumerate((
            ("strings", "Strings"), ("required_strings", "Required strings"),
            ("forbidden_strings", "Forbidden strings"),
            ("required_patterns", "Required patterns"),
            ("forbidden_patterns", "Forbidden patterns"),
        )):
            row = start + offset
            ctk.CTkLabel(simple, text=label, anchor="w").grid(row=row, column=0, sticky="nw", padx=10, pady=4)
            box = ctk.CTkTextbox(simple, height=82, wrap="none")
            box.grid(row=row, column=1, sticky="ew", padx=10, pady=4)
            self.simple_fields[key] = box
        simple_actions = ctk.CTkFrame(simple, fg_color="transparent")
        simple_actions.grid(row=start + len(self.simple_fields), column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        simple_actions.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(simple_actions, text="Validate Changes", command=self._validate_simple).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(simple_actions, text="Save Check Strings", command=self._save_simple).grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ctk.CTkButton(simple_actions, text="Run Check Tests", command=self._run_tests).grid(row=0, column=2, sticky="ew", padx=(6, 0))
        self.simple_status = ctk.CTkLabel(simple, text="Select a check on the left.", anchor="w")
        self.simple_status.grid(row=start + len(self.simple_fields) + 1, column=0, columnspan=2, sticky="ew", padx=10)

        self.editor = YamlEditor(advanced_page, "Check YAML")
        self.editor.grid(row=0, column=0, sticky="nsew")

        actions = ctk.CTkFrame(editor_panel, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        actions.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(actions, text="Validate YAML", command=self._validate_yaml).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(actions, text="Save YAML", command=self._save_yaml).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(actions, text="Reload From Disk", command=app_controller.reload_from_disk).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        tailoring = ctk.CTkLabel(
            editor_panel,
            text="Tailor customer/site differences in profiles first; edit YAML checks here when the actual requirement logic differs.",
            anchor="w",
            justify="left",
            wraplength=560,
            text_color=("#475467", "#d0d5dd"),
        )
        tailoring.grid(row=3, column=0, sticky="ew", pady=(8, 0))

    def refresh(self, checks: list[CheckDefinition], yaml_paths: list[Path]) -> None:
        self.checks = checks
        self.yaml_paths = yaml_paths
        values = [path.name for path in yaml_paths]
        self.library_select.configure(values=values)
        if self.current_yaml_path not in yaml_paths:
            self.current_yaml_path = yaml_paths[0] if yaml_paths else None
        if self.current_yaml_path is not None:
            self.library_select.set(self.current_yaml_path.name)
            self.editor.set_text(self.current_yaml_path.read_text(encoding="utf-8"))
        else:
            self.library_select.set("")
            self.editor.set_text("")
        self.editor.set_status(f"{len(checks)} checks loaded")
        self._render_check_rows()

    def _filtered_checks(self) -> list[CheckDefinition]:
        query = self.search.get().strip().lower()
        family = self.family_filter.get()
        severity = self.severity_filter.get()
        filtered: list[CheckDefinition] = []
        for check in self.checks:
            if family != "All families" and check.stig_family != family:
                continue
            if severity != "All severities" and check.severity != severity:
                continue
            haystack = f"{check.vuln_id} {check.title} {check.looking_for} {check.severity} {check.check_type}".lower()
            if query and query not in haystack:
                continue
            filtered.append(check)
        return filtered

    def _render_check_rows(self) -> None:
        for child in self.scroll.winfo_children():
            child.destroy()
        for row_index, check in enumerate(self._filtered_checks()):
            row = ctk.CTkFrame(self.scroll, corner_radius=8, border_width=1)
            row.grid(row=row_index, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=check.vuln_id, font=ctk.CTkFont(weight="bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
            ctk.CTkLabel(row, text=check.title, anchor="w", wraplength=330, justify="left").grid(row=1, column=0, sticky="ew", padx=10, pady=(2, 2))
            if check.looking_for:
                ctk.CTkLabel(row, text=check.looking_for, anchor="w", wraplength=330, justify="left", text_color=("#475467", "#d0d5dd")).grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 4))
            mode = "Automated" if check.automated and check.check_type != "manual_review" else "Manual"
            ctk.CTkLabel(row, text=f"{check.stig_family}  |  {check.severity}  |  {mode}  |  {check.check_type}", text_color=("#475467", "#d0d5dd"), anchor="w").grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8))
            ctk.CTkButton(
                row, text="Edit", width=62,
                command=lambda selected=check: self._select_check(selected),
            ).grid(row=0, column=1, rowspan=4, sticky="e", padx=8, pady=8)

    def _select_check(self, check: CheckDefinition) -> None:
        self.selected_check = check
        mode = "Automated" if check.automated and check.check_type != "manual_review" else "Manual review"
        values = {
            "vuln_id": check.vuln_id, "title": check.title,
            "family": check.stig_family, "severity": check.severity,
            "check_type": check.check_type, "automation": mode,
            "source": " ".join(filter(None, [check.source_benchmark, check.source_version, check.source_release])) or "Not recorded",
            "commands": "\n".join(check.commands) or "None",
        }
        for key, value in values.items():
            self.simple_labels[key].configure(text=value)
        for key, box in self.simple_fields.items():
            box.delete("1.0", "end")
            current = check.conditions.get(key, [])
            if current:
                box.insert("1.0", yaml.safe_dump(current, sort_keys=False).strip())
        self.simple_status.configure(text="Edit list values as YAML, then validate and save.")
        self.edit_tabs.set("Simple Editor")

    def _simple_updates(self) -> dict[str, list[object]]:
        updates: dict[str, list[object]] = {}
        for key, box in self.simple_fields.items():
            text = box.get("1.0", "end").strip()
            if not text:
                updates[key] = []
                continue
            value = yaml.safe_load(text)
            if not isinstance(value, list):
                raise ValueError(f"{key} must be a YAML list")
            updates[key] = value
        return updates

    def _validate_simple(self) -> None:
        try:
            if self.selected_check is None:
                raise ValueError("Select a check first")
            ok, message = self.app_controller.validate_check_simple(
                self.selected_check.vuln_id, self._simple_updates()
            )
        except (ValueError, yaml.YAMLError) as exc:
            ok, message = False, str(exc)
        self.simple_status.configure(text=message, text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"))

    def _save_simple(self) -> None:
        try:
            if self.selected_check is None:
                raise ValueError("Select a check first")
            path = self.app_controller.check_source_paths.get(self.selected_check.vuln_id)
            if path is None:
                raise ValueError("The source YAML file could not be resolved")
            ok, message = self.app_controller.save_check_simple(
                path, self.selected_check.vuln_id, self._simple_updates()
            )
        except (ValueError, yaml.YAMLError) as exc:
            ok, message = False, str(exc)
        self.simple_status.configure(text=message, text_color=("#027a48", "#6ce9a6") if ok else ("#b42318", "#f97066"))

    def _run_tests(self) -> None:
        if self.selected_check is None:
            self.simple_status.configure(text="Select a check first.")
            return
        summary = self.app_controller.run_check_fixture_tests(self.selected_check)
        if not summary.results:
            message, ok = "No standardized fixtures are available for this check yet.", False
        else:
            passed = sum(1 for item in summary.results if item.passed)
            lines = [f"Automation Validation: {passed} / {len(summary.results)} passed"]
            lines.extend(f"{item.name}: {'PASS' if item.passed else 'FAIL'} {item.message}" for item in summary.results)
            message, ok = "\n".join(lines), summary.passed and summary.complete
        self.simple_status.configure(text=message, text_color=("#027a48", "#6ce9a6") if ok else ("#b54708", "#fdb022"))

    def _validate_yaml(self) -> None:
        ok, message = self.app_controller.validate_check_yaml(self.editor.get_text())
        self.editor.set_status(message, ok=ok)

    def _selected_yaml_path(self) -> Path | None:
        selected = self.library_select.get()
        for path in self.yaml_paths:
            if path.name == selected:
                return path
        return None

    def _load_selected_yaml(self) -> None:
        path = self._selected_yaml_path()
        if path is None:
            self.editor.set_status("Choose a check library", ok=False)
            return
        self.current_yaml_path = path
        self.editor.set_text(path.read_text(encoding="utf-8"))
        self.editor.set_status(f"Loaded {path.name}")

    def _save_yaml(self) -> None:
        path = self._selected_yaml_path()
        if path is None:
            self.editor.set_status("Choose a check library", ok=False)
            return
        ok, message = self.app_controller.save_check_yaml(path, self.editor.get_text())
        self.editor.set_status(message, ok=ok)

