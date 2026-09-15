"""Setup tab for STIG sources, checklist output, and site profiles."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import customtkinter as ctk

from stig_audit_pro.config import DEFAULT_PROFILE_NAME
from stig_audit_pro.core.models import SiteProfile
from stig_audit_pro.gui.widgets import (
    DANGER,
    DANGER_HOVER,
    PageFrame,
    Panel,
    TEXT_MUTED,
    confirm_action,
    label_value,
)
from stig_audit_pro.gui.yaml_editor import YamlEditor
from stig_audit_pro.stig.stig_comparator import RULE_FIELDS, StigComparisonReport, StigRuleChange
from stig_audit_pro.stig.stig_diff import RuleDiff, RuleChange, StigDiff
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata


class StigTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.metadata_items: list[StigBenchmarkMetadata] = []
        self.rule_lookup: dict[str, tuple[StigBenchmarkMetadata, StigRuleMetadata]] = {}
        self.selected_ckl_path: Path | None = None
        self.selected_ckl_paths: dict[str, Path | None] = {
            "IOSXE_L2": None,
            "IOSXE_NDM": None,
            "COMBINED": None,
        }
        self.selected_output_dir: Path | None = None
        self.current_profile_path: Path | None = None
        self.base_profile_path: Path | None = None
        self.comparison_report: StigComparisonReport | None = None
        self.comparison_lookup: dict[str, StigRuleChange] = {}
        self.library_items: list[StigBenchmarkMetadata] = []
        self.library_diff: StigDiff | None = None
        self.library_diff_lookup: dict[str, RuleDiff] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.setup_tabs = ctk.CTkTabview(self)
        self.setup_tabs.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        source_page = self.setup_tabs.add("STIG Source")
        library_page = self.setup_tabs.add("STIG Library")
        compare_page = self.setup_tabs.add("Compare STIGs")
        checklist_page = self.setup_tabs.add("Checklist Output")
        profiles_page = self.setup_tabs.add("Profiles")
        for tab in (source_page, library_page, compare_page, checklist_page, profiles_page):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        self._build_source_page(source_page)
        self._build_library_page(library_page)
        self._build_compare_page(compare_page)
        self._build_checklist_page(checklist_page)
        self._build_profiles_page(profiles_page)

    def _build_source_page(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=2)
        parent.grid_columnconfigure(1, weight=3)
        parent.grid_rowconfigure(0, weight=1)

        source_panel = Panel(parent, "STIG Source")
        source_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        source_panel.grid_columnconfigure(0, weight=1)
        source_panel.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(source_panel, text="Family").grid(row=1, column=0, sticky="w", padx=12, pady=(8, 4))
        self.family_select = ctk.CTkComboBox(source_panel, values=["IOSXE_L2", "IOSXE_NDM"], state="readonly")
        self.family_select.set("IOSXE_L2")
        self.family_select.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))

        button_row = ctk.CTkFrame(source_panel, fg_color="transparent")
        button_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 8))
        button_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(button_row, text="Find Selected", command=self._download_latest).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(button_row, text="Find L2 + NDM", command=self._download_core_stigs).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(button_row, text="Import ZIP/XML", command=self._import_source).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        ctk.CTkLabel(source_panel, text="Direct ZIP/XML URL").grid(row=4, column=0, sticky="w", padx=12, pady=(6, 4))
        url_row = ctk.CTkFrame(source_panel, fg_color="transparent")
        url_row.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))
        url_row.grid_columnconfigure(0, weight=1)
        self.download_url = ctk.CTkEntry(url_row, placeholder_text="Paste Cyber Exchange ZIP/XML link")
        self.download_url.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.download_url.bind("<Return>", lambda _event: self._download_url())
        ctk.CTkButton(url_row, text="Download URL", width=120, command=self._download_url).grid(row=0, column=1)

        ctk.CTkButton(source_panel, text="Refresh Cached STIGs", command=self.app_controller.refresh_stig_metadata).grid(row=6, column=0, sticky="ew", padx=12, pady=(0, 8))
        ctk.CTkButton(source_panel, text="Build Starter Checks", command=self._generate_starter_checks).grid(row=7, column=0, sticky="ew", padx=12, pady=(0, 8))

        self.source_status = ctk.CTkLabel(source_panel, text="No STIG metadata loaded.", anchor="w", text_color=TEXT_MUTED)
        self.source_status.grid(row=8, column=0, sticky="ew", padx=12, pady=(2, 8))

        columns = ("family", "version", "benchmark_date", "rules")
        self.benchmark_tree = ttk.Treeview(source_panel, columns=columns, show="tree headings", height=8, selectmode="browse")
        self.benchmark_tree.heading("#0", text="Benchmark / Rule")
        self.benchmark_tree.heading("family", text="Family")
        self.benchmark_tree.heading("version", text="Version")
        self.benchmark_tree.heading("benchmark_date", text="Benchmark Date")
        self.benchmark_tree.heading("rules", text="Rules")
        self.benchmark_tree.column("#0", width=270, anchor="w")
        self.benchmark_tree.column("family", width=90, anchor="w")
        self.benchmark_tree.column("version", width=80, anchor="w")
        self.benchmark_tree.column("benchmark_date", width=120, anchor="w")
        self.benchmark_tree.column("rules", width=60, anchor="e")
        self.benchmark_tree.grid(row=10, column=0, sticky="nsew", padx=12, pady=(4, 12))
        self.benchmark_tree.bind("<<TreeviewSelect>>", self._selection_changed)

        detail_panel = Panel(parent, "STIG Metadata")
        detail_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        detail_panel.grid_columnconfigure(0, weight=1)
        detail_panel.grid_rowconfigure(1, weight=1)
        self.metadata = ctk.CTkTextbox(detail_panel, wrap="word")
        self.metadata.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self.metadata.insert("1.0", "Download or import a STIG ZIP/XML to view metadata here.")
        self.metadata.configure(state="disabled")

    def _build_library_page(self, parent: ctk.CTkBaseClass) -> None:
        """Build the local, versioned STIG release and impact workflow."""
        parent.grid_columnconfigure(0, weight=3)
        parent.grid_columnconfigure(1, weight=2)
        parent.grid_rowconfigure(1, weight=1)

        controls = Panel(parent, "Installed STIG Releases")
        controls.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 6))
        controls.grid_columnconfigure(7, weight=1)
        ctk.CTkButton(
            controls, text="Refresh", width=90,
            command=lambda: self.app_controller.refresh_stig_metadata(),
        ).grid(row=1, column=0, padx=(12, 6), pady=10)
        ctk.CTkButton(
            controls, text="Compare Previous", width=130,
            command=self._compare_library_previous,
        ).grid(row=1, column=1, padx=6, pady=10)
        ctk.CTkButton(
            controls, text="Compare Selected", width=130,
            command=self._compare_library_selected,
        ).grid(row=1, column=2, padx=6, pady=10)
        ctk.CTkButton(
            controls, text="Coverage", width=95,
            command=self._show_library_coverage,
        ).grid(row=1, column=3, padx=6, pady=10)
        ctk.CTkButton(
            controls, text="Generate Missing Starters", width=175,
            command=self._generate_library_starters,
        ).grid(row=1, column=4, padx=6, pady=10)
        ctk.CTkButton(
            controls, text="Mark Rule Reviewed", width=130,
            command=self._mark_library_rule_reviewed,
        ).grid(row=1, column=5, padx=6, pady=10)
        ctk.CTkButton(
            controls, text="Export Diff", width=105,
            command=self._export_library_diff,
        ).grid(row=1, column=6, padx=(6, 12), pady=10)
        self.library_status = ctk.CTkLabel(
            controls,
            text=("Import a STIG ZIP/XML to store an immutable release. "
                  "Select one release to compare it with its previous release, "
                  "or two compatible releases to compare them directly."),
            anchor="w", justify="left", wraplength=1050, text_color=TEXT_MUTED,
        )
        self.library_status.grid(row=2, column=0, columnspan=8, sticky="ew", padx=12, pady=(0, 10))

        release_panel = Panel(parent, "Release Library")
        release_panel.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(6, 12))
        release_panel.grid_columnconfigure(0, weight=1)
        release_panel.grid_rowconfigure(1, weight=1)
        release_columns = ("family", "benchmark", "version", "release", "rules")
        self.library_tree = ttk.Treeview(
            release_panel, columns=release_columns, show="headings", selectmode="extended"
        )
        for column, title, width in (
            ("family", "Family", 100), ("benchmark", "Benchmark", 180),
            ("version", "Version", 85), ("release", "Release", 90),
            ("rules", "Rules", 60),
        ):
            self.library_tree.heading(column, text=title)
            self.library_tree.column(column, width=width, anchor="w")
        self.library_tree.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))

        impact_panel = Panel(parent, "What Changed and What Needs Attention")
        impact_panel.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(6, 12))
        impact_panel.grid_columnconfigure(0, weight=1)
        impact_panel.grid_rowconfigure(2, weight=1)
        filter_row = ctk.CTkFrame(impact_panel, fg_color="transparent")
        filter_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 4))
        filter_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(filter_row, text="Filter").grid(row=0, column=0, padx=(0, 8))
        self.library_filter = ctk.CTkComboBox(
            filter_row,
            values=["All", "Added", "Removed", "Changed", "Unchanged", "YAML Review Required"],
            state="readonly", command=lambda _value: self._render_library_diff(),
        )
        self.library_filter.set("All")
        self.library_filter.grid(row=0, column=1, sticky="ew")
        diff_columns = ("change", "vuln", "fields", "impact")
        self.library_diff_tree = ttk.Treeview(
            impact_panel, columns=diff_columns, show="headings", selectmode="browse", height=12
        )
        for column, title, width in (
            ("change", "Change", 82), ("vuln", "Vuln ID", 105),
            ("fields", "Changed Fields", 155), ("impact", "Automation Impact", 210),
        ):
            self.library_diff_tree.heading(column, text=title)
            self.library_diff_tree.column(column, width=width, anchor="w")
        self.library_diff_tree.grid(row=2, column=0, sticky="nsew", padx=12, pady=(4, 8))
        self.library_diff_tree.bind("<<TreeviewSelect>>", self._library_diff_selection_changed)
        self.library_details = ctk.CTkTextbox(impact_panel, wrap="word", height=180)
        self.library_details.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))
        self._set_library_details(
            "A normalized comparison shows added, removed, changed, and unchanged rules. "
            "YAML impact identifies only automation that needs deliberate review; it never rewrites a check."
        )

    def _build_checklist_page(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        output_panel = Panel(parent, "Checklist Output")
        output_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        output_panel.grid_columnconfigure(1, weight=1)

        self.l2_ckl_template = self._add_ckl_template_row(
            output_panel,
            row=1,
            label="L2 template",
            family_key="IOSXE_L2",
            placeholder="Blank or existing L2 .ckl file",
        )
        self.ndm_ckl_template = self._add_ckl_template_row(
            output_panel,
            row=2,
            label="NDM template",
            family_key="IOSXE_NDM",
            placeholder="Blank or existing NDM .ckl file",
        )
        self.combined_ckl_template = self._add_ckl_template_row(
            output_panel,
            row=3,
            label="L2 + NDM template",
            family_key="COMBINED",
            placeholder="Optional combined L2 and NDM .ckl file",
        )
        self.ckl_template = self.l2_ckl_template

        ctk.CTkLabel(output_panel, text="Destination").grid(row=4, column=0, sticky="w", padx=12, pady=6)
        self.output_folder = ctk.CTkEntry(output_panel, placeholder_text="Completed-file folder")
        self.output_folder.grid(row=4, column=1, sticky="ew", padx=(12, 6), pady=6)
        self._bind_checklist_refresh(self.output_folder)
        ctk.CTkButton(output_panel, text="Browse", width=82, command=self._browse_output).grid(row=4, column=2, sticky="e", padx=(0, 12), pady=6)

        self.checklist_status = ctk.CTkLabel(
            output_panel,
            text="Select reusable CKL templates and the completed-file destination here. Scan family and report choices are selected on Audit Run.",
            anchor="w",
            text_color=TEXT_MUTED,
            wraplength=720,
            justify="left",
        )
        self.checklist_status.grid(row=5, column=0, columnspan=3, sticky="ew", padx=12, pady=(10, 12))

        summary_panel = Panel(parent, "Audit Readiness")
        summary_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        summary_panel.grid_columnconfigure(0, weight=1)
        self.setup_summary = ctk.CTkTextbox(summary_panel, wrap="word", height=260)
        self.setup_summary.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self._set_setup_summary("Audit Run shows the live readiness checklist before a scan starts.")

    def _build_compare_page(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=3)
        parent.grid_columnconfigure(1, weight=2)
        parent.grid_rowconfigure(1, weight=1)

        source_panel = Panel(parent, "Old vs. New STIG")
        source_panel.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 6))
        source_panel.grid_columnconfigure(0, weight=0)
        source_panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(source_panel, text="Old STIG").grid(row=1, column=0, sticky="w", padx=(12, 6), pady=5)
        self.old_stig_entry = ctk.CTkEntry(source_panel, placeholder_text="Previous XCCDF XML or STIG ZIP")
        self.old_stig_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=5)
        ctk.CTkButton(
            source_panel,
            text="Browse",
            width=82,
            command=lambda: self._browse_comparison_source("old"),
        ).grid(row=1, column=2, sticky="e", padx=(6, 12), pady=5)

        ctk.CTkLabel(source_panel, text="New STIG").grid(row=2, column=0, sticky="w", padx=(12, 6), pady=5)
        self.new_stig_entry = ctk.CTkEntry(source_panel, placeholder_text="Current XCCDF XML or STIG ZIP")
        self.new_stig_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=5)
        ctk.CTkButton(
            source_panel,
            text="Browse",
            width=82,
            command=lambda: self._browse_comparison_source("new"),
        ).grid(row=2, column=2, sticky="e", padx=(6, 12), pady=5)

        controls = ctk.CTkFrame(source_panel, fg_color="transparent")
        controls.grid(row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(6, 10))
        controls.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(controls, text="Benchmark").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.comparison_family = ctk.CTkComboBox(
            controls,
            values=["All benchmarks", "IOSXE_L2", "IOSXE_NDM"],
            state="readonly",
            width=160,
        )
        self.comparison_family.set("All benchmarks")
        self.comparison_family.grid(row=0, column=1, sticky="w", padx=(0, 12))
        ctk.CTkButton(controls, text="Compare", width=110, command=self._compare_stigs).grid(row=0, column=2, padx=(0, 8))
        self.export_comparison_button = ctk.CTkButton(
            controls,
            text="Export Markdown",
            width=140,
            state="disabled",
            command=self._export_comparison,
        )
        self.export_comparison_button.grid(row=0, column=4, sticky="e")

        self.comparison_status = ctk.CTkLabel(
            source_panel,
            text="Choose the previous and current STIG packages. Files are read directly and are not added to the cache.",
            anchor="w",
            justify="left",
            wraplength=1000,
            text_color=TEXT_MUTED,
        )
        self.comparison_status.grid(row=4, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 12))

        differences_panel = Panel(parent, "Differences")
        differences_panel.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(6, 12))
        differences_panel.grid_columnconfigure(0, weight=1)
        differences_panel.grid_rowconfigure(1, weight=1)
        columns = ("change", "family", "control", "fields", "target")
        self.comparison_tree = ttk.Treeview(
            differences_panel,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        headings = {
            "change": "Change",
            "family": "Family",
            "control": "Control",
            "fields": "Changed Fields",
            "target": "Local Target",
        }
        widths = {"change": 74, "family": 94, "control": 142, "fields": 190, "target": 230}
        for column in columns:
            self.comparison_tree.heading(column, text=headings[column])
            self.comparison_tree.column(column, width=widths[column], anchor="w")
        self.comparison_tree.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self.comparison_tree.bind("<<TreeviewSelect>>", self._comparison_selection_changed)

        details_panel = Panel(parent, "Update Guidance")
        details_panel.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(6, 12))
        details_panel.grid_columnconfigure(0, weight=1)
        details_panel.grid_rowconfigure(1, weight=1)
        self.comparison_details = ctk.CTkTextbox(details_panel, wrap="word")
        self.comparison_details.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self._set_comparison_details(
            "Select two STIG sources to see rule changes and the affected check, base profile, and site profile files."
        )

    def _build_profiles_page(self, parent: ctk.CTkBaseClass) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        header = Panel(parent, "Profile Selection")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 6))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="Active profile").grid(row=1, column=0, sticky="w", padx=12, pady=(10, 6))
        self.profile_select = ctk.CTkComboBox(
            header,
            values=[DEFAULT_PROFILE_NAME],
            command=self._profile_selected,
            state="readonly",
        )
        self.profile_select.set(DEFAULT_PROFILE_NAME)
        self.profile_select.grid(row=1, column=1, sticky="ew", padx=(12, 6), pady=(10, 6))
        ctk.CTkButton(
            header,
            text="New",
            width=82,
            command=self._new_profile,
        ).grid(row=1, column=2, sticky="e", padx=6, pady=(10, 6))
        ctk.CTkButton(
            header,
            text="Delete",
            width=82,
            command=self._delete_profile,
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
        ).grid(row=1, column=3, sticky="e", padx=(6, 12), pady=(10, 6))

        self.profile_note = ctk.CTkLabel(
            header,
            text="Selected profiles can inherit the base IOS-XE file and override only the values that differ.",
            anchor="w",
            text_color=TEXT_MUTED,
            wraplength=980,
            justify="left",
        )
        self.profile_note.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 10))

        base_panel = ctk.CTkFrame(parent, fg_color="transparent")
        base_panel.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=(6, 12))
        base_panel.grid_columnconfigure(0, weight=1)
        base_panel.grid_rowconfigure(0, weight=1)
        self.base_editor = YamlEditor(base_panel, "Base IOS-XE YAML")
        self.base_editor.grid(row=0, column=0, sticky="nsew")
        base_buttons = ctk.CTkFrame(base_panel, fg_color="transparent")
        base_buttons.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        base_buttons.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(base_buttons, text="Validate Base", command=self._validate_base_yaml).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(base_buttons, text="Save Base", command=self._save_base_yaml).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        profile_side = ctk.CTkFrame(parent, fg_color="transparent")
        profile_side.grid(row=1, column=1, sticky="nsew", padx=(6, 12), pady=(6, 12))
        profile_side.grid_columnconfigure(0, weight=1)
        profile_side.grid_rowconfigure(1, weight=1)

        effective_panel = Panel(profile_side, "Effective Values")
        effective_panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        effective_panel.grid_columnconfigure(1, weight=1)
        self.value_labels: dict[str, ctk.CTkLabel] = {}
        labels = [
            ("profile_name", "Name"),
            ("inherits", "Inherits"),
            ("unused_vlan", "Unused VLAN"),
            ("native_vlan", "Native VLAN"),
            ("management_vlan", "Management VLAN"),
            ("dhcp_vlans", "DHCP Snooping VLANs"),
            ("arp_vlans", "ARP Inspection VLANs"),
            ("radius_group", "RADIUS Group"),
            ("tacacs_group", "TACACS Group"),
        ]
        for offset, (key, text) in enumerate(labels, start=1):
            self.value_labels[key] = label_value(effective_panel, offset, text, "-")

        selected_panel = ctk.CTkFrame(profile_side, fg_color="transparent")
        selected_panel.grid(row=1, column=0, sticky="nsew")
        selected_panel.grid_columnconfigure(0, weight=1)
        selected_panel.grid_rowconfigure(0, weight=1)
        self.profile_editor = YamlEditor(selected_panel, "Selected Profile YAML")
        self.profile_editor.grid(row=0, column=0, sticky="nsew")
        selected_buttons = ctk.CTkFrame(selected_panel, fg_color="transparent")
        selected_buttons.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        selected_buttons.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(selected_buttons, text="Validate Profile", command=self._validate_profile_yaml).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(selected_buttons, text="Save Profile", command=self._save_profile_yaml).grid(row=0, column=1, sticky="ew", padx=(6, 0))

    def _add_ckl_template_row(
        self,
        panel: ctk.CTkBaseClass,
        *,
        row: int,
        label: str,
        family_key: str,
        placeholder: str,
    ) -> ctk.CTkEntry:
        ctk.CTkLabel(panel, text=label).grid(row=row, column=0, sticky="w", padx=12, pady=6)
        entry = ctk.CTkEntry(panel, placeholder_text=placeholder)
        entry.grid(row=row, column=1, sticky="ew", padx=(12, 6), pady=6)
        self._bind_checklist_refresh(entry)
        ctk.CTkButton(
            panel,
            text="Browse",
            width=82,
            command=lambda: self._browse_ckl(family_key),
        ).grid(row=row, column=2, sticky="e", padx=(0, 12), pady=6)
        return entry

    def refresh_metadata(self, metadata_items: list[StigBenchmarkMetadata]) -> None:
        self.metadata_items = metadata_items
        self.rule_lookup = {}
        for item in self.benchmark_tree.get_children():
            self.benchmark_tree.delete(item)
        for benchmark_index, metadata in enumerate(metadata_items):
            bench_iid = f"benchmark-{benchmark_index}"
            self.benchmark_tree.insert(
                "",
                "end",
                iid=bench_iid,
                text=metadata.display_name,
                values=(
                    metadata.family,
                    metadata.version,
                    metadata.benchmark_release_date or "Unknown",
                    metadata.rule_count,
                ),
                open=False,
            )
            for rule_index, rule in enumerate(metadata.rules):
                rule_iid = f"rule-{benchmark_index}-{rule_index}"
                self.rule_lookup[rule_iid] = (metadata, rule)
                self.benchmark_tree.insert(
                    bench_iid,
                    "end",
                    iid=rule_iid,
                    text=f"{rule.stig_id or rule.vuln_id} - {rule.title}",
                    values=(metadata.family, rule.severity, "", ""),
                )
        self.source_status.configure(text=f"{len(metadata_items)} cached STIG source(s) loaded.")
        if metadata_items:
            self._show_benchmark(metadata_items[0])
        else:
            self._set_detail("Download or import a STIG ZIP/XML to view metadata here.")

    def refresh_library(self, releases: list[StigBenchmarkMetadata]) -> None:
        self.library_items = releases
        for item in self.library_tree.get_children():
            self.library_tree.delete(item)
        for release in releases:
            if release.database_id is None:
                continue
            self.library_tree.insert(
                "", "end", iid=str(release.database_id), values=(
                    release.family, release.benchmark_id, release.version,
                    release.release_label, release.rule_count,
                )
            )
        self.library_status.configure(
            text=f"{len(releases)} installed STIG release(s). "
                 "Releases are retained independently and never overwrite older imports."
        )

    def show_library_diff(self, diff: StigDiff) -> None:
        self.library_diff = diff
        self.library_filter.set("All")
        self._render_library_diff()

    def _selected_library_ids(self) -> list[int]:
        result: list[int] = []
        for item in self.library_tree.selection():
            try:
                result.append(int(item))
            except ValueError:
                continue
        return result

    def _compare_library_previous(self) -> None:
        selected = self._selected_library_ids()
        if len(selected) != 1:
            self.library_status.configure(text="Select exactly one installed release to compare with its previous release.")
            return
        self.app_controller.compare_installed_stig_to_previous(selected[0])

    def _compare_library_selected(self) -> None:
        selected = self._selected_library_ids()
        if len(selected) != 2:
            self.library_status.configure(text="Select exactly two compatible installed releases to compare.")
            return
        self.app_controller.compare_installed_stigs(selected[0], selected[1])

    def _show_library_coverage(self) -> None:
        selected = self._selected_library_ids()
        if len(selected) != 1:
            self.library_status.configure(text="Select one installed release to view coverage.")
            return
        try:
            coverage = self.app_controller.installed_stig_coverage(selected[0])
        except Exception as exc:
            self.library_status.configure(text=f"Could not calculate coverage: {exc}")
            return
        self._set_library_details(
            f"Coverage: {coverage.family} {coverage.benchmark_id} {coverage.release}\n\n"
            f"Total rules: {coverage.total_rules}\n"
            f"Automated mappings: {coverage.automated} ({coverage.automation_mapping_percent:.2f}%)\n"
            f"Current reviewed automation: {coverage.current_reviewed_automation_percent:.2f}%\n"
            f"Manual review: {coverage.manual_review}\n"
            f"Missing check: {coverage.missing_check}\n"
            f"Changed / review required: {coverage.changed_review_required}\n"
            f"Retired mapping review: {coverage.retired_mapping}\n\n"
            "Current reviewed automation counts only automated checks whose recorded STIG fingerprint matches this release."
        )
        self.library_status.configure(text="Coverage calculated for the selected release.")

    def _generate_library_starters(self) -> None:
        selected = self._selected_library_ids()
        if len(selected) != 1:
            self.library_status.configure(text="Select one installed release before generating starter checks.")
            return
        try:
            path = self.app_controller.generate_installed_stig_starters(selected[0])
            self.library_status.configure(text=f"Generated non-overwriting manual_review starters in {path.name}.")
        except Exception as exc:
            self.library_status.configure(text=f"Starter generation failed: {exc}")

    def _mark_library_rule_reviewed(self) -> None:
        selected_releases = self._selected_library_ids()
        selected_rules = self.library_diff_tree.selection()
        if len(selected_releases) != 1 or len(selected_rules) != 1:
            self.library_status.configure(
                text="Select one current release and one uniquely mapped rule in the difference view."
            )
            return
        rule = self.library_diff_lookup.get(selected_rules[0])
        if rule is None or rule.new_rule is None:
            self.library_status.configure(text="Only a current (added, changed, or unchanged) rule can be marked reviewed.")
            return
        try:
            self.app_controller.mark_installed_stig_automation_reviewed(
                selected_releases[0], rule.vuln_id
            )
            self.library_status.configure(
                text=f"Recorded review of {rule.vuln_id} against the selected release fingerprint."
            )
        except Exception as exc:
            self.library_status.configure(text=f"Could not mark review: {exc}")

    def _export_library_diff(self) -> None:
        if self.library_diff is None:
            self.library_status.configure(text="Compare releases before exporting a diff.")
            return
        destination = filedialog.asksaveasfilename(
            title="Export STIG release diff",
            initialdir=str(self.app_controller.operator_workspace.stig_comparisons),
            defaultextension=".xlsx",
            initialfile="stig_release_diff.xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("JSON", "*.json"), ("CSV", "*.csv")],
        )
        if not destination:
            return
        try:
            path = self.app_controller.export_installed_stig_diff(
                self.library_diff, Path(destination)
            )
            self.library_status.configure(text=f"Exported STIG difference report to {path.name}.")
        except Exception as exc:
            self.library_status.configure(text=f"Diff export failed: {exc}")

    def _render_library_diff(self) -> None:
        for item in self.library_diff_tree.get_children():
            self.library_diff_tree.delete(item)
        self.library_diff_lookup = {}
        diff = self.library_diff
        if diff is None:
            return
        if diff.status.value == "NO_PREVIOUS_RELEASE":
            self.library_status.configure(
                text="No previous compatible release exists. This import is the baseline; it is not treated as every rule changing."
            )
            self._set_library_details("Baseline release installed. Import a later release to calculate a normalized rule and YAML impact diff.")
            return
        active_filter = self.library_filter.get()
        review_impacts = {"AUTOMATION_REVIEW_REQUIRED", "MANUAL_RULE_REVIEW"}
        impacts_by_vuln: dict[str, list[object]] = {}
        for impact in diff.yaml_impacts:
            impacts_by_vuln.setdefault(impact.vuln_id, []).append(impact)
        visible: list[RuleDiff] = []
        for rule in diff.rule_diffs:
            if active_filter == "YAML Review Required":
                if not any(item.impact.value in review_impacts for item in impacts_by_vuln.get(rule.vuln_id, [])):
                    continue
            elif active_filter != "All" and rule.classification.value.title() != active_filter:
                continue
            visible.append(rule)
        for index, rule in enumerate(visible):
            iid = f"library-diff-{index}"
            self.library_diff_lookup[iid] = rule
            rule_impacts = impacts_by_vuln.get(rule.vuln_id, [])
            impact_text = ", ".join(sorted({self._friendly_impact(item.impact.value) for item in rule_impacts})) or "No local check"
            self.library_diff_tree.insert(
                "", "end", iid=iid, values=(
                    rule.classification.value, rule.vuln_id,
                    ", ".join(rule.changed_fields) or "-", impact_text,
                )
            )
        summary = diff.summary
        self.library_status.configure(
            text=(f"{diff.family} {diff.old_release} -> {diff.new_release}: "
                  f"{summary['added']} added, {summary['removed']} removed, "
                  f"{summary['changed']} changed, {summary['unchanged']} unchanged; "
                  f"{summary['yaml_review_required']} YAML review required.")
        )
        if visible:
            first = "library-diff-0"
            self.library_diff_tree.selection_set(first)
            self.library_diff_tree.focus(first)
            self._show_library_rule_diff(visible[0])
        else:
            self._set_library_details("No rules match the current filter.")

    def _library_diff_selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.library_diff_tree.selection()
        if selected and selected[0] in self.library_diff_lookup:
            self._show_library_rule_diff(self.library_diff_lookup[selected[0]])

    def _show_library_rule_diff(self, rule: RuleDiff) -> None:
        diff = self.library_diff
        impacts = [] if diff is None else [
            item for item in diff.yaml_impacts if item.vuln_id == rule.vuln_id
        ]
        lines = [
            f"{rule.classification.value}: {rule.vuln_id}",
            f"Old Rule ID: {rule.old_rule_id or '-'}",
            f"New Rule ID: {rule.new_rule_id or '-'}",
            f"Match basis: {rule.match_basis or '-'}",
            f"Changed fields: {', '.join(rule.changed_fields) or 'None'}",
            "",
            "WHY IT MATTERS:",
            self._why_diff_matters(rule),
        ]
        if rule.notes:
            lines.extend(["", "Matching notes:"] + [f"- {note}" for note in rule.notes])
        if impacts:
            lines.extend(["", "YAML impact:"])
            for impact in impacts:
                lines.extend([
                    f"- {self._friendly_impact(impact.impact.value)}: {impact.yaml_file or 'No local check'}",
                    f"  Check type: {impact.check_type or '-'}; automation: {impact.automation_status or '-'}",
                    f"  Recommendation: {impact.recommended_action}",
                ])
        for field in rule.field_diffs:
            if field.field not in {"check_text", "fix_text"}:
                continue
            lines.extend([
                "", f"OLD {field.field.upper()}:", field.old_value or "(empty)",
                f"NEW {field.field.upper()}:", field.new_value or "(empty)",
            ])
        self._set_library_details("\n".join(lines))

    @staticmethod
    def _friendly_impact(value: str) -> str:
        return {
            "AUTOMATION_REVIEW_REQUIRED": "Automation needs review",
            "NEW_CHECK_REQUIRED": "New rule — create a check",
            "RETIRE_CHECK_REVIEW": "Removed rule — review retirement",
            "FIX_GUIDANCE_CHANGED": "DISA fix guidance changed",
            "METADATA_UPDATE": "Metadata update",
            "MANUAL_RULE_REVIEW": "Manual procedure changed",
            "NO_ACTION_REQUIRED": "No action",
            "NO_LOCAL_CHECK": "No local check",
            "AMBIGUOUS_MAPPING": "Mapping needs review",
        }.get(value, value.replace("_", " ").title())

    @staticmethod
    def _why_diff_matters(rule: RuleDiff) -> str:
        fields = set(rule.changed_fields)
        if rule.classification is RuleChange.ADDED:
            return "DISA added a requirement. Create a manual-review starter, then decide whether deterministic automation is appropriate."
        if rule.classification is RuleChange.REMOVED:
            return "DISA removed this vulnerability. Keep historical mappings, but review whether the check should run for the new release."
        if "check_text" in fields:
            return "DISA changed the check procedure. Review the existing automation because required evidence or evaluation logic may have changed."
        if fields == {"fix_text"}:
            return "DISA changed remediation guidance. STIG Audit Pro remains read-only, so audit logic may still be valid, but the guidance must be reviewed."
        if fields and fields <= {"severity", "title", "rule_id", "stig_id"}:
            return "DISA changed rule metadata. Update local metadata; automated evaluation logic does not appear to require modification."
        return "Review the field-level changes and the recommended automation impact before using this release for new audits."

    def _set_library_details(self, text: str) -> None:
        self.library_details.configure(state="normal")
        self.library_details.delete("1.0", "end")
        self.library_details.insert("1.0", text)
        self.library_details.configure(state="disabled")

    def refresh_profile(self, profile: SiteProfile, yaml_path: Path, base_path: Path) -> None:
        self.current_profile_path = yaml_path
        self.base_profile_path = base_path
        if hasattr(self.app_controller, "available_profile_names"):
            values = self.app_controller.available_profile_names()
            self.profile_select.configure(values=values)
        self.profile_select.set(profile.profile_name)
        self.profile_editor.set_text(yaml_path.read_text(encoding="utf-8"))
        self.profile_editor.set_status("Profile loaded")
        self.base_editor.set_text(base_path.read_text(encoding="utf-8"))
        self.base_editor.set_status("Base loaded")
        self.value_labels["profile_name"].configure(text=profile.profile_name)
        self.value_labels["inherits"].configure(text=str(getattr(profile, "inherits", None) or "-"))
        self.value_labels["unused_vlan"].configure(text=str(profile.unused_vlan))
        self.value_labels["native_vlan"].configure(text=str(profile.native_vlan))
        self.value_labels["management_vlan"].configure(text=str(profile.management_vlan))
        self.value_labels["dhcp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.dhcp_snooping.vlans))
        self.value_labels["arp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.arp_inspection.vlans))
        self.value_labels["radius_group"].configure(text=profile.endpoint_authentication.radius_group)
        tacacs_group = profile.variables.get("tacacs_group", "-")
        self.value_labels["tacacs_group"].configure(text=str(tacacs_group))

    def show_comparison(self, report: StigComparisonReport) -> None:
        self.comparison_report = report
        self.comparison_lookup = {}
        for item in self.comparison_tree.get_children():
            self.comparison_tree.delete(item)
        for index, change in enumerate(report.changes):
            iid = f"comparison-{index}"
            self.comparison_lookup[iid] = change
            self.comparison_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    change.kind,
                    change.family,
                    change.control_id,
                    ", ".join(change.changed_fields) or "Entire control",
                    change.update_target,
                ),
            )
        old_summary = self._benchmark_versions(report.old_benchmarks)
        new_summary = self._benchmark_versions(report.new_benchmarks)
        self.comparison_status.configure(
            text=f"{report.summary}. Old: {old_summary}. New: {new_summary}."
        )
        self.export_comparison_button.configure(state="normal")
        if report.changes:
            first = "comparison-0"
            self.comparison_tree.selection_set(first)
            self.comparison_tree.focus(first)
            self.comparison_tree.see(first)
            self._show_comparison_change(report.changes[0])
        else:
            self._set_comparison_details(
                "No rule-level differences were found. Benchmark version and release metadata are still included in the exported report."
            )

    def set_status(self, message: str) -> None:
        self.source_status.configure(text=message)

    def set_comparison_status(self, message: str) -> None:
        self.comparison_status.configure(text=message)

    def set_checklist_status(self, message: str) -> None:
        self.checklist_status.configure(text=message)
        self._set_setup_summary(message)

    def set_scan_running(self, running: bool) -> None:
        return

    def set_ckl_template_path(self, family_key: str, path: Path) -> None:
        entries = {
            "IOSXE_L2": self.l2_ckl_template,
            "IOSXE_NDM": self.ndm_ckl_template,
            "COMBINED": self.combined_ckl_template,
        }
        entry = entries.get(family_key)
        if entry is None:
            return
        self.selected_ckl_paths[family_key] = path
        if family_key == "IOSXE_L2":
            self.selected_ckl_path = path
        entry.delete(0, "end")
        entry.insert(0, str(path))
        self._checklist_options_changed()

    def set_checklist_output_dir(self, path: Path) -> None:
        self.selected_output_dir = path
        self.output_folder.delete(0, "end")
        self.output_folder.insert(0, str(path))
        self._checklist_options_changed()

    def get_checklist_settings(self) -> dict[str, object]:
        self._sync_checklist_state()
        return {
            "ckl_paths": dict(self.selected_ckl_paths),
            "output_dir": self.selected_output_dir,
        }

    def _sync_checklist_state(self) -> None:
        entries = {
            "IOSXE_L2": self.l2_ckl_template,
            "IOSXE_NDM": self.ndm_ckl_template,
            "COMBINED": self.combined_ckl_template,
        }
        self.selected_ckl_paths = {
            key: Path(value) if (value := entry.get().strip().strip('"')) else None
            for key, entry in entries.items()
        }
        self.selected_ckl_path = self.selected_ckl_paths["IOSXE_L2"]
        output_text = self.output_folder.get().strip().strip('"')
        self.selected_output_dir = Path(output_text) if output_text else None

    def _checklist_options_changed(self, *_unused: object) -> None:
        self._sync_checklist_state()
        if hasattr(self.app_controller, "refresh_audit_preflight"):
            self.app_controller.refresh_audit_preflight()

    def _bind_checklist_refresh(self, entry: ctk.CTkEntry) -> None:
        entry.bind("<KeyRelease>", lambda _event: self.after_idle(self._checklist_options_changed))
        entry.bind("<FocusOut>", lambda _event: self.after_idle(self._checklist_options_changed))

    def _browse_ckl(self, family_key: str = "IOSXE_L2") -> None:
        labels = {
            "IOSXE_L2": "L2",
            "IOSXE_NDM": "NDM",
            "COMBINED": "combined L2 and NDM",
        }
        path = filedialog.askopenfilename(
            title=f"Select {labels.get(family_key, family_key)} checklist template",
            initialdir=str(self.app_controller.operator_workspace.ckl_templates),
            filetypes=[("DISA checklist", "*.ckl"), ("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        selected = Path(path)
        if hasattr(self.app_controller, "set_checklist_template"):
            self.app_controller.set_checklist_template(family_key, selected)
        else:
            self.set_ckl_template_path(family_key, selected)
        if not self.output_folder.get().strip():
            if hasattr(self.app_controller, "set_checklist_output_dir"):
                self.app_controller.set_checklist_output_dir(selected.parent)
            else:
                self.set_checklist_output_dir(selected.parent)
        self.set_checklist_status(f"Selected {labels.get(family_key, family_key)} template: {selected.name}.")

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(
            title="Select completed-file destination",
            initialdir=str(self.app_controller.operator_workspace.completed_ckls),
        )
        if not path:
            return
        selected = Path(path)
        if hasattr(self.app_controller, "set_checklist_output_dir"):
            self.app_controller.set_checklist_output_dir(selected)
        else:
            self.set_checklist_output_dir(selected)
        self.set_checklist_status(f"Destination selected: {selected}.")

    def _profile_selected(self, value: str) -> None:
        self.app_controller.select_profile(value)

    def _new_profile(self) -> None:
        dialog = ctk.CTkInputDialog(
            title="New Profile",
            text="Profile name (letters, numbers, underscores, or hyphens):",
        )
        profile_name = (dialog.get_input() or "").strip()
        if not profile_name:
            self.profile_editor.set_status("Profile creation cancelled")
            return
        ok, message = self.app_controller.create_profile(profile_name)
        self.profile_editor.set_status(message, ok=ok)

    def _delete_profile(self) -> None:
        profile_name = self.profile_select.get().strip()
        if not profile_name:
            self.profile_editor.set_status("Choose a profile to delete", ok=False)
            return
        if profile_name == DEFAULT_PROFILE_NAME:
            self.profile_editor.set_status("The base profile cannot be deleted", ok=False)
            return
        if not confirm_action(
            self,
            title="Delete Profile",
            message=(
                f"Delete the profile '{profile_name}'? Device groups that "
                "reference it will need a new profile selected."
            ),
            confirm_text="Delete",
        ):
            self.profile_editor.set_status("Profile delete cancelled")
            return
        ok, message = self.app_controller.delete_profile(profile_name)
        self.profile_editor.set_status(message, ok=ok)

    def _validate_base_yaml(self) -> None:
        ok, message = self.app_controller.validate_profile_yaml(self.base_editor.get_text())
        self.base_editor.set_status(message, ok=ok)

    def _save_base_yaml(self) -> None:
        if self.base_profile_path is None:
            self.base_editor.set_status("Base profile is not loaded", ok=False)
            return
        ok, message = self.app_controller.save_profile_yaml(
            self.base_profile_path,
            self.base_editor.get_text(),
            activate=self.current_profile_path == self.base_profile_path,
        )
        self.base_editor.set_status(message, ok=ok)

    def _validate_profile_yaml(self) -> None:
        ok, message = self.app_controller.validate_profile_yaml(self.profile_editor.get_text())
        self.profile_editor.set_status(message, ok=ok)

    def _save_profile_yaml(self) -> None:
        if self.current_profile_path is None:
            self.profile_editor.set_status("Choose a profile first", ok=False)
            return
        ok, message = self.app_controller.save_profile_yaml(
            self.current_profile_path,
            self.profile_editor.get_text(),
        )
        self.profile_editor.set_status(message, ok=ok)

    def _browse_comparison_source(self, which: str) -> None:
        path = filedialog.askopenfilename(
            title=f"Select {which} STIG source",
            initialdir=str(self.app_controller.operator_workspace.stig_packages),
            filetypes=[("STIG source", "*.zip *.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        entry = self.old_stig_entry if which == "old" else self.new_stig_entry
        entry.delete(0, "end")
        entry.insert(0, path)

    def _compare_stigs(self) -> None:
        old_text = self.old_stig_entry.get().strip().strip('"')
        new_text = self.new_stig_entry.get().strip().strip('"')
        if not old_text or not new_text:
            self.set_comparison_status("Choose both an old and a new STIG source before comparing.")
            return
        family_value = self.comparison_family.get()
        family = None if family_value == "All benchmarks" else family_value
        report = self.app_controller.compare_stig_sources(
            Path(old_text),
            Path(new_text),
            family,
        )
        if report is not None:
            self.show_comparison(report)

    def _export_comparison(self) -> None:
        if self.comparison_report is None:
            self.set_comparison_status("Run a STIG comparison before exporting.")
            return
        old_stem = Path(self.comparison_report.old_source).stem
        new_stem = Path(self.comparison_report.new_source).stem
        destination = filedialog.asksaveasfilename(
            title="Export STIG comparison report",
            initialdir=str(self.app_controller.operator_workspace.stig_comparisons),
            defaultextension=".md",
            initialfile=f"stig_comparison_{old_stem}_to_{new_stem}.md",
            filetypes=[("Markdown report", "*.md"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            path = self.comparison_report.write_markdown(destination)
            self.set_comparison_status(
                f"Exported {self.comparison_report.summary} to {path}."
            )
            if hasattr(self.app_controller, "set_status"):
                self.app_controller.set_status(f"Exported STIG comparison report to {path.name}.")
        except OSError as exc:
            self.set_comparison_status(f"Could not export comparison report: {exc}")

    def _comparison_selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.comparison_tree.selection()
        if not selected:
            return
        change = self.comparison_lookup.get(selected[0])
        if change is not None:
            self._show_comparison_change(change)

    def _show_comparison_change(self, change: StigRuleChange) -> None:
        fields = ", ".join(change.changed_fields) or "Entire control"
        lines = [
            f"{change.kind}: {change.control_id}",
            change.title,
            "",
            f"Family: {change.family}",
            f"Old ID: {change.old_identifier}",
            f"New ID: {change.new_identifier}",
            f"Changed fields: {fields}",
            f"Local target: {change.update_target}",
            "",
            "Recommended review:",
        ]
        lines.extend(f"- {guidance}" for guidance in change.guidance_lines())
        if change.kind == "Changed":
            lines.extend(["", "Changed content:"])
            for attribute, label in RULE_FIELDS:
                if label not in change.changed_fields:
                    continue
                old_value = getattr(change.old_rule, attribute, "") if change.old_rule else ""
                new_value = getattr(change.new_rule, attribute, "") if change.new_rule else ""
                lines.extend(
                    [
                        "",
                        label,
                        f"OLD: {old_value or '(empty)'}",
                        f"NEW: {new_value or '(empty)'}",
                    ]
                )
        self._set_comparison_details("\n".join(lines))

    def _set_comparison_details(self, text: str) -> None:
        self.comparison_details.configure(state="normal")
        self.comparison_details.delete("1.0", "end")
        self.comparison_details.insert("1.0", text)
        self.comparison_details.configure(state="disabled")

    @staticmethod
    def _benchmark_versions(benchmarks: tuple[StigBenchmarkMetadata, ...]) -> str:
        return ", ".join(
            f"{item.family} {item.version or 'version unknown'} "
            f"({item.benchmark_release_date or 'date unknown'})"
            for item in benchmarks
        )

    def _download_latest(self) -> None:
        self.app_controller.download_latest_stig(self.family_select.get())

    def _download_core_stigs(self) -> None:
        self.app_controller.download_core_stigs()

    def _download_url(self) -> None:
        self.app_controller.download_stig_from_url(self.download_url.get(), self.family_select.get())

    def _generate_starter_checks(self) -> None:
        self.app_controller.generate_starter_checks_from_stigs()

    def _import_source(self) -> None:
        path = filedialog.askopenfilename(
            title="Import STIG source",
            initialdir=str(self.app_controller.operator_workspace.stig_packages),
            filetypes=[("STIG source", "*.zip *.xml"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.import_stig_source(Path(path), self.family_select.get())

    def _run_checklist_audit(self) -> None:
        self.app_controller.show_tab("Audit Run")
        self.set_checklist_status("Checklist audits run from Audit Run.")

    def _run_l2_audit(self) -> None:
        self._run_checklist_audit()

    def _selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.benchmark_tree.selection()
        if not selected:
            return
        iid = selected[0]
        if iid in self.rule_lookup:
            metadata, rule = self.rule_lookup[iid]
            self._show_rule(metadata, rule)
            return
        if iid.startswith("benchmark-"):
            index = int(iid.split("-", 1)[1])
            if index < len(self.metadata_items):
                self._show_benchmark(self.metadata_items[index])

    def _show_benchmark(self, metadata: StigBenchmarkMetadata) -> None:
        text = (
            f"{metadata.display_name}\n\n"
            f"Family: {metadata.family}\n"
            f"Benchmark ID: {metadata.benchmark_id}\n"
            f"Version: {metadata.version}\n"
            f"Release: {metadata.release_info}\n"
            f"Benchmark Date: {metadata.benchmark_release_date}\n"
            f"Status Date: {metadata.release_date}\n"
            f"Rules: {metadata.rule_count}\n"
            f"Source: {metadata.source_filename}\n"
            f"Imported: {metadata.imported_at}\n"
        )
        self._set_detail(text)

    def _show_rule(self, metadata: StigBenchmarkMetadata, rule: StigRuleMetadata) -> None:
        text = (
            f"{rule.stig_id or rule.vuln_id}\n{rule.title}\n\n"
            f"Family: {metadata.family}\n"
            f"Vuln ID: {rule.vuln_id}\n"
            f"Rule ID: {rule.rule_id}\n"
            f"Severity: {rule.severity}\n\n"
            f"Check Text:\n{rule.check_text}\n\n"
            f"Fix Text:\n{rule.fix_text}"
        )
        self._set_detail(text)

    def _set_detail(self, text: str) -> None:
        self.metadata.configure(state="normal")
        self.metadata.delete("1.0", "end")
        self.metadata.insert("1.0", text)
        self.metadata.configure(state="disabled")

    def _set_setup_summary(self, text: str) -> None:
        self.setup_summary.configure(state="normal")
        self.setup_summary.delete("1.0", "end")
        self.setup_summary.insert("1.0", text)
        self.setup_summary.configure(state="disabled")
