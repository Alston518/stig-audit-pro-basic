"""Operator-safe diagnostics, support, and data protection controls."""

from __future__ import annotations

import customtkinter as ctk

from stig_audit_pro.gui.widgets import PageFrame, Panel


class AdministrationTab(PageFrame):
    def __init__(self, master, app_controller) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        heading = ctk.CTkFrame(self, fg_color="transparent")
        heading.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        heading.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(heading, text="Administration & Diagnostics", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(heading, text="Refresh Health", command=self.refresh).grid(row=0, column=1, padx=4)
        ctk.CTkButton(heading, text="Create Support Bundle", command=app_controller.create_support_bundle).grid(row=0, column=2, padx=4)
        ctk.CTkButton(heading, text="Back Up Data", command=app_controller.backup_application_data).grid(row=0, column=3, padx=4)
        ctk.CTkButton(heading, text="Restore Data", command=app_controller.restore_application_data, fg_color="#b42318", hover_color="#912018").grid(row=0, column=4, padx=4)
        folders = Panel(self, "Files & Folders")
        folders.grid(row=1, column=0, sticky="ew", padx=12, pady=6)
        folders.grid_columnconfigure(4, weight=1)
        ctk.CTkButton(folders, text="Open Workspace", command=app_controller.open_operator_workspace).grid(row=1, column=0, padx=(12, 6), pady=10)
        ctk.CTkButton(folders, text="Open Editable Checks", command=app_controller.open_checks_folder).grid(row=1, column=1, padx=6, pady=10)
        ctk.CTkButton(folders, text="Open Site Profiles", command=app_controller.open_profiles_folder).grid(row=1, column=2, padx=6, pady=10)
        ctk.CTkButton(folders, text="Open All App Data", command=app_controller.open_application_data_folder).grid(row=1, column=3, padx=6, pady=10)
        ctk.CTkLabel(
            folders,
            text=f"Workspace: {app_controller.operator_workspace.root}",
            anchor="w",
        ).grid(row=2, column=0, columnspan=5, sticky="ew", padx=12, pady=(0, 10))

        panel = Panel(self, "Application Health")
        panel.grid(row=2, column=0, sticky="nsew", padx=12, pady=(6, 12))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        self.details = ctk.CTkTextbox(panel, wrap="word", font=ctk.CTkFont(size=14))
        self.details.grid(row=1, column=0, sticky="nsew", padx=12, pady=12)
        ctk.CTkLabel(panel, text="Support bundles exclude credentials and raw device evidence. Evidence is kept indefinitely until you explicitly purge or delete it.", anchor="w", justify="left", wraplength=900).grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.refresh()

    def refresh(self) -> None:
        health = self.app_controller.application_health()
        lines = [f"{label:<30} {value}" for label, value in health]
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")


__all__ = ["AdministrationTab"]
