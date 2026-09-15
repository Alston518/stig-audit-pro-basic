"""Customer-facing offline license status and import controls."""

from __future__ import annotations

from datetime import timezone
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from stig_audit_pro.gui.widgets import PageFrame, Panel
from stig_audit_pro.licensing import LicenseManager, LicenseStatus


class LicenseTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        panel = Panel(self, "Offline License")
        panel.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        panel.grid_columnconfigure(1, weight=1)

        self.values: dict[str, ctk.CTkLabel] = {}
        labels = (
            ("status", "Status"),
            ("edition", "Edition"),
            ("customer", "Customer name"),
            ("license_id", "License ID"),
            ("expires", "Expiration date"),
            ("devices", "Device limit"),
            ("location", "License-file location"),
        )
        for row, (name, title) in enumerate(labels, start=1):
            ctk.CTkLabel(panel, text=title, anchor="w").grid(
                row=row, column=0, sticky="nw", padx=12, pady=6
            )
            value = ctk.CTkLabel(
                panel,
                text="—",
                anchor="w",
                justify="left",
                wraplength=760,
                font=ctk.CTkFont(weight="bold"),
            )
            value.grid(row=row, column=1, sticky="ew", padx=12, pady=6)
            self.values[name] = value

        buttons = ctk.CTkFrame(panel, fg_color="transparent")
        buttons.grid(row=8, column=0, columnspan=2, sticky="ew", padx=12, pady=(16, 8))
        buttons.grid_columnconfigure((0, 1), weight=1)
        self.import_button = ctk.CTkButton(
            buttons,
            text="Import License",
            command=self._choose_license,
        )
        self.import_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(
            buttons,
            text="View License Status",
            command=self.app_controller.refresh_license_status,
        ).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.message = ctk.CTkLabel(
            panel,
            text=(
                "Licenses are verified locally with the bundled publisher public key. "
                "No internet connection is required."
            ),
            anchor="w",
            justify="left",
            wraplength=900,
            text_color=("#475467", "#d0d5dd"),
        )
        self.message.grid(
            row=9, column=0, columnspan=2, sticky="ew", padx=12, pady=(4, 12)
        )

    def refresh(self, manager: LicenseManager) -> None:
        expires = "—"
        if manager.expires_at is not None:
            expires = (
                manager.expires_at.astimezone(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
        status = manager.status.value
        if manager.status is not LicenseStatus.VALID:
            status += " (Free mode)"
        self.values["status"].configure(text=status)
        self.values["edition"].configure(text=manager.edition)
        self.values["customer"].configure(text=manager.customer_name or "—")
        self.values["license_id"].configure(text=manager.license_id or "—")
        self.values["expires"].configure(text=expires)
        self.values["devices"].configure(text=str(manager.max_devices))
        self.values["location"].configure(text=str(manager.license_path))
        self.import_button.configure(
            text=(
                "Replace License"
                if manager.license_path.is_file()
                else "Import License"
            )
        )
        if manager.status is LicenseStatus.INVALID and manager.validation_errors:
            self.message.configure(
                text=(
                    "The installed license was rejected. "
                    f"{manager.validation_errors[0]}"
                )
            )
        elif manager.status is LicenseStatus.EXPIRED:
            self.message.configure(
                text=(
                    "This signed license has expired. The application is in Free mode; "
                    "existing results and CKL files remain available."
                )
            )
        elif manager.status is LicenseStatus.MISSING:
            self.message.configure(
                text="No license is installed. The application is operating in Free mode."
            )
        else:
            self.message.configure(
                text=(
                    "The license is valid and was verified locally. "
                    "The public key and signature are intentionally not displayed."
                )
            )

    def set_message(self, message: str) -> None:
        self.message.configure(text=message)

    def _choose_license(self) -> None:
        path = filedialog.askopenfilename(
            title="Import STIG Audit Pro license",
            filetypes=[
                ("STIG Audit Pro license", "*.license.json"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.app_controller.import_license_file(Path(path))
