"""YAML editor surface used by Checks and Profiles tabs."""

from __future__ import annotations

import customtkinter as ctk

from stig_audit_pro.gui.widgets import BORDER_DARK, BORDER_LIGHT, PANEL_DARK, PANEL_LIGHT, TEXT_MUTED


class YamlEditor(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, title: str) -> None:
        super().__init__(
            master,
            corner_radius=8,
            border_width=1,
            fg_color=(PANEL_LIGHT, PANEL_DARK),
            border_color=(BORDER_LIGHT, BORDER_DARK),
        )
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w")
        self.status_label = ctk.CTkLabel(header, text="Ready", text_color=TEXT_MUTED)
        self.status_label.grid(row=0, column=1, sticky="e")

        self.textbox = ctk.CTkTextbox(self, wrap="none", font=ctk.CTkFont(family="Consolas", size=12))
        self.textbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    def set_text(self, text: str) -> None:
        self.textbox.delete("1.0", "end")
        self.textbox.insert("1.0", text)

    def get_text(self) -> str:
        return self.textbox.get("1.0", "end").strip() + "\n"

    def set_status(self, text: str, ok: bool = True) -> None:
        color = ("#1f6f45", "#7ee2a8") if ok else ("#9f1d1d", "#ffb4b4")
        self.status_label.configure(text=text, text_color=color)
