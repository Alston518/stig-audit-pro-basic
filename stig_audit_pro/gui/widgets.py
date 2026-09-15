"""Small reusable customtkinter widgets for the desktop GUI."""

from __future__ import annotations

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk

SURFACE_LIGHT = "#f5f7fa"
SURFACE_DARK = "#111827"
PANEL_LIGHT = "#ffffff"
PANEL_DARK = "#172033"
BORDER_LIGHT = "#d0d5dd"
BORDER_DARK = "#344054"
TEXT_MUTED = ("#475467", "#d0d5dd")
PRIMARY = "#246bfe"
PRIMARY_HOVER = "#1d56d6"
DANGER = "#b42318"
DANGER_HOVER = "#912018"
SUCCESS = "#16803c"
WARNING = "#b54708"
NEUTRAL = "#667085"

STATUS_COLORS = {
    "NotAFinding": ("#d9f2e5", "#1f6f45"),
    "Open": ("#fde2e2", "#9f1d1d"),
    "Not_Applicable": ("#e4e7ec", "#4b5563"),
    "Not_Reviewed": ("#fff2cc", "#8a6116"),
    "Error": ("#ffe4cc", "#9a3412"),
    "Skipped": ("#e5e7eb", "#374151"),
}

STATUS_ACCENTS = {
    "NotAFinding": SUCCESS,
    "Open": DANGER,
    "Not_Applicable": NEUTRAL,
    "Not_Reviewed": WARNING,
    "Error": "#c2410c",
    "Skipped": NEUTRAL,
}


class PageFrame(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, **kwargs: object) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)


class Panel(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, title: str | None = None, **kwargs: object) -> None:
        super().__init__(
            master,
            corner_radius=8,
            border_width=1,
            fg_color=(PANEL_LIGHT, PANEL_DARK),
            border_color=(BORDER_LIGHT, BORDER_DARK),
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        self._row = 0
        if title:
            label = ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=15, weight="bold"))
            label.grid(row=self._row, column=0, sticky="w", padx=14, pady=(12, 6))
            self._row += 1

    def next_row(self) -> int:
        row = self._row
        self._row += 1
        return row


class Metric(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkBaseClass,
        label: str,
        value: str = "0",
        accent: str = PRIMARY,
    ) -> None:
        super().__init__(
            master,
            corner_radius=8,
            border_width=1,
            fg_color=(PANEL_LIGHT, PANEL_DARK),
            border_color=(BORDER_LIGHT, BORDER_DARK),
        )
        self.grid_columnconfigure(1, weight=1)
        self.accent = ctk.CTkFrame(self, width=4, corner_radius=2, fg_color=accent)
        self.accent.grid(row=0, column=0, rowspan=2, sticky="nsw", padx=(0, 0), pady=8)
        self.value_label = ctk.CTkLabel(self, text=value, font=ctk.CTkFont(size=22, weight="bold"))
        self.value_label.grid(row=0, column=1, sticky="w", padx=12, pady=(8, 0))
        self.label = ctk.CTkLabel(self, text=label, text_color=TEXT_MUTED)
        self.label.grid(row=1, column=1, sticky="w", padx=12, pady=(0, 8))

    def set(self, value: int | str) -> None:
        self.value_label.configure(text=str(value))


def label_value(parent: ctk.CTkBaseClass, row: int, label: str, value: str) -> ctk.CTkLabel:
    ctk.CTkLabel(parent, text=label, anchor="w").grid(row=row, column=0, sticky="w", padx=12, pady=4)
    value_label = ctk.CTkLabel(parent, text=value, anchor="e", font=ctk.CTkFont(weight="bold"))
    value_label.grid(row=row, column=1, sticky="e", padx=12, pady=4)
    return value_label


def configure_treeview_style() -> None:
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:  # type: ignore[name-defined]
        pass
    style.configure(
        "Treeview",
        rowheight=28,
        borderwidth=0,
        background=PANEL_LIGHT,
        fieldbackground=PANEL_LIGHT,
        foreground="#101828",
        font=("Segoe UI", 10),
    )
    style.configure(
        "Treeview.Heading",
        background="#eef2f6",
        foreground="#344054",
        font=("Segoe UI", 10, "bold"),
        relief="flat",
    )
    style.map(
        "Treeview",
        background=[("selected", "#dbeafe")],
        foreground=[("selected", "#101828")],
    )


def status_accent(status: str) -> str:
    return STATUS_ACCENTS.get(status, PRIMARY)


def confirm_action(
    parent: ctk.CTkBaseClass,
    *,
    title: str,
    message: str,
    confirm_text: str = "Yes",
) -> bool:
    """Show a lightweight confirmation dialog and return True only when confirmed."""
    confirmed = False
    dialog = ctk.CTkToplevel(parent)
    dialog.title(title)
    dialog.geometry("420x170")
    dialog.resizable(False, False)
    dialog.transient(parent.winfo_toplevel())
    dialog.grid_columnconfigure(0, weight=1)
    dialog.grid_rowconfigure(0, weight=1)

    content = ctk.CTkFrame(dialog, fg_color="transparent")
    content.grid(row=0, column=0, sticky="nsew", padx=18, pady=16)
    content.grid_columnconfigure((0, 1), weight=1)

    ctk.CTkLabel(
        content,
        text=message,
        anchor="w",
        justify="left",
        wraplength=380,
    ).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(4, 20))

    def close(value: bool) -> None:
        nonlocal confirmed
        confirmed = value
        dialog.grab_release()
        dialog.destroy()

    ctk.CTkButton(
        content,
        text="Cancel",
        fg_color="transparent",
        border_width=1,
        text_color=("gray10", "gray90"),
        command=lambda: close(False),
    ).grid(row=1, column=0, sticky="ew", padx=(0, 6))
    ctk.CTkButton(
        content,
        text=confirm_text,
        fg_color=DANGER,
        hover_color=DANGER_HOVER,
        command=lambda: close(True),
    ).grid(row=1, column=1, sticky="ew", padx=(6, 0))

    dialog.protocol("WM_DELETE_WINDOW", lambda: close(False))
    dialog.bind("<Escape>", lambda _event: close(False))
    dialog.after(10, dialog.grab_set)
    parent.wait_window(dialog)
    return confirmed
