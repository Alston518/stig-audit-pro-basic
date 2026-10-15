"""Exercise first-run password flow all the way into the Basic GUI."""
from __future__ import annotations

import tkinter

import pytest


def test_first_launch_and_relaunch_keep_same_encrypted_vault(tmp_path, monkeypatch):
    import customtkinter as ctk
    import tkinter.simpledialog as prompts
    import tkinter.messagebox as messagebox
    import stig_audit_pro.basic_app as basic
    import stig_audit_pro.storage.basic_output_vault as vault_module

    try:
        check=ctk.CTk()
    except tkinter.TclError as exc:
        pytest.skip(f"Tk is unavailable: {exc}")
    check.destroy()

    local_vault=tmp_path / "vault"
    monkeypatch.setattr(basic, "default_vault_root", lambda: local_vault)
    original=basic.BasicOutputVault.open_or_create
    monkeypatch.setattr(basic.BasicOutputVault, "open_or_create",
                        lambda password: original(password, local_vault))
    prompts_used=[]
    errors=[]
    monkeypatch.setattr(messagebox, "showerror",
                        lambda title, message, **kwargs: errors.append((title, message)))
    def short_mainloop(root):
        assert root.winfo_exists()
        root.update_idletasks()
        root.destroy()
    monkeypatch.setattr(ctk.CTk, "mainloop", short_mainloop)

    answers=iter(["short", "a secure test password", "a secure test password"])
    monkeypatch.setattr(prompts, "askstring",
                        lambda title, prompt, **kwargs: prompts_used.append(title) or next(answers))
    basic.run_basic_gui()
    assert (local_vault / "vault.json").is_file()
    assert len(prompts_used)==3
    assert errors and "too short" in errors[0][0].lower()

    answers=iter(["a secure test password"])
    monkeypatch.setattr(prompts, "askstring", lambda *args, **kwargs: next(answers))
    basic.run_basic_gui()
    assert not list(local_vault.glob("*.sapenc"))


def test_wrong_password_cannot_open_basic_workspace(tmp_path, monkeypatch):
    import customtkinter as ctk
    import tkinter.simpledialog as prompts
    import tkinter.messagebox as messagebox
    import stig_audit_pro.basic_app as basic

    try:
        check=ctk.CTk()
    except tkinter.TclError as exc:
        pytest.skip(f"Tk is unavailable: {exc}")
    check.destroy()

    local_vault=tmp_path / "vault"
    original=basic.BasicOutputVault.open_or_create
    original("a secure test password",local_vault)
    monkeypatch.setattr(basic, "default_vault_root", lambda: local_vault)
    monkeypatch.setattr(basic.BasicOutputVault, "open_or_create",
                        lambda password: original(password, local_vault))
    monkeypatch.setattr(prompts, "askstring", lambda *args, **kwargs: "wrong password")
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    monkeypatch.setattr(basic, "BasicApp", lambda *args, **kwargs: pytest.fail("GUI opened on wrong password"))
    basic.run_basic_gui()
