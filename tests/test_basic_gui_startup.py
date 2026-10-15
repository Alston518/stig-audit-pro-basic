"""Exercise the actual visible startup/unlock screen without mock password dialogs."""
from __future__ import annotations

import tkinter
import pytest


def _root():
    import customtkinter as ctk
    try:
        return ctk.CTk()
    except tkinter.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")


def test_unlock_screen_validates_and_reopens_vault(tmp_path):
    from stig_audit_pro.basic_app import BasicUnlockScreen
    vault_root = tmp_path / "vault"
    unlocked = []
    root = _root()
    try:
        screen = BasicUnlockScreen(root, unlocked.append, vault_root=vault_root)
        assert screen.creating
        assert root.state() != "withdrawn"
        screen.password_input.insert(0,"short")
        screen.attempt_unlock()
        assert not unlocked
        assert not (vault_root / "vault.json").exists()
        screen.password_input.delete(0,"end")
        screen.password_input.insert(0,"strong password for tests")
        screen.confirm_input.insert(0,"different")
        screen.attempt_unlock()
        assert not unlocked
        screen.confirm_input.delete(0,"end")
        screen.confirm_input.insert(0,"strong password for tests")
        screen.attempt_unlock()
        assert len(unlocked)==1
        assert (vault_root / "vault.json").is_file()
        encrypted = unlocked[0].save("test-report.txt", b"host-192.0.2.10")
        assert b"host-192.0.2.10" not in encrypted.read_bytes()
    finally:
        root.destroy()

    second_root = _root()
    try:
        screen = BasicUnlockScreen(second_root, unlocked.append, vault_root=vault_root)
        assert not screen.creating
        screen.password_input.insert(0,"wrong password")
        screen.attempt_unlock()
        assert len(unlocked)==1
        assert screen.unlock_button.cget("state") == "normal"
        screen.password_input.delete(0,"end")
        screen.password_input.insert(0,"strong password for tests")
        screen.attempt_unlock()
        assert len(unlocked)==2
        assert unlocked[-1].read(encrypted) == ("test-report.txt",b"host-192.0.2.10")
    finally:
        second_root.destroy()


def test_unlock_screen_does_not_open_gui_on_wrong_password(tmp_path):
    from stig_audit_pro.basic_app import BasicUnlockScreen
    from stig_audit_pro.storage.basic_output_vault import BasicOutputVault
    location = tmp_path / "vault"
    BasicOutputVault.open_or_create("strong password for tests", location)
    root = _root()
    observed=[]
    try:
        screen = BasicUnlockScreen(root, observed.append, vault_root=location)
        screen.password_input.insert(0,"wrong password")
        screen.attempt_unlock()
        assert not observed
        assert "incorrect" in screen.error_label.cget("text").lower()
    finally:
        root.destroy()
