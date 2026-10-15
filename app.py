"""Desktop entry point for STIG Audit Pro Basic.

Packaged windowed executables have no visible stderr. Report startup errors
instead of silently terminating after an operator unlocks the workspace.
"""
from __future__ import annotations

import traceback
from pathlib import Path


def _report_startup_error() -> None:
    """Write only startup exception details; never log a vault password."""
    error=traceback.format_exc()
    location=None
    try:
        from platformdirs import user_log_path
        location=Path(user_log_path("STIG Audit Pro Basic",appauthor=False)) / "startup-error.log"
        location.parent.mkdir(parents=True,exist_ok=True)
        location.write_text(error,encoding="utf-8")
    except OSError:
        location=None
    try:
        from tkinter import messagebox
        text="The application could not finish starting.\n\n" + error[-1500:]
        if location is not None:
            text+="\n\nDiagnostic log: "+str(location)
        messagebox.showerror("STIG Audit Pro Basic - Startup Error",text)
    except Exception:
        pass



def _self_test() -> None:
    """Test the packaged visible unlock screen and the real Basic GUI."""
    import tempfile
    import customtkinter as ctk
    from stig_audit_pro.basic_app import BasicApp, BasicUnlockScreen

    with tempfile.TemporaryDirectory(prefix="stig-basic-selftest-") as directory:
        location=Path(directory) / "vault"
        first=ctk.CTk()
        unlocked=[]
        try:
            screen=BasicUnlockScreen(first,unlocked.append,vault_root=location)
            assert screen.creating
            screen.password_input.insert(0,"disposable test password only")
            screen.confirm_input.insert(0,"disposable test password only")
            screen.attempt_unlock()
            assert len(unlocked)==1, screen.error_label.cget("text")
            vault=unlocked[0]
            saved=vault.save("test.txt",b"private test content")
            assert vault.read(saved)==("test.txt",b"private test content")
            screen.panel.destroy()
            BasicApp(first,vault)
            first.update_idletasks()
            first.update()
        finally:
            first.destroy()

        second=ctk.CTk()
        reopened=[]
        try:
            screen=BasicUnlockScreen(second,reopened.append,vault_root=location)
            assert not screen.creating
            screen.password_input.insert(0,"disposable test password only")
            screen.attempt_unlock()
            assert len(reopened)==1, screen.error_label.cget("text")
            assert reopened[0].read(saved)[1]==b"private test content"
        finally:
            second.destroy()

def main() -> None:
    try:
        from stig_audit_pro.logging_config import configure_logging
        configure_logging()
        import sys
        if sys.argv[1:] == ["--self-test"]:
            _self_test()
            return
        from stig_audit_pro.basic_app import run_basic_gui
        run_basic_gui()
    except Exception:
        _report_startup_error()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
