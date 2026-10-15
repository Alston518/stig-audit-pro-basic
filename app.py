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
    """Exercise bundled GUI + vault startup with isolated, disposable test data.

    This command never unlocks or exports an operator's existing vault.
    """
    import tempfile
    import customtkinter as ctk
    from stig_audit_pro.basic_app import BasicApp
    from stig_audit_pro.storage.basic_output_vault import BasicOutputVault
    with tempfile.TemporaryDirectory(prefix="stig-basic-selftest-") as directory:
        vault=BasicOutputVault.open_or_create("disposable test password only", Path(directory) / "vault")
        probe=vault.save("self-test.txt",b"self-test-only")
        assert vault.read(probe)==("self-test.txt",b"self-test-only")
        root=ctk.CTk()
        try:
            BasicApp(root,vault)
            root.update_idletasks()
            root.update()
        finally:
            root.destroy()


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
