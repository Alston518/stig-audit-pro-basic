"""Offline smoke entry point for a PyInstaller Basic build; no live SSH."""

from __future__ import annotations

import os
import queue
import sys
import threading
from pathlib import Path

from stig_audit_pro.basic_app import BasicApp
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore
from stig_audit_pro.licensing import LicenseManager
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
from stig_audit_pro.storage.device_groups import DeviceTargetRecord


def main() -> None:
    output = Path(os.environ["BASIC_SMOKE_OUTPUT"]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    bundled = Path(sys._MEIPASS) / "data"
    checks = load_check_library(bundled / "checks" / "iosxe_l2.yaml").checks
    profiles = bundled / "profiles"
    profile = load_profile(profiles / "base_iosxe_access.yaml", profiles_dir=profiles)
    vault = AtRestVault.open(output / "test-vault.json", "1", create=True)

    app = BasicApp.__new__(BasicApp)
    app.license_policy = BasicLicensePolicy(LicenseManager(output / "test-license.json"))
    app.artifacts = ProtectedArtifactStore(vault)
    app.events = queue.Queue()
    app.cancel_event = threading.Event()
    reports = output / "reports"
    app._run(
        [DeviceTargetRecord(ip="192.0.2.10")], checks, profile, None,
        ["iosxe_l2"], "Sample outputs", {}, True, False, reports,
    )
    protected = list(reports.glob("*.txt.sapenc"))
    final = list(app.events.queue)[-1].message
    assert len(protected) == 1, final
    assert str(protected[0]) in final, final
    assert b"192.0.2.10" in app.artifacts.read(protected[0])
    assert not list(reports.glob("*.txt"))
    print("PACKAGED_BASIC_REPORT_OK", protected[0].name)

    # Build the actual five-tab UI in the packaged environment with isolated
    # workspace and license paths. This catches missing Tk/data assets and
    # widget construction errors without contacting a device or user vault.
    os.environ["WIN_PD_OVERRIDE_PERSONAL"] = str(output / "Documents")
    os.environ["STIG_AUDIT_BASIC_LICENSE_PATH"] = str(output / "test-license.json")
    import customtkinter as ctk

    root = ctk.CTk()
    root.withdraw()
    try:
        gui = BasicApp(root, vault)
        root.update_idletasks()
        assert gui.tabs.get() == "Audit"
        assert gui.run_state_label.cget("text") == "NO RUN YET"
        assert gui.open_folder_button.cget("state") == "disabled"
        gui.mode.set("Live SSH")
        gui.update_mode_badge()
        assert "LIVE SSH" in gui.mode_badge.cget("text")
        print("PACKAGED_BASIC_GUI_OK")
        gui.on_close()
    finally:
        try:
            root.destroy()
        except Exception:
            # BasicApp.on_close already destroys the interpreter on success.
            pass


if __name__ == "__main__":
    main()
