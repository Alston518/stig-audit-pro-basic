"""Offline smoke entry point for a PyInstaller Basic build; no live SSH."""

from __future__ import annotations

import os
import queue
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from stig_audit_pro.basic_app import BasicApp
from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile
from stig_audit_pro.gui.basic_host_keys import HostKeyBatchRequest, ReviewHostKeyBatchDialog
from stig_audit_pro.infrastructure.ssh.host_key_batch import HostKeyBatchEntry, HostKeyBatchPlan
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore
from stig_audit_pro.licensing import LicenseManager
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
from stig_audit_pro.reports.basic_summary import Filter, render_pdf, summarize
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceTargetRecord


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
    assert len(list(reports.glob("*.manifest.json.sapenc"))) == 1
    manifest = next(reports.glob("*.manifest.json.sapenc"))
    assert b'"file_hashes"' in app.artifacts.read_manifest(manifest)
    assert not list(reports.glob("*.txt"))
    print("PACKAGED_BASIC_REPORT_OK", protected[0].name)

    completed = list(app.events.queue)[-1]
    summary = summarize(completed.summary_results, Filter(), completed.summary_targets)
    assert render_pdf(summary).startswith(b"%PDF")
    app.last_results = completed.summary_results
    app.last_targets = completed.summary_targets
    app.last_families = completed.summary_families
    app.last_run_id = completed.summary_run_id
    app._summary_filter = lambda: Filter()
    app.output_dir = SimpleNamespace(get=lambda: str(reports))
    app.summary_pdf = SimpleNamespace(get=lambda: True)
    app.summary_html = SimpleNamespace(get=lambda: True)
    app.summary_csv = SimpleNamespace(get=lambda: True)
    app.messagebox = SimpleNamespace(
        showerror=lambda *args: (_ for _ in ()).throw(RuntimeError(args)),
        showinfo=lambda *_args: None,
    )
    app.preview_summary = lambda: None
    summary_files = app.export_summary()
    assert len(summary_files) == 3
    assert all(path.name.endswith(".sapenc") for path in summary_files)
    assert len(list(reports.glob("*.manifest.json.sapenc"))) == 2
    print("PACKAGED_BASIC_SUMMARY_OK")

    # Build the actual five-tab UI in the packaged environment with isolated
    # workspace and license paths. This catches missing Tk/data assets and
    # widget construction errors without contacting a device or user vault.
    os.environ["WIN_PD_OVERRIDE_PERSONAL"] = str(output / "Documents")
    os.environ["STIG_AUDIT_BASIC_LICENSE_PATH"] = str(output / "test-license.json")
    import customtkinter as ctk
    from tkinter import ttk

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
        gui._display_protected_manifest(manifest)
        assert "ENCRYPTED AUDIT MANIFEST" in gui.results_box.get("1.0", "end")
        assert protected[0].name in gui.results_box.get("1.0", "end")
        review = ReviewHostKeyBatchDialog.__new__(ReviewHostKeyBatchDialog)
        review.request = HostKeyBatchRequest(
            HostKeyBatchPlan((HostKeyBatchEntry(
                DeviceTarget("192.0.2.25"), "ssh-rsa", "synthetic-key", "SHA256:example",
            ),), (), ()), threading.Event(),
        )
        review_frame = ttk.Frame(root)
        review_list = review.body(review_frame)
        assert isinstance(review_list, ttk.Treeview)
        assert len(review_list.get_children()) == 1
        review_frame.destroy()
        gui.device_group_store.save_group(DeviceGroup(
            group_name="smoke_building",
            profile_name="base_iosxe_access",
            targets=[DeviceTargetRecord(ip="192.0.2.25")],
        ))
        gui.refresh_group_controls()
        assert "smoke_building" in gui.saved_group.cget("values")
        gui.saved_group.set("smoke_building")
        gui.apply_saved_group("smoke_building")
        assert "192.0.2.25" in gui.devices.get("1.0", "end")
        imported = output / "prior_profile.yaml"
        imported.write_text("profile_name: Smoke imported\nunused_vlan: 900\n", encoding="utf-8")
        gui.site_setup_panel.filedialog = SimpleNamespace(
            askopenfilename=lambda **_kwargs: str(imported),
        )
        gui.site_setup_panel.messagebox = SimpleNamespace(
            showinfo=lambda *_args: None,
            showerror=lambda *args: (_ for _ in ()).throw(RuntimeError(args)),
        )
        gui.site_setup_panel.import_profile_file()
        assert "Smoke_imported" in gui.profile.cget("values")
        assert (gui.data_root / "profiles" / "Smoke_imported.yaml").is_file()
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
