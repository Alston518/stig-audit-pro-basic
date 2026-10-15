"""Security boundaries of the Basic executable."""

from __future__ import annotations

import sys
import queue
import threading
import types
from pathlib import Path

import pytest

from stig_audit_pro.core.ssh_runner import (
    DeviceCredentials,
    DeviceTarget,
    NetmikoSshRunner,
)
from stig_audit_pro.infrastructure.ssh.netmiko_runner import NetmikoRunner
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault, VaultUnlockError
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.licensing import LicenseManager
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
from stig_audit_pro.stig.ckl_writer import CklAsset
from stig_audit_pro.storage.device_groups import DeviceTargetRecord


@pytest.mark.parametrize("runner", [NetmikoRunner(), NetmikoSshRunner()])
def test_basic_ssh_requires_known_server_key(monkeypatch, runner):
    parameters = {}

    def reject_key(**kwargs):
        parameters.update(kwargs)
        raise RuntimeError("Unknown server host key")

    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=reject_key))
    result = runner.run_commands(
        DeviceTarget(ip="192.0.2.10"),
        DeviceCredentials("operator", "example"),
        ["show version"],
    )
    assert parameters["ssh_strict"] is True
    assert parameters["system_host_keys"] is True
    assert parameters["use_keys"] is False
    assert parameters["allow_agent"] is False
    assert result.status == "skipped"
    assert result.outputs == {}


def test_basic_artifacts_are_encrypted_and_only_exported_explicitly(tmp_path):
    vault_path = tmp_path / "basic-vault.json"
    vault = AtRestVault.open(vault_path, "a long test passphrase", create=True)
    store = ProtectedArtifactStore(vault)
    clear_path = tmp_path / "device.txt"
    sensitive = b"hostname SECRET-SWITCH\n"

    protected_path = store.save(clear_path, sensitive)

    assert protected_path.name == "device.txt.sapenc"
    assert not clear_path.exists()
    assert sensitive not in protected_path.read_bytes()
    assert store.read(protected_path) == sensitive
    with pytest.raises(VaultUnlockError):
        AtRestVault.open(vault_path, "a different passphrase")

    modified = bytearray(protected_path.read_bytes())
    modified[-1] ^= 1
    protected_path.write_bytes(modified)
    with pytest.raises(VaultUnlockError):
        store.read(protected_path)


def test_basic_vault_accepts_short_simple_passphrase(tmp_path):
    vault_path = tmp_path / "basic-vault.json"
    created = AtRestVault.open(vault_path, "1", create=True)
    protected = created.encrypt(b"audit data", "report")

    reopened = AtRestVault.open(vault_path, "1")
    assert reopened.decrypt(protected, "report") == b"audit data"
    with pytest.raises(VaultUnlockError):
        AtRestVault.open(vault_path, "2")


def test_basic_artifact_export_requires_an_explicit_destination(tmp_path):
    vault = AtRestVault.open(tmp_path / "basic-vault.json", "a long test passphrase", create=True)
    store = ProtectedArtifactStore(vault)
    protected = store.save(tmp_path / "finding.ckl", b"<CHECKLIST>example</CHECKLIST>")
    destination = tmp_path / "shared" / "finding.ckl"
    assert not destination.exists()
    store.export(protected, destination)
    assert destination.read_bytes() == b"<CHECKLIST>example</CHECKLIST>"


def test_free_basic_run_writes_only_encrypted_txt_and_ckl(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app

    ip = "192.0.2.10"
    row = CheckResult(
        ip=ip, hostname="SW-10", vuln_id="V-1", stig_family="IOSXE_L2",
        title="Example", severity="cat2", status="Open",
    )
    asset = CklAsset(scan_ip=ip, hostname="SW-10", management_ip=ip)
    result = types.SimpleNamespace(
        results=[row], assets={ip: asset},
        summary=types.SimpleNamespace(outcomes=[], cancelled_count=0, failure_count=0),
    )
    monkeypatch.setattr(
        basic_app, "AuditService",
        lambda: types.SimpleNamespace(run_offline=lambda **_kwargs: result),
    )
    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.license_policy = BasicLicensePolicy(LicenseManager(tmp_path / "license.json"))
    app.artifacts = ProtectedArtifactStore(
        AtRestVault.open(tmp_path / "basic-vault.json", "a long test passphrase", create=True)
    )
    app.events = queue.Queue()
    app.cancel_event = threading.Event()
    template = Path(__file__).resolve().parents[1] / "Checklist Templates" / "IOSXE_L2_Template.ckl"

    app._run(
        [DeviceTargetRecord(ip=ip)], [], None, None, ["iosxe_l2"],
        "Sample outputs", {"iosxe_l2": str(template)}, True, True,
        tmp_path / "reports",
    )

    event = app.events.get_nowait()
    assert event.message.startswith("Completed."), event.message
    assert app.license_policy.device_limit == 1
    protected = list((tmp_path / "reports").glob("*.sapenc"))
    assert sorted(path.suffixes[-2] for path in protected) == [".ckl", ".txt"]
    assert not list((tmp_path / "reports").glob("*.txt"))
    assert not list((tmp_path / "reports").glob("*.ckl"))
    assert b"SW-10" in app.artifacts.read(next(path for path in protected if ".txt." in path.name))
    assert b"CHECKLIST" in app.artifacts.read(next(path for path in protected if ".ckl." in path.name))


def test_summary_formats_render_in_memory_then_encrypt(tmp_path):
    from stig_audit_pro.reports.basic_summary import (
        Filter, STATUSES, CATS, render_csv, render_html, render_pdf, summarize,
    )

    row = CheckResult(
        ip="192.0.2.10", hostname="SW-10", vuln_id="V-1",
        stig_family="IOSXE_L2", title="Sensitive finding", severity="cat2",
        status="Open",
    )
    report = summarize([row], Filter(statuses=frozenset(STATUSES), cats=frozenset(CATS)), [row.ip])
    store = ProtectedArtifactStore(
        AtRestVault.open(tmp_path / "basic-vault.json", "a long test passphrase", create=True)
    )
    for suffix, renderer in (("csv", render_csv), ("html", render_html), ("pdf", render_pdf)):
        protected = store.save(tmp_path / f"summary.{suffix}", renderer(report))
        assert protected.is_file()
        assert not (tmp_path / f"summary.{suffix}").exists()
        assert b"Sensitive finding" not in protected.read_bytes()
        assert store.read(protected)


def test_basic_launch_unlocks_vault_before_building_ui(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app
    import customtkinter
    from tkinter import simpledialog

    events = []

    class Root:
        def withdraw(self): pass
        def deiconify(self): events.append("visible")
        def after(self, delay, callback): events.append(("after", delay)); callback()
        def mainloop(self): pass
        def destroy(self): pass

    entries = iter(("a long test passphrase", "a long test passphrase"))
    captured = []
    monkeypatch.setattr(customtkinter, "CTk", Root)
    monkeypatch.setattr(simpledialog, "askstring", lambda *_args, **_kwargs: next(entries))
    monkeypatch.setattr(basic_app, "default_vault_path", lambda: tmp_path / "basic-vault.json")
    monkeypatch.setattr(basic_app, "BasicApp", lambda _root, vault: (events.append("build"), captured.append(vault)))

    basic_app.run_basic_gui()

    assert (tmp_path / "basic-vault.json").is_file()
    assert len(captured) == 1
    assert isinstance(captured[0], AtRestVault)
    assert events == ["visible", "build", ("after", 0), "visible"]


def test_basic_launch_shows_error_if_main_window_cannot_initialize(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app
    import customtkinter
    from tkinter import messagebox, simpledialog

    events = []

    class Root:
        def withdraw(self): events.append("withdraw")
        def deiconify(self): events.append("deiconify")
        def mainloop(self): events.append("mainloop")
        def destroy(self): events.append("destroy")

    answers = iter(("a long test passphrase", "a long test passphrase"))
    monkeypatch.setattr(customtkinter, "CTk", Root)
    monkeypatch.setattr(simpledialog, "askstring", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr(messagebox, "showerror", lambda title, message, **_kwargs: events.append((title, message)))
    monkeypatch.setattr(basic_app, "default_vault_path", lambda: tmp_path / "basic-vault.json")
    monkeypatch.setattr(basic_app, "BasicApp", lambda *_args: (_ for _ in ()).throw(RuntimeError("UI failed")))

    basic_app.run_basic_gui()

    assert any(isinstance(item, tuple) and "could not start" in item[0].lower() for item in events)
    assert events[-1] == "destroy"
    assert "mainloop" not in events


def test_basic_launch_shows_error_if_vault_has_unexpected_io_failure(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app
    import customtkinter
    from tkinter import messagebox, simpledialog

    events = []

    class Root:
        def withdraw(self): pass
        def destroy(self): events.append("destroy")

    answers = iter(("passphrase", "passphrase"))
    monkeypatch.setattr(customtkinter, "CTk", Root)
    monkeypatch.setattr(simpledialog, "askstring", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr(messagebox, "showerror", lambda title, message, **_kwargs: events.append((title, message)))
    monkeypatch.setattr(basic_app, "default_vault_path", lambda: tmp_path / "basic-vault.json")
    monkeypatch.setattr(basic_app.AtRestVault, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")))

    basic_app.run_basic_gui()

    assert any(isinstance(item, tuple) and "audit data" in item[0].lower() for item in events)
    assert events[-1] == "destroy"
