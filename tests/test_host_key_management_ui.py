"""Bulk host-key controls use one explicit decision and no typed verification note."""

from __future__ import annotations

from types import SimpleNamespace

import paramiko

from stig_audit_pro.gui import basic_host_keys
from stig_audit_pro.gui.basic_host_keys import ManageHostKeysDialog, ReviewHostKeyBatchDialog
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore


def test_bulk_review_accepts_without_operator_note(monkeypatch):
    asked = []
    monkeypatch.setattr(
        basic_host_keys.messagebox, "askyesno",
        lambda *args, **kwargs: asked.append((args, kwargs)) or True,
    )
    dialog = ReviewHostKeyBatchDialog.__new__(ReviewHostKeyBatchDialog)
    dialog.request = SimpleNamespace(plan=SimpleNamespace(unknown=(object(),)))
    dialog.note = SimpleNamespace(get=lambda: "")

    assert dialog.validate()
    dialog.apply()
    assert "first use" in dialog.result.lower()
    assert "not independently verified" in dialog.result.lower()
    assert len(asked) == 1


def test_bulk_review_keeps_optional_verification_source():
    dialog = ReviewHostKeyBatchDialog.__new__(ReviewHostKeyBatchDialog)
    dialog.note = SimpleNamespace(get=lambda: "Checked against console inventory")

    dialog.apply()

    assert dialog.result == "Checked against console inventory"


def test_manage_dialog_removes_multiple_selected_hosts_with_one_confirmation(monkeypatch, tmp_path, caplog):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)
    store.path.write_text(
        f"switch-a {key.get_name()} {key.get_base64()}\n"
        f"switch-b {key.get_name()} {key.get_base64()}\n"
        f"switch-c {key.get_name()} {key.get_base64()}\n", encoding="utf-8",
    )
    asked = []
    monkeypatch.setattr(
        basic_host_keys.messagebox, "askyesno",
        lambda *args, **kwargs: asked.append((args, kwargs)) or True,
    )
    dialog = ManageHostKeysDialog.__new__(ManageHostKeysDialog)
    dialog.store = store
    dialog.hosts = store.list_hosts()
    dialog.listbox = SimpleNamespace(
        curselection=lambda: (0, 1),
        get=lambda index: ("switch-a", "switch-b", "switch-c")[index],
    )
    dialog._populate = lambda: None
    dialog._select = lambda: None

    with caplog.at_level("WARNING", logger="stig_audit_pro.activity"):
        dialog._remove()

    assert set(store.list_hosts()) == {"switch-c"}
    assert len(asked) == 1
    assert "HOST_KEYS_BULK_REMOVED" in caplog.text
    assert "count=2" in caplog.text
