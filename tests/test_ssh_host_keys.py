from __future__ import annotations

import base64
import json
import threading
from contextlib import nullcontext

import paramiko
import pytest

from stig_audit_pro.core.ssh_runner import DeviceCredentials, DeviceTarget
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore
from stig_audit_pro.infrastructure.ssh.netmiko_runner import NetmikoRunner


def test_enrollment_requires_independent_verification_and_writes_known_hosts(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = base64.b64encode(b"test-public-key-bytes").decode("ascii")

    with pytest.raises(ValueError, match="verification note"):
        store.enroll("switch01.example", 22, "ssh-ed25519", key, verification_note="", operator="alice")

    fingerprint = store.enroll(
        "switch01.example",
        22,
        "ssh-ed25519",
        key,
        verification_note="Compared to the console inventory by a second operator.",
        operator="alice",
    )
    assert fingerprint.startswith("SHA256:")
    assert "switch01.example ssh-ed25519" in (tmp_path / "known_hosts").read_text()
    metadata = (tmp_path / "known_hosts.json").read_text()
    assert "Compared to the console inventory" in metadata


def test_fingerprint_is_stable():
    encoded = base64.b64encode(b"key").decode("ascii")
    assert HostKeyTrustStore.fingerprint("ssh-ed25519", b"key") == HostKeyTrustStore.fingerprint(
        "ssh-ed25519", base64.b64decode(encoded)
    )


def test_remove_forgets_only_selected_host_and_records_the_action(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)
    store.path.write_text(
        f"switch-a,switch-alias {key.get_name()} {key.get_base64()}\n", encoding="utf-8"
    )
    assert set(store.list_hosts()) == {"switch-a", "switch-alias"}
    assert store.remove("switch-a", operator="test operator")
    assert set(store.list_hosts()) == {"switch-alias"}
    assert not store.remove("switch-a", operator="test operator")
    assert json.loads(store.metadata_path.read_text())[-1]["action"] == "removed"


def test_bulk_remove_forgets_selected_hosts_once_and_preserves_others(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)
    store.path.write_text(
        f"switch-a,alias-a {key.get_name()} {key.get_base64()}\n"
        f"switch-b {key.get_name()} {key.get_base64()}\n"
        f"switch-c {key.get_name()} {key.get_base64()}\n",
        encoding="utf-8",
    )
    before = store.list_hosts()

    removed = store.remove_many(
        ("switch-a", "switch-b"), operator="operator",
        expected={name: before[name] for name in ("switch-a", "switch-b")},
    )

    assert removed == ("switch-a", "switch-b")
    assert set(store.list_hosts()) == {"alias-a", "switch-c"}
    history = json.loads(store.metadata_path.read_text(encoding="utf-8"))
    assert history[-1]["action"] == "removed_bulk"
    assert history[-1]["hosts"] == ["switch-a", "switch-b"]


def test_bulk_remove_rejects_stale_fingerprint_without_deleting_anything(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)
    store.path.write_text(
        f"switch-a {key.get_name()} {key.get_base64()}\n"
        f"switch-b {key.get_name()} {key.get_base64()}\n", encoding="utf-8",
    )
    original = store.path.read_bytes()

    with pytest.raises(ValueError, match="changed"):
        store.remove_many(
            ("switch-a", "switch-b"), operator="operator",
            expected={"switch-a": ("ssh-rsa SHA256:stale",), "switch-b": store.list_hosts()["switch-b"]},
        )

    assert store.path.read_bytes() == original


def test_first_use_enrollment_cannot_replace_a_different_saved_key(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key_a, key_b = (paramiko.RSAKey.generate(1024) for _ in range(2))
    args = dict(operator="operator", verification_note="Verified independently")
    store.enroll("switch-a", 22, key_a.get_name(), key_a.get_base64(), **args)
    original = store.path.read_bytes()
    with pytest.raises(ValueError, match="different"):
        store.enroll("switch-a", 22, key_b.get_name(), key_b.get_base64(), replace=False, **args)
    assert store.path.read_bytes() == original


@pytest.mark.parametrize("decision", ["approve", "decline", "cancel", "changed"])
def test_live_runner_retries_only_approved_first_use_and_stays_strict(
    monkeypatch, tmp_path, decision
):
    import netmiko

    store = HostKeyTrustStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)
    fingerprint = store.fingerprint(key.get_name(), key.asbytes())
    calls = []
    prompts = []
    cancel = threading.Event()

    def connect(**params):
        assert params["ssh_strict"] and params["alt_host_keys"]
        calls.append(params["host"])
        if len(calls) == 1:
            if decision == "changed":
                raise paramiko.BadHostKeyException("switch-a", key, paramiko.RSAKey.generate(1024))
            raise paramiko.SSHException("Server 'switch-a' not found in known_hosts")
        assert "switch-a" in store.list_hosts()
        return nullcontext(type("Connection", (), {"send_command": lambda *_a, **_k: "ok"})())

    def approve(target, observed, cancellation):
        prompts.append(observed.fingerprint)
        assert observed.fingerprint == fingerprint
        if decision == "cancel":
            cancellation.set()
        if decision != "approve":
            return None
        return "Verified independently", "operator"

    monkeypatch.setattr(netmiko, "ConnectHandler", connect)
    monkeypatch.setattr(store, "discover", lambda *_args: (key.get_name(), key.get_base64(), fingerprint))
    result = NetmikoRunner(store, approve_unknown=approve).run_commands(
        DeviceTarget("switch-a"), DeviceCredentials("operator", "test"), ["show version"],
        cancel_event=cancel,
    )
    assert len(calls) == (2 if decision == "approve" else 1)
    assert len(prompts) == (0 if decision == "changed" else 1)
    assert result.status == {"approve": "scanned", "cancel": "cancelled"}.get(decision, "skipped")
    assert bool(store.list_hosts()) == (decision == "approve")
