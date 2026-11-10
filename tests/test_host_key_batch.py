"""Bulk host-key review only enrolls first-use keys shown to the operator."""

from __future__ import annotations

import base64
import importlib
import json
import threading

import pytest

from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore


def _batch():
    return importlib.import_module("stig_audit_pro.infrastructure.ssh.host_key_batch")


def _key(value: bytes) -> tuple[str, str, str]:
    algorithm = "ssh-ed25519"
    return algorithm, base64.b64encode(value).decode("ascii"), HostKeyTrustStore.fingerprint(algorithm, value)


def test_batch_separates_unknown_changed_known_and_unreachable(tmp_path, monkeypatch):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    known = _key(b"known-key")
    changed = _key(b"old-key")
    store.enroll("known", 22, known[0], known[1], verification_note="inventory", operator="tester")
    store.enroll("changed", 22, changed[0], changed[1], verification_note="inventory", operator="tester")
    observed = {
        "known": known, "changed": _key(b"new-key"),
        "unknown-1": _key(b"first-key"), "unknown-2": _key(b"second-key"),
    }

    def discover(host, _port, _timeout):
        if host == "unreachable":
            raise OSError("unreachable")
        return observed[host]

    monkeypatch.setattr(store, "discover", discover)
    targets = [DeviceTarget(name) for name in ("known", "changed", "unknown-1", "unknown-2", "unreachable")]
    plan = _batch().collect_host_key_batch(targets, store, threading.Event(), concurrency=3)

    assert [entry.target.ip for entry in plan.unknown] == ["unknown-1", "unknown-2"]
    assert [entry.target.ip for entry in plan.changed] == ["changed"]
    assert plan.failed == ("unreachable",)


def test_batch_approval_saves_only_reviewed_keys_with_one_note(tmp_path, monkeypatch):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    observed = {name: _key(name.encode()) for name in ("switch-a", "switch-b")}
    monkeypatch.setattr(store, "discover", lambda host, _port, _timeout: observed[host])
    targets = [DeviceTarget(name) for name in observed]
    plan = _batch().collect_host_key_batch(targets, store, threading.Event())

    enrolled = _batch().enroll_host_key_batch(
        store, plan.unknown, verification_note="Compared with approved console inventory",
        operator="tester",
    )

    assert enrolled == ("switch-a", "switch-b")
    assert set(store.list_hosts()) == set(observed)
    history = json.loads(store.metadata_path.read_text(encoding="utf-8"))
    assert all(item["verification_note"] == "Compared with approved console inventory" for item in history)


def test_batch_enrollment_rejects_key_different_from_shown_fingerprint(tmp_path):
    store = HostKeyTrustStore(tmp_path / "known_hosts")
    algorithm, public_key, _fingerprint = _key(b"actual-key")
    entry = _batch().HostKeyBatchEntry(DeviceTarget("switch-a"), algorithm, public_key, "SHA256:wrong")

    with pytest.raises(ValueError, match="fingerprint"):
        _batch().enroll_host_key_batch(store, [entry], verification_note="inventory", operator="tester")
    assert store.list_hosts() == {}
