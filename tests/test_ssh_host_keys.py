from __future__ import annotations

import base64

import pytest

from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore


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
