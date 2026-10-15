"""Cryptographic tests for the password-unlocked Basic output vault."""
from __future__ import annotations

import pytest

from stig_audit_pro.storage.basic_output_vault import BasicOutputVault, VaultError


def test_vault_encrypts_and_recovers_output(tmp_path):
    vault = BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    saved = vault.save("scan.txt", b"device configuration: secret-network")
    raw = saved.read_bytes()
    assert b"secret-network" not in raw
    assert b"scan.txt" not in raw
    assert vault.read(saved) == ("scan.txt", b"device configuration: secret-network")
    reopened = BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    assert reopened.read(saved)[1] == b"device configuration: secret-network"


def test_wrong_password_does_not_overwrite_vault(tmp_path):
    first = BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    report = first.save("scan.txt", b"important report")
    before = report.read_bytes()
    with pytest.raises(VaultError, match="Incorrect password"):
        BasicOutputVault.open_or_create("wrong test password 123", tmp_path)
    assert report.read_bytes() == before


def test_tampered_report_is_rejected(tmp_path):
    vault = BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    report = vault.save("scan.txt", b"important report")
    blob = bytearray(report.read_bytes())
    blob[-1] ^= 1
    report.write_bytes(blob)
    with pytest.raises(VaultError, match="integrity check"):
        vault.read(report)


def test_does_not_overwrite_reports_or_allow_traversal(tmp_path):
    vault = BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    first = vault.save("scan.txt", b"one")
    second = vault.save("scan.txt", b"two")
    assert first != second
    with pytest.raises(ValueError):
        vault.save("../secret.txt", b"bad")
    with pytest.raises(VaultError):
        vault.read(tmp_path / "other.sapenc")


def test_preexisting_orphan_is_not_discarded(tmp_path):
    (tmp_path / "orphan.sapenc").write_bytes(b"original")
    with pytest.raises(VaultError, match="metadata"):
        BasicOutputVault.open_or_create("long test password for vault", tmp_path)
    assert (tmp_path / "orphan.sapenc").read_bytes() == b"original"
