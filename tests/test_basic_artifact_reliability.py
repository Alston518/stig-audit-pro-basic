"""Failure-path checks for Basic's encrypted report store."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore


def test_failed_readable_export_removes_partial_plaintext(tmp_path):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    store = ProtectedArtifactStore(vault)
    protected = store.save(tmp_path / "report.txt", b"sensitive report content")
    destination = tmp_path / "export" / "report.txt"

    with patch.object(os, "fsync", side_effect=OSError("simulated disk sync failure")):
        with pytest.raises(OSError, match="simulated disk sync failure"):
            store.export(protected, destination)

    assert not destination.exists()
    assert protected.is_file()
    assert store.read(protected) == b"sensitive report content"


def test_export_refuses_existing_destination_without_deleting_it(tmp_path):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    store = ProtectedArtifactStore(vault)
    protected = store.save(tmp_path / "report.txt", b"new report")
    destination = tmp_path / "report-copy.txt"
    destination.write_bytes(b"existing content")

    with pytest.raises(FileExistsError):
        store.export(protected, destination)

    assert destination.read_bytes() == b"existing content"


def test_failed_export_warns_if_plaintext_cleanup_is_blocked(tmp_path):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    store = ProtectedArtifactStore(vault)
    protected = store.save(tmp_path / "report.txt", b"sensitive report content")
    destination = tmp_path / "report-copy.txt"
    original_unlink = Path.unlink

    def blocked_unlink(path, *args, **kwargs):
        if path == destination:
            raise PermissionError("simulated cleanup denial")
        return original_unlink(path, *args, **kwargs)

    with patch.object(os, "fsync", side_effect=OSError("simulated disk sync failure")):
        with patch.object(Path, "unlink", blocked_unlink):
            with pytest.raises(OSError, match="unencrypted file may remain"):
                store.export(protected, destination)

    assert destination.exists()


def test_failed_encrypted_save_leaves_no_report_or_temp_file(tmp_path):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    store = ProtectedArtifactStore(vault)
    report_folder = tmp_path / "reports"

    with patch.object(os, "fsync", side_effect=OSError("simulated disk sync failure")):
        with pytest.raises(OSError, match="simulated disk sync failure"):
            store.save(report_folder / "report.txt", b"sensitive report content")

    assert list(report_folder.iterdir()) == []


def test_encrypted_save_does_not_replace_file_created_during_publish(tmp_path, monkeypatch):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    destination = tmp_path / "report.txt.sapenc"
    real_link = os.link

    def concurrent_creator(source, target, *args, **kwargs):
        Path(target).write_bytes(b"another process created this file")
        return real_link(source, target, *args, **kwargs)

    monkeypatch.setattr(os, "link", concurrent_creator)

    with pytest.raises(FileExistsError):
        vault.write_file(destination, b"sensitive report", "basic-report/report.txt", replace=False)

    assert destination.read_bytes() == b"another process created this file"
    assert not list(tmp_path.glob(".*.tmp"))
