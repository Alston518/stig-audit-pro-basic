from __future__ import annotations

from pathlib import Path

from stig_audit_pro import build_info


def test_build_metadata_reads_release_date_and_commit(monkeypatch, tmp_path):
    metadata = tmp_path / "BUILD_INFO.txt"
    metadata.write_text(
        "Package date: 2026-10-23\nCommit: b1d430fae6091399\n", encoding="utf-8"
    )
    monkeypatch.setattr(build_info, "_metadata_paths", lambda: [metadata])

    loaded = build_info.load_build_metadata()

    assert loaded["date"] == "2026-10-23"
    assert loaded["id"] == "b1d430fae609"
    assert loaded["version"]


def test_build_metadata_has_source_fallback(monkeypatch):
    monkeypatch.setattr(build_info, "_metadata_paths", lambda: [Path("missing-build-info.txt")])

    loaded = build_info.load_build_metadata()

    assert loaded["date"] == "Development build"
    assert loaded["id"] == "source"
