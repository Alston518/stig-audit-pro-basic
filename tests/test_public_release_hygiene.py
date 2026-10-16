"""Guardrails for the dedicated public Basic repository."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]


def test_owner_only_and_pro_release_material_is_absent():
    prohibited = (
        "CODEX_HANDOFF.md",
        "ENTERPRISE_ROADMAP.md",
        "ROOT_GUARD_SETUP_GUIDE.md",
        "TESTER_GETTING_STARTED.md",
        "editing",
        "tools/license_admin",
        "stig-audit-pro.spec",
        "STIG Audit Pro Basic.spec",
        "data/device_groups/session_targets.yaml",
        "stig_audit_pro/resources/licensing/public_keys/awc-test-2026-08.pem",
    )
    present = []
    for path in prohibited:
        candidate = ROOT / path
        if candidate.is_file():
            present.append(path)
        elif candidate.is_dir() and any(
            item.is_file() and "__pycache__" not in item.parts
            for item in candidate.rglob("*")
        ):
            present.append(path)
    assert present == []


def test_bundled_trust_store_contains_public_keys_only():
    trust_store = ROOT / "stig_audit_pro" / "resources" / "licensing" / "public_keys"
    private_markers = (
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
    )
    pem_files = list(trust_store.glob("*.pem"))
    assert {path.name for path in pem_files} == {
        "stig-audit-prod-2026-01.pem",
        "stig-audit-prod-2026-02.pem",
    }
    for path in pem_files:
        content = path.read_bytes()
        assert all(marker not in content for marker in private_markers)


def test_public_operator_docs_do_not_publish_license_issuance_commands():
    documents = [ROOT / "README.md", ROOT / "BASIC_LICENSING.md"]
    documents.extend((ROOT / "docs").glob("*.md"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in documents)
    assert "tools.license_admin" not in combined
    assert "tools/license_admin" not in combined
    assert "awc-test-2026-08" not in combined
    assert "--private-key" not in combined


def test_public_profiles_and_guides_are_sanitized():
    indicators = (
        "armywarcollege",
        "cedu-carpa",
        "dedu-carpa",
        "ISE1-EDU",
        "ISE2-EDU",
        "172.16.100.",
    )
    text_paths = list((ROOT / "data" / "profiles").glob("*.yaml"))
    text_paths.append(ROOT / "docs" / "profile_values.json")
    combined = "\n".join(path.read_text(encoding="utf-8-sig") for path in text_paths)
    assert all(indicator.casefold() not in combined.casefold() for indicator in indicators)

    for path in (ROOT / "docs").glob("*.docx"):
        with ZipFile(path) as document:
            xml = b"\n".join(
                document.read(name)
                for name in document.namelist()
                if name.endswith(".xml")
            ).decode("utf-8", errors="ignore")
        assert all(indicator.casefold() not in xml.casefold() for indicator in indicators)
