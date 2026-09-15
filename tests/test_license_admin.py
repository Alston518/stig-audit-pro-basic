from __future__ import annotations

import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from stig_audit_pro.licensing import LicenseStatus
from tools.license_admin.canonicalize import canonicalize_license as admin_canonicalize
from tools.license_admin.issue import issue_license
from tools.license_admin.keygen import generate_key_pair
from tools.license_admin.verify import verify_license

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_key_pair_generation_and_restrictive_private_permissions(tmp_path: Path):
    private_path = tmp_path / "publisher-private.pem"
    public_path = tmp_path / "publisher-public.pem"

    generated = generate_key_pair(
        key_id="test-admin-key",
        private_key_output=private_path,
        public_key_output=public_path,
    )

    assert private_path.is_file()
    assert public_path.is_file()
    assert b"PRIVATE KEY" in private_path.read_bytes()
    assert b"PUBLIC KEY" in public_path.read_bytes()
    assert generated.fingerprint.startswith("SHA256:")
    if os.name != "nt":
        assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        generate_key_pair(
            key_id="test-admin-key",
            private_key_output=private_path,
            public_key_output=public_path,
        )


def test_license_generation_self_verifies_output(tmp_path: Path):
    private_path = tmp_path / "publisher-private.pem"
    public_path = tmp_path / "publisher-public.pem"
    generate_key_pair(
        key_id="test-admin-key",
        private_key_output=private_path,
        public_key_output=public_path,
    )
    output = tmp_path / "issued.license.json"
    issued = issue_license(
        private_key_path=private_path,
        key_id="test-admin-key",
        customer_name="Admin Tool Test",
        edition="Pro",
        expires_at="2027-07-28T23:59:59Z",
        max_devices=10,
        enabled_features=["multi_device_scan", "l2_checks"],
        output_path=output,
        issued_at=datetime(2026, 7, 28, 16, 0, tzinfo=timezone.utc),
    )

    assert issued.path == output.resolve()
    assert issued.license_id.startswith("LIC-2026-")
    manager = verify_license(
        license_path=output,
        public_key_path=public_path,
    )
    assert manager.status is LicenseStatus.VALID
    assert manager.signature_verified
    assert manager.customer_name == "Admin Tool Test"


def test_admin_cli_verify_returns_nonzero_for_wrong_key(tmp_path: Path):
    private_path = tmp_path / "publisher-private.pem"
    public_path = tmp_path / "publisher-public.pem"
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_key_pair(
        key_id="test-admin-key",
        private_key_output=private_path,
        public_key_output=public_path,
    )
    generate_key_pair(
        key_id="wrong-key",
        private_key_output=wrong_private,
        public_key_output=wrong_public,
    )
    output = tmp_path / "issued.license.json"
    issue_license(
        private_key_path=private_path,
        key_id="test-admin-key",
        customer_name="CLI Test",
        edition="Pro",
        expires_at="2027-07-28T23:59:59Z",
        max_devices=1,
        enabled_features=[],
        output_path=output,
        issued_at=datetime(2026, 7, 28, 16, 0, tzinfo=timezone.utc),
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.license_admin",
            "verify",
            "--license",
            str(output),
            "--public-key",
            str(wrong_public),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "Signature valid: NO" in completed.stdout


def test_generator_and_verifier_share_canonicalizer():
    from stig_audit_pro.licensing.canonicalize import canonicalize_license

    assert admin_canonicalize is canonicalize_license


def test_production_private_keys_are_not_present_in_repository():
    for path in PROJECT_ROOT.rglob("*.pem"):
        if ".git" in path.parts:
            continue
        assert b"PRIVATE KEY" not in path.read_bytes(), str(path)
    customer_python = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PROJECT_ROOT / "stig_audit_pro").rglob("*.py")
    )
    assert "Ed25519PrivateKey" not in customer_python


def test_administrative_tooling_is_excluded_from_customer_packaging():
    spec = (PROJECT_ROOT / "stig-audit-pro.spec").read_text(encoding="utf-8")

    assert '"tools"' in spec
    assert '"tools.license_admin"' in spec
    assert "project_root / \"tools\"" not in spec
