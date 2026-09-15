from __future__ import annotations

import base64
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stig_audit_pro.licensing import (
    LicenseManager,
    LicensePolicyError,
    LicenseStatus,
)
from stig_audit_pro.licensing.canonicalize import canonicalize_license
from stig_audit_pro.licensing.manager import SUPPORTED_FEATURES

NOW = datetime(2026, 7, 28, 16, 0, 0, tzinfo=timezone.utc)
KEY_ID = "test-key-2026"


@pytest.fixture
def signing_material(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()
    public_dir = tmp_path / "public_keys"
    public_dir.mkdir()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (public_dir / f"{KEY_ID}.pem").write_bytes(public_pem)
    return private_key, public_dir


def payload(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "license_id": "LIC-2026-TEST0001",
        "customer_name": "Test Customer",
        "product": "STIG Audit Pro",
        "edition": "Pro",
        "issued_at": "2026-07-28T15:00:00Z",
        "expires_at": "2027-07-28T23:59:59Z",
        "max_devices": 2,
        "features": {
            name: name
            in {
                "multi_device_scan",
                "ckl_export",
                "l2_checks",
                "advanced_reporting",
            }
            for name in sorted(SUPPORTED_FEATURES)
        },
    }
    value.update(overrides)
    return value


def signed_document(
    private_key: Ed25519PrivateKey,
    license_payload: dict[str, object] | None = None,
    *,
    key_id: str = KEY_ID,
) -> dict[str, object]:
    license_value = license_payload or payload()
    signature = private_key.sign(canonicalize_license(license_value))
    return {
        "license": license_value,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def write_document(path: Path, document: dict[str, object]) -> Path:
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def manager_for(
    path: Path,
    public_dir: Path,
    *,
    now: datetime = NOW,
) -> LicenseManager:
    return LicenseManager(
        path,
        public_key_dir=public_dir,
        now_provider=lambda: now,
    )


def test_successful_signature_verification(signing_material, tmp_path: Path):
    private_key, public_dir = signing_material
    path = write_document(tmp_path / "valid.json", signed_document(private_key))
    manager = manager_for(path, public_dir)

    assert manager.load() is LicenseStatus.VALID
    assert manager.is_valid
    assert manager.signature_verified
    assert manager.customer_name == "Test Customer"
    assert manager.key_id == KEY_ID


def test_public_key_cannot_sign_a_license(signing_material):
    private_key, _ = signing_material
    public_key = private_key.public_key()

    assert not hasattr(public_key, "sign")
    with pytest.raises(AttributeError):
        getattr(public_key, "sign")(canonicalize_license(payload()))


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("customer_name", "Modified Customer"),
        ("expires_at", "2028-07-28T23:59:59Z"),
        ("max_devices", 500),
    ],
)
def test_modifying_signed_scalar_invalidates_signature(
    signing_material,
    tmp_path: Path,
    field: str,
    changed: object,
):
    private_key, public_dir = signing_material
    document = signed_document(private_key)
    document["license"][field] = changed  # type: ignore[index]
    path = write_document(tmp_path / f"tampered-{field}.json", document)

    manager = manager_for(path, public_dir)
    assert manager.load() is LicenseStatus.INVALID
    assert manager.edition == "Free"
    assert manager.max_devices == 1


def test_modifying_feature_flag_invalidates_signature(
    signing_material, tmp_path: Path
):
    private_key, public_dir = signing_material
    document = signed_document(private_key)
    document["license"]["features"]["ndm_checks"] = True  # type: ignore[index]
    path = write_document(tmp_path / "tampered-feature.json", document)

    assert manager_for(path, public_dir).load() is LicenseStatus.INVALID


def test_missing_signature_is_rejected(signing_material, tmp_path: Path):
    _, public_dir = signing_material
    path = write_document(tmp_path / "missing-signature.json", {"license": payload()})

    assert manager_for(path, public_dir).load() is LicenseStatus.INVALID


def test_invalid_base64_signature_is_rejected(signing_material, tmp_path: Path):
    private_key, public_dir = signing_material
    document = signed_document(private_key)
    document["signature"]["value"] = "not valid base64!!!"  # type: ignore[index]
    path = write_document(tmp_path / "bad-base64.json", document)

    manager = manager_for(path, public_dir)
    assert manager.load() is LicenseStatus.INVALID
    assert "Base64" in manager.validation_errors[0]


def test_unknown_key_id_is_rejected(signing_material, tmp_path: Path):
    private_key, public_dir = signing_material
    document = signed_document(private_key, key_id="unknown-key")
    path = write_document(tmp_path / "unknown-key.json", document)

    manager = manager_for(path, public_dir)
    assert manager.load() is LicenseStatus.INVALID
    assert "Unknown" in manager.validation_errors[0]


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"product": "Different Product"}, "product"),
        ({"schema_version": 2}, "schema_version"),
    ],
)
def test_wrong_product_and_schema_are_rejected(
    signing_material,
    tmp_path: Path,
    overrides: dict[str, object],
    expected_error: str,
):
    private_key, public_dir = signing_material
    document = signed_document(private_key, payload(**overrides))
    path = write_document(tmp_path / f"bad-{expected_error}.json", document)

    manager = manager_for(path, public_dir)
    assert manager.load() is LicenseStatus.INVALID
    assert expected_error in manager.validation_errors[0]


def test_expired_license_enters_free_mode(signing_material, tmp_path: Path):
    private_key, public_dir = signing_material
    expired = payload(
        issued_at="2025-07-01T00:00:00Z",
        expires_at="2026-07-27T23:59:59Z",
        max_devices=25,
    )
    path = write_document(
        tmp_path / "expired.json", signed_document(private_key, expired)
    )
    manager = manager_for(path, public_dir)

    assert manager.load() is LicenseStatus.EXPIRED
    assert manager.is_expired
    assert manager.signature_verified
    assert manager.edition == "Free"
    assert manager.max_devices == 1
    assert manager.license_id == "LIC-2026-TEST0001"
    assert not manager.feature_enabled("l2_checks")


def test_missing_license_enters_free_mode(signing_material, tmp_path: Path):
    _, public_dir = signing_material
    manager = manager_for(tmp_path / "absent.json", public_dir)

    assert manager.load() is LicenseStatus.MISSING
    assert manager.edition == "Free"
    assert manager.max_devices == 1
    assert not manager.feature_enabled("multi_device_scan")


def test_invalid_license_enters_free_mode(signing_material, tmp_path: Path):
    _, public_dir = signing_material
    path = tmp_path / "invalid.json"
    path.write_text("{broken", encoding="utf-8")
    manager = manager_for(path, public_dir)

    assert manager.load() is LicenseStatus.INVALID
    assert manager.edition == "Free"
    assert manager.max_devices == 1
    assert manager.validation_errors


def test_duplicate_json_keys_are_rejected(signing_material, tmp_path: Path):
    _, public_dir = signing_material
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"license":{},"license":{},"signature":{}}',
        encoding="utf-8",
    )
    manager = manager_for(path, public_dir)

    assert manager.load() is LicenseStatus.INVALID
    assert "Duplicate JSON object key" in manager.validation_errors[0]


def test_valid_license_enables_only_configured_features(
    signing_material, tmp_path: Path
):
    private_key, public_dir = signing_material
    path = write_document(tmp_path / "valid.json", signed_document(private_key))
    manager = manager_for(path, public_dir)
    manager.load()

    assert manager.feature_enabled("l2_checks")
    assert manager.feature_enabled("ckl_export")
    assert not manager.feature_enabled("ndm_checks")
    with pytest.raises(LicensePolicyError):
        manager.require_feature("ndm_checks", refresh=False)


def test_free_mode_permits_one_unique_target(signing_material, tmp_path: Path):
    _, public_dir = signing_material
    manager = manager_for(tmp_path / "missing.json", public_dir)
    manager.load()

    assert manager.require_scan_targets(["192.0.2.1"], refresh=False) == (
        "192.0.2.1",
    )
    with pytest.raises(LicensePolicyError, match="1 device"):
        manager.require_scan_targets(
            ["192.0.2.1", "192.0.2.2"], refresh=False
        )


def test_paid_mode_enforces_device_limit(signing_material, tmp_path: Path):
    private_key, public_dir = signing_material
    path = write_document(tmp_path / "paid.json", signed_document(private_key))
    manager = manager_for(path, public_dir)
    manager.load()

    assert len(
        manager.require_scan_targets(
            ["192.0.2.1", "192.0.2.2"], refresh=False
        )
    ) == 2
    with pytest.raises(LicensePolicyError, match=r"permits 2.*3 unique"):
        manager.require_scan_targets(
            ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
            refresh=False,
        )


def test_duplicate_targets_are_normalized_and_counted_once(
    signing_material, tmp_path: Path
):
    _, public_dir = signing_material
    manager = manager_for(tmp_path / "missing.json", public_dir)
    manager.load()

    assert manager.require_scan_targets(
        ["2001:0db8::1", "2001:db8:0:0::1"], refresh=False
    ) == ("2001:db8::1",)


def test_valid_import_copies_to_configured_application_path(
    signing_material, tmp_path: Path
):
    private_key, public_dir = signing_material
    source = write_document(tmp_path / "source.json", signed_document(private_key))
    destination = tmp_path / "app-data" / "stig-audit-pro.license.json"
    manager = manager_for(destination, public_dir)

    assert manager.import_license(source) == destination
    assert destination.is_file()
    assert manager.status is LicenseStatus.VALID


def test_tampered_import_does_not_replace_existing_license(
    signing_material, tmp_path: Path
):
    private_key, public_dir = signing_material
    valid = signed_document(private_key)
    installed = write_document(tmp_path / "installed.json", valid)
    manager = manager_for(installed, public_dir)
    manager.load()
    tampered = deepcopy(valid)
    tampered["license"]["customer_name"] = "Tampered"  # type: ignore[index]
    candidate = write_document(tmp_path / "candidate.json", tampered)
    original_bytes = installed.read_bytes()

    with pytest.raises(ValueError):
        manager.import_license(candidate)
    assert installed.read_bytes() == original_bytes
