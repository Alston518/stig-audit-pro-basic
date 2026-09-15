"""Administrative verification and untrusted inspection commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stig_audit_pro.licensing import LicenseManager, LicenseStatus


def verify_license(
    *,
    license_path: str | Path,
    public_key_path: str | Path,
) -> LicenseManager:
    public_pem = Path(public_key_path).read_bytes()
    manager = LicenseManager(
        license_path,
        public_key_loader=lambda _key_id: public_pem,
    )
    manager.load()
    return manager


def verification_report(manager: LicenseManager) -> str:
    verified = manager.signature_verified and manager.status in {
        LicenseStatus.VALID,
        LicenseStatus.EXPIRED,
    }
    if not verified:
        errors = "; ".join(manager.validation_errors) or manager.status.value
        return "\n".join(
            [
                "Signature valid: NO",
                "Cryptographically verified contents: unavailable",
                f"Validation error: {errors}",
            ]
        )
    enabled = sorted(
        name for name, value in manager.licensed_features.items() if value
    )
    return "\n".join(
        [
            "Signature valid: YES",
            "Product: STIG Audit Pro",
            f"Customer: {manager.customer_name}",
            f"License ID: {manager.license_id}",
            f"Edition: {manager.licensed_edition}",
            f"Expiration: {_timestamp(manager.expires_at)}",
            f"Device limit: {manager.licensed_max_devices}",
            f"Enabled features: {', '.join(enabled) if enabled else 'None'}",
            f"Key ID: {manager.key_id}",
            f"Currently expired: {'YES' if manager.is_expired else 'NO'}",
        ]
    )


def inspect_license(path: str | Path) -> tuple[Any, str]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    report = (
        "Parsed contents (UNVERIFIED — do not treat these values as trusted):\n"
        + json.dumps(document, indent=2, ensure_ascii=False)
        + "\n\nCryptographically verified contents: NOT CHECKED"
    )
    return document, report


def _timestamp(value: Any) -> str:
    if value is None:
        return "—"
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")
