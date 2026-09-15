"""Create and self-verify signed offline STIG Audit Pro licenses."""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from stig_audit_pro.licensing import LicenseManager, LicenseStatus
from stig_audit_pro.licensing.manager import (
    PRODUCT_NAME,
    SIGNATURE_ALGORITHM,
    SUPPORTED_FEATURES,
    SUPPORTED_SCHEMA_VERSION,
    validate_key_id,
)
from tools.license_admin.canonicalize import canonicalize_license
from tools.license_admin.crypto import load_private_key, public_key_pem


@dataclass(frozen=True)
class IssuedLicense:
    path: Path
    license_id: str
    customer_name: str
    edition: str
    expires_at: str
    max_devices: int
    enabled_features: tuple[str, ...]
    key_id: str


def issue_license(
    *,
    private_key_path: str | Path,
    key_id: str,
    customer_name: str,
    edition: str,
    expires_at: str,
    max_devices: int,
    enabled_features: list[str] | tuple[str, ...],
    output_path: str | Path,
    issued_at: datetime | None = None,
    license_id: str | None = None,
    force: bool = False,
) -> IssuedLicense:
    now = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    validate_key_id(key_id)
    if not customer_name.strip():
        raise ValueError("Customer name must not be empty")
    if not edition.strip():
        raise ValueError("Edition must not be empty")
    if max_devices <= 0:
        raise ValueError("Maximum device count must be positive")
    parsed_expiration = _parse_utc(expires_at)
    unknown = sorted(set(enabled_features) - SUPPORTED_FEATURES)
    if unknown:
        raise ValueError(f"Unknown feature name(s): {', '.join(unknown)}")
    if parsed_expiration < now:
        raise ValueError(
            "Expiration must not be earlier than the license issuance timestamp"
        )

    private_key = load_private_key(private_key_path)
    generated_id = license_id or f"LIC-{now.year}-{secrets.token_hex(4).upper()}"
    issued_text = _format_utc(now)
    expires_text = _format_utc(parsed_expiration)
    enabled = set(enabled_features)
    payload = {
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "license_id": generated_id,
        "customer_name": customer_name.strip(),
        "product": PRODUCT_NAME,
        "edition": edition.strip(),
        "issued_at": issued_text,
        "expires_at": expires_text,
        "max_devices": max_devices,
        "features": {
            name: name in enabled for name in sorted(SUPPORTED_FEATURES)
        },
    }
    signature = private_key.sign(canonicalize_license(payload))
    document = {
        "license": payload,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }

    destination = Path(output_path).expanduser().resolve()
    if destination.exists() and not force:
        raise FileExistsError(
            f"License output already exists: {destination}. Use --force to overwrite it."
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    public_pem = public_key_pem(private_key.public_key())
    verification_now = datetime.now(timezone.utc)
    verifier = LicenseManager(
        temporary,
        public_key_loader=lambda candidate_key_id: (
            public_pem
            if candidate_key_id == key_id
            else _raise_unknown_key(candidate_key_id)
        ),
        now_provider=lambda: verification_now,
    )
    status = verifier.load()
    if (
        status not in {LicenseStatus.VALID, LicenseStatus.EXPIRED}
        or not verifier.signature_verified
    ):
        temporary.unlink(missing_ok=True)
        details = "; ".join(verifier.validation_errors) or status.value
        raise ValueError(f"New license failed immediate self-verification: {details}")
    os.replace(temporary, destination)

    return IssuedLicense(
        path=destination,
        license_id=generated_id,
        customer_name=payload["customer_name"],
        edition=payload["edition"],
        expires_at=expires_text,
        max_devices=max_devices,
        enabled_features=tuple(sorted(enabled)),
        key_id=key_id,
    )


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise ValueError(
            "Expiration must be an ISO 8601 timezone-aware UTC timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Expiration must include the UTC timezone")
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError("Expiration must use UTC")
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _raise_unknown_key(key_id: str) -> bytes:
    raise FileNotFoundError(key_id)
