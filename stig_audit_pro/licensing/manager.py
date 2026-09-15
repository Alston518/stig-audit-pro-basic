"""Centralized offline-license loading, validation, import, and policy checks."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from stig_audit_pro.config import LICENSE_FILENAME
from stig_audit_pro.licensing.canonicalize import (
    CanonicalizationError,
    canonicalize_license,
)
from stig_audit_pro.licensing.paths import default_license_path

LOGGER = logging.getLogger(__name__)

PRODUCT_NAME = "STIG Audit Pro"
SUPPORTED_SCHEMA_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
ISSUED_AT_FUTURE_TOLERANCE = timedelta(minutes=5)
SUPPORTED_FEATURES = frozenset(
    {
        "multi_device_scan",
        "ckl_export",
        "l2_checks",
        "ndm_checks",
        "saved_presets",
        "advanced_reporting",
    }
)
_LICENSE_FIELDS = frozenset(
    {
        "schema_version",
        "license_id",
        "customer_name",
        "product",
        "edition",
        "issued_at",
        "expires_at",
        "max_devices",
        "features",
    }
)
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "value"})
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ValidationFailure(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def validate_key_id(key_id: str) -> str:
    if not _KEY_ID_PATTERN.fullmatch(key_id):
        raise ValueError(
            "key_id must start with an alphanumeric character and contain only "
            "letters, numbers, period, underscore, or hyphen"
        )
    return key_id


class LicenseStatus(str, Enum):
    FREE = "FREE"
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"
    MISSING = "MISSING"


class LicensePolicyError(PermissionError):
    """Raised when the current license does not permit an operation."""


class LicenseImportError(ValueError):
    """Raised when a selected license cannot be safely installed."""


class _ValidationFailure(ValueError):
    pass


class LicenseManager:
    """The only customer-side component that parses or verifies license files."""

    def __init__(
        self,
        license_path: str | Path | None = None,
        *,
        public_key_dir: str | Path | None = None,
        public_key_loader: Callable[[str], bytes] | None = None,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        configured_path = os.environ.get("STIG_AUDIT_PRO_LICENSE_PATH")
        self.license_path = Path(
            license_path or configured_path or default_license_path()
        ).expanduser()
        self._public_key_dir = Path(public_key_dir) if public_key_dir else None
        self._public_key_loader = public_key_loader
        self._now_provider = now_provider or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._reset(LicenseStatus.FREE)

    def load(self) -> LicenseStatus:
        with self._lock:
            self._reset(LicenseStatus.FREE)
            if not self.license_path.is_file():
                self.status = LicenseStatus.MISSING
                return self.status
            try:
                raw_text = self.license_path.read_text(encoding="utf-8")
            except OSError as exc:
                return self._fail(f"License file is not readable: {exc}")

            try:
                document = json.loads(
                    raw_text,
                    object_pairs_hook=_object_without_duplicate_keys,
                )
            except (json.JSONDecodeError, UnicodeError, _ValidationFailure) as exc:
                return self._fail(f"License file is not valid JSON: {exc}")

            try:
                payload, signature = self._validate_unsigned_structure(document)
                public_key = self._load_public_key(signature["key_id"])
                signature_bytes = self._decode_signature(signature["value"])
                public_key.verify(signature_bytes, canonicalize_license(payload))
                self.signature_verified = True
                issued_at = self._parse_utc_timestamp(payload["issued_at"], "issued_at")
                expires_at = self._parse_utc_timestamp(
                    payload["expires_at"], "expires_at"
                )
                now = self._current_utc()
                if issued_at > now + ISSUED_AT_FUTURE_TOLERANCE:
                    raise _ValidationFailure(
                        "License issued_at is unreasonably far in the future"
                    )
                if expires_at < issued_at:
                    raise _ValidationFailure(
                        "License expires_at must not be earlier than issued_at"
                    )
                self._validate_device_limit(payload["max_devices"])
                features = self._validate_features(payload["features"])
                self._apply_trusted_payload(
                    payload,
                    key_id=signature["key_id"],
                    issued_at=issued_at,
                    expires_at=expires_at,
                    features=features,
                )
                self.status = (
                    LicenseStatus.EXPIRED
                    if now > expires_at
                    else LicenseStatus.VALID
                )
                return self.status
            except InvalidSignature:
                return self._fail("License signature verification failed")
            except (
                _ValidationFailure,
                CanonicalizationError,
                ValueError,
                TypeError,
            ) as exc:
                return self._fail(str(exc))
            except Exception as exc:
                LOGGER.exception(
                    "Unexpected offline-license validation failure for %s",
                    self.license_path,
                )
                return self._fail(
                    "License validation failed because the file or bundled key could not be processed"
                )

    def reload(self) -> LicenseStatus:
        return self.load()

    @property
    def is_valid(self) -> bool:
        return self.status is LicenseStatus.VALID

    @property
    def is_expired(self) -> bool:
        return self.status is LicenseStatus.EXPIRED

    @property
    def edition(self) -> str:
        return self._trusted_edition if self.is_valid else "Free"

    @property
    def customer_name(self) -> str:
        return self._trusted_customer_name

    @property
    def license_id(self) -> str:
        return self._trusted_license_id

    @property
    def issued_at(self) -> datetime | None:
        return self._trusted_issued_at

    @property
    def expires_at(self) -> datetime | None:
        return self._trusted_expires_at

    @property
    def max_devices(self) -> int:
        return self._trusted_max_devices if self.is_valid else 1

    @property
    def key_id(self) -> str:
        return self._trusted_key_id

    @property
    def licensed_edition(self) -> str:
        return self._trusted_edition

    @property
    def licensed_max_devices(self) -> int:
        return self._trusted_max_devices

    @property
    def licensed_features(self) -> Mapping[str, bool]:
        return dict(self._trusted_features)

    @property
    def validation_errors(self) -> tuple[str, ...]:
        return tuple(self._validation_errors)

    @property
    def mode_summary(self) -> str:
        if self.status is LicenseStatus.VALID:
            return f"Valid — {self.edition}"
        return f"{self.status.value.title()} — Free mode"

    def feature_enabled(self, feature_name: str, *, refresh: bool = False) -> bool:
        self._validate_feature_name(feature_name)
        if refresh:
            self.reload()
        return self.is_valid and self._trusted_features.get(feature_name, False)

    def require_feature(self, feature_name: str, *, refresh: bool = True) -> None:
        self._validate_feature_name(feature_name)
        if refresh:
            self.reload()
        if self.feature_enabled(feature_name):
            return
        readable = feature_name.replace("_", " ")
        raise LicensePolicyError(
            f"{readable.title()} is not available in {self.edition} mode. "
            "Import a valid license that enables this feature."
        )

    def normalize_unique_targets(self, targets: Iterable[str]) -> tuple[str, ...]:
        normalized: list[str] = []
        seen: set[str] = set()
        for target in targets:
            try:
                value = str(ipaddress.ip_address(str(target).strip()))
            except ValueError as exc:
                raise LicensePolicyError(
                    f"Scan target is not a valid IP address: {target}"
                ) from exc
            if value not in seen:
                normalized.append(value)
                seen.add(value)
        return tuple(normalized)

    def require_scan_targets(
        self, targets: Iterable[str], *, refresh: bool = True
    ) -> tuple[str, ...]:
        if refresh:
            self.reload()
        normalized = self.normalize_unique_targets(targets)
        requested = len(normalized)
        permitted = self.max_devices
        if requested > 1 and not self.feature_enabled("multi_device_scan"):
            raise LicensePolicyError(
                f"This license permits 1 device per scan; {requested} unique devices "
                "were requested. Multi Device Scan is not enabled."
            )
        if requested > permitted:
            raise LicensePolicyError(
                f"This license permits {permitted} device(s) per scan; "
                f"{requested} unique devices were requested."
            )
        return normalized

    def import_license(self, source_path: str | Path) -> Path:
        source = Path(source_path).expanduser()
        candidate = LicenseManager(
            source,
            public_key_dir=self._public_key_dir,
            public_key_loader=self._public_key_loader,
            now_provider=self._now_provider,
        )
        status = candidate.load()
        if status is not LicenseStatus.VALID:
            detail = (
                candidate.validation_errors[0]
                if candidate.validation_errors
                else f"License status is {status.value}"
            )
            raise LicenseImportError(
                f"The selected license was not imported: {detail}."
            )
        destination = self.license_path
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{LICENSE_FILENAME}.tmp")
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)
        except OSError as exc:
            LOGGER.exception("Could not install license at %s", destination)
            raise LicenseImportError(
                "The license is valid but could not be copied to the application-data directory."
            ) from exc
        self.reload()
        return destination

    def _validate_unsigned_structure(
        self, document: Any
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if not isinstance(document, dict):
            raise _ValidationFailure("License document must be a JSON object")
        if set(document) != {"license", "signature"}:
            raise _ValidationFailure(
                "License document must contain only top-level license and signature objects"
            )
        payload = document.get("license")
        signature = document.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise _ValidationFailure(
                "Top-level license and signature values must be objects"
            )
        if set(payload) != _LICENSE_FIELDS:
            missing = sorted(_LICENSE_FIELDS - set(payload))
            unknown = sorted(set(payload) - _LICENSE_FIELDS)
            raise _ValidationFailure(
                self._field_set_error("license", missing, unknown)
            )
        if set(signature) != _SIGNATURE_FIELDS:
            missing = sorted(_SIGNATURE_FIELDS - set(signature))
            unknown = sorted(set(signature) - _SIGNATURE_FIELDS)
            raise _ValidationFailure(
                self._field_set_error("signature", missing, unknown)
            )

        self._require_exact_int(payload["schema_version"], "schema_version")
        for field in (
            "license_id",
            "customer_name",
            "product",
            "edition",
            "issued_at",
            "expires_at",
        ):
            self._require_nonempty_string(payload[field], field)
        self._require_exact_int(payload["max_devices"], "max_devices")
        if not isinstance(payload["features"], dict):
            raise _ValidationFailure("features must be an object")
        for field in ("algorithm", "key_id", "value"):
            self._require_nonempty_string(signature[field], f"signature.{field}")

        if payload["schema_version"] != SUPPORTED_SCHEMA_VERSION:
            raise _ValidationFailure(
                f"Unsupported license schema_version: {payload['schema_version']}"
            )
        if payload["product"] != PRODUCT_NAME:
            raise _ValidationFailure(
                f"License product must exactly equal {PRODUCT_NAME}"
            )
        if signature["algorithm"] != SIGNATURE_ALGORITHM:
            raise _ValidationFailure(
                f"Signature algorithm must exactly equal {SIGNATURE_ALGORITHM}"
            )
        try:
            validate_key_id(signature["key_id"])
        except ValueError as exc:
            raise _ValidationFailure("signature.key_id has an invalid format") from exc
        return payload, signature

    def _load_public_key(self, key_id: str) -> Ed25519PublicKey:
        try:
            if self._public_key_loader is not None:
                pem = self._public_key_loader(key_id)
            elif self._public_key_dir is not None:
                path = self._public_key_dir / f"{key_id}.pem"
                if not path.is_file():
                    raise FileNotFoundError(path)
                pem = path.read_bytes()
            else:
                resource = (
                    resources.files("stig_audit_pro")
                    .joinpath("resources")
                    .joinpath("licensing")
                    .joinpath("public_keys")
                    .joinpath(f"{key_id}.pem")
                )
                pem = resource.read_bytes()
        except (FileNotFoundError, OSError) as exc:
            raise _ValidationFailure(
                f"Unknown license signing key_id: {key_id}"
            ) from exc
        try:
            key = serialization.load_pem_public_key(pem)
        except (TypeError, ValueError) as exc:
            raise _ValidationFailure(
                f"Bundled public key {key_id} is not a valid PEM public key"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise _ValidationFailure(
                f"Bundled public key {key_id} is not an Ed25519 public key"
            )
        return key

    def _decode_signature(self, value: str) -> bytes:
        try:
            signature = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _ValidationFailure(
                "signature.value is not valid Base64"
            ) from exc
        if len(signature) != 64:
            raise _ValidationFailure(
                "signature.value is not a 64-byte Ed25519 signature"
            )
        return signature

    def _parse_utc_timestamp(self, value: str, field: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(
                value[:-1] + "+00:00" if value.endswith("Z") else value
            )
        except ValueError as exc:
            raise _ValidationFailure(
                f"{field} must be a valid timezone-aware UTC timestamp"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise _ValidationFailure(
                f"{field} must be a timezone-aware UTC timestamp"
            )
        return parsed.astimezone(timezone.utc)

    def _validate_device_limit(self, value: Any) -> None:
        self._require_exact_int(value, "max_devices")
        if value <= 0:
            raise _ValidationFailure("max_devices must be a positive integer")

    def _validate_features(self, value: Any) -> dict[str, bool]:
        if not isinstance(value, dict):
            raise _ValidationFailure("features must be an object")
        unknown = sorted(set(value) - SUPPORTED_FEATURES)
        if unknown:
            raise _ValidationFailure(
                f"Unsupported license feature name(s): {', '.join(unknown)}"
            )
        for name, enabled in value.items():
            if type(enabled) is not bool:
                raise _ValidationFailure(
                    f"Feature {name} must be a Boolean"
                )
        return {name: bool(value.get(name, False)) for name in SUPPORTED_FEATURES}

    def _apply_trusted_payload(
        self,
        payload: Mapping[str, Any],
        *,
        key_id: str,
        issued_at: datetime,
        expires_at: datetime,
        features: dict[str, bool],
    ) -> None:
        self._trusted_license_id = payload["license_id"]
        self._trusted_customer_name = payload["customer_name"]
        self._trusted_edition = payload["edition"]
        self._trusted_issued_at = issued_at
        self._trusted_expires_at = expires_at
        self._trusted_max_devices = payload["max_devices"]
        self._trusted_features = features
        self._trusted_key_id = key_id

    def _current_utc(self) -> datetime:
        now = self._now_provider()
        if now.tzinfo is None:
            raise _ValidationFailure(
                "Internal UTC clock provider returned a naive timestamp"
            )
        return now.astimezone(timezone.utc)

    def _fail(self, message: str) -> LicenseStatus:
        self.status = LicenseStatus.INVALID
        self._validation_errors.append(message)
        LOGGER.warning("Offline license rejected at %s: %s", self.license_path, message)
        return self.status

    def _reset(self, status: LicenseStatus) -> None:
        self.status = status
        self.signature_verified = False
        self._validation_errors: list[str] = []
        self._trusted_license_id = ""
        self._trusted_customer_name = ""
        self._trusted_edition = ""
        self._trusted_issued_at: datetime | None = None
        self._trusted_expires_at: datetime | None = None
        self._trusted_max_devices = 1
        self._trusted_features = {
            name: False for name in SUPPORTED_FEATURES
        }
        self._trusted_key_id = ""

    def _validate_feature_name(self, feature_name: str) -> None:
        if feature_name not in SUPPORTED_FEATURES:
            raise ValueError(f"Unknown application feature: {feature_name}")

    @staticmethod
    def _require_exact_int(value: Any, field: str) -> None:
        if type(value) is not int:
            raise _ValidationFailure(f"{field} must be an integer")

    @staticmethod
    def _require_nonempty_string(value: Any, field: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise _ValidationFailure(f"{field} must be a non-empty string")

    @staticmethod
    def _field_set_error(
        name: str, missing: list[str], unknown: list[str]
    ) -> str:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unsupported {', '.join(unknown)}")
        return f"{name} object has " + " and ".join(details)
