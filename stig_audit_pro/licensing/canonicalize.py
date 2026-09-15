"""Deterministic JSON serialization shared by license issuance and verification.

The license schema intentionally excludes floating-point values.  Canonical
bytes use UTF-8, lexicographically sorted object keys, JSON's lowercase
Boolean/null tokens, and no insignificant whitespace.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the license format."""


def canonicalize_license(payload: Mapping[str, Any]) -> bytes:
    """Return the exact bytes signed for a complete ``license`` object."""

    _reject_floats(payload)
    try:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(f"License payload is not valid JSON: {exc}") from exc
    return text.encode("utf-8")


def _reject_floats(value: Any, path: str = "license") -> None:
    if isinstance(value, float):
        raise CanonicalizationError(f"Floating-point values are not allowed at {path}")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"Object key at {path} must be a string")
            _reject_floats(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_floats(child, f"{path}[{index}]")
