"""Neutralize untrusted strings that spreadsheet programs treat as formulas."""

from __future__ import annotations

from typing import Any


FORMULA_PREFIXES = ("=", "+", "-", "@")


def safe_spreadsheet_value(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.lstrip()
        if stripped.startswith(FORMULA_PREFIXES):
            return "'" + value
    return value


def safe_spreadsheet_row(row):
    if isinstance(row, dict):
        return {key: safe_spreadsheet_value(value) for key, value in row.items()}
    return [safe_spreadsheet_value(value) for value in row]


__all__ = ["FORMULA_PREFIXES", "safe_spreadsheet_row", "safe_spreadsheet_value"]
