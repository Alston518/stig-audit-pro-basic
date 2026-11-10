"""Bounded matching for check YAML and imported profile patterns."""

from __future__ import annotations

import regex


MAX_PATTERN_LENGTH = 4096
MATCH_TIMEOUT_SECONDS = 0.05


def search(pattern: str, value: str, *, flags: int = 0):
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError("Regex pattern exceeds the 4096 character limit")
    try:
        return regex.search(pattern, value, flags=flags, timeout=MATCH_TIMEOUT_SECONDS)
    except TimeoutError as exc:
        raise ValueError("Regex evaluation timed out") from exc
