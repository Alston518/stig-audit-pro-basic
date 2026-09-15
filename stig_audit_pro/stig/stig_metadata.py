"""Normalized, fingerprinted metadata extracted from DISA XCCDF benchmarks.

These domain models are independent of SQLAlchemy so they can be snapshotted,
serialized in reports, and adapted to the local SQLite repository.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


RULE_FINGERPRINT_FIELDS: tuple[str, ...] = (
    "vuln_id",
    "rule_id",
    "stig_id",
    "group_id",
    "title",
    "severity",
    "check_text",
    "fix_text",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> str:
    """Serialize a value deterministically for stable fingerprints."""

    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def fingerprint_value(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def normalize_identifier(value: str | None) -> str:
    """Normalize identifiers without changing their punctuation."""

    return " ".join(unicodedata.normalize("NFKC", value or "").strip().split()).upper()


def normalize_metadata_text(value: str | None) -> str:
    """Normalize prose fields where whitespace has no semantic meaning."""

    normalized = unicodedata.normalize("NFKC", value or "")
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    return " ".join(normalized.split())


def normalize_procedure_text(value: str | None) -> str:
    """Normalize XCCDF procedures while retaining IOS command syntax.

    Line endings, trailing whitespace, and surrounding empty lines are noise.
    Leading indentation and whitespace inside nonempty lines are preserved
    because they can convey configuration hierarchy or literal commands.
    """

    normalized = unicodedata.normalize("NFKC", value or "")
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    compact: list[str] = []
    for line in lines:
        if not line and compact and not compact[-1]:
            continue
        compact.append(line)
    return "\n".join(compact)


def extract_release(release_info: str, version: str = "") -> str:
    """Extract a release label without conflating it with STIG version."""

    match = re.search(
        r"\bRelease\s*:\s*([^,;\n]+?)(?=\s+Benchmark\s+Date\b|$)",
        release_info,
        re.IGNORECASE,
    )
    if match:
        return " ".join(match.group(1).split())
    match = re.search(r"\bV?\d+R(\d+)\b", version, re.IGNORECASE)
    return match.group(1) if match else ""


class StigRuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_id: str
    rule_id: str = ""
    stig_id: str = ""
    group_id: str = ""
    title: str = ""
    severity: str = ""
    discussion: str = ""
    identifiers: list[str] = Field(default_factory=list)
    check_text: str = ""
    fix_text: str = ""
    rule_fingerprint: str = ""
    check_fingerprint: str = ""
    fix_fingerprint: str = ""
    field_fingerprints: dict[str, str] = Field(default_factory=dict)
    database_id: int | None = None

    @model_validator(mode="after")
    def populate_fingerprints(self) -> Self:
        self.calculate_fingerprints()
        return self

    def normalized_fields(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for field_name in RULE_FINGERPRINT_FIELDS:
            value = str(getattr(self, field_name, "") or "")
            if field_name in {"vuln_id", "rule_id", "stig_id", "group_id"}:
                result[field_name] = normalize_identifier(value)
            elif field_name in {"check_text", "fix_text"}:
                result[field_name] = normalize_procedure_text(value)
            else:
                result[field_name] = normalize_metadata_text(value)
        return result

    def calculate_fingerprints(self) -> "StigRuleMetadata":
        normalized = self.normalized_fields()
        self.field_fingerprints = {
            name: fingerprint_value(value) for name, value in normalized.items()
        }
        self.check_fingerprint = self.field_fingerprints["check_text"]
        self.fix_fingerprint = self.field_fingerprints["fix_text"]
        self.rule_fingerprint = fingerprint_value(normalized)
        return self


class StigBenchmarkMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_path: str = ""
    source_filename: str = ""
    source_sha256: str = ""
    family: str = ""
    benchmark_id: str = ""
    title: str = ""
    version: str = ""
    release: str = ""
    release_info: str = ""
    release_date: str = ""
    imported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    benchmark_fingerprint: str = ""
    database_id: int | None = None
    rules: list[StigRuleMetadata] = Field(default_factory=list)

    @model_validator(mode="after")
    def populate_release_and_fingerprints(self) -> Self:
        if not self.release:
            self.release = extract_release(self.release_info, self.version)
        self.calculate_fingerprints()
        return self

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def rule_by_vuln(self, vuln_id: str) -> StigRuleMetadata | None:
        wanted = normalize_identifier(vuln_id)
        for rule in self.rules:
            if normalize_identifier(rule.vuln_id) == wanted:
                return rule
        return None

    @property
    def display_name(self) -> str:
        return self.title or self.benchmark_id or Path(self.source_filename).stem

    @property
    def benchmark_release_date(self) -> str:
        match = re.search(
            r"\bBenchmark Date:\s*"
            r"(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}|\d{4}-\d{2}-\d{2})",
            self.release_info,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1)
        return self.release_date

    @property
    def release_label(self) -> str:
        if self.version and self.release and self.release not in self.version:
            return f"{self.version} Release {self.release}"
        return self.version or self.release or "Unknown release"

    def calculate_fingerprints(self) -> "StigBenchmarkMetadata":
        for rule in self.rules:
            rule.calculate_fingerprints()
        normalized = {
            "family": normalize_identifier(self.family),
            "benchmark_id": normalize_identifier(self.benchmark_id),
            "title": normalize_metadata_text(self.title),
            "version": normalize_metadata_text(self.version),
            "release": normalize_metadata_text(self.release),
            "release_info": normalize_metadata_text(self.release_info),
            "release_date": normalize_metadata_text(self.release_date),
            "rules": sorted(rule.rule_fingerprint for rule in self.rules),
        }
        self.benchmark_fingerprint = fingerprint_value(normalized)
        if not self.source_sha256 and self.source_path:
            try:
                source = Path(self.source_path)
                if source.is_file():
                    self.source_sha256 = sha256_bytes(source.read_bytes())
            except OSError:
                # Persistence validates this field. In-memory comparisons can
                # still be useful when the original source is unavailable.
                pass
        return self
