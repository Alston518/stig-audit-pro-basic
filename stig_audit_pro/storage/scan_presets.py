"""Credential-free reusable scan preset storage."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from stig_audit_pro.licensing.paths import application_data_dir


class ReportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    text: bool = True
    csv: bool = False
    json_report: bool = Field(default=True, alias="json")
    excel: bool = True
    ckl: bool = False
    cklb: bool = False


class ScanPreset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    preset_name: str
    device_group: str | None = None
    target_ips: list[str] = Field(default_factory=list)
    stig_families: list[str] = Field(default_factory=list)
    profile_name: str
    concurrency: int = Field(default=5, ge=1, le=20)
    connect_timeout: int = Field(default=30, ge=1, le=600)
    command_timeout: int = Field(default=30, ge=1, le=3600)
    report_options: ReportOptions = Field(default_factory=ReportOptions)

    @field_validator("preset_name", "profile_name")
    @classmethod
    def required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value must not be blank")
        return cleaned

    @field_validator("device_group")
    @classmethod
    def normalize_group(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("target_ips", "stig_families")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        output: list[str] = []
        for value in values:
            cleaned = value.strip()
            if cleaned and cleaned not in output:
                output.append(cleaned)
        return output


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip()).strip("._")
    return f"{cleaned or 'scan_preset'}.yaml"


class ScanPresetStore:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root is not None else application_data_dir() / "scan_presets"
        self.root.mkdir(parents=True, exist_ok=True)

    def list_presets(self) -> list[str]:
        presets: list[str] = []
        for path in sorted(self.root.glob("*.yaml")):
            try:
                presets.append(self.load(path.stem).preset_name)
            except Exception:
                continue
        return presets

    def load(self, name: str) -> ScanPreset:
        path = self._resolve(name)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise ValueError(f"Could not read scan preset {path}: {exc}") from exc
        return ScanPreset.model_validate(data)

    def save(self, preset: ScanPreset) -> Path:
        path = self.root / _safe_filename(preset.preset_name)
        payload = yaml.safe_dump(
            preset.model_dump(mode="json", by_alias=True), sort_keys=False, allow_unicode=True
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return path

    def delete(self, name: str) -> bool:
        path = self._resolve(name)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _resolve(self, name: str) -> Path:
        direct = self.root / _safe_filename(name)
        if direct.exists():
            return direct
        for path in self.root.glob("*.yaml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if str(data.get("preset_name", "")).casefold() == name.casefold():
                    return path
            except Exception:
                continue
        return direct


__all__ = ["ReportOptions", "ScanPreset", "ScanPresetStore"]
