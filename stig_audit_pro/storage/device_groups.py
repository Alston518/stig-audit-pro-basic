"""Local YAML storage for reusable device groups."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class DeviceTargetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    profile_override: str | None = None
    checked: bool = True

    @field_validator("ip")
    @classmethod
    def ip_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("ip must not be empty")
        return value.strip()


class DeviceGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_name: str
    profile_name: str | None = None
    targets: list[DeviceTargetRecord] = Field(default_factory=list)

    @field_validator("group_name")
    @classmethod
    def name_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("group_name must not be empty")
        return value.strip()

    @field_validator("profile_name")
    @classmethod
    def profile_name_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            return None
        return value.strip() if value is not None else None


def safe_group_filename(group_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", group_name.strip()).strip("_")
    return f"{safe or 'device_group'}.yaml"


class DeviceGroupStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def list_groups(self) -> list[str]:
        names: list[str] = []
        for path in sorted(self.root.glob("*.yaml")):
            try:
                group = self.load_group(path.stem)
                names.append(group.group_name)
            except Exception:
                names.append(path.stem)
        return names

    def load_group(self, group_name: str) -> DeviceGroup:
        path = self._path_for(group_name)
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return DeviceGroup.model_validate(data)

    def save_group(self, group: DeviceGroup) -> Path:
        path = self.root / safe_group_filename(group.group_name)
        data = {
            "group_name": group.group_name,
            "profile_name": group.profile_name,
            "targets": [
                {
                    "ip": target.ip,
                    "profile_override": target.profile_override,
                    "checked": target.checked,
                }
                for target in group.targets
            ],
        }
        with path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False)
        return path

    def _path_for(self, group_name: str) -> Path:
        exact = self.root / safe_group_filename(group_name)
        if exact.exists():
            return exact
        for path in self.root.glob("*.yaml"):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
                if str(data.get("group_name", "")).lower() == group_name.lower():
                    return path
            except Exception:
                continue
        return exact
