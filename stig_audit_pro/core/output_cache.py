"""Per-device command output cache."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "value"


class CommandOutputCache:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def device_dir(self, ip: str) -> Path:
        path = self.root / _safe_name(ip)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def command_path(self, ip: str, command: str) -> Path:
        return self.device_dir(ip) / f"{_safe_name(command)}.txt"

    def metadata_path(self, ip: str) -> Path:
        return self.device_dir(ip) / "metadata.json"

    def save_output(self, ip: str, command: str, output: str) -> Path:
        path = self.command_path(ip, command)
        path.write_text(output, encoding="utf-8")
        return path

    def load_output(self, ip: str, command: str) -> str | None:
        path = self.command_path(ip, command)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def save_device_outputs(self, ip: str, outputs: dict[str, str]) -> None:
        for command, output in outputs.items():
            self.save_output(ip, command, output)
        metadata = {
            "ip": ip,
            "commands": sorted(outputs),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.metadata_path(ip).write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def load_device_outputs(self, ip: str, commands: list[str]) -> dict[str, str]:
        loaded: dict[str, str] = {}
        for command in commands:
            output = self.load_output(ip, command)
            if output is not None:
                loaded[command] = output
        return loaded
