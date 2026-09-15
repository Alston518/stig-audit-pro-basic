"""Plan safe commands needed for selected checks."""

from __future__ import annotations

from stig_audit_pro.core.command_policy import (
    DEFAULT_AUDIT_COMMANDS,
    DEFAULT_COMMAND_POLICY,
    UnsafeCommandError,
)
from stig_audit_pro.core.models import CheckDefinition


def is_safe_command(command: str) -> bool:
    """Compatibility wrapper around the authoritative command policy."""

    return DEFAULT_COMMAND_POLICY.is_allowed(command)


def validate_safe_commands(commands: list[str]) -> None:
    """Validate every command, raising :class:`UnsafeCommandError` on failure."""

    DEFAULT_COMMAND_POLICY.validate_many(commands)


def normalize_safe_commands(commands: list[str]) -> list[str]:
    """Validate and return commands in their canonical registered spelling."""

    return DEFAULT_COMMAND_POLICY.validate_many(commands)


def plan_commands(checks: list[CheckDefinition], run_all: bool = False) -> list[str]:
    commands: list[str] = []
    if run_all:
        commands.extend(DEFAULT_AUDIT_COMMANDS)
    else:
        commands.append("terminal length 0")
        for check in checks:
            commands.extend(check.commands)

    deduped: list[str] = []
    seen: set[str] = set()
    for command in commands:
        normalized = DEFAULT_COMMAND_POLICY.validate(command)
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


__all__ = [
    "UnsafeCommandError",
    "is_safe_command",
    "normalize_safe_commands",
    "plan_commands",
    "validate_safe_commands",
]
