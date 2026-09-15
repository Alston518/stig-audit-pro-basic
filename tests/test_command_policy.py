from __future__ import annotations

import pytest
import yaml

from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.command_policy import (
    APPROVED_COMMANDS,
    DEFAULT_COMMAND_POLICY,
    UnsafeCommandError,
)
from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_check_library


@pytest.mark.parametrize("command", APPROVED_COMMANDS)
def test_every_registered_command_is_approved(command: str) -> None:
    assert DEFAULT_COMMAND_POLICY.validate(command) == command


@pytest.mark.parametrize(
    "command",
    [
        "configure terminal",
        "show running-config\nconfigure terminal",
        "show running-config\rconfigure terminal",
        "show running-config ; reload",
        "show running-config && reload",
        "show running-config || reload",
        "write memory",
        "copy running-config startup-config",
        "reload",
        "terminal length 0\nreload",
        "show arbitrary-command",
        "show running-config | reload",
        "show running-config\x00reload",
        "show\trunning-config",
    ],
)
def test_unsafe_or_unknown_commands_fail_closed(command: str) -> None:
    with pytest.raises(UnsafeCommandError):
        DEFAULT_COMMAND_POLICY.validate(command)


def test_whitespace_is_normalized_to_registered_command() -> None:
    assert (
        DEFAULT_COMMAND_POLICY.validate("  show   running-config  ")
        == "show running-config"
    )


def test_planner_uses_canonical_policy_values() -> None:
    check = CheckDefinition(
        vuln_id="V-TEST",
        title="Test",
        stig_family="IOSXE_L2",
        severity="cat2",
        check_type="command_contains",
        commands=[" show   version "],
    )
    assert plan_commands([check]) == ["terminal length 0", "show version"]


def test_unsafe_yaml_fails_during_loading(tmp_path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "library_name": "unsafe",
                "library_version": "1",
                "checks": [
                    {
                        "vuln_id": "V-TEST",
                        "title": "Unsafe",
                        "stig_family": "IOSXE_L2",
                        "severity": "cat1",
                        "check_type": "command_contains",
                        "commands": ["show running-config ; reload"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="chaining|approved"):
        load_check_library(path)


def test_nested_yaml_command_reference_uses_same_policy(tmp_path) -> None:
    path = tmp_path / "unsafe-nested.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "checks": [
                    {
                        "vuln_id": "V-TEST",
                        "title": "Unsafe nested",
                        "stig_family": "IOSXE_L2",
                        "severity": "cat1",
                        "check_type": "command_contains",
                        "commands": ["show running-config"],
                        "conditions": {"command": "write memory"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="not approved"):
        load_check_library(path)


def test_legacy_library_has_explicit_compatibility_metadata(tmp_path) -> None:
    path = tmp_path / "legacy.yaml"
    path.write_text("library_name: legacy\nchecks: []\n", encoding="utf-8")
    library = load_check_library(path)
    assert library.schema_version == 1
    assert library.library_version == "legacy"


def test_partially_versioned_library_is_rejected(tmp_path) -> None:
    path = tmp_path / "partial.yaml"
    path.write_text("schema_version: 1\nchecks: []\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError, match="both schema_version"):
        load_check_library(path)
