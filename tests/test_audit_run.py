from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.models import (
    AuditRun,
    CollectionMode,
    DeviceStatus,
    RunDevice,
    RunStatus,
)
from stig_audit_pro.core.result_model import CheckResult


def test_audit_run_has_uuid_utc_start_and_v02_version() -> None:
    run = AuditRun(device_count=2, stig_families=["IOSXE_L2", "IOSXE_L2"])
    assert str(UUID(run.run_id)) == run.run_id
    assert run.started_at.utcoffset() == timedelta(0)
    assert run.status == RunStatus.CREATED
    assert run.app_version == APP_VERSION == "0.2.0"
    assert run.stig_families == ["IOSXE_L2"]


def test_audit_run_forbids_credentials() -> None:
    with pytest.raises(ValidationError, match="password"):
        AuditRun(password="must-never-persist")  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="enable_secret"):
        AuditRun(enable_secret="must-never-persist")  # type: ignore[call-arg]


def test_audit_run_validates_counts_and_completion_time() -> None:
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="must not exceed"):
        AuditRun(device_count=1, success_count=2)
    with pytest.raises(ValidationError, match="earlier"):
        AuditRun(started_at=now, completed_at=now - timedelta(seconds=1))


def test_run_device_tracks_lifecycle_without_credentials() -> None:
    run = AuditRun(device_count=1, collection_mode=CollectionMode.OFFLINE_IMPORTED)
    device = RunDevice(
        run_id=run.run_id,
        target_ip=" 192.0.2.10 ",
        status=DeviceStatus.COLLECTING,
    )
    assert device.target_ip == "192.0.2.10"
    assert device.status == DeviceStatus.COLLECTING
    with pytest.raises(ValidationError, match="password"):
        RunDevice(
            run_id=run.run_id,
            target_ip="192.0.2.10",
            password="secret",
        )


def test_check_result_traceability_fields_are_report_independent() -> None:
    run = AuditRun(device_count=1)
    result = CheckResult(
        run_id=run.run_id,
        ip="192.0.2.10",
        hostname="SW01",
        vuln_id="V-1",
        rule_id="SV-1r1_rule",
        stig_id="CISC-L2-000001",
        check_id="local-check-1",
        check_type="command_contains",
        stig_family="IOSXE_L2",
        title="Example",
        severity="cat2",
        status="Open",
        commands_used=["show running-config"],
        evidence_artifact_ids=[7],
        profile_values_used={"native_vlan": 333},
        evaluation_reason="Required configuration was absent.",
        parser_warnings=["One interface block was incomplete."],
    )
    assert result.evidence_artifact_ids == [7]
    assert result.profile_values_used["native_vlan"] == 333
    assert not result.passed
