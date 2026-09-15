"""Pydantic domain models for checks, profiles, and audit runs."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stig_audit_pro.config import APP_VERSION, SUPPORTED_CHECK_TYPES, VALID_STATUSES
from stig_audit_pro.core.command_policy import DEFAULT_COMMAND_POLICY


StatusLiteral = Literal[
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
]

CheckTypeLiteral = Literal[
    "command_contains",
    "command_not_contains",
    "command_pattern_policy",
    "command_regex",
    "section_contains",
    "section_not_contains",
    "interface_policy",
    "interface_config_policy",
    "management_access_policy",
    "ntp_authentication_policy",
    "trunk_vlan_policy",
    "acl_deny_logging_policy",
    "dhcp_snooping_policy",
    "arp_inspection_policy",
    "dod_banner_policy",
    "radius_server_policy",
    "root_guard_neighbor_policy",
    "vty_session_limit_policy",
    "manual_review",
]


class StrictModel(BaseModel):
    """Base model with unknown-key rejection for external/domain schemas."""

    model_config = ConfigDict(extra="forbid")


class ResultMapping(StrictModel):
    pass_status: StatusLiteral = "NotAFinding"
    fail_status: StatusLiteral = "Open"
    error_status: StatusLiteral = "Error"


class EvidenceConfig(StrictModel):
    include_command_output: bool = False
    include_failed_objects: bool = True
    pass_comment: str = ""
    fail_comment: str = ""
    error_comment: str = ""
    finding_details_template: str = "default"


def _normalize_nested_commands(value: Any) -> Any:
    """Validate command references inside free-form parser/condition mappings."""

    if isinstance(value, list):
        return [_normalize_nested_commands(item) for item in value]
    if not isinstance(value, dict):
        return value

    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key == "command":
            if not isinstance(item, str):
                raise ValueError("command references must be strings")
            normalized[key] = DEFAULT_COMMAND_POLICY.validate(item)
        elif key == "commands":
            if not isinstance(item, list) or not all(
                isinstance(command, str) for command in item
            ):
                raise ValueError("commands references must be a list of strings")
            normalized[key] = DEFAULT_COMMAND_POLICY.validate_many(item)
        else:
            normalized[key] = _normalize_nested_commands(item)
    return normalized


class CheckDefinition(StrictModel):
    vuln_id: str
    title: str
    looking_for: str = ""
    stig_family: str
    severity: str
    check_type: CheckTypeLiteral
    commands: list[str] = Field(default_factory=list)
    automated: bool = True
    check_id: str | None = None
    stig_id: str | None = None
    group_id: str | None = None
    rule_id: str | None = None
    source_benchmark: str | None = None
    source_version: str | None = None
    source_release: str | None = None
    automation_status: str | None = None
    review_status: str | None = None
    last_reviewed_stig_fingerprint: str | None = None
    reviewed_release: str | None = None
    reviewed_at: datetime | None = None
    parser: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    conditions: dict[str, Any] = Field(default_factory=dict)
    result: ResultMapping = Field(default_factory=ResultMapping)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @field_validator("vuln_id", "title", "stig_family", "severity")
    @classmethod
    def require_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @field_validator("check_type")
    @classmethod
    def validate_supported_check_type(cls, value: str) -> str:
        if value not in SUPPORTED_CHECK_TYPES:
            raise ValueError(f"unsupported check_type: {value}")
        return value

    @field_validator("commands")
    @classmethod
    def commands_must_be_approved(cls, value: list[str]) -> list[str]:
        return DEFAULT_COMMAND_POLICY.validate_many(value)

    @model_validator(mode="after")
    def validate_check_semantics(self) -> Self:
        if self.automated and self.check_type != "manual_review" and not self.commands:
            raise ValueError("automated checks must declare at least one command")

        # These mappings intentionally remain extensible because each check
        # type owns its parser/condition schema.  Any command-like values they
        # contain still pass through the central runtime policy.
        self.parser = _normalize_nested_commands(self.parser)
        self.scope = _normalize_nested_commands(self.scope)
        self.conditions = _normalize_nested_commands(self.conditions)
        return self


class CheckLibrary(StrictModel):
    schema_version: Literal[1] = 1
    library_name: str | None = None
    library_version: str = "legacy"
    checks: list[CheckDefinition] = Field(default_factory=list)

    @field_validator("library_name")
    @classmethod
    def library_name_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("library_name must not be blank")
        return value

    @field_validator("library_version")
    @classmethod
    def library_version_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("library_version must not be blank")
        return value

    @model_validator(mode="after")
    def vuln_ids_must_be_unique(self) -> Self:
        metadata_fields = {"schema_version", "library_version"}
        supplied_metadata = metadata_fields.intersection(self.model_fields_set)
        if supplied_metadata and supplied_metadata != metadata_fields:
            raise ValueError(
                "schema_version and library_version must be declared together"
            )
        seen: set[str] = set()
        duplicates: set[str] = set()
        for check in self.checks:
            if check.vuln_id in seen:
                duplicates.add(check.vuln_id)
            seen.add(check.vuln_id)
        if duplicates:
            raise ValueError(f"duplicate vuln_id values: {', '.join(sorted(duplicates))}")
        return self


class DisabledPortPolicy(StrictModel):
    require_shutdown: bool = True
    required_access_vlan: int = 999


class TrunkPolicy(StrictModel):
    vlan_1_must_be_pruned: bool = True
    additional_pruned_vlans: list[int] = Field(default_factory=list)


class DhcpSnoopingPolicy(StrictModel):
    enabled: bool = True
    vlans: list[int] = Field(default_factory=list)
    required_global_commands: list[str] = Field(default_factory=lambda: ["ip dhcp snooping"])


class ArpInspectionPolicy(StrictModel):
    enabled: bool = True
    vlans: list[int] = Field(default_factory=list)


class RootGuardPolicy(StrictModel):
    upstream_switches: list[str] = Field(default_factory=list)


class ManagementNetwork(StrictModel):
    network_address: str
    subnet_mask: str


class ManagementAccessPolicy(StrictModel):
    acl_name: str = "MANAGEMENT_NET"
    networks: list[ManagementNetwork] = Field(default_factory=list)


class EndpointAuthenticationPolicy(StrictModel):
    radius_group: str = "ISE-RADIUS"
    radius_servers: list[str] = Field(default_factory=list)
    radius_server_addresses: dict[str, str] = Field(default_factory=dict)


class ProfileComments(StrictModel):
    default_open_prefix: str = "Automated STIG validation found noncompliant configuration."
    default_pass_prefix: str = "Automated STIG validation found required configuration present."
    default_error_prefix: str = (
        "Automated STIG validation could not confidently evaluate this requirement."
    )


class SiteProfile(StrictModel):
    profile_name: str
    inherits: str | None = None
    variables: dict[str, Any] = Field(default_factory=dict)
    unused_vlan: int = 999
    native_vlan: int = 333
    management_vlan: int = 300
    disabled_port_policy: DisabledPortPolicy = Field(default_factory=DisabledPortPolicy)
    trunk_policy: TrunkPolicy = Field(default_factory=TrunkPolicy)
    dhcp_snooping: DhcpSnoopingPolicy = Field(default_factory=DhcpSnoopingPolicy)
    arp_inspection: ArpInspectionPolicy = Field(default_factory=ArpInspectionPolicy)
    root_guard: RootGuardPolicy = Field(default_factory=RootGuardPolicy)
    management_access: ManagementAccessPolicy = Field(
        default_factory=ManagementAccessPolicy
    )
    endpoint_authentication: EndpointAuthenticationPolicy = Field(
        default_factory=EndpointAuthenticationPolicy
    )
    comments: ProfileComments = Field(default_factory=ProfileComments)

    @field_validator("profile_name")
    @classmethod
    def profile_name_must_be_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("profile_name must not be empty")
        return value

    @field_validator("unused_vlan", "native_vlan", "management_vlan")
    @classmethod
    def vlan_must_be_valid(cls, value: int) -> int:
        if value < 1 or value > 4094:
            raise ValueError("VLAN must be between 1 and 4094")
        return value


class RunStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DeviceStatus(str, Enum):
    QUEUED = "QUEUED"
    CONNECTING = "CONNECTING"
    COLLECTING = "COLLECTING"
    PARSING = "PARSING"
    EVALUATING = "EVALUATING"
    COMPLETE = "COMPLETE"
    AUTH_FAILED = "AUTH_FAILED"
    CONNECT_FAILED = "CONNECT_FAILED"
    COLLECTION_FAILED = "COLLECTION_FAILED"
    EVALUATION_FAILED = "EVALUATION_FAILED"
    CANCELLED = "CANCELLED"


class CollectionMode(str, Enum):
    LIVE_SSH = "LIVE_SSH"
    SAMPLE = "SAMPLE"
    OFFLINE_IMPORTED = "OFFLINE_IMPORTED"
    IMPORTED_HISTORICAL_AUDIT = "IMPORTED_HISTORICAL_AUDIT"


def _utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AuditRun(StrictModel):
    """Reproducible top-level record for one audit execution.

    Credentials are deliberately absent.  ``extra='forbid'`` also prevents a
    caller from accidentally attaching password/secret fields to this model.
    """

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    status: RunStatus = RunStatus.CREATED
    app_version: str = APP_VERSION
    description: str | None = None
    preset_name: str | None = None
    collection_mode: CollectionMode = CollectionMode.LIVE_SSH
    stig_families: list[str] = Field(default_factory=list)
    profile_name: str | None = None
    profile_sha256: str | None = None
    check_pack_sha256: str | None = None
    stig_benchmark: str | None = None
    stig_version: str | None = None
    stig_release: str | None = None
    device_count: int = Field(default=0, ge=0)
    success_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    cancelled_count: int = Field(default=0, ge=0)

    @field_validator("run_id", mode="before")
    @classmethod
    def run_id_must_be_uuid(cls, value: object) -> str:
        try:
            return str(UUID(str(value)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("run_id must be a UUID") from exc

    @field_validator("started_at", "completed_at", mode="after")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        return _utc_datetime(value)

    @field_validator("stig_families")
    @classmethod
    def normalize_families(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for family in value:
            clean = family.strip()
            if not clean:
                raise ValueError("STIG family must not be blank")
            if clean not in seen:
                normalized.append(clean)
                seen.add(clean)
        return normalized

    @model_validator(mode="after")
    def completion_time_is_valid(self) -> Self:
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must not be earlier than started_at")
        completed_devices = self.success_count + self.failure_count + self.cancelled_count
        if completed_devices > self.device_count:
            raise ValueError("run outcome counts must not exceed device_count")
        return self

    @property
    def selected_stig_families(self) -> tuple[str, ...]:
        return tuple(self.stig_families)


class RunDevice(StrictModel):
    id: int | None = None
    run_id: str
    target_ip: str
    hostname: str | None = None
    serial_number: str | None = None
    ios_version: str | None = None
    status: DeviceStatus = DeviceStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None

    @field_validator("run_id", mode="before")
    @classmethod
    def run_id_must_be_uuid(cls, value: object) -> str:
        try:
            return str(UUID(str(value)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("run_id must be a UUID") from exc

    @field_validator("target_ip")
    @classmethod
    def target_must_not_be_blank(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("target_ip must not be blank")
        return clean

    @field_validator("started_at", "completed_at", mode="after")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def completion_time_is_valid(self) -> Self:
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at must not be earlier than started_at")
        return self


def validate_status(value: str) -> str:
    if value not in VALID_STATUSES:
        raise ValueError(f"unsupported result status: {value}")
    return value


__all__ = [
    "ArpInspectionPolicy",
    "AuditRun",
    "CheckDefinition",
    "CheckLibrary",
    "CheckTypeLiteral",
    "CollectionMode",
    "DeviceStatus",
    "DhcpSnoopingPolicy",
    "DisabledPortPolicy",
    "EndpointAuthenticationPolicy",
    "EvidenceConfig",
    "ManagementAccessPolicy",
    "ManagementNetwork",
    "ProfileComments",
    "ResultMapping",
    "RootGuardPolicy",
    "RunDevice",
    "RunStatus",
    "SiteProfile",
    "StatusLiteral",
    "StrictModel",
    "TrunkPolicy",
    "validate_status",
]
