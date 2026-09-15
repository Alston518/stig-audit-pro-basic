"""SQLAlchemy 2.x ORM models for local audit and STIG persistence.

The ORM objects intentionally remain infrastructure types.  Application and
core layers may use dataclasses or Pydantic models without depending on
SQLAlchemy, while repositories translate their attributes to these records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for the single local SQLite schema."""


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    __table_args__ = (CheckConstraint("id = 1", name="ck_schema_version_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuditRun(Base):
    __tablename__ = "audit_run"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    app_version: Mapped[str] = mapped_column(String(32), nullable=False)
    profile_name: Mapped[str | None] = mapped_column(String(255))
    profile_sha256: Mapped[str | None] = mapped_column(String(64))
    check_pack_sha256: Mapped[str | None] = mapped_column(String(64))
    stig_families: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    stig_benchmark: Mapped[str | None] = mapped_column(String(255))
    stig_version: Mapped[str | None] = mapped_column(String(64))
    stig_release: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(String(512))
    preset_name: Mapped[str | None] = mapped_column(String(255))
    collection_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="LIVE_SSH"
    )
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancelled_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    devices: Mapped[list["RunDevice"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", passive_deletes=True
    )


class RunDevice(Base):
    __tablename__ = "run_device"
    __table_args__ = (Index("ix_run_device_run_id", "run_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("audit_run.id", ondelete="CASCADE"), nullable=False
    )
    target_ip: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    serial_number: Mapped[str | None] = mapped_column(String(255))
    ios_version: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    run: Mapped[AuditRun] = relationship(back_populates="devices")
    check_results: Mapped[list["CheckResult"]] = relationship(
        back_populates="run_device", cascade="all, delete-orphan", passive_deletes=True
    )
    evidence_artifacts: Mapped[list["EvidenceArtifact"]] = relationship(
        back_populates="run_device", cascade="all, delete-orphan", passive_deletes=True
    )


class CheckResult(Base):
    __tablename__ = "check_result"
    __table_args__ = (
        Index("ix_check_result_device_status", "run_device_id", "status"),
        Index("ix_check_result_vuln_id", "vuln_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("run_device.id", ondelete="CASCADE"), nullable=False
    )
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(255))
    stig_id: Mapped[str | None] = mapped_column(String(255))
    check_id: Mapped[str | None] = mapped_column(String(255))
    stig_family: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_details: Mapped[str | None] = mapped_column(Text)
    comments: Mapped[str | None] = mapped_column(Text)
    evaluation_reason: Mapped[str | None] = mapped_column(Text)
    check_type: Mapped[str | None] = mapped_column(String(128))
    commands_used: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    profile_values: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    failed_objects: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    parser_warnings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    error_message: Mapped[str | None] = mapped_column(Text)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    run_device: Mapped[RunDevice] = relationship(back_populates="check_results")
    evidence_links: Mapped[list["ResultEvidence"]] = relationship(
        back_populates="check_result", cascade="all, delete-orphan", passive_deletes=True
    )
    evidence_artifacts: Mapped[list["EvidenceArtifact"]] = relationship(
        secondary="result_evidence", viewonly=True, overlaps="evidence_links"
    )


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifact"
    __table_args__ = (
        UniqueConstraint(
            "run_device_id", "relative_path", name="uq_evidence_device_relative_path"
        ),
        Index("ix_evidence_artifact_run_device", "run_device_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("run_device.id", ondelete="CASCADE"), nullable=False
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)

    run_device: Mapped[RunDevice] = relationship(back_populates="evidence_artifacts")
    result_links: Mapped[list["ResultEvidence"]] = relationship(
        back_populates="evidence_artifact",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    check_results: Mapped[list[CheckResult]] = relationship(
        secondary="result_evidence", viewonly=True, overlaps="result_links"
    )


class ResultEvidence(Base):
    __tablename__ = "result_evidence"

    check_result_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("check_result.id", ondelete="CASCADE"),
        primary_key=True,
    )
    evidence_artifact_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("evidence_artifact.id", ondelete="CASCADE"),
        primary_key=True,
    )

    check_result: Mapped[CheckResult] = relationship(
        back_populates="evidence_links", overlaps="evidence_artifacts,check_results"
    )
    evidence_artifact: Mapped[EvidenceArtifact] = relationship(
        back_populates="result_links", overlaps="evidence_artifacts,check_results"
    )


class StigBenchmark(Base):
    __tablename__ = "stig_benchmark"
    __table_args__ = (
        Index("ix_stig_benchmark_family_benchmark", "family", "benchmark_id"),
        Index("ix_stig_benchmark_source_sha256", "source_sha256"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    family: Mapped[str] = mapped_column(String(255), nullable=False)
    benchmark_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(64))
    release: Mapped[str | None] = mapped_column(String(64))
    release_info: Mapped[str | None] = mapped_column(Text)
    release_date: Mapped[str | None] = mapped_column(String(64))
    source_filename: Mapped[str | None] = mapped_column(String(512))
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    benchmark_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    rules: Mapped[list["StigRule"]] = relationship(
        back_populates="benchmark", cascade="all, delete-orphan", passive_deletes=True
    )


class StigRule(Base):
    __tablename__ = "stig_rule"
    __table_args__ = (
        Index("ix_stig_rule_vuln_id", "vuln_id"),
        Index("ix_stig_rule_rule_id", "rule_id"),
        Index("ix_stig_rule_benchmark", "benchmark_db_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    benchmark_db_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("stig_benchmark.id", ondelete="CASCADE"), nullable=False
    )
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(255))
    stig_id: Mapped[str | None] = mapped_column(String(255))
    group_id: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str | None] = mapped_column(Text)
    check_text: Mapped[str | None] = mapped_column(Text)
    fix_text: Mapped[str | None] = mapped_column(Text)
    rule_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    check_fingerprint: Mapped[str | None] = mapped_column(String(64))
    fix_fingerprint: Mapped[str | None] = mapped_column(String(64))
    field_fingerprints: Mapped[dict[str, str]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    benchmark: Mapped[StigBenchmark] = relationship(back_populates="rules")
    mappings: Mapped[list["CheckMapping"]] = relationship(
        back_populates="stig_rule", passive_deletes=True
    )


class CheckMapping(Base):
    __tablename__ = "check_mapping"
    __table_args__ = (
        Index("ix_check_mapping_vuln_rule", "vuln_id", "rule_id"),
        Index("ix_check_mapping_stig_rule", "stig_rule_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stig_rule_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("stig_rule.id", ondelete="SET NULL")
    )
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(255))
    stig_id: Mapped[str | None] = mapped_column(String(255))
    check_file: Mapped[str | None] = mapped_column(Text)
    check_id: Mapped[str | None] = mapped_column(String(255))
    check_type: Mapped[str | None] = mapped_column(String(128))
    source_benchmark: Mapped[str | None] = mapped_column(String(255))
    source_version: Mapped[str | None] = mapped_column(String(64))
    source_release: Mapped[str | None] = mapped_column(String(64))
    automation_status: Mapped[str] = mapped_column(String(64), nullable=False)
    review_status: Mapped[str | None] = mapped_column(String(64))
    last_reviewed_stig_fingerprint: Mapped[str | None] = mapped_column(String(64))
    reviewed_release: Mapped[str | None] = mapped_column(String(64))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    stig_rule: Mapped[StigRule | None] = relationship(back_populates="mappings")


class ActivityLog(Base):
    """Secret-free application activity trail for the local desktop product."""

    __tablename__ = "activity_log"
    __table_args__ = (
        Index("ix_activity_log_timestamp", "timestamp"),
        Index("ix_activity_log_object", "object_type", "object_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    object_type: Mapped[str] = mapped_column(String(128), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    local_username: Mapped[str | None] = mapped_column(String(255))


# Explicit aliases make it clear at call sites when an ORM record is intended,
# while preserving intuitive model names for direct schema inspection.
AuditRunRecord = AuditRun
RunDeviceRecord = RunDevice
CheckResultRecord = CheckResult
EvidenceArtifactRecord = EvidenceArtifact
ResultEvidenceRecord = ResultEvidence
StigBenchmarkRecord = StigBenchmark
StigRuleRecord = StigRule
CheckMappingRecord = CheckMapping
ActivityLogRecord = ActivityLog
