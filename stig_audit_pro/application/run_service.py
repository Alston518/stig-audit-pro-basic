"""Persistent audit-run lifecycle, history, snapshots, and offline imports."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from stig_audit_pro.application.audit_package_service import AuditPackageService
from stig_audit_pro.application.audit_service import AuditService, AuditServiceResult
from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.command_policy import DEFAULT_COMMAND_POLICY
from stig_audit_pro.core.evidence import EvidenceArtifact
from stig_audit_pro.core.models import AuditRun, CollectionMode, DeviceStatus, RunStatus
from stig_audit_pro.core.result_model import CheckResult, FindingObject
from stig_audit_pro.infrastructure.persistence import Database
from stig_audit_pro.infrastructure.persistence.repositories import ActivityLogRepository, AuditRunRepository
from stig_audit_pro.logging_config import audit_logger
from stig_audit_pro.parsers.iosxe_facts import parse_facts


LOGGER = logging.getLogger(__name__)


class TargetLike(Protocol):
    ip: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Path):
        return value.as_posix()
    if hasattr(value, "__dict__"):
        return {
            key: _plain(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return value


def _snapshot_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return yaml.safe_dump(
        _plain(value),
        sort_keys=True,
        allow_unicode=True,
        default_flow_style=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class OfflineEvidenceDevice(BaseModel):
    """Operator-supplied evidence for one device; no SSH is initiated."""

    model_config = ConfigDict(extra="forbid")

    target_ip: str
    hostname: str | None = None
    source: str
    collected_at: datetime
    imported_at: datetime = Field(default_factory=_utc_now)
    outputs: dict[str, str]

    @field_validator("target_ip", "source")
    @classmethod
    def required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value must not be blank")
        return cleaned

    @field_validator("collected_at", "imported_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("outputs")
    @classmethod
    def approved_commands(cls, value: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for command, output in value.items():
            approved = DEFAULT_COMMAND_POLICY.validate(command)
            if approved in normalized:
                raise ValueError(f"duplicate command after normalization: {approved}")
            if not isinstance(output, str):
                raise ValueError("offline command output must be text")
            normalized[approved] = output
        if not normalized:
            raise ValueError("at least one command output is required")
        return normalized

    @property
    def ip(self) -> str:
        return self.target_ip


@dataclass(slots=True)
class RunContext:
    run: AuditRun
    device_ids: dict[str, int]
    commands_requested: list[str]
    lock: threading.RLock = field(default_factory=threading.RLock)
    artifacts_by_device: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def run_id(self) -> str:
        return self.run.run_id


@dataclass(frozen=True, slots=True)
class RunHistoryItem:
    id: str
    started_at: datetime
    status: str
    description: str
    preset_name: str
    collection_mode: str
    stig_families: tuple[str, ...]
    stig_version: str
    stig_release: str
    profile_name: str
    device_count: int
    open_count: int
    pass_count: int
    error_count: int


class RunService:
    """Own the durable boundary around an :class:`AuditService` execution."""

    def __init__(
        self,
        database: Database | None = None,
        *,
        repository: AuditRunRepository | None = None,
        evidence_store: Any | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.database = database or Database()
        self.repository = repository or AuditRunRepository(self.database)
        self.activity_log = ActivityLogRepository(self.database)
        if evidence_store is None:
            from stig_audit_pro.infrastructure.evidence.evidence_store import EvidenceStore

            evidence_store = EvidenceStore(repository=self.repository)
        self.evidence_store = evidence_store
        self.audit_service = audit_service or AuditService()
        location = self.database.path or self.database.url
        LOGGER.info("Audit history database: %s", location)
        LOGGER.info("Audit evidence root: %s", self.evidence_store.root)

    def begin_run(
        self,
        *,
        targets: Iterable[TargetLike | str],
        checks: Iterable[Any],
        profile: Any,
        stig_families: Iterable[str],
        commands_requested: Iterable[str],
        run_id: str | None = None,
        description: str | None = None,
        preset_name: str | None = None,
        collection_mode: CollectionMode | str = CollectionMode.LIVE_SSH,
        stig_benchmark: str | None = None,
        stig_version: str | None = None,
        stig_release: str | None = None,
    ) -> RunContext:
        target_list = list(targets)
        target_ips = [
            str(target if isinstance(target, str) else target.ip).strip()
            for target in target_list
        ]
        if any(not ip for ip in target_ips) or len(set(target_ips)) != len(target_ips):
            raise ValueError("Audit targets must be non-empty and unique")
        check_list = list(checks)
        profile_bytes = _snapshot_bytes(profile)
        check_snapshot = {
            "schema_version": 1,
            "checks": [_plain(check) for check in check_list],
        }
        check_bytes = _snapshot_bytes(check_snapshot)
        run = AuditRun(
            run_id=run_id or str(uuid4()),
            status=RunStatus.CREATED,
            description=description,
            preset_name=preset_name,
            collection_mode=collection_mode,
            stig_families=list(stig_families),
            profile_name=getattr(profile, "profile_name", None),
            profile_sha256=_sha256(profile_bytes),
            check_pack_sha256=_sha256(check_bytes),
            stig_benchmark=stig_benchmark,
            stig_version=stig_version,
            stig_release=stig_release,
            device_count=len(target_list),
        )
        device_ids: dict[str, int] = {}
        self.repository.create_run(run)
        try:
            self.evidence_store.create_run(
                run.run_id,
                check_snapshot=check_bytes,
                profile_snapshot=profile_bytes,
                metadata={
                    "collection_mode": run.collection_mode.value,
                    "description": description,
                    "preset_name": preset_name,
                },
            )
            for ip in target_ips:
                device = self.repository.add_device(run.run_id, target_ip=ip, status="QUEUED")
                device_ids[ip] = device.id
                self.evidence_store.prepare_device(run.run_id, ip, metadata={"target_ip": ip})
            self.repository.update_run(run.run_id, status=RunStatus.RUNNING)
            self.activity_log.record("AUDIT_STARTED", "audit_run", run.run_id, details={"device_count": len(target_ips), "collection_mode": run.collection_mode.value})
        except Exception:
            self.repository.delete_run(run.run_id)
            self.evidence_store.delete_run(run.run_id)
            raise
        return RunContext(
            run.model_copy(update={"status": RunStatus.RUNNING}),
            device_ids,
            DEFAULT_COMMAND_POLICY.validate_many(commands_requested),
        )

    def evidence_sink(self, context: RunContext) -> Callable[[str, str | None, dict[str, str]], None]:
        """Return a thread-safe sink compatible with ``AuditService``."""

        def persist(target_ip: str, hostname: str | None, outputs: dict[str, str]) -> None:
            run_device_id = context.device_ids[target_ip]
            facts = parse_facts(
                outputs.get("show running-config", ""),
                outputs.get("show version", ""),
                outputs.get("show inventory", ""),
            )
            device_facts = {
                "target_ip": target_ip,
                "hostname": hostname or facts.hostname,
                "serial_number": facts.serial_number,
                "ios_version": facts.version,
                "model": facts.model,
            }
            with context.lock:
                self.repository.update_device(
                    run_device_id,
                    hostname=hostname or facts.hostname,
                    serial_number=facts.serial_number,
                    ios_version=facts.version,
                    status=DeviceStatus.COLLECTING,
                )
                self.evidence_store.prepare_device(
                    context.run_id,
                    target_ip,
                    hostname=hostname,
                    device_facts=device_facts,
                )
                artifacts = context.artifacts_by_device.setdefault(target_ip, {})
                for command, output in outputs.items():
                    approved = DEFAULT_COMMAND_POLICY.validate(command)
                    artifact = self.evidence_store.write_evidence(
                        context.run_id,
                        target_ip,
                        approved,
                        output,
                        run_device_id=run_device_id,
                    )
                    artifacts[approved] = artifact

        return persist

    def persist_result(
        self,
        context: RunContext,
        service_result: AuditServiceResult,
    ) -> list[CheckResult]:
        """Persist all terminal outcomes/results and finalize an immutable manifest."""

        result_by_ip: dict[str, list[CheckResult]] = {}
        for result in service_result.results:
            result_by_ip.setdefault(result.ip, []).append(result)

        persisted_results: list[CheckResult] = []
        for outcome in service_result.summary.outcomes:
            run_device_id = context.device_ids[outcome.target_ip]
            asset = service_result.assets.get(outcome.target_ip)
            outputs = service_result.outputs.get(outcome.target_ip, {})
            facts = parse_facts(
                outputs.get("show running-config", ""),
                outputs.get("show version", ""),
                outputs.get("show inventory", ""),
            )
            self.repository.update_device(
                run_device_id,
                status=outcome.status,
                hostname=outcome.hostname or (asset.hostname if asset else facts.hostname),
                serial_number=facts.serial_number,
                ios_version=facts.version,
                started_at=service_result.summary.started_at,
                completed_at=service_result.summary.completed_at,
                error_message=outcome.error_message,
            )
            device_results: list[CheckResult] = []
            artifact_map = context.artifacts_by_device.get(outcome.target_ip, {})
            for result in result_by_ip.get(outcome.target_ip, []):
                artifact_ids = [
                    artifact.artifact_id
                    for command in result.commands_used
                    if (artifact := artifact_map.get(command)) is not None
                    and artifact.artifact_id is not None
                ]
                traced = result.model_copy(update={
                    "run_id": context.run_id,
                    "evidence_artifact_ids": artifact_ids,
                })
                stored = self.repository.add_check_result(run_device_id, traced)
                if artifact_ids:
                    self.repository.link_result_evidence(stored.id, artifact_ids)
                persisted_results.append(traced)
                device_results.append(traced)
            self.evidence_store.write_results(
                context.run_id, outcome.target_ip, device_results
            )

        self.repository.refresh_run_counts(context.run_id)
        self.repository.update_run(
            context.run_id,
            status=service_result.summary.status,
            completed_at=service_result.summary.completed_at,
        )
        stored_run = self.repository.get_run(context.run_id, include_details=False)
        status_counts = Counter(result.status for result in persisted_results)
        artifact_rows = self.repository.list_evidence_artifacts(context.run_id)
        manifest = {
            "run_id": context.run_id,
            "application_version": context.run.app_version,
            "started_at": service_result.summary.started_at,
            "completed_at": service_result.summary.completed_at,
            "status": service_result.summary.status.value,
            "collection_mode": context.run.collection_mode.value,
            "targets": list(context.device_ids),
            "detected_hostnames": {
                outcome.target_ip: outcome.hostname
                for outcome in service_result.summary.outcomes
                if outcome.hostname
            },
            "device_facts": [
                {
                    "target_ip": row.target_ip,
                    "hostname": row.hostname,
                    "serial_number": row.serial_number,
                    "ios_version": row.ios_version,
                    "status": row.status,
                    "error_message": row.error_message,
                }
                for row in self.repository.list_devices(context.run_id)
            ],
            "selected_profile": context.run.profile_name,
            "profile_sha256": context.run.profile_sha256,
            "selected_check_libraries": list(context.run.stig_families),
            "check_library_sha256": context.run.check_pack_sha256,
            "stig_family": list(context.run.stig_families),
            "stig_benchmark": context.run.stig_benchmark,
            "stig_version": context.run.stig_version,
            "stig_release": context.run.stig_release,
            "commands_requested": context.commands_requested,
            "commands_actually_executed": sorted({row.command for row in artifact_rows}),
            "evidence_artifacts": [
                {
                    "id": row.id,
                    "command": row.command,
                    "relative_path": row.relative_path,
                    "sha256": row.sha256,
                    "byte_length": row.byte_length,
                    "collected_at": row.collected_at,
                }
                for row in artifact_rows
            ],
            "result_counts": dict(sorted(status_counts.items())),
            "device_counts": {
                "total": stored_run.device_count if stored_run else len(context.device_ids),
                "success": stored_run.success_count if stored_run else 0,
                "failure": stored_run.failure_count if stored_run else 0,
                "cancelled": stored_run.cancelled_count if stored_run else 0,
            },
        }
        self.evidence_store.finalize_run(context.run_id, manifest)
        self.activity_log.record("AUDIT_COMPLETED", "audit_run", context.run_id, details={"status": service_result.summary.status.value, "result_counts": dict(status_counts)})
        return persisted_results

    def import_offline(
        self,
        *,
        devices: Iterable[OfflineEvidenceDevice],
        checks: list[Any],
        profile_provider: Callable[[OfflineEvidenceDevice], Any],
        profile_snapshot: Any,
        stig_families: Iterable[str],
        concurrency: int = 5,
        description: str | None = None,
        event_queue: Any | None = None,
    ) -> tuple[RunContext, AuditServiceResult]:
        imported = list(devices)
        commands = sorted({command for item in imported for command in item.outputs})
        context = self.begin_run(
            targets=imported,
            checks=checks,
            profile=profile_snapshot,
            stig_families=stig_families,
            commands_requested=commands,
            description=description or "Offline evidence import",
            collection_mode=CollectionMode.OFFLINE_IMPORTED,
        )
        by_ip = {item.target_ip: item for item in imported}
        def imported_sink(
            target_ip: str, hostname: str | None, outputs: dict[str, str]
        ) -> None:
            source = by_ip[target_ip]
            run_device_id = context.device_ids[target_ip]
            self.evidence_store.prepare_device(
                context.run_id,
                target_ip,
                hostname=hostname or source.hostname,
                metadata={
                    "source": source.source,
                    "source_collected_at": source.collected_at,
                    "imported_at": source.imported_at,
                    "collection_mode": CollectionMode.OFFLINE_IMPORTED.value,
                },
            )
            artifacts = context.artifacts_by_device.setdefault(target_ip, {})
            for command, output in outputs.items():
                artifact = self.evidence_store.write_evidence(
                    context.run_id,
                    target_ip,
                    command,
                    output,
                    collected_at=source.collected_at,
                    run_device_id=run_device_id,
                )
                artifacts[command] = artifact

        try:
            result = self.audit_service.run_offline(
                run_id=context.run_id,
                targets=imported,
                checks=checks,
                profile_provider=profile_provider,
                output_loader=lambda target: by_ip[target.ip].outputs,
                concurrency=concurrency,
                event_queue=event_queue,
                evidence_sink=imported_sink,
            )
            result.results[:] = self.persist_result(context, result)
            return context, result
        except Exception as exc:
            self.abort_run(context, str(exc))
            raise

    def list_history(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        search: str = "",
    ) -> list[RunHistoryItem]:
        items: list[RunHistoryItem] = []
        for run in self.repository.list_runs(
            limit=max(1, min(limit, 1000)),
            offset=max(0, offset),
            search=search,
        ):
            counts = self.repository.result_counts(run.id)
            items.append(RunHistoryItem(
                id=run.id,
                started_at=run.started_at,
                status=run.status,
                description=run.description or "",
                preset_name=run.preset_name or "",
                collection_mode=run.collection_mode,
                stig_families=tuple(run.stig_families or ()),
                stig_version=run.stig_version or "",
                stig_release=run.stig_release or "",
                profile_name=run.profile_name or "",
                device_count=run.device_count,
                open_count=counts.get("Open", 0),
                pass_count=counts.get("NotAFinding", 0),
                error_count=(
                    counts.get("Error", 0)
                    + counts.get("Skipped", 0)
                    + run.failure_count
                ),
            ))
        return items

    def count_history(self, *, search: str = "") -> int:
        return self.repository.count_runs(search=search)

    def abort_run(
        self,
        context: RunContext,
        error_message: str,
        *,
        cancelled: bool = False,
    ) -> None:
        """Close an interrupted run so history never remains falsely RUNNING."""

        completed_at = _utc_now()
        device_status = (
            DeviceStatus.CANCELLED if cancelled else DeviceStatus.EVALUATION_FAILED
        )
        terminal = {
            "COMPLETE", "AUTH_FAILED", "CONNECT_FAILED", "COLLECTION_FAILED",
            "EVALUATION_FAILED", "CANCELLED",
        }
        for device in self.repository.list_devices(context.run_id):
            if device.status not in terminal:
                self.repository.update_device(
                    device.id,
                    status=device_status,
                    completed_at=completed_at,
                    error_message=error_message,
                )
        self.repository.refresh_run_counts(context.run_id)
        status = RunStatus.CANCELLED if cancelled else RunStatus.FAILED
        self.repository.update_run(
            context.run_id, status=status, completed_at=completed_at
        )
        try:
            self.evidence_store.finalize_run(context.run_id, {
                "run_id": context.run_id,
                "application_version": context.run.app_version,
                "started_at": context.run.started_at,
                "completed_at": completed_at,
                "status": status.value,
                "collection_mode": context.run.collection_mode.value,
                "targets": list(context.device_ids),
                "commands_requested": context.commands_requested,
                "error": error_message,
            })
        except Exception:
            audit_logger(
                LOGGER,
                run_id=context.run_id,
                audit_stage="finalize",
                error_type="abort_manifest",
            ).exception("Could not finalize the interrupted audit manifest")
        self.activity_log.record(
            "AUDIT_CANCELLED" if cancelled else "AUDIT_FAILED",
            "audit_run", context.run_id,
            details={"error_type": type(error_message).__name__, "message": str(error_message)[:1000]},
        )

    def load_results(self, run_id: str) -> list[CheckResult]:
        run = self.repository.get_run(run_id)
        if run is None:
            raise KeyError(f"Unknown audit run: {run_id}")
        results: list[CheckResult] = []
        for device in run.devices:
            for stored in device.check_results:
                failed = [FindingObject(**item) for item in (stored.failed_objects or [])]
                evidence_ids = [link.evidence_artifact_id for link in stored.evidence_links]
                results.append(CheckResult(
                    ip=device.target_ip,
                    hostname=device.hostname or "unknown",
                    vuln_id=stored.vuln_id,
                    rule_id=stored.rule_id,
                    stig_id=stored.stig_id,
                    check_id=stored.check_id,
                    stig_family=stored.stig_family,
                    title=getattr(stored, "title", None) or stored.vuln_id,
                    severity=stored.severity,
                    status=stored.status,
                    run_id=run.id,
                    check_type=stored.check_type,
                    failed_objects=failed,
                    finding_details=stored.finding_details or "",
                    comments=stored.comments or "",
                    evaluation_reason=stored.evaluation_reason or "",
                    commands_used=list(stored.commands_used or []),
                    evidence_artifact_ids=evidence_ids,
                    profile_values_used=dict(stored.profile_values or {}),
                    error_message=stored.error_message,
                    parser_warnings=list(stored.parser_warnings or []),
                    timestamp=stored.evaluated_at,
                ))
        return results

    def evidence_for_result(self, result: CheckResult) -> list[Any]:
        if not result.run_id or not result.evidence_artifact_ids:
            return []
        wanted = set(result.evidence_artifact_ids)
        return [
            artifact
            for artifact in self.repository.list_evidence_artifacts(result.run_id)
            if artifact.id in wanted
        ]

    def save_manual_decision(self, result: CheckResult, *, status: str, finding_details: str, comments: str) -> list[CheckResult]:
        if not result.run_id:
            raise ValueError("Manual decisions require a persisted Audit Run")
        self.repository.update_result_decision(result.run_id, result.ip, result.vuln_id, status=status, finding_details=finding_details, comments=comments)
        self.activity_log.record("MANUAL_REVIEW_RECORDED", "check_result", f"{result.run_id}:{result.ip}:{result.vuln_id}", details={"status": status})
        return self.load_results(result.run_id)

    def verify_evidence(self, run_id: str) -> Any:
        return self.evidence_store.verify_evidence(run_id)

    def purge_raw_evidence(self, run_id: str) -> int:
        removed = self.evidence_store.purge_raw_evidence(run_id)
        self.activity_log.record("EVIDENCE_PURGED", "audit_run", run_id, details={"files_removed": removed})
        return removed

    def delete_run(self, run_id: str) -> bool:
        deleted_files = self.evidence_store.delete_run(run_id)
        deleted_record = self.repository.delete_run(run_id)
        if deleted_files or deleted_record:
            self.activity_log.record("AUDIT_DELETED", "audit_run", run_id, details={"evidence_deleted": bool(deleted_files)})
        return bool(deleted_files or deleted_record)

    def import_audit_package(self, package_path: str | Path) -> str:
        """Install a verified portable audit as immutable historical data.

        Original evidence/result bytes are retained. Database primary keys are
        rebuilt locally, so evidence links are remapped without trusting IDs
        from another installation.
        """

        service = AuditPackageService()
        verification = service.verify(package_path)
        if not verification.valid or not verification.run_id:
            details = "; ".join(verification.problems) or verification.status
            raise ValueError(f"Audit package verification failed: {details}")
        run_id = verification.run_id
        if self.repository.get_run(run_id, include_details=False) is not None:
            raise ValueError(f"Audit run is already present in History: {run_id}")

        imported = service.import_to(
            package_path,
            evidence_root=self.evidence_store.root,
        )
        manifest_path = imported.run_directory / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if imported.includes_evidence:
                integrity = self.evidence_store.verify_evidence(run_id)
                if not integrity.is_valid:
                    raise ValueError(
                        "The audit package is internally consistent, but its evidence "
                        f"does not match the audit hashes ({integrity.aggregate.value})."
                    )

            self.repository.create_run(
                id=run_id,
                started_at=manifest.get("started_at"),
                completed_at=manifest.get("completed_at"),
                status=manifest.get("status") or "COMPLETE",
                app_version=manifest.get("application_version") or APP_VERSION,
                profile_name=manifest.get("selected_profile"),
                profile_sha256=manifest.get("profile_sha256"),
                check_pack_sha256=manifest.get("check_library_sha256"),
                stig_families=(
                    manifest.get("stig_family")
                    or manifest.get("selected_check_libraries")
                    or []
                ),
                stig_benchmark=manifest.get("stig_benchmark"),
                stig_version=manifest.get("stig_version"),
                stig_release=manifest.get("stig_release"),
                description=(
                    f"Imported historical audit — {manifest.get('description')}"
                    if manifest.get("description")
                    else "Imported historical audit"
                ),
                preset_name=manifest.get("preset_name"),
                collection_mode=CollectionMode.IMPORTED_HISTORICAL_AUDIT.value,
            )

            device_directories = sorted(
                path
                for path in (imported.run_directory / "devices").iterdir()
                if path.is_dir() and not path.is_symlink()
            )
            manifest_devices = {
                str(item.get("target_ip")): item
                for item in (manifest.get("device_facts") or [])
                if isinstance(item, Mapping) and item.get("target_ip")
            }
            for device_directory in device_directories:
                device_payload = json.loads(
                    (device_directory / "device.json").read_text(encoding="utf-8")
                )
                target_ip = str(device_payload.get("target_ip") or "").strip()
                if not target_ip:
                    raise ValueError(
                        f"Imported device metadata is missing target_ip: {device_directory.name}"
                    )
                facts = device_payload.get("device_facts") or {}
                historical_device = manifest_devices.get(target_ip, {})
                device = self.repository.add_device(
                    run_id,
                    target_ip=target_ip,
                    hostname=(
                        device_payload.get("hostname")
                        or historical_device.get("hostname")
                        or facts.get("hostname")
                    ),
                    serial_number=(
                        historical_device.get("serial_number")
                        or facts.get("serial_number")
                    ),
                    ios_version=(
                        historical_device.get("ios_version")
                        or facts.get("ios_version")
                    ),
                    status=(
                        historical_device.get("status")
                        or device_payload.get("status")
                        or "COMPLETE"
                    ),
                    started_at=manifest.get("started_at"),
                    completed_at=manifest.get("completed_at"),
                    error_message=historical_device.get("error_message"),
                )

                old_to_new_artifact: dict[int, int] = {}
                artifacts_by_command: dict[str, list[int]] = {}
                for artifact_payload in device_payload.get("evidence_artifacts") or []:
                    payload = dict(artifact_payload)
                    relative_path = self._imported_evidence_path(
                        run_id, str(payload.get("relative_path") or "")
                    )
                    artifact = EvidenceArtifact.model_validate({
                        "run_id": run_id,
                        "command": payload.get("command"),
                        "relative_path": relative_path,
                        "sha256": payload.get("sha256"),
                        "collected_at": payload.get("collected_at"),
                        "byte_length": payload.get("byte_length"),
                    })
                    stored_artifact = self.repository.add_evidence_artifact(
                        device.id, artifact
                    )
                    old_id = payload.get("artifact_id") or payload.get("id")
                    if old_id is not None:
                        old_to_new_artifact[int(old_id)] = stored_artifact.id
                    artifacts_by_command.setdefault(artifact.command, []).append(
                        stored_artifact.id
                    )

                results_path = device_directory / "results.json"
                if not results_path.is_file():
                    continue
                result_payloads = json.loads(results_path.read_text(encoding="utf-8"))
                if not isinstance(result_payloads, list):
                    raise ValueError(f"Imported results are not a list: {results_path.name}")
                for result_payload in result_payloads:
                    parsed = CheckResult.model_validate({
                        **dict(result_payload),
                        "run_id": run_id,
                        "ip": target_ip,
                        "hostname": (
                            result_payload.get("hostname")
                            or device_payload.get("hostname")
                            or facts.get("hostname")
                            or "unknown"
                        ),
                    })
                    stored_result = self.repository.add_check_result(device.id, parsed)
                    evidence_ids = [
                        old_to_new_artifact[old_id]
                        for old_id in parsed.evidence_artifact_ids
                        if old_id in old_to_new_artifact
                    ]
                    if not evidence_ids:
                        evidence_ids = [
                            artifact_id
                            for command in parsed.commands_used
                            for artifact_id in artifacts_by_command.get(command, [])
                        ]
                    if evidence_ids:
                        self.repository.link_result_evidence(
                            stored_result.id, evidence_ids
                        )

            self.repository.refresh_run_counts(run_id)
            self.activity_log.record(
                "AUDIT_PACKAGE_IMPORTED",
                "audit_run",
                run_id,
                details={
                    "classification": "IMPORTED_HISTORICAL_AUDIT",
                    "includes_evidence": imported.includes_evidence,
                },
            )
            return run_id
        except Exception:
            self.repository.delete_run(run_id)
            self.evidence_store.delete_run(run_id)
            raise

    @staticmethod
    def _imported_evidence_path(run_id: str, value: str) -> str:
        normalized = value.strip().replace("\\", "/")
        path = Path(normalized)
        if not normalized or path.is_absolute() or ".." in path.parts:
            raise ValueError("Imported audit contains an unsafe evidence path")
        if path.parts[0] == run_id:
            return path.as_posix()
        if path.parts[0] == "devices":
            return (Path(run_id) / path).as_posix()
        raise ValueError("Imported evidence path is not scoped to the audit run")

    def read_evidence(self, relative_path: str) -> str:
        return self.evidence_store.read_evidence(relative_path)


__all__ = [
    "OfflineEvidenceDevice",
    "RunContext",
    "RunHistoryItem",
    "RunService",
]
