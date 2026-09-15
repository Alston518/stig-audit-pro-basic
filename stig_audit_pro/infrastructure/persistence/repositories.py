"""Repositories for audit history, evidence metadata, and STIG releases."""

from __future__ import annotations

import getpass
import hashlib
import json
import re
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import selectinload

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.infrastructure.persistence.database import Database
from stig_audit_pro.infrastructure.persistence.db_models import (
    ActivityLog,
    AuditRun,
    CheckMapping,
    CheckResult,
    EvidenceArtifact,
    ResultEvidence,
    RunDevice,
    StigBenchmark,
    StigRule,
    utc_now,
)


def _mapping(value: object | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return dict(model_dump(mode="python"))
    if is_dataclass(value):
        return asdict(value)
    result: dict[str, Any] = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        try:
            candidate = getattr(value, name)
        except (AttributeError, RuntimeError):
            continue
        if not callable(candidate):
            result[name] = candidate
    return result


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, datetime):
        return value
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    if is_dataclass(value):
        return _plain(asdict(value))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _plain(model_dump(mode="python"))
    return value


def _datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if value is None:
        return default
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return _datetime(parsed)
    raise TypeError(f"Expected datetime or ISO timestamp, got {type(value).__name__}")


def _filtered(record_type: type, payload: Mapping[str, Any]) -> dict[str, Any]:
    columns = {column.name for column in record_type.__table__.columns}
    return {key: _plain(value) for key, value in payload.items() if key in columns}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        _plain(value), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_SECRET_KEYS = {
    "password", "passphrase", "secret", "enable_secret", "private_key",
    "private_signing_key", "token", "api_key",
}
_SECRET_TEXT = re.compile(
    r"(?i)(password|passphrase|enable[_ -]?secret|private[_ -]?key|token|api[_ -]?key)\s*[:=]\s*([^\s,;]+)"
)


def _sanitize_activity_value(value: Any) -> Any:
    """Remove credential-shaped values before they can reach persistence."""

    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _SECRET_KEYS
            else _sanitize_activity_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_activity_value(item) for item in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    return _plain(value)


class ActivityLogRepository:
    """Append and query a local, sanitized application activity trail."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        action: str,
        object_type: str,
        object_id: str | None = None,
        *,
        details: Mapping[str, Any] | None = None,
        local_username: str | None = None,
    ) -> ActivityLog:
        record = ActivityLog(
            timestamp=utc_now(),
            action=str(action).strip(),
            object_type=str(object_type).strip(),
            object_id=str(object_id) if object_id is not None else None,
            details=_sanitize_activity_value(details or {}),
            local_username=(local_username or _safe_username()),
        )
        if not record.action or not record.object_type:
            raise ValueError("Activity action and object type are required")
        with self.database.session() as session:
            session.add(record)
        return record

    def list_recent(self, *, limit: int = 100) -> list[ActivityLog]:
        safe_limit = max(1, min(int(limit), 1000))
        statement = select(ActivityLog).order_by(
            ActivityLog.timestamp.desc(), ActivityLog.id.desc()
        ).limit(safe_limit)
        with self.database.session() as session:
            return list(session.scalars(statement))


def _safe_username() -> str | None:
    try:
        value = getpass.getuser().strip()
    except Exception:
        return None
    return value[:255] or None


class AuditRunRepository:
    """Persist and retrieve immutable-context audit history records."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def create_run(self, run: object | None = None, **values: Any) -> AuditRun:
        payload = _mapping(run)
        payload.update(values)
        payload.setdefault("id", payload.pop("run_id", None) or str(uuid.uuid4()))
        if "stig_families" not in payload:
            payload["stig_families"] = payload.pop("selected_stig_families", [])
        payload["status"] = _plain(payload.get("status", "CREATED"))
        payload["started_at"] = _datetime(payload.get("started_at"), utc_now())
        payload["completed_at"] = _datetime(payload.get("completed_at"))
        payload.setdefault("app_version", APP_VERSION)
        payload.setdefault("collection_mode", "LIVE_SSH")
        record = AuditRun(**_filtered(AuditRun, payload))
        with self.database.session() as session:
            session.add(record)
        return record

    # A concise alias is convenient for application services.
    create = create_run

    def get_run(self, run_id: str, *, include_details: bool = True) -> AuditRun | None:
        statement = select(AuditRun).where(AuditRun.id == str(run_id))
        if include_details:
            statement = statement.options(
                selectinload(AuditRun.devices)
                .selectinload(RunDevice.check_results)
                .selectinload(CheckResult.evidence_links),
                selectinload(AuditRun.devices).selectinload(
                    RunDevice.evidence_artifacts
                ),
            )
        with self.database.session() as session:
            return session.scalar(statement)

    get = get_run

    @staticmethod
    def _run_search(query: str):
        cleaned = str(query or "").strip().casefold()
        if not cleaned:
            return None
        columns = (
            AuditRun.id,
            AuditRun.description,
            AuditRun.preset_name,
            AuditRun.collection_mode,
            AuditRun.profile_name,
            AuditRun.stig_benchmark,
            AuditRun.stig_version,
            AuditRun.stig_release,
            AuditRun.status,
            cast(AuditRun.stig_families, String),
        )
        return or_(*(
            func.lower(cast(column, String)).contains(cleaned, autoescape=True)
            for column in columns
        ))

    def list_runs(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
        search: str = "",
    ) -> list[AuditRun]:
        statement = select(AuditRun).order_by(AuditRun.started_at.desc(), AuditRun.id.desc())
        if (criterion := self._run_search(search)) is not None:
            statement = statement.where(criterion)
        if offset:
            statement = statement.offset(offset)
        if limit is not None:
            statement = statement.limit(limit)
        with self.database.session() as session:
            return list(session.scalars(statement))

    list = list_runs

    def update_run(self, run_id: str, **values: Any) -> AuditRun:
        payload = dict(values)
        if "run_id" in payload:
            raise ValueError("An audit run ID cannot be changed")
        if "status" in payload:
            payload["status"] = _plain(payload["status"])
        if "completed_at" in payload:
            payload["completed_at"] = _datetime(payload["completed_at"])
        with self.database.session() as session:
            record = session.get(AuditRun, str(run_id))
            if record is None:
                raise KeyError(f"Unknown audit run: {run_id}")
            for key, value in _filtered(AuditRun, payload).items():
                if key != "id":
                    setattr(record, key, value)
            session.flush()
            return record

    def add_device(
        self,
        run_id: str,
        device: object | None = None,
        **values: Any,
    ) -> RunDevice:
        payload = _mapping(device)
        payload.update(values)
        payload["run_id"] = str(run_id)
        payload.setdefault("target_ip", payload.pop("ip", None))
        if not payload.get("target_ip"):
            raise ValueError("Run devices require target_ip")
        payload["status"] = _plain(payload.get("status", "QUEUED"))
        payload["started_at"] = _datetime(payload.get("started_at"))
        payload["completed_at"] = _datetime(payload.get("completed_at"))
        record = RunDevice(**_filtered(RunDevice, payload))
        with self.database.session() as session:
            if session.get(AuditRun, str(run_id)) is None:
                raise KeyError(f"Unknown audit run: {run_id}")
            session.add(record)
        return record

    create_device = add_device

    def get_device(self, run_device_id: int) -> RunDevice | None:
        with self.database.session() as session:
            return session.get(RunDevice, run_device_id)

    def find_device(self, run_id: str, target_ip: str) -> RunDevice | None:
        statement = (
            select(RunDevice)
            .where(RunDevice.run_id == str(run_id), RunDevice.target_ip == target_ip)
            .order_by(RunDevice.id)
        )
        with self.database.session() as session:
            return session.scalars(statement).first()

    def list_devices(self, run_id: str) -> list[RunDevice]:
        statement = (
            select(RunDevice)
            .where(RunDevice.run_id == str(run_id))
            .order_by(RunDevice.id)
        )
        with self.database.session() as session:
            return list(session.scalars(statement))

    def update_device(self, run_device_id: int, **values: Any) -> RunDevice:
        payload = dict(values)
        if "status" in payload:
            payload["status"] = _plain(payload["status"])
        for key in ("started_at", "completed_at"):
            if key in payload:
                payload[key] = _datetime(payload[key])
        with self.database.session() as session:
            record = session.get(RunDevice, run_device_id)
            if record is None:
                raise KeyError(f"Unknown run device: {run_device_id}")
            for key, value in _filtered(RunDevice, payload).items():
                if key not in {"id", "run_id"}:
                    setattr(record, key, value)
            session.flush()
            return record

    def add_check_result(
        self,
        run_device_id: int,
        result: object | None = None,
        **values: Any,
    ) -> CheckResult:
        payload = _mapping(result)
        payload.update(values)
        payload["run_device_id"] = run_device_id
        payload.setdefault("evaluated_at", payload.pop("timestamp", None) or utc_now())
        payload["evaluated_at"] = _datetime(payload["evaluated_at"], utc_now())
        payload.setdefault("evaluation_reason", payload.get("error_message"))
        if "profile_values" not in payload:
            payload["profile_values"] = payload.pop("profile_values_used", {})
        record = CheckResult(**_filtered(CheckResult, payload))
        with self.database.session() as session:
            if session.get(RunDevice, run_device_id) is None:
                raise KeyError(f"Unknown run device: {run_device_id}")
            session.add(record)
        return record

    def add_evidence_artifact(
        self,
        run_device_id: int,
        artifact: object | None = None,
        **values: Any,
    ) -> EvidenceArtifact:
        payload = _mapping(artifact)
        payload.update(values)
        payload["run_device_id"] = run_device_id
        payload["collected_at"] = _datetime(payload.get("collected_at"), utc_now())
        record = EvidenceArtifact(**_filtered(EvidenceArtifact, payload))
        with self.database.session() as session:
            if session.get(RunDevice, run_device_id) is None:
                raise KeyError(f"Unknown run device: {run_device_id}")
            session.add(record)
        return record

    def link_result_evidence(
        self, check_result_id: int, evidence_artifact_ids: Iterable[int]
    ) -> None:
        with self.database.session() as session:
            result = session.get(CheckResult, check_result_id)
            if result is None:
                raise KeyError(f"Unknown check result: {check_result_id}")
            for artifact_id in dict.fromkeys(int(item) for item in evidence_artifact_ids):
                if session.get(EvidenceArtifact, artifact_id) is None:
                    raise KeyError(f"Unknown evidence artifact: {artifact_id}")
                key = (check_result_id, artifact_id)
                if session.get(ResultEvidence, key) is None:
                    session.add(
                        ResultEvidence(
                            check_result_id=check_result_id,
                            evidence_artifact_id=artifact_id,
                        )
                    )

    def list_check_results(self, run_id: str) -> list[CheckResult]:
        statement = (
            select(CheckResult)
            .join(RunDevice, CheckResult.run_device_id == RunDevice.id)
            .where(RunDevice.run_id == str(run_id))
            .options(selectinload(CheckResult.evidence_links))
            .order_by(RunDevice.id, CheckResult.id)
        )
        with self.database.session() as session:
            return list(session.scalars(statement))

    def count_runs(self, *, search: str = "") -> int:
        statement = select(func.count(AuditRun.id))
        if (criterion := self._run_search(search)) is not None:
            statement = statement.where(criterion)
        with self.database.session() as session:
            return int(session.scalar(statement) or 0)

    def update_result_decision(
        self, run_id: str, target_ip: str, vuln_id: str, *,
        status: str, finding_details: str = "", comments: str = "",
    ) -> CheckResult:
        allowed = {"Open", "NotAFinding", "Not_Applicable", "Not_Reviewed"}
        if status not in allowed:
            raise ValueError(f"Unsupported reviewer status: {status}")
        statement = (
            select(CheckResult).join(RunDevice)
            .where(RunDevice.run_id == run_id, RunDevice.target_ip == target_ip, CheckResult.vuln_id == vuln_id)
            .order_by(CheckResult.id)
        )
        with self.database.session() as session:
            records = list(session.scalars(statement))
            if len(records) != 1:
                raise ValueError("A reviewer decision requires exactly one matching historical result")
            record = records[0]
            record.status = status
            record.finding_details = finding_details
            record.comments = comments
            record.evaluation_reason = "Manual reviewer decision"
            record.evaluated_at = utc_now()
            session.flush()
            return record

    def list_evidence_artifacts(self, run_id: str) -> list[EvidenceArtifact]:
        statement = (
            select(EvidenceArtifact)
            .join(RunDevice, EvidenceArtifact.run_device_id == RunDevice.id)
            .where(RunDevice.run_id == str(run_id))
            .order_by(RunDevice.id, EvidenceArtifact.id)
        )
        with self.database.session() as session:
            return list(session.scalars(statement))

    def result_counts(self, run_id: str) -> dict[str, int]:
        statement = (
            select(CheckResult.status, func.count(CheckResult.id))
            .join(RunDevice, CheckResult.run_device_id == RunDevice.id)
            .where(RunDevice.run_id == str(run_id))
            .group_by(CheckResult.status)
        )
        with self.database.session() as session:
            return {status: int(count) for status, count in session.execute(statement)}

    def refresh_run_counts(self, run_id: str) -> AuditRun:
        statement = (
            select(RunDevice.status, func.count(RunDevice.id))
            .where(RunDevice.run_id == str(run_id))
            .group_by(RunDevice.status)
        )
        with self.database.session() as session:
            record = session.get(AuditRun, str(run_id))
            if record is None:
                raise KeyError(f"Unknown audit run: {run_id}")
            counts = {status: int(count) for status, count in session.execute(statement)}
            failure_statuses = {
                "AUTH_FAILED",
                "CONNECT_FAILED",
                "COLLECTION_FAILED",
                "EVALUATION_FAILED",
            }
            record.device_count = sum(counts.values())
            record.success_count = counts.get("COMPLETE", 0)
            record.cancelled_count = counts.get("CANCELLED", 0)
            record.failure_count = sum(counts.get(status, 0) for status in failure_statuses)
            session.flush()
            return record

    def delete_run(self, run_id: str) -> bool:
        """Delete structured history; raw files are managed by EvidenceStore."""

        with self.database.session() as session:
            record = session.get(AuditRun, str(run_id))
            if record is None:
                return False
            session.delete(record)
            return True


class StigPersistenceRepository:
    """Low-level versioned STIG release and mapping persistence."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def add_benchmark(
        self,
        benchmark: object | None = None,
        *,
        rules: Iterable[object] | None = None,
        **values: Any,
    ) -> StigBenchmark:
        payload = _mapping(benchmark)
        payload.update(values)
        rule_values = list(rules if rules is not None else payload.pop("rules", []))
        payload.setdefault("release", _release_from_payload(payload))
        payload["imported_at"] = _datetime(payload.get("imported_at"), utc_now())
        payload.setdefault("source_sha256", _source_hash(payload, rule_values))
        payload.setdefault(
            "benchmark_fingerprint",
            _canonical_sha256(
                {
                    key: value
                    for key, value in payload.items()
                    if key
                    in {
                        "family",
                        "benchmark_id",
                        "title",
                        "version",
                        "release",
                        "release_info",
                        "release_date",
                    }
                }
                | {"rules": [_mapping(rule) for rule in rule_values]}
            ),
        )

        with self.database.session() as session:
            existing = session.scalar(
                select(StigBenchmark).where(
                    StigBenchmark.source_sha256 == payload["source_sha256"],
                    StigBenchmark.family == payload.get("family", ""),
                    StigBenchmark.benchmark_id == payload.get("benchmark_id", ""),
                    StigBenchmark.version == payload.get("version"),
                    StigBenchmark.release == payload.get("release"),
                )
            )
            if existing is not None:
                return existing

            record = StigBenchmark(**_filtered(StigBenchmark, payload))
            for rule in rule_values:
                rule_payload = _mapping(rule)
                fingerprints = dict(rule_payload.get("field_fingerprints") or {})
                rule_payload.setdefault(
                    "check_fingerprint",
                    fingerprints.get("check_text")
                    or _canonical_sha256(rule_payload.get("check_text", "")),
                )
                rule_payload.setdefault(
                    "fix_fingerprint",
                    fingerprints.get("fix_text")
                    or _canonical_sha256(rule_payload.get("fix_text", "")),
                )
                rule_payload.setdefault("rule_fingerprint", _canonical_sha256(rule_payload))
                rule_payload["field_fingerprints"] = fingerprints
                record.rules.append(StigRule(**_filtered(StigRule, rule_payload)))
            session.add(record)
            session.flush()
            return record

    save_benchmark = add_benchmark

    def get_benchmark(self, benchmark_db_id: int) -> StigBenchmark | None:
        statement = (
            select(StigBenchmark)
            .where(StigBenchmark.id == benchmark_db_id)
            .options(selectinload(StigBenchmark.rules))
        )
        with self.database.session() as session:
            return session.scalar(statement)

    def list_benchmarks(
        self,
        *,
        family: str | None = None,
        benchmark_id: str | None = None,
    ) -> list[StigBenchmark]:
        statement = select(StigBenchmark).options(selectinload(StigBenchmark.rules))
        if family is not None:
            statement = statement.where(StigBenchmark.family == family)
        if benchmark_id is not None:
            statement = statement.where(StigBenchmark.benchmark_id == benchmark_id)
        statement = statement.order_by(
            StigBenchmark.imported_at.desc(), StigBenchmark.id.desc()
        )
        with self.database.session() as session:
            return list(session.scalars(statement))

    def previous_benchmark(self, benchmark_db_id: int) -> StigBenchmark | None:
        current = self.get_benchmark(benchmark_db_id)
        if current is None:
            raise KeyError(f"Unknown STIG benchmark: {benchmark_db_id}")
        statement = (
            select(StigBenchmark)
            .where(
                StigBenchmark.family == current.family,
                StigBenchmark.benchmark_id == current.benchmark_id,
                StigBenchmark.id != current.id,
                (StigBenchmark.imported_at < current.imported_at)
                | (
                    (StigBenchmark.imported_at == current.imported_at)
                    & (StigBenchmark.id < current.id)
                ),
            )
            .options(selectinload(StigBenchmark.rules))
            .order_by(StigBenchmark.imported_at.desc(), StigBenchmark.id.desc())
        )
        with self.database.session() as session:
            return session.scalars(statement).first()

    def add_mapping(
        self, mapping: object | None = None, **values: Any
    ) -> CheckMapping:
        payload = _mapping(mapping)
        payload.update(values)
        payload.setdefault("automation_status", "MANUAL_REVIEW")
        payload["reviewed_at"] = _datetime(payload.get("reviewed_at"))
        record = CheckMapping(**_filtered(CheckMapping, payload))
        with self.database.session() as session:
            session.add(record)
        return record

    def list_mappings(
        self, *, vuln_id: str | None = None, stig_rule_id: int | None = None
    ) -> list[CheckMapping]:
        statement = select(CheckMapping)
        if vuln_id is not None:
            statement = statement.where(CheckMapping.vuln_id == vuln_id)
        if stig_rule_id is not None:
            statement = statement.where(CheckMapping.stig_rule_id == stig_rule_id)
        statement = statement.order_by(CheckMapping.check_file, CheckMapping.check_id)
        with self.database.session() as session:
            return list(session.scalars(statement))

    def mark_mapping_reviewed(
        self,
        mapping_id: int,
        *,
        stig_fingerprint: str,
        reviewed_release: str | None = None,
        reviewed_at: datetime | None = None,
    ) -> CheckMapping:
        with self.database.session() as session:
            mapping = session.get(CheckMapping, mapping_id)
            if mapping is None:
                raise KeyError(f"Unknown check mapping: {mapping_id}")
            mapping.last_reviewed_stig_fingerprint = stig_fingerprint
            mapping.reviewed_release = reviewed_release
            mapping.reviewed_at = _datetime(reviewed_at, utc_now())
            mapping.review_status = "CURRENT"
            session.flush()
            return mapping


def _release_from_payload(payload: Mapping[str, Any]) -> str | None:
    if payload.get("release"):
        return str(payload["release"])
    for candidate in (payload.get("release_info"), payload.get("version")):
        match = re.search(r"\bV?\d+R\d+\b", str(candidate or ""), flags=re.IGNORECASE)
        if match:
            return match.group(0).upper().lstrip("V")
    return None


def _source_hash(payload: Mapping[str, Any], rules: Iterable[object]) -> str:
    source_path = payload.get("source_path")
    if source_path:
        path = Path(str(source_path))
        try:
            if path.is_file():
                return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            pass
    return _canonical_sha256({"metadata": dict(payload), "rules": list(rules)})
