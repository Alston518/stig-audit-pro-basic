"""Audit application service coordinating collection, parsing, and evaluation."""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from stig_audit_pro.application.scan_orchestrator import (
    DeviceScanOutcome,
    ScanEvent,
    ScanOrchestrator,
    ScanSummary,
)
from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.models import CheckDefinition, DeviceStatus, SiteProfile
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.ssh_runner import DeviceCredentials, DeviceTarget
from stig_audit_pro.infrastructure.ssh.netmiko_runner import NetmikoRunner
from stig_audit_pro.stig.ckl_writer import CklAsset, extract_ckl_asset


class TargetRecord(Protocol):
    ip: str


@dataclass(slots=True)
class DeviceAuditPayload:
    outputs: dict[str, str] = field(default_factory=dict)
    results: list[CheckResult] = field(default_factory=list)
    asset: CklAsset | None = None


@dataclass(slots=True)
class AuditServiceResult:
    summary: ScanSummary
    results: list[CheckResult]
    assets: dict[str, CklAsset]
    outputs: dict[str, dict[str, str]]


ProfileProvider = Callable[[TargetRecord], SiteProfile]
RunnerFactory = Callable[[], NetmikoRunner]
SampleLoader = Callable[[TargetRecord], dict[str, str]]
EvidenceSink = Callable[[str, str | None, dict[str, str]], None]


class AuditService:
    """Run read-only device audits without owning any GUI widget state."""

    def __init__(
        self,
        *,
        runner_factory: RunnerFactory = NetmikoRunner,
    ) -> None:
        self.runner_factory = runner_factory

    def run_live(
        self,
        *,
        run_id: str,
        targets: Iterable[TargetRecord],
        credentials: DeviceCredentials,
        checks: list[CheckDefinition],
        profile_provider: ProfileProvider,
        concurrency: int = 5,
        connect_timeout: int = 30,
        command_timeout: int = 30,
        cancel_event: threading.Event | None = None,
        event_queue: queue.Queue[ScanEvent] | None = None,
        evidence_sink: EvidenceSink | None = None,
    ) -> AuditServiceResult:
        commands = plan_commands(checks, run_all=False)

        def worker(target: TargetRecord, cancellation, report) -> DeviceScanOutcome:
            runner = self.runner_factory()  # one worker, one adapter, one connection
            report(DeviceStatus.COLLECTING, "Collecting approved command output")
            command_run = runner.run_commands(
                DeviceTarget(ip=target.ip, timeout=connect_timeout),
                credentials,
                commands,
                cancel_event=cancellation,
                command_timeout=command_timeout,
            )
            if command_run.status == "cancelled":
                return DeviceScanOutcome(target.ip, DeviceStatus.CANCELLED)
            if command_run.status != "scanned":
                status = _connection_failure_status(command_run.error_message or "")
                return DeviceScanOutcome(
                    target.ip, status, error_message=command_run.error_message
                )
            return self._evaluate_device(
                run_id, target, checks, profile_provider,
                command_run.outputs, report, evidence_sink,
            )

        summary = ScanOrchestrator[TargetRecord](concurrency).run(
            run_id=run_id, targets=targets, worker=worker,
            target_ip=lambda target: target.ip,
            cancel_event=cancel_event, event_queue=event_queue,
        )
        return _combine(summary)

    def run_offline(
        self,
        *,
        run_id: str,
        targets: Iterable[TargetRecord],
        checks: list[CheckDefinition],
        profile_provider: ProfileProvider,
        output_loader: SampleLoader,
        concurrency: int = 5,
        cancel_event: threading.Event | None = None,
        event_queue: queue.Queue[ScanEvent] | None = None,
        evidence_sink: EvidenceSink | None = None,
    ) -> AuditServiceResult:
        # Validate all commands before any source is read.  Offline data is held
        # to the same command policy as live data.
        plan_commands(checks, run_all=False)

        def worker(target: TargetRecord, cancellation, report) -> DeviceScanOutcome:
            if cancellation.is_set():
                return DeviceScanOutcome(target.ip, DeviceStatus.CANCELLED)
            report(DeviceStatus.COLLECTING, "Loading offline command output")
            try:
                outputs = output_loader(target)
            except Exception as exc:
                return DeviceScanOutcome(
                    target.ip, DeviceStatus.COLLECTION_FAILED, error_message=str(exc)
                )
            return self._evaluate_device(
                run_id, target, checks, profile_provider, outputs, report, evidence_sink
            )

        summary = ScanOrchestrator[TargetRecord](concurrency).run(
            run_id=run_id, targets=targets, worker=worker,
            target_ip=lambda target: target.ip,
            cancel_event=cancel_event, event_queue=event_queue,
        )
        return _combine(summary)

    @staticmethod
    def _evaluate_device(
        run_id: str,
        target: TargetRecord,
        checks: list[CheckDefinition],
        profile_provider: ProfileProvider,
        outputs: dict[str, str],
        report: Callable[[DeviceStatus, str, str | None], None],
        evidence_sink: EvidenceSink | None,
    ) -> DeviceScanOutcome:
        try:
            # Preserve captured bytes before profile resolution or parsing can
            # fail. The stable target IP identifies the device directory; a
            # discovered hostname is metadata and never renames the path.
            if evidence_sink:
                evidence_sink(target.ip, None, outputs)
            profile = profile_provider(target)
            report(DeviceStatus.PARSING, "Parsing evidence")
            asset = extract_ckl_asset(
                outputs, target.ip, management_vlan=profile.management_vlan
            )
            report(DeviceStatus.EVALUATING, "Evaluating STIG checks", asset.hostname)
            evaluated = CheckEngine(profile).evaluate_all(
                checks, outputs=outputs, ip=target.ip, hostname=asset.hostname
            )
            definitions = {check.vuln_id: check for check in checks}
            results: list[CheckResult] = []
            for result in evaluated:
                check = definitions.get(result.vuln_id)
                update = {
                    "run_id": run_id,
                    "rule_id": check.rule_id if check else None,
                    "stig_id": check.stig_id if check else None,
                    "check_id": check.check_id if check else None,
                    "check_type": check.check_type if check else None,
                    "evaluation_reason": result.finding_details or result.comments,
                    "profile_values_used": profile.model_dump(mode="json"),
                }
                results.append(result.model_copy(update=update))
            return DeviceScanOutcome(
                target.ip, DeviceStatus.COMPLETE, asset.hostname,
                payload=DeviceAuditPayload(outputs, results, asset),
            )
        except Exception as exc:
            return DeviceScanOutcome(
                target.ip, DeviceStatus.EVALUATION_FAILED, error_message=str(exc)
            )


def _connection_failure_status(message: str) -> DeviceStatus:
    lowered = message.casefold()
    if "auth" in lowered or "password" in lowered or "permission denied" in lowered:
        return DeviceStatus.AUTH_FAILED
    if "timed out" in lowered or "connection" in lowered or "socket" in lowered:
        return DeviceStatus.CONNECT_FAILED
    return DeviceStatus.COLLECTION_FAILED


def _combine(summary: ScanSummary) -> AuditServiceResult:
    results: list[CheckResult] = []
    assets: dict[str, CklAsset] = {}
    outputs: dict[str, dict[str, str]] = {}
    for outcome in summary.outcomes:
        if not isinstance(outcome.payload, DeviceAuditPayload):
            continue
        results.extend(outcome.payload.results)
        outputs[outcome.target_ip] = outcome.payload.outputs
        if outcome.payload.asset:
            assets[outcome.target_ip] = outcome.payload.asset
    return AuditServiceResult(summary, results, assets, outputs)


__all__ = ["AuditService", "AuditServiceResult", "DeviceAuditPayload"]
