"""Bounded, cancellable multi-device scan orchestration.

The orchestrator deliberately knows nothing about Tk, Netmiko, credentials, or
the check engine.  A caller supplies a per-device worker and consumes immutable
events from a thread-safe queue.  This keeps every GUI update on Tk's main
thread and makes the concurrency behavior testable without network hardware.
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Generic, Iterable, TypeVar

from stig_audit_pro.core.models import DeviceStatus, RunStatus


TargetT = TypeVar("TargetT")


class ScanEventType(str, Enum):
    RUN_STATUS = "RUN_STATUS"
    DEVICE_STATUS = "DEVICE_STATUS"
    PROGRESS = "PROGRESS"


@dataclass(frozen=True, slots=True)
class ScanEvent:
    event_type: ScanEventType
    run_id: str
    status: str
    target_ip: str | None = None
    hostname: str | None = None
    message: str = ""
    completed: int = 0
    total: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class DeviceScanOutcome:
    """Result returned by one device worker.

    ``payload`` holds service-specific data such as CheckResult objects and is
    intentionally opaque to the concurrency layer.
    """

    target_ip: str
    status: DeviceStatus = DeviceStatus.COMPLETE
    hostname: str | None = None
    error_message: str | None = None
    payload: Any = None

    @property
    def successful(self) -> bool:
        return self.status == DeviceStatus.COMPLETE


@dataclass(slots=True)
class ScanSummary:
    run_id: str
    status: RunStatus
    outcomes: list[DeviceScanOutcome]
    started_at: datetime
    completed_at: datetime

    @property
    def success_count(self) -> int:
        return sum(outcome.successful for outcome in self.outcomes)

    @property
    def cancelled_count(self) -> int:
        return sum(outcome.status == DeviceStatus.CANCELLED for outcome in self.outcomes)

    @property
    def failure_count(self) -> int:
        return len(self.outcomes) - self.success_count - self.cancelled_count


DeviceWorker = Callable[
    [TargetT, threading.Event, Callable[[DeviceStatus, str, str | None], None]],
    DeviceScanOutcome,
]


class ScanOrchestrator(Generic[TargetT]):
    """Execute independent device workers with a strict concurrency bound."""

    MIN_CONCURRENCY = 1
    MAX_CONCURRENCY = 20
    DEFAULT_CONCURRENCY = 5

    def __init__(self, concurrency: int = DEFAULT_CONCURRENCY) -> None:
        if not self.MIN_CONCURRENCY <= concurrency <= self.MAX_CONCURRENCY:
            raise ValueError("concurrency must be between 1 and 20")
        self.concurrency = concurrency

    def run(
        self,
        *,
        run_id: str,
        targets: Iterable[TargetT],
        worker: DeviceWorker[TargetT],
        target_ip: Callable[[TargetT], str] = lambda target: str(target),
        cancel_event: threading.Event | None = None,
        event_queue: queue.Queue[ScanEvent] | None = None,
    ) -> ScanSummary:
        """Run a scan synchronously while workers execute concurrently.

        Devices are submitted only as worker capacity becomes available.  Once
        cancellation is requested, no additional device is submitted and all
        remaining targets receive a CANCELLED outcome/event.
        """

        cancellation = cancel_event or threading.Event()
        events = event_queue or queue.Queue()
        target_list = list(targets)
        total = len(target_list)
        started_at = datetime.now(timezone.utc)
        outcomes_by_index: dict[int, DeviceScanOutcome] = {}

        self._emit(
            events,
            ScanEvent(ScanEventType.RUN_STATUS, run_id, RunStatus.RUNNING.value, total=total),
        )
        for item in target_list:
            self._emit(
                events,
                ScanEvent(
                    ScanEventType.DEVICE_STATUS,
                    run_id,
                    DeviceStatus.QUEUED.value,
                    target_ip=target_ip(item),
                    total=total,
                ),
            )

        pending: dict[Future[DeviceScanOutcome], int] = {}
        next_index = 0

        def execute(index: int) -> DeviceScanOutcome:
            item = target_list[index]
            ip = target_ip(item)

            def report(
                status: DeviceStatus,
                message: str = "",
                hostname: str | None = None,
            ) -> None:
                self._emit(
                    events,
                    ScanEvent(
                        ScanEventType.DEVICE_STATUS,
                        run_id,
                        status.value,
                        target_ip=ip,
                        hostname=hostname,
                        message=message,
                        completed=len(outcomes_by_index),
                        total=total,
                    ),
                )

            if cancellation.is_set():
                return DeviceScanOutcome(ip, DeviceStatus.CANCELLED)
            report(DeviceStatus.CONNECTING, "Connecting")
            try:
                outcome = worker(item, cancellation, report)
                if not isinstance(outcome, DeviceScanOutcome):
                    raise TypeError("device worker must return DeviceScanOutcome")
                if outcome.target_ip != ip:
                    raise ValueError("device worker returned an outcome for a different target")
                return outcome
            except Exception as exc:
                return DeviceScanOutcome(
                    target_ip=ip,
                    status=DeviceStatus.EVALUATION_FAILED,
                    error_message=str(exc),
                )

        with ThreadPoolExecutor(
            max_workers=self.concurrency,
            thread_name_prefix="stig-audit-device",
        ) as executor:
            while next_index < total and len(pending) < self.concurrency and not cancellation.is_set():
                future = executor.submit(execute, next_index)
                pending[future] = next_index
                next_index += 1

            while pending:
                done, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                for future in done:
                    index = pending.pop(future)
                    outcome = future.result()
                    outcomes_by_index[index] = outcome
                    completed = len(outcomes_by_index)
                    self._emit(
                        events,
                        ScanEvent(
                            ScanEventType.DEVICE_STATUS,
                            run_id,
                            outcome.status.value,
                            target_ip=outcome.target_ip,
                            hostname=outcome.hostname,
                            message=outcome.error_message or outcome.status.value.replace("_", " ").title(),
                            completed=completed,
                            total=total,
                        ),
                    )
                    self._emit(
                        events,
                        ScanEvent(
                            ScanEventType.PROGRESS,
                            run_id,
                            RunStatus.RUNNING.value,
                            completed=completed,
                            total=total,
                        ),
                    )

                while (
                    next_index < total
                    and len(pending) < self.concurrency
                    and not cancellation.is_set()
                ):
                    future = executor.submit(execute, next_index)
                    pending[future] = next_index
                    next_index += 1

                if cancellation.is_set():
                    # Futures not yet executing are cancelled. Running workers
                    # retain the shared event and must check it between commands.
                    for future, index in tuple(pending.items()):
                        if future.cancel():
                            pending.pop(future)
                            ip = target_ip(target_list[index])
                            outcomes_by_index[index] = DeviceScanOutcome(
                                ip, DeviceStatus.CANCELLED
                            )

        # Targets never submitted after cancellation are explicitly represented.
        for index in range(next_index, total):
            ip = target_ip(target_list[index])
            outcomes_by_index[index] = DeviceScanOutcome(ip, DeviceStatus.CANCELLED)
            self._emit(
                events,
                ScanEvent(
                    ScanEventType.DEVICE_STATUS,
                    run_id,
                    DeviceStatus.CANCELLED.value,
                    target_ip=ip,
                    message="Cancelled before connection",
                    total=total,
                ),
            )

        outcomes = [outcomes_by_index[index] for index in sorted(outcomes_by_index)]
        status = self._run_status(outcomes, cancellation.is_set())
        completed_at = datetime.now(timezone.utc)
        self._emit(
            events,
            ScanEvent(
                ScanEventType.RUN_STATUS,
                run_id,
                status.value,
                completed=len(outcomes),
                total=total,
            ),
        )
        return ScanSummary(run_id, status, outcomes, started_at, completed_at)

    @staticmethod
    def _emit(events: queue.Queue[ScanEvent], event: ScanEvent) -> None:
        events.put(event)

    @staticmethod
    def _run_status(
        outcomes: list[DeviceScanOutcome], cancelled: bool
    ) -> RunStatus:
        if not outcomes:
            return RunStatus.CANCELLED if cancelled else RunStatus.COMPLETE
        successful = sum(outcome.successful for outcome in outcomes)
        cancelled_count = sum(
            outcome.status == DeviceStatus.CANCELLED for outcome in outcomes
        )
        failed = len(outcomes) - successful - cancelled_count
        if cancelled and successful == 0 and failed == 0:
            return RunStatus.CANCELLED
        if successful == len(outcomes):
            return RunStatus.COMPLETE
        if successful > 0:
            return RunStatus.PARTIAL
        if cancelled_count == len(outcomes):
            return RunStatus.CANCELLED
        return RunStatus.FAILED


__all__ = [
    "DeviceScanOutcome",
    "DeviceWorker",
    "ScanEvent",
    "ScanEventType",
    "ScanOrchestrator",
    "ScanSummary",
]
