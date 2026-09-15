from __future__ import annotations

import queue
import threading
import time
from collections import Counter

from stig_audit_pro.application.scan_orchestrator import (
    DeviceScanOutcome,
    ScanEventType,
    ScanOrchestrator,
)
from stig_audit_pro.core.models import DeviceStatus, RunStatus


RUN_ID = "00000000-0000-4000-8000-000000000001"


def test_five_devices_overlap_and_worker_limit_is_honored():
    lock = threading.Lock()
    active = 0
    high_water = 0
    barrier = threading.Barrier(5)

    def worker(target, _cancel, report):
        nonlocal active, high_water
        report(DeviceStatus.COLLECTING, "collecting")
        with lock:
            active += 1
            high_water = max(high_water, active)
        barrier.wait(timeout=2)
        time.sleep(0.02)
        with lock:
            active -= 1
        return DeviceScanOutcome(target, payload=target)

    summary = ScanOrchestrator(concurrency=5).run(
        run_id=RUN_ID,
        targets=[f"192.0.2.{index}" for index in range(1, 6)],
        worker=worker,
    )

    assert summary.status == RunStatus.COMPLETE
    assert high_water == 5
    assert [outcome.payload for outcome in summary.outcomes] == [
        f"192.0.2.{index}" for index in range(1, 6)
    ]


def test_one_failure_does_not_stop_other_devices_and_events_are_emitted():
    events = queue.Queue()

    def worker(target, _cancel, report):
        report(DeviceStatus.COLLECTING, "collecting")
        if target.endswith(".2"):
            raise RuntimeError("synthetic failure")
        report(DeviceStatus.EVALUATING, "evaluating")
        return DeviceScanOutcome(target)

    summary = ScanOrchestrator(concurrency=3).run(
        run_id=RUN_ID,
        targets=["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        worker=worker,
        event_queue=events,
    )
    emitted = []
    while not events.empty():
        emitted.append(events.get_nowait())

    assert summary.status == RunStatus.PARTIAL
    assert summary.success_count == 2
    assert summary.failure_count == 1
    assert {outcome.target_ip for outcome in summary.outcomes} == {
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    }
    event_types = Counter(event.event_type for event in emitted)
    assert event_types[ScanEventType.RUN_STATUS] == 2
    assert event_types[ScanEventType.PROGRESS] == 3
    assert any(event.status == DeviceStatus.EVALUATION_FAILED for event in emitted)


def test_cancellation_stops_submitting_queued_devices():
    cancellation = threading.Event()
    started: list[str] = []

    def worker(target, cancel, _report):
        started.append(target)
        if target.endswith(".1"):
            cancellation.set()
        for _ in range(20):
            if cancel.is_set():
                return DeviceScanOutcome(target, DeviceStatus.CANCELLED)
            time.sleep(0.002)
        return DeviceScanOutcome(target)

    targets = [f"192.0.2.{index}" for index in range(1, 11)]
    summary = ScanOrchestrator(concurrency=2).run(
        run_id=RUN_ID,
        targets=targets,
        worker=worker,
        cancel_event=cancellation,
    )

    assert len(started) <= 2
    assert len(summary.outcomes) == len(targets)
    assert summary.cancelled_count == len(targets)
    assert summary.status == RunStatus.CANCELLED


def test_orchestrator_rejects_out_of_range_concurrency():
    for value in (0, 21):
        try:
            ScanOrchestrator(value)
        except ValueError as exc:
            assert "between 1 and 20" in str(exc)
        else:  # pragma: no cover - explicit assertion message
            raise AssertionError(f"concurrency {value} was accepted")
