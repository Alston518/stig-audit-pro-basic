#!/usr/bin/env python3
"""Synthetic concurrency/queue benchmark; no Cisco device is contacted."""

from __future__ import annotations

import argparse
import json
import queue
import sys
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stig_audit_pro.application.scan_orchestrator import DeviceScanOutcome, ScanOrchestrator
from stig_audit_pro.core.models import DeviceStatus


@dataclass(frozen=True)
class FakeTarget:
    ip: str


def benchmark(device_count: int, concurrency: int, delay: float) -> dict:
    events: queue.Queue = queue.Queue()
    targets = [FakeTarget(f"192.0.2.{index + 1}") for index in range(device_count)]

    def worker(target, cancellation, report):
        report(DeviceStatus.COLLECTING, "Synthetic evidence collection")
        time.sleep(delay)
        report(DeviceStatus.EVALUATING, "Synthetic evaluation")
        return DeviceScanOutcome(target.ip, DeviceStatus.COMPLETE)

    tracemalloc.start()
    started = time.perf_counter()
    summary = ScanOrchestrator(concurrency).run(run_id="benchmark", targets=targets, worker=worker, target_ip=lambda item: item.ip, event_queue=events)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"devices": device_count, "concurrency": concurrency, "elapsed_seconds": round(elapsed, 3), "peak_memory_mb": round(peak / 1024 ** 2, 2), "events": events.qsize(), "outcomes": len(summary.outcomes), "status": summary.status.value}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices", nargs="+", type=int, default=[50, 100, 500, 1000])
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--delay", type=float, default=0.001)
    args = parser.parse_args()
    results = [benchmark(count, args.concurrency, args.delay) for count in args.devices]
    print(json.dumps(results, indent=2))
    return 0 if all(item["outcomes"] == item["devices"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
