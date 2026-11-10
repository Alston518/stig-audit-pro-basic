"""Collect first-use SSH fingerprints for one operator review before a scan."""

from __future__ import annotations

import base64
import binascii
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable

from paramiko import SSHException

from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore


@dataclass(frozen=True, slots=True)
class HostKeyBatchEntry:
    target: DeviceTarget
    algorithm: str
    public_key: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class HostKeyBatchPlan:
    unknown: tuple[HostKeyBatchEntry, ...]
    changed: tuple[HostKeyBatchEntry, ...]
    failed: tuple[str, ...]


def collect_host_key_batch(
    targets: Iterable[DeviceTarget],
    store: HostKeyTrustStore,
    cancellation: threading.Event,
    *,
    concurrency: int = 3,
) -> HostKeyBatchPlan:
    """Discover keys without credentials; never approve or replace one here."""

    if not 1 <= concurrency <= 20:
        raise ValueError("Host-key discovery concurrency must be between 1 and 20")
    known = store.list_hosts()

    def inspect(target: DeviceTarget) -> tuple[str, HostKeyBatchEntry | str | None]:
        if cancellation.is_set():
            return "cancelled", None
        try:
            algorithm, public_key, fingerprint = store.discover(
                target.ip, target.port, min(target.timeout, 10),
            )
        except (OSError, EOFError, ValueError, SSHException):
            return "failed", target.ip
        entry = HostKeyBatchEntry(target, algorithm, public_key, fingerprint)
        marker = target.ip if target.port == 22 else f"[{target.ip}]:{target.port}"
        saved = known.get(marker, ())
        if not saved:
            return "unknown", entry
        if f"{algorithm} {fingerprint}" in saved:
            return "known", None
        return "changed", entry

    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="stig-host-key") as executor:
        results = tuple(executor.map(inspect, targets))
    return HostKeyBatchPlan(
        unknown=tuple(value for kind, value in results if kind == "unknown"),
        changed=tuple(value for kind, value in results if kind == "changed"),
        failed=tuple(value for kind, value in results if kind == "failed"),
    )


def enroll_host_key_batch(
    store: HostKeyTrustStore,
    entries: Iterable[HostKeyBatchEntry],
    *,
    verification_note: str,
    operator: str,
) -> tuple[str, ...]:
    """Save only displayed first-use keys; never replace a stored key."""

    reviewed = tuple(entries)
    if not verification_note.strip():
        raise ValueError("A verification note is required for bulk host-key approval")
    for entry in reviewed:
        try:
            raw = base64.b64decode(entry.public_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"Invalid public key for {entry.target.ip}") from exc
        if store.fingerprint(entry.algorithm, raw) != entry.fingerprint:
            raise ValueError(f"Displayed fingerprint changed for {entry.target.ip}")
    enrolled: list[str] = []
    for entry in reviewed:
        store.enroll(
            entry.target.ip, entry.target.port, entry.algorithm, entry.public_key,
            verification_note=verification_note, operator=operator, replace=False,
        )
        enrolled.append(entry.target.ip)
    return tuple(enrolled)


__all__ = ["HostKeyBatchEntry", "HostKeyBatchPlan", "collect_host_key_batch", "enroll_host_key_batch"]
