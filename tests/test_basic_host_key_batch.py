"""Basic scan gates bulk SSH host-key enrollment on one operator review."""

from __future__ import annotations

import base64
import logging
import queue
import threading
from pathlib import Path
from types import SimpleNamespace

from stig_audit_pro.basic_app import BasicApp
from stig_audit_pro.core.ssh_runner import DeviceTarget
from stig_audit_pro.gui.basic_host_keys import HostKeyBatchRequest, TOFU_BATCH_NOTE
from stig_audit_pro.infrastructure.ssh.host_key_batch import HostKeyBatchEntry, HostKeyBatchPlan
from stig_audit_pro.infrastructure.ssh.host_keys import HostKeyTrustStore
from stig_audit_pro.storage.device_groups import DeviceTargetRecord


def _plan(store):
    key = b"new-public-key"
    algorithm = "ssh-ed25519"
    entry = HostKeyBatchEntry(
        DeviceTarget("192.0.2.10"), algorithm, base64.b64encode(key).decode("ascii"),
        store.fingerprint(algorithm, key),
    )
    return HostKeyBatchPlan((entry,), (), ())


def test_basic_batch_review_enrolls_displayed_key_once(monkeypatch, tmp_path, caplog):
    from stig_audit_pro import basic_app

    store = HostKeyTrustStore(tmp_path / "known_hosts")
    plan = _plan(store)
    app = BasicApp.__new__(BasicApp)
    app.cancel_event = threading.Event()
    app.events = queue.Queue()
    app._request_host_key_batch_approval = lambda reviewed, _cancel: (
        "Compared with approved inventory" if reviewed is plan else None
    )
    monkeypatch.setattr(basic_app, "collect_host_key_batch", lambda *_args, **_kwargs: plan)

    with caplog.at_level(logging.WARNING, logger="stig_audit_pro.activity"):
        app._prepare_host_key_batch([DeviceTarget("192.0.2.10")], store, "run-1")

    assert "192.0.2.10" in store.list_hosts()
    assert "HOST_KEY_BATCH_APPROVED" in caplog.text
    assert not app.cancel_event.is_set()


def test_no_note_bulk_acceptance_is_labeled_unverified_in_activity(monkeypatch, tmp_path, caplog):
    from stig_audit_pro import basic_app

    store = HostKeyTrustStore(tmp_path / "known_hosts")
    plan = _plan(store)
    app = BasicApp.__new__(BasicApp)
    app.cancel_event = threading.Event()
    app.events = queue.Queue()
    app._request_host_key_batch_approval = lambda *_args: TOFU_BATCH_NOTE
    monkeypatch.setattr(basic_app, "collect_host_key_batch", lambda *_args, **_kwargs: plan)

    with caplog.at_level(logging.WARNING, logger="stig_audit_pro.activity"):
        app._prepare_host_key_batch([DeviceTarget("192.0.2.10")], store, "run-1")

    assert "method=first_use_unverified" in caplog.text


def test_declining_batch_review_cancels_without_enrollment(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app

    store = HostKeyTrustStore(tmp_path / "known_hosts")
    plan = _plan(store)
    app = BasicApp.__new__(BasicApp)
    app.cancel_event = threading.Event()
    app.events = queue.Queue()
    app._request_host_key_batch_approval = lambda *_args: None
    monkeypatch.setattr(basic_app, "collect_host_key_batch", lambda *_args, **_kwargs: plan)

    app._prepare_host_key_batch([DeviceTarget("192.0.2.10")], store, "run-1")

    assert app.cancel_event.is_set()
    assert store.list_hosts() == {}


def test_batch_request_waits_for_one_gui_decision():
    app = BasicApp.__new__(BasicApp)
    app.events = queue.Queue()
    cancellation = threading.Event()
    answer = []
    plan = HostKeyBatchPlan((), (), ())
    worker = threading.Thread(
        target=lambda: answer.append(app._request_host_key_batch_approval(plan, cancellation)),
    )
    worker.start()
    request = app.events.get(timeout=2)
    assert isinstance(request, HostKeyBatchRequest)
    request.approval_note = "Verified against inventory"
    request.done.set()
    worker.join(timeout=2)
    assert answer == ["Verified against inventory"]


def test_live_run_reviews_keys_before_starting_ssh(monkeypatch, tmp_path):
    from stig_audit_pro import basic_app

    order = []
    app = BasicApp.__new__(BasicApp)
    app.events = queue.Queue()
    app.cancel_event = threading.Event()
    app.license_policy = SimpleNamespace(validate=lambda addresses, *_args: tuple(addresses))
    app._prepare_host_key_batch = lambda targets, store, run_id: order.append(
        ("review", tuple(target.ip for target in targets))
    )

    class Service:
        def __init__(self, **_kwargs):
            pass

        def run_live(self, **_kwargs):
            order.append(("ssh",))
            return SimpleNamespace(
                assets={}, results=[], summary=SimpleNamespace(
                    outcomes=(), failure_count=1, cancelled_count=0,
                ),
            )

    monkeypatch.setattr(basic_app, "HostKeyTrustStore", lambda: object())
    monkeypatch.setattr(basic_app, "AuditService", Service)
    app._run(
        [DeviceTargetRecord(ip="192.0.2.10")], [], None, object(), ["iosxe_l2"],
        "Live SSH", {}, True, False, Path(tmp_path) / "reports",
        verify_host_key=True, approve_unknown=lambda *_args: None,
    )
    assert order == [("review", ("192.0.2.10",)), ("ssh",)]
