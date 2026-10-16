"""Regression checks for Basic audit output and operator status."""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from types import SimpleNamespace

from stig_audit_pro import basic_app
from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.core.ssh_runner import DeviceCommandRun, DeviceCredentials
from stig_audit_pro.core.yaml_loader import load_profile
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore
from stig_audit_pro.licensing import LicenseManager
from stig_audit_pro.licensing.basic_policy import BasicLicensePolicy
from stig_audit_pro.storage.device_groups import DeviceTargetRecord


def _app(tmp_path: Path, *, allow_batch: bool = False):
    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.license_policy = (
        SimpleNamespace(validate=lambda targets, *_args: tuple(targets))
        if allow_batch else BasicLicensePolicy(LicenseManager(tmp_path / "license.json"))
    )
    app.artifacts = ProtectedArtifactStore(
        AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    )
    app.events = queue.Queue()
    app.cancel_event = threading.Event()
    return app


def _last_message(app) -> str:
    messages = [event.message for event in list(app.events.queue) if hasattr(event, "message")]
    return messages[-1]


def test_all_failed_ssh_devices_do_not_claim_reports_were_written(monkeypatch, tmp_path):
    class UntrustedKeyRunner:
        def run_commands(self, target, *_args, **_kwargs):
            return DeviceCommandRun(target.ip, "skipped", {}, "SSH host key is not trusted")

    monkeypatch.setattr(
        basic_app, "AuditService",
        lambda: AuditService(runner_factory=UntrustedKeyRunner),
    )
    app = _app(tmp_path)
    output = tmp_path / "reports"

    app._run(
        [DeviceTargetRecord(ip="192.0.2.10")], [], None,
        DeviceCredentials("operator", "test"), ["iosxe_l2"], "Live SSH",
        {}, True, False, output,
    )

    final = _last_message(app)
    assert "failed" in final.lower()
    assert "192.0.2.10" in final
    assert "ssh settings" in final.lower()
    assert "Completed. Files written" not in final
    assert not list(output.glob("*"))


def test_same_octet_batch_writes_distinct_encrypted_reports(monkeypatch, tmp_path):
    app = _app(tmp_path, allow_batch=True)
    output = tmp_path / "reports"
    profile_root = Path(__file__).resolve().parents[1] / "data" / "profiles"
    profile = load_profile(profile_root / "base_iosxe_access.yaml", profiles_dir=profile_root)

    app._run(
        [DeviceTargetRecord(ip="192.0.2.10"), DeviceTargetRecord(ip="198.51.100.10")],
        [], profile, None, ["iosxe_l2"], "Sample outputs", {}, True, False, output,
    )

    protected = sorted(output.glob("*.txt.sapenc"))
    assert len(protected) == 2, _last_message(app)
    assert protected[0].name != protected[1].name
    assert "2 encrypted" in _last_message(app).lower()
    assert all(app.artifacts.read(path) for path in protected)


def test_partial_batch_lists_saved_report_and_failed_device(monkeypatch, tmp_path):
    app = _app(tmp_path, allow_batch=True)
    output = tmp_path / "reports"
    profile_root = Path(__file__).resolve().parents[1] / "data" / "profiles"
    profile = load_profile(profile_root / "base_iosxe_access.yaml", profiles_dir=profile_root)
    original_loader = basic_app.sample_outputs

    def load(target):
        if target.ip == "198.51.100.26":
            raise FileNotFoundError("Demo output is missing")
        return original_loader(target)

    monkeypatch.setattr(basic_app, "sample_outputs", load)
    app._run(
        [DeviceTargetRecord(ip="192.0.2.10"), DeviceTargetRecord(ip="198.51.100.26")],
        [], profile, None, ["iosxe_l2"], "Sample outputs", {}, True, False, output,
    )

    saved = list(output.glob("*.txt.sapenc"))
    final = _last_message(app)
    assert len(saved) == 1
    assert "partial audit" in final.lower()
    assert str(saved[0]) in final
    assert "198.51.100.26" in final


def test_report_stem_is_windows_safe_for_ipv6_and_hostnames():
    asset = SimpleNamespace(management_ip=None)
    names = {
        basic_app.report_stem(asset, target, ["iosxe_l2"])
        for target in ("2001:db8::10", "2001:db8:1::10", "switch-a", "switch_a")
    }
    assert len(names) == 4
    assert all(not any(char in name for char in '<>:"/\\|?*') for name in names)


def test_poll_rechecks_queue_after_worker_finishes():
    event = SimpleNamespace(message="Audit failed: no reports created")

    class RaceQueue:
        def __init__(self):
            self.queued = False

        def get_nowait(self):
            if not self.queued:
                self.queued = True
                raise queue.Empty
            if self.queued is True:
                self.queued = "delivered"
                return event
            raise queue.Empty

        def empty(self):
            return self.queued != True

    calls = []
    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.events = RaceQueue()
    app.thread = SimpleNamespace(is_alive=lambda: False)
    app.root = SimpleNamespace(after=lambda _delay, callback: calls.append(callback))
    app.status = SimpleNamespace(configure=lambda **kwargs: calls.append(kwargs["text"]))
    app.results_box = SimpleNamespace(insert=lambda *_args: None)

    app.poll()
    assert len(calls) == 1
    calls[0]()
    assert "Audit failed" in calls[1]


def test_csv_without_header_keeps_first_device(tmp_path):
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text("192.0.2.10\n198.51.100.20\n", encoding="utf-8")
    assert basic_app.parse_device_file(csv_path) == (["192.0.2.10", "198.51.100.20"], [])


def test_csv_with_header_selects_address_column(tmp_path):
    csv_path = tmp_path / "devices.csv"
    csv_path.write_text("name,host\nfirst,192.0.2.10\nsecond,198.51.100.20\n", encoding="utf-8")
    assert basic_app.parse_device_file(csv_path) == (["192.0.2.10", "198.51.100.20"], [])


def test_ssh_secret_fields_are_cleared_after_capture():
    class Entry:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

        def delete(self, *_args):
            self.value = ""

    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.user = Entry("operator")
    app.password = Entry("password")
    app.secret = Entry("enable-secret")

    credentials = app._take_ssh_credentials()

    assert credentials == DeviceCredentials("operator", "password", "enable-secret")
    assert app.password.get() == ""
    assert app.secret.get() == ""


def test_window_close_waits_for_active_audit():
    messages = []
    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.thread = SimpleNamespace(is_alive=lambda: True)
    app.cancel_event = threading.Event()
    app.root = SimpleNamespace(destroy=lambda: messages.append("destroy"))
    app.status = SimpleNamespace(configure=lambda **kwargs: messages.append(kwargs["text"]))
    app.messagebox = SimpleNamespace(showinfo=lambda *_args: messages.append("informed"))

    app.on_close()

    assert app.cancel_event.is_set()
    assert "destroy" not in messages
    assert any("cancel" in message.lower() for message in messages)


def test_completion_event_exposes_saved_files_and_counts(monkeypatch, tmp_path):
    app = _app(tmp_path)
    profile_root = Path(__file__).resolve().parents[1] / "data" / "profiles"
    profile = load_profile(profile_root / "base_iosxe_access.yaml", profiles_dir=profile_root)
    output = tmp_path / "reports"

    app._run(
        [DeviceTargetRecord(ip="192.0.2.10")], [], profile, None,
        ["iosxe_l2"], "Sample outputs", {}, True, False, output,
    )

    event = list(app.events.queue)[-1]
    assert event.run_state == "completed"
    assert event.device_count == 1
    assert event.failed_count == 0
    assert len(event.report_paths) == 1
    assert Path(event.report_paths[0]).is_file()
    assert event.output_dir == output.resolve()


def test_live_progress_never_displays_raw_ssh_exception():
    event = SimpleNamespace(
        event_type="DEVICE_STATUS", status="COLLECTION_FAILED",
        target_ip="192.0.2.10", message="password=SECRET123 host key rejected",
    )
    rendered = basic_app._scan_event_text(event)
    assert "192.0.2.10" in rendered
    assert "ssh settings" in rendered.lower()
    assert "SECRET123" not in rendered


def test_result_card_shows_actual_saved_file_count(tmp_path):
    values = {}

    def widget(name):
        return SimpleNamespace(configure=lambda **kwargs: values.setdefault(name, []).append(kwargs))

    app = basic_app.BasicApp.__new__(basic_app.BasicApp)
    app.colors = {"teal": "green", "amber": "yellow", "red": "red"}
    app.run_state_label = widget("state")
    app.run_counts_label = widget("counts")
    app.run_folder_label = widget("folder")
    app.open_folder_button = widget("open")
    app.view_latest_button = widget("view")
    protected = tmp_path / "report.txt.sapenc"
    protected.write_bytes(b"test")
    event = SimpleNamespace(
        run_state="partial", report_paths=[str(protected)], output_dir=tmp_path,
        failed_count=1, cancelled_count=0,
    )

    app._apply_run_completion(event)

    assert values["state"][-1]["text"] == "PARTIAL"
    assert "1 protected file" in values["counts"][-1]["text"]
    assert "1 failed device" in values["counts"][-1]["text"]
    assert str(tmp_path) in values["folder"][-1]["text"]
    assert values["open"][-1]["state"] == "normal"
    assert values["view"][-1]["state"] == "normal"


def test_report_save_failure_keeps_paths_already_written(monkeypatch, tmp_path):
    app = _app(tmp_path, allow_batch=True)
    profile_root = Path(__file__).resolve().parents[1] / "data" / "profiles"
    profile = load_profile(profile_root / "base_iosxe_access.yaml", profiles_dir=profile_root)
    output = tmp_path / "reports"
    real_save = app.artifacts.save
    saves = 0

    def save_once(path, contents):
        nonlocal saves
        saves += 1
        if saves == 2:
            raise PermissionError("simulated failure with password=PRIVATE")
        return real_save(path, contents)

    app.artifacts.save = save_once
    app._run(
        [DeviceTargetRecord(ip="192.0.2.10"), DeviceTargetRecord(ip="198.51.100.20")],
        [], profile, None, ["iosxe_l2"], "Sample outputs", {}, True, False, output,
    )

    event = list(app.events.queue)[-1]
    assert event.run_state == "partial"
    assert len(event.report_paths) == 1
    assert Path(event.report_paths[0]).is_file()
    assert "PRIVATE" not in event.message


def test_summary_export_reports_partial_protected_files(monkeypatch, tmp_path):
    app = _app(tmp_path, allow_batch=True)
    app.last_targets = ["192.0.2.10"]
    app.last_families = ["iosxe_l2"]
    app.last_results = []
    app.last_run_id = "example-run"
    app._summary_filter = lambda: None
    app.output_dir = SimpleNamespace(get=lambda: str(tmp_path / "summaries"))
    app.summary_pdf = SimpleNamespace(get=lambda: True)
    app.summary_html = SimpleNamespace(get=lambda: True)
    app.summary_csv = SimpleNamespace(get=lambda: False)
    errors = []
    app.messagebox = SimpleNamespace(showerror=lambda *args: errors.append(args))
    monkeypatch.setattr(basic_app, "summarize", lambda *_args: {})
    monkeypatch.setattr(basic_app, "render_pdf", lambda _report: b"PDF content")
    monkeypatch.setattr(basic_app, "render_html", lambda _report: b"HTML content")
    real_save = app.artifacts.save
    calls = 0

    def fail_second(path, content):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("password=PRIVATE")
        return real_save(path, content)

    app.artifacts.save = fail_second
    paths = app.export_summary()

    assert len(paths) == 1
    assert paths[0].is_file()
    assert "1 encrypted file" in errors[0][1]
    assert str(paths[0]) in errors[0][1]
    assert "PRIVATE" not in errors[0][1]
