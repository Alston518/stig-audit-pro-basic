"""Operator can read an encrypted manifest without exporting plaintext."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from stig_audit_pro.basic_app import BasicApp
from stig_audit_pro.gui.protected_reports import ProtectedReportWorkspace
from stig_audit_pro.infrastructure.security.at_rest import AtRestVault
from stig_audit_pro.infrastructure.security.basic_artifacts import ProtectedArtifactStore


def _app(tmp_path, selected):
    app = BasicApp.__new__(BasicApp)
    app.last_output_dir = tmp_path
    app.report_workspace = ProtectedReportWorkspace()
    app.artifacts = ProtectedArtifactStore(AtRestVault.open(tmp_path / "vault.json", "test", create=True))
    app.filedialog = SimpleNamespace(askopenfilenames=lambda **_kwargs: selected)
    events = []
    app.messagebox = SimpleNamespace(
        showwarning=lambda *args: events.append(("warning", args)),
        showerror=lambda *args: events.append(("error", args)),
    )
    app.results_box = SimpleNamespace(
        delete=lambda *_args: events.append(("clear",)),
        insert=lambda *_args: events.append(("text", _args[-1])),
    )
    app.tabs = SimpleNamespace(set=lambda name: events.append(("tab", name)))
    app._refresh_report_selectors = lambda **_kwargs: None
    app._display_selected_report = lambda: events.append(("report",))
    return app, events


def _manifest(app, tmp_path):
    return app.artifacts.save_manifest(
        tmp_path / "audit_123.manifest.json",
        json.dumps({
            "run_id": "run-123", "operator": "tester", "tool_version": "0.2.0",
            "stig_release": "Release: 2", "timestamp": "2026-11-06T13:00:00+00:00",
            "file_hashes": {"switch.txt.sapenc": "a" * 64},
        }).encode("utf-8"),
    )


def test_report_import_opens_selected_manifest_in_memory(tmp_path):
    app, events = _app(tmp_path, ())
    manifest = _manifest(app, tmp_path)
    app.filedialog.askopenfilenames = lambda **_kwargs: (str(manifest),)

    app.import_protected_report()

    preview = next(event[1] for event in events if event[0] == "text")
    assert "run-123" in preview
    assert "Release: 2" in preview
    assert "switch.txt.sapenc" in preview
    assert "a" * 64 in preview
    assert not any(event[0] in {"warning", "error"} for event in events)
    assert app.report_workspace.reports() == ()


def test_importing_reports_and_manifest_together_does_not_warn(tmp_path):
    app, events = _app(tmp_path, ())
    manifest = _manifest(app, tmp_path)
    report = tmp_path / "switch.txt.sapenc"
    app.filedialog.askopenfilenames = lambda **_kwargs: (str(report), str(manifest))

    app.import_protected_report()

    assert [item.path for item in app.report_workspace.reports()] == [report.resolve()]
    assert ("report",) in events
    assert not any(event[0] in {"warning", "error"} for event in events)


def test_manifest_picker_uses_report_folder_and_only_manifest_files(tmp_path):
    app, events = _app(tmp_path, ())
    manifest = _manifest(app, tmp_path)
    observed = {}
    app.filedialog.askopenfilename = lambda **options: observed.update(options) or str(manifest)

    app.view_protected_manifest()

    assert observed["initialdir"] == str(tmp_path)
    assert "*.manifest.json.sapenc" in str(observed["filetypes"])
    assert any(event[0] == "text" for event in events)
