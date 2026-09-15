import json
from uuid import uuid4

import pytest

from stig_audit_pro.core.models import AuditRun
from stig_audit_pro.infrastructure.evidence import EvidenceStore, RunFinalizedError
from stig_audit_pro.infrastructure.persistence import AuditRunRepository, Database


def _store(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    repository = AuditRunRepository(database)
    return database, repository, EvidenceStore(tmp_path / "runs", repository)


def _create_run(repository, store, run_id, ip="192.0.2.10"):
    repository.create_run(AuditRun(run_id=run_id, device_count=1))
    device = repository.add_device(run_id, target_ip=ip)
    store.create_run(
        run_id,
        check_snapshot={"schema_version": 1, "checks": []},
        profile_snapshot={"profile_name": "test"},
    )
    store.prepare_device(run_id, ip)
    return device


def test_two_runs_for_same_ip_never_overwrite_and_manifest_is_secret_free(tmp_path):
    database, repository, store = _store(tmp_path)
    try:
        first_id, second_id = str(uuid4()), str(uuid4())
        first_device = _create_run(repository, store, first_id)
        second_device = _create_run(repository, store, second_id)
        first = store.write_evidence(
            first_id, "192.0.2.10", "show running-config", "first\n",
            run_device_id=first_device.id,
        )
        second = store.write_evidence(
            second_id, "192.0.2.10", "show running-config", "second\n",
            run_device_id=second_device.id,
        )
        first_manifest = store.finalize_run(first_id, {
            "password": "must-not-appear",
            "nested": {"enable_secret": "also-secret"},
        })
        store.finalize_run(second_id)

        assert first.relative_path != second.relative_path
        assert store.read_evidence(first.relative_path) == "first\n"
        assert store.read_evidence(second.relative_path) == "second\n"
        manifest_text = first_manifest.read_text(encoding="utf-8")
        assert "must-not-appear" not in manifest_text
        assert "also-secret" not in manifest_text
        manifest = json.loads(manifest_text)
        assert manifest["evidence_artifacts"][0]["sha256"] == first.sha256
        with pytest.raises(RunFinalizedError):
            store.write_evidence(first_id, "192.0.2.10", "show version", "late")
    finally:
        database.dispose()


def test_purge_raw_evidence_retains_structured_bundle(tmp_path):
    database, repository, store = _store(tmp_path)
    try:
        run_id = str(uuid4())
        device = _create_run(repository, store, run_id)
        artifact = store.write_evidence(
            run_id, "192.0.2.10", "show version", "version",
            run_device_id=device.id,
        )
        store.write_results(run_id, "192.0.2.10", [{"status": "Open"}])
        manifest = store.finalize_run(run_id)
        assert store.purge_raw_evidence(run_id) == 1
        assert manifest.is_file()
        assert (store.run_path(run_id) / "devices" / "192.0.2.10" / "results.json").is_file()
        assert not (store.root / artifact.relative_path).exists()
    finally:
        database.dispose()
