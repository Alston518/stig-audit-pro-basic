import json
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import inspect, text

from stig_audit_pro.application.audit_package_service import AuditPackageService
from stig_audit_pro.application.backup_service import BackupService, BackupSource
from stig_audit_pro.application.support_bundle_service import SupportBundleService
from stig_audit_pro.core.models import AuditRun
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.infrastructure.persistence import Database
from stig_audit_pro.infrastructure.persistence.db_models import ActivityLog
from stig_audit_pro.infrastructure.persistence.repositories import (
    ActivityLogRepository,
    AuditRunRepository,
)


def test_activity_log_redacts_secret_fields(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    item = ActivityLogRepository(database).record("AUDIT_STARTED", "audit", "one", details={"password": "do-not-store", "nested": {"token": "abc"}, "message": "password=hunter2"})
    assert item.details == {"password": "[REDACTED]", "nested": {"token": "[REDACTED]"}, "message": "password=[REDACTED]"}


def test_v1_database_is_backed_up_and_migrated(tmp_path):
    path = tmp_path / "audit.sqlite3"
    database = Database(path)
    with database.engine.begin() as connection:
        connection.execute(text("DROP TABLE activity_log"))
        connection.execute(text("UPDATE schema_version SET version = 1 WHERE id = 1"))
    database.dispose()
    migrated = Database(path)
    assert "activity_log" in inspect(migrated.engine).get_table_names()
    assert list(tmp_path.glob("audit.sqlite3.pre-v3-*.bak"))


def test_v2_database_adds_historical_result_title_without_data_loss(tmp_path):
    path = tmp_path / "audit.sqlite3"
    database = Database(path)
    repository = AuditRunRepository(database)
    run = AuditRun(run_id=str(uuid4()), device_count=1)
    repository.create_run(run)
    device = repository.add_device(run.run_id, target_ip="192.0.2.90")
    repository.add_check_result(device.id, CheckResult(
        ip="192.0.2.90",
        hostname="SW90",
        vuln_id="V-MIGRATION",
        stig_family="IOSXE_L2",
        title="Title unavailable in schema v2",
        severity="cat2",
        status="Open",
    ))
    with database.engine.begin() as connection:
        connection.execute(text("UPDATE schema_version SET version = 2 WHERE id = 1"))
        connection.execute(text("ALTER TABLE check_result RENAME TO check_result_v2"))
        connection.execute(text(
            "CREATE TABLE check_result ("
            "id INTEGER PRIMARY KEY, run_device_id INTEGER NOT NULL, vuln_id VARCHAR(128) NOT NULL, "
            "rule_id VARCHAR(255), stig_id VARCHAR(255), check_id VARCHAR(255), "
            "stig_family VARCHAR(255) NOT NULL, severity VARCHAR(32) NOT NULL, "
            "status VARCHAR(32) NOT NULL, finding_details TEXT, comments TEXT, "
            "evaluation_reason TEXT, check_type VARCHAR(128), commands_used JSON NOT NULL, "
            "profile_values JSON NOT NULL, failed_objects JSON NOT NULL, parser_warnings JSON NOT NULL, "
            "error_message TEXT, evaluated_at DATETIME NOT NULL, "
            "FOREIGN KEY(run_device_id) REFERENCES run_device(id) ON DELETE CASCADE)"
        ))
        connection.execute(text(
            "INSERT INTO check_result SELECT id, run_device_id, vuln_id, rule_id, stig_id, check_id, "
            "stig_family, severity, status, finding_details, comments, evaluation_reason, check_type, "
            "commands_used, profile_values, failed_objects, parser_warnings, error_message, evaluated_at "
            "FROM check_result_v2"
        ))
        connection.execute(text("DROP TABLE check_result_v2"))
    database.dispose()

    migrated = Database(path)
    try:
        assert "title" in {
            column["name"]
            for column in inspect(migrated.engine).get_columns("check_result")
        }
        assert list(tmp_path.glob("audit.sqlite3.pre-v3-*.bak"))
        migrated_result = AuditRunRepository(migrated).list_check_results(run.run_id)[0]
        assert migrated_result.vuln_id == "V-MIGRATION"
        assert migrated_result.title is None
    finally:
        migrated.dispose()


def test_support_bundle_excludes_and_redacts_secrets(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    log = tmp_path / "app.log"
    log.write_text(
        "password=hunter2\nnormal diagnostic\n"
        "INFO paramiko.transport: Auth banner: sensitive device notice\n",
        encoding="utf-8",
    )
    target = SupportBundleService(database, log_paths=[log]).create(tmp_path / "support.zip")
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        content = "\n".join(archive.read(name).decode("utf-8") for name in names)
    assert "hunter2" not in content
    assert "sensitive device notice" not in content
    assert "THIRD-PARTY SSH DIAGNOSTIC" in content
    assert "[REDACTED]" in content
    assert not any("evidence" in name.lower() for name in names)


def test_backup_and_restore_validate_product_archive(tmp_path):
    database = Database(tmp_path / "source.sqlite3")
    data = tmp_path / "profiles"
    data.mkdir()
    (data / "site.yaml").write_text("profile_name: site\n", encoding="utf-8")
    backup = BackupService(database_path=database.path, sources=[BackupSource("profiles", data)])
    archive = backup.create(tmp_path / "backup.zip")
    restore_root = tmp_path / "restored"
    backup.restore(archive, destination_root=restore_root)
    assert (restore_root / "database/stig-audit-pro.sqlite3").is_file()
    assert (restore_root / "data/profiles/site.yaml").is_file()


def test_in_place_restore_preserves_safety_backup_and_exact_destinations(tmp_path):
    database_path = tmp_path / "app-data" / "stig-audit-pro.sqlite3"
    profiles = tmp_path / "app-data" / "profiles"
    profiles.mkdir(parents=True)
    profile = profiles / "site.yaml"
    profile.write_text("profile_name: original\n", encoding="utf-8")
    database = Database(database_path)
    service = BackupService(
        database_path=database_path,
        sources=[BackupSource("profiles", profiles)],
    )
    archive = service.create(tmp_path / "known-good.zip")
    profile.write_text("profile_name: changed\n", encoding="utf-8")
    AuditRunRepository(database).create_run(AuditRun(run_id=str(uuid4())))
    database.dispose()

    inspection = service.inspect(archive)
    safety = service.restore_in_place(archive)

    assert inspection.entry_count >= 2
    assert safety.is_file()
    assert profile.read_text(encoding="utf-8") == "profile_name: original\n"
    restored_database = Database(database_path)
    try:
        assert AuditRunRepository(restored_database).count_runs() == 0
    finally:
        restored_database.dispose()


def test_backup_inspection_rejects_modified_content(tmp_path):
    database = Database(tmp_path / "source.sqlite3")
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "site.yaml").write_text("profile_name: site\n", encoding="utf-8")
    service = BackupService(
        database_path=database.path,
        sources=[BackupSource("profiles", profiles)],
    )
    archive_path = service.create(tmp_path / "backup.zip")
    database.dispose()
    with zipfile.ZipFile(archive_path) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries["data/profiles/site.yaml"] = b"profile_name: tampered\n"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)

    with pytest.raises(ValueError, match="integrity verification"):
        service.inspect(archive_path)


def test_audit_package_detects_modified_entry(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    for name, value in (("manifest.json", "{}"), ("checks.snapshot.yaml", "checks: []"), ("profile.snapshot.yaml", "profile_name: site")):
        (run / name).write_text(value, encoding="utf-8")
    service = AuditPackageService()
    package = service.export(run_id="run-1", run_directory=run, destination=tmp_path / "run.zip")
    assert service.verify(package).valid
    with zipfile.ZipFile(package) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries["audit/manifest.json"] = b"tampered"
    with zipfile.ZipFile(package, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    verification = service.verify(package)
    assert not verification.valid
    assert verification.status == "MODIFIED"
