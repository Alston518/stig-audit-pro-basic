from uuid import uuid4

from sqlalchemy import text

from stig_audit_pro.core.models import AuditRun
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.infrastructure.persistence import (
    CURRENT_SCHEMA_VERSION,
    AuditRunRepository,
    Database,
)
from stig_audit_pro.infrastructure.persistence.migrations import get_schema_version


def test_temporary_sqlite_schema_foreign_keys_and_history_crud(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    try:
        repository = AuditRunRepository(database)
        run = AuditRun(run_id=str(uuid4()), device_count=1)
        repository.create_run(run)
        device = repository.add_device(run.run_id, target_ip="192.0.2.10")
        result = CheckResult(
            run_id=run.run_id,
            ip="192.0.2.10",
            hostname="SW01",
            vuln_id="V-1",
            rule_id="SV-1",
            stig_id="TEST-1",
            check_id="check-1",
            check_type="command_contains",
            stig_family="IOSXE_L2",
            title="Test",
            severity="cat2",
            status="Open",
            commands_used=["show running-config"],
        )
        stored_result = repository.add_check_result(device.id, result)
        artifact = repository.add_evidence_artifact(
            device.id,
            command="show running-config",
            relative_path=f"{run.run_id}/devices/192.0.2.10/evidence/show.txt",
            sha256="a" * 64,
            byte_length=4,
        )
        repository.link_result_evidence(stored_result.id, [artifact.id])
        repository.update_device(device.id, status="COMPLETE")
        repository.refresh_run_counts(run.run_id)

        assert database.foreign_keys_enabled()
        assert get_schema_version(database.engine) == CURRENT_SCHEMA_VERSION
        loaded = repository.get_run(run.run_id)
        assert loaded is not None
        assert loaded.devices[0].check_results[0].title == "Test"
        assert loaded.devices[0].check_results[0].evidence_links[0].evidence_artifact_id == artifact.id
        assert repository.result_counts(run.run_id) == {"Open": 1}
        assert repository.list_runs()[0].success_count == 1

        assert repository.delete_run(run.run_id)
        assert repository.get_run(run.run_id) is None
        with database.engine.connect() as connection:
            assert connection.scalar(text("select count(*) from evidence_artifact")) == 0
    finally:
        database.dispose()


def test_database_path_is_injected_and_never_uses_user_database(tmp_path):
    selected = tmp_path / "isolated.sqlite3"
    database = Database(selected)
    try:
        assert database.path == selected.resolve()
    finally:
        database.dispose()


def test_audit_history_supports_database_paging_and_search(tmp_path):
    database = Database(tmp_path / "history-search.sqlite3")
    try:
        repository = AuditRunRepository(database)
        for description in ("Quarterly access audit", "Core validation", "Branch review"):
            repository.create_run(
                AuditRun(run_id=str(uuid4()), description=description)
            )

        assert repository.count_runs() == 3
        first_page = repository.list_runs(limit=2, offset=0)
        second_page = repository.list_runs(limit=2, offset=2)
        assert len(first_page) == 2
        assert len(second_page) == 1
        assert not ({item.id for item in first_page} & {item.id for item in second_page})
        assert repository.count_runs(search="quarterly") == 1
        assert repository.list_runs(search="ACCESS")[0].description == "Quarterly access audit"
    finally:
        database.dispose()
