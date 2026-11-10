from __future__ import annotations

from stig_audit_pro.infrastructure.persistence import ActivityLogRepository, Database


def test_activity_log_hash_chain_detects_tampering(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    try:
        log = ActivityLogRepository(database)
        first = log.record("AUDIT_STARTED", "audit_run", "run-1", details={"targets": 1})
        second = log.record("MANUAL_REVIEW_RECORDED", "check_result", "run-1:device:V-1", details={"status": "Open"})

        valid, error = log.verify_chain()
        assert valid is True
        assert error is None
        assert second.previous_hash == first.event_hash

        with database.engine.begin() as connection:
            connection.exec_driver_sql("UPDATE activity_log SET details = '{\"status\":\"NotAFinding\"}' WHERE id = 2")

        valid, error = log.verify_chain()
        assert valid is False
        assert "hash mismatch" in (error or "")
    finally:
        database.dispose()
