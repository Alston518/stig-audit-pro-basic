from pathlib import Path

from stig_audit_pro.infrastructure.persistence import Database
from stig_audit_pro.stig.stig_repository import StigRepository


FIXTURES = Path(__file__).parent / "fixtures"


def test_multiple_releases_coexist_and_new_import_compares_previous(tmp_path):
    database = Database(tmp_path / "history.sqlite3")
    try:
        repository = StigRepository(database)
        repository.diff_root = tmp_path / "diffs"
        first = repository.import_source(
            FIXTURES / "stig_release_1.xml",
            "IOSXE_L2",
            checks_dir=FIXTURES / "stig_diff_checks.yaml",
        )
        second = repository.import_source(
            FIXTURES / "stig_release_2.xml",
            "IOSXE_L2",
            checks_dir=FIXTURES / "stig_diff_checks.yaml",
        )

        assert first.baseline
        assert second.previous is not None
        assert second.previous.database_id == first.benchmark.database_id
        assert second.diff.summary["changed"] == 4
        releases = repository.list_releases(
            family="IOSXE_L2", benchmark_id="Synthetic_IOSXE_L2_STIG"
        )
        assert len(releases) == 2
        assert {item.release for item in releases} == {"1", "2"}
        assert len(list((tmp_path / "diffs").glob("*.json"))) == 2
    finally:
        database.dispose()


def test_coverage_separates_mapped_from_reviewed_current(tmp_path):
    database = Database(tmp_path / "history.sqlite3")
    try:
        repository = StigRepository(database)
        repository.diff_root = tmp_path / "diffs"
        imported = repository.import_source(
            FIXTURES / "stig_release_2.xml",
            "IOSXE_L2",
            checks_dir=FIXTURES / "stig_diff_checks.yaml",
        )
        coverage = repository.coverage(
            imported.benchmark.database_id,
            checks_dir=FIXTURES / "stig_diff_checks.yaml",
        )
        assert coverage.total_rules == 6
        assert coverage.automated == 4
        assert coverage.manual_review == 1
        assert coverage.missing_check == 1
        assert coverage.automation_mapping_percent > 0
        assert coverage.current_reviewed_automation_percent == 0
    finally:
        database.dispose()


def test_marked_mapping_counts_as_current_reviewed_automation(tmp_path):
    database = Database(tmp_path / "history.sqlite3")
    try:
        repository = StigRepository(database)
        imported = repository.import_source(
            FIXTURES / "stig_release_2.xml",
            "IOSXE_L2",
            checks_dir=FIXTURES / "stig_diff_checks.yaml",
        )
        benchmark_id = imported.benchmark.database_id
        assert benchmark_id is not None
        repository.sync_check_mappings(
            benchmark_id, checks_dir=FIXTURES / "stig_diff_checks.yaml"
        )
        rule = imported.benchmark.rule_by_vuln("V-100")
        assert rule is not None and rule.database_id is not None
        mappings = repository.persistence.list_mappings(
            stig_rule_id=rule.database_id
        )
        assert len(mappings) == 1
        repository.mark_automation_reviewed(
            mappings[0].id,
            stig_fingerprint=rule.rule_fingerprint,
            reviewed_release=imported.benchmark.release_label,
        )
        coverage = repository.coverage(
            benchmark_id, checks_dir=FIXTURES / "stig_diff_checks.yaml"
        )
        assert coverage.current_reviewed_automation_percent > 0
    finally:
        database.dispose()
