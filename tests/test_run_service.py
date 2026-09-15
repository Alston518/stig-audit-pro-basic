from datetime import datetime, timezone

import pytest

from stig_audit_pro.application.audit_package_service import AuditPackageService
from stig_audit_pro.application.run_service import OfflineEvidenceDevice, RunService
from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.infrastructure.evidence import EvidenceStore
from stig_audit_pro.infrastructure.persistence import AuditRunRepository, Database


def test_offline_import_creates_reproducible_run_and_history(tmp_path):
    database = Database(tmp_path / "history.sqlite3")
    repository = AuditRunRepository(database)
    store = EvidenceStore(tmp_path / "runs", repository)
    service = RunService(database, repository=repository, evidence_store=store)
    profile = SiteProfile(profile_name="offline-test")
    check = CheckDefinition(
        vuln_id="V-1",
        rule_id="SV-1",
        stig_id="TEST-1",
        title="Hostname is present",
        stig_family="IOSXE_L2",
        severity="cat2",
        check_type="command_contains",
        commands=["show running-config"],
        conditions={"contains": "hostname SW01"},
    )
    collected_at = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
    imported = OfflineEvidenceDevice(
        target_ip="192.0.2.20",
        hostname="SW01",
        source="authorized collector bundle 42",
        collected_at=collected_at,
        outputs={"show running-config": "hostname SW01\n"},
    )
    try:
        context, result = service.import_offline(
            devices=[imported],
            checks=[check],
            profile_provider=lambda _target: profile,
            profile_snapshot=profile,
            stig_families=["IOSXE_L2"],
            concurrency=1,
        )
        assert result.results[0].status == "NotAFinding"
        assert result.results[0].run_id == context.run_id
        assert len(result.results[0].evidence_artifact_ids) == 1
        run = repository.get_run(context.run_id)
        assert run is not None
        assert run.collection_mode == "OFFLINE_IMPORTED"
        assert run.status == "COMPLETE"
        artifact = repository.list_evidence_artifacts(context.run_id)[0]
        assert artifact.collected_at.replace(tzinfo=timezone.utc) == collected_at
        assert service.evidence_store.load_manifest(context.run_id)["collection_mode"] == "OFFLINE_IMPORTED"
        historical = service.load_results(context.run_id)
        assert historical[0].evidence_artifact_ids == result.results[0].evidence_artifact_ids
        assert service.list_history()[0].pass_count == 1
    finally:
        database.dispose()


def test_portable_audit_package_import_rebuilds_history_and_traceability(tmp_path):
    source_database = Database(tmp_path / "source.sqlite3")
    source_repository = AuditRunRepository(source_database)
    source_store = EvidenceStore(tmp_path / "source-runs", source_repository)
    source_service = RunService(
        source_database,
        repository=source_repository,
        evidence_store=source_store,
    )
    profile = SiteProfile(profile_name="portable-site")
    check = CheckDefinition(
        vuln_id="V-PORTABLE",
        rule_id="SV-PORTABLE",
        stig_id="CISC-PORTABLE",
        title="Portable audit titles remain exact",
        stig_family="IOSXE_L2",
        severity="cat2",
        check_type="command_contains",
        commands=["show running-config"],
        conditions={"contains": "hostname SW01"},
    )
    imported_evidence = OfflineEvidenceDevice(
        target_ip="192.0.2.25",
        hostname="SW01",
        source="approved offline collector",
        collected_at=datetime(2026, 2, 3, 4, 5, tzinfo=timezone.utc),
        outputs={"show running-config": "hostname SW01\n"},
    )
    context, _result = source_service.import_offline(
        devices=[imported_evidence],
        checks=[check],
        profile_provider=lambda _target: profile,
        profile_snapshot=profile,
        stig_families=["IOSXE_L2"],
        concurrency=1,
    )
    package = AuditPackageService().export(
        run_id=context.run_id,
        run_directory=source_store.run_path(context.run_id),
        destination=tmp_path / "portable-audit.zip",
        include_evidence=True,
    )

    destination_database = Database(tmp_path / "destination.sqlite3")
    destination_repository = AuditRunRepository(destination_database)
    destination_store = EvidenceStore(
        tmp_path / "destination-runs", destination_repository
    )
    destination_service = RunService(
        destination_database,
        repository=destination_repository,
        evidence_store=destination_store,
    )
    try:
        imported_run_id = destination_service.import_audit_package(package)
        assert imported_run_id == context.run_id
        historical_run = destination_repository.get_run(imported_run_id)
        assert historical_run is not None
        assert historical_run.collection_mode == "IMPORTED_HISTORICAL_AUDIT"
        historical_result = destination_service.load_results(imported_run_id)[0]
        assert historical_result.title == "Portable audit titles remain exact"
        assert historical_result.status == "NotAFinding"
        assert len(historical_result.evidence_artifact_ids) == 1
        assert destination_service.verify_evidence(imported_run_id).is_valid
        assert "hostname SW01" in destination_service.read_evidence(
            destination_service.evidence_for_result(historical_result)[0].relative_path
        )
        with pytest.raises(ValueError, match="already present"):
            destination_service.import_audit_package(package)
    finally:
        source_database.dispose()
        destination_database.dispose()
