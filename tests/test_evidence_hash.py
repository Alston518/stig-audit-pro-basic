import hashlib
from uuid import uuid4

from stig_audit_pro.core.evidence import EvidenceIntegrityStatus
from stig_audit_pro.infrastructure.evidence import EvidenceStore


def _finalized_store(tmp_path, output="exact UTF-8 café\n"):
    store = EvidenceStore(tmp_path / "runs")
    run_id = str(uuid4())
    store.create_run(run_id)
    store.prepare_device(run_id, "198.51.100.7")
    artifact = store.write_evidence(
        run_id, "198.51.100.7", "show running-config", output
    )
    store.finalize_run(run_id)
    return store, run_id, artifact, output


def test_sha256_is_over_exact_utf8_bytes_and_verifies(tmp_path):
    store, run_id, artifact, output = _finalized_store(tmp_path)
    assert artifact.sha256 == hashlib.sha256(output.encode("utf-8")).hexdigest()
    assert artifact.byte_length == len(output.encode("utf-8"))
    verification = store.verify_evidence(run_id)
    assert verification.aggregate == EvidenceIntegrityStatus.VALID
    assert verification.is_valid


def test_modified_and_missing_evidence_are_detected(tmp_path):
    store, run_id, artifact, _output = _finalized_store(tmp_path)
    path = store.root / artifact.relative_path
    path.write_text("tampered", encoding="utf-8")
    assert store.verify_evidence(run_id).aggregate == EvidenceIntegrityStatus.MODIFIED
    path.unlink()
    assert store.verify_evidence(run_id).aggregate == EvidenceIntegrityStatus.MISSING
