# STIG Audit Basic Security and Audit Integrity Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Basic STIG audit workflow fail closed on incomplete evidence while preserving auditable automated decisions and laying out the remaining persistence, host-key, package, and usability work.

**Architecture:** Add an explicit internal decision state to the check engine, map unsafe or incomplete evidence to `Error`/`Not_Reviewed`, and persist the original automated decision separately from a later reviewer decision. Extend the existing SQLite schema with forward-only migrations. Follow with encrypted evidence wiring, host-key trust enforcement, append-only event chaining, and signed package verification as separate tested increments.

**Tech Stack:** Python 3.12, Pydantic, SQLAlchemy/SQLite, pytest, Paramiko/Netmiko, existing AES-GCM vault.

**Spec:** `C:\Users\AWC\.codex\attachments\143aeec1-15a3-48c7-9d8e-732136bab720\Pasted text.txt`

## Global Constraints

- Missing, invalid, truncated, or unsupported evidence must never produce an automated PASS.
- Manual review must remain `Not_Reviewed` until a reviewer records a decision and justification.
- Original automated decisions must remain available after manual review.
- Unknown or changed SSH host keys must block collection.
- No private signing key or shared credential may be embedded in the application.
- Security claims must be limited to behavior covered by tests and documentation.

## Review Focus

- Empty command output for an absence-based rule must become evidence error.
- A manual-review rule must not become `Open` merely because it is not automated.
- A reviewer override must not erase the automated result or its evidence references.
- A parser warning or unsupported check must remain visible and non-passing.
- Existing valid compliant fixtures must retain their expected PASS behavior.

---

### Task 1: Explicit decision states and fail-closed evaluation

**Files:**
- Modify: `stig_audit_pro/core/check_engine.py`
- Modify: `stig_audit_pro/core/result_model.py`
- Test: `tests/test_check_engine_integrity.py`

**Interfaces:**
- Produce `DecisionState` values `PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL_REVIEW`, `EVIDENCE_ERROR`, and `UNSUPPORTED`.
- `EvaluationOutcome` carries `decision_state`.
- `CheckResult` carries `decision_state` and `automated_status` while keeping the existing report `status` field.

- [ ] Write tests for missing/empty/invalid evidence, manual review, unsupported checks, and valid compliant evidence.
- [ ] Run the focused tests and verify the new cases fail before implementation.
- [ ] Implement explicit state mapping and conservative evidence validation.
- [ ] Run focused and existing check-engine tests.
- [ ] Commit the tested change.

### Task 2: Preserve automated decisions through reviewer overrides

**Files:**
- Modify: `stig_audit_pro/infrastructure/persistence/db_models.py`
- Modify: `stig_audit_pro/infrastructure/persistence/migrations.py`
- Modify: `stig_audit_pro/infrastructure/persistence/repositories.py`
- Modify: `stig_audit_pro/application/run_service.py`
- Test: `tests/test_run_service.py`, `tests/test_database.py`

**Interfaces:**
- Add nullable automated decision/status fields and reviewer justification/timestamp fields.
- `save_manual_decision` writes reviewer fields and leaves automated fields unchanged.

- [ ] Add migration and repository tests.
- [ ] Implement migration and persistence changes.
- [ ] Verify old databases migrate and new databases persist both states.
- [ ] Commit the tested change.

### Task 3: Encrypt evidence-store payloads in the existing vault

**Files:**
- Modify: `stig_audit_pro/infrastructure/evidence/evidence_store.py`
- Modify: `stig_audit_pro/application/run_service.py`
- Modify: `stig_audit_pro/basic_app.py`
- Test: `tests/test_evidence_store.py`, `tests/test_basic_output_reliability.py`

- [ ] Add tests proving raw evidence is ciphertext on disk and readable only with the unlocked vault.
- [ ] Add vault-backed atomic read/write and plaintext hash verification.
- [ ] Wire Basic scans to a persistent RunService using the unlocked vault.
- [ ] Verify interrupted writes and legacy migration behavior.
- [ ] Commit the tested change.

### Task 4: Strict SSH host-key trust and enrollment service

**Files:**
- Create: `stig_audit_pro/infrastructure/ssh/host_keys.py`
- Modify: `stig_audit_pro/core/ssh_runner.py`
- Modify: `stig_audit_pro/infrastructure/ssh/netmiko_runner.py`
- Test: `tests/test_ssh_host_keys.py`, existing SSH tests

- [ ] Test unknown, matching, changed, and revoked host keys.
- [ ] Implement a protected trust store and explicit operator enrollment API.
- [ ] Configure Netmiko/Paramiko to fail closed with the trust store.
- [ ] Add operator-facing enrollment guidance and audit events.
- [ ] Commit the tested change.

### Task 5: Hash-chained activity events and tamper-evident packages

**Files:**
- Modify: `stig_audit_pro/infrastructure/persistence/db_models.py`
- Modify: `stig_audit_pro/infrastructure/persistence/migrations.py`
- Modify: `stig_audit_pro/infrastructure/persistence/repositories.py`
- Modify: `stig_audit_pro/application/audit_package_service.py`
- Create: `stig_audit_pro/application/package_signing.py`
- Test: `tests/test_activity_log_chain.py`, `tests/test_audit_package_service.py`

- [ ] Add canonical event hashing and chain verification.
- [ ] Add canonical package manifests and unsigned/signed/invalid verification states.
- [ ] Use only operator-provisioned signing keys.
- [ ] Commit the tested change.

### Task 6: History GUI, recovery, retention, and documentation

**Files:**
- Modify: `stig_audit_pro/basic_app.py`
- Modify: `docs/07_Basic_Encryption_SSH_and_Licensing.md`
- Modify: `docs/08_Report_Output_Troubleshooting.md`
- Create: `docs/SECURITY_AND_AUDIT_INTEGRITY.md`
- Test: GUI smoke and service integration tests

- [ ] Add history/filter/detail/re-export views backed by durable runs.
- [ ] Add retention, deletion, recovery, and privileged-admin limitations.
- [ ] Run full test suite and packaged smoke tests.
- [ ] Commit and publish the completed tested stages.

## Gaps after the first deliverable

The first implementation pass intentionally does not claim completion of encrypted RunService evidence, strict SSH enrollment UI, digital signatures, or history GUI until their tests and migrations are complete. Those remain explicit follow-on tasks above.
