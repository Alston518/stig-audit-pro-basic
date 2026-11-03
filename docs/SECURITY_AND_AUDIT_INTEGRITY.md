# Security and audit integrity

This document describes the security behavior currently implemented in the Basic application branch.

## Evaluation states

The check engine keeps an internal decision state separate from the CKL/report status:

- `PASS` and `FAIL` are automated decisions based on validated evidence.
- `NOT_APPLICABLE` is used when a declared scope has no matching objects and requires reviewer attention.
- `MANUAL_REVIEW` produces `Not_Reviewed` until an operator records a decision.
- `EVIDENCE_ERROR` produces `Error` for missing, empty, or Cisco-invalid command output.
- `UNSUPPORTED` produces `Skipped` and remains visible for follow-up.

An empty or invalid command response cannot become a passing check. Existing report status mappings are retained for compatibility, but unsafe mappings cannot override the fail-closed `Error` result.

## Reviewer decisions

When a reviewer changes a result, the database retains the original automated status, decision state, finding details, comments, and evaluation reason. The reviewer status, justification, and UTC review time are stored separately. The activity log records the review action without storing credentials.

## Evidence encryption

`EvidenceStore` accepts the unlocked `AtRestVault`. New command evidence is written as authenticated AES-GCM ciphertext. The SHA-256 value stored in the manifest is calculated over the original plaintext, and verification decrypts the file before checking that hash. Reading encrypted evidence without the unlocked vault fails closed. Basic report files continue to use the existing `.sapenc` format.

The current Basic GUI report flow still writes its protected report artifacts directly. Wiring every GUI scan into the persistent RunService/evidence history is a follow-on task and must be completed before claiming that the full GUI workflow has durable encrypted evidence history.

## SSH host keys

Live SSH verifies host keys by default. Paramiko rejects unknown or changed keys before authentication. On first connection, Basic discovers the public key without authenticating and shows its SHA256 fingerprint. Select **Trust and Save** to accept the key on first use. Compare the fingerprint with an independent trusted source when your policy requires identity verification. Basic records first-use acceptance and the Windows operator identity, saves the key in its local OpenSSH trust store, and retries the audit with verification enabled. Cancel skips that device.

Use **Audit Setup → Manage SSH host keys** to review fingerprints or remove a host's stored keys. Removal requires confirmation and is recorded alongside enrollment history. A changed key blocks the audit. If an approved rotation is confirmed independently, remove the old entry and run the audit again to verify and enroll the replacement.

## Activity log chain

Activity records include a previous hash and an event hash calculated from the UTC timestamp, action, object, sanitized details, and local username. `ActivityLogRepository.verify_chain()` detects changed records or broken ordering.

This is tamper evidence for the local application database. A user with administrator access to the host can still delete or replace the database, its backups, or the application. Independent export or central collection is required for a stronger administrative boundary.

## Remaining security work

The next tested increments are:

1. Wire the Basic GUI scan path to `RunService` using the unlocked vault and add history/detail/re-export views.
2. Add canonical package signatures with an operator-provisioned signing key or certificate; never embed a private key.
3. Add retention, recovery, and encrypted-database migration procedures.

The project does not claim these follow-on capabilities until their tests and documentation are present.
