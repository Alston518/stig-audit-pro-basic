# Data Model

SQLite stores structured history; raw evidence and immutable context snapshots live in the per-run filesystem tree. Credentials are deliberately absent from both.

## Audit records

- `audit_run`: UUID, UTC timestamps, lifecycle state, application version, collection mode, selected STIG/profile/check fingerprints, benchmark identity, description/preset, and device outcome counts.
- `run_device`: target and discovered facts plus the per-device lifecycle and error.
- `check_result`: normalized finding, traceability metadata, commands, inputs, failed objects, warnings, reason, and UTC evaluation time.
- `evidence_artifact`: command, relative path, exact-byte SHA-256, UTC collection time, and byte length.
- `result_evidence`: many-to-many links from findings to artifacts. Raw output is not copied into every finding.
- `activity_log`: timestamped, secret-free records of important local actions such as audit lifecycle, evidence purge, check edits, backups, and package exports.

## STIG records

- `stig_benchmark`: one immutable imported release and its source/fingerprint metadata.
- `stig_rule`: normalized rule fields, individual field hashes, and overall rule fingerprint.
- `check_mapping`: the local YAML mapping and its explicit review state for a particular rule fingerprint.
- stored release differences retain field changes and YAML impact without changing check automation.

## Keys and indexes

Foreign keys cascade run/device/result metadata appropriately and are enabled for every SQLite connection. Indexed access paths include run devices by run, results by device/status and Vuln ID, rules by Vuln/Rule ID, and benchmarks by family/benchmark ID.

## Filesystem companion

```text
runs/<run UUID>/
  manifest.json
  checks.snapshot.yaml
  profile.snapshot.yaml
  devices/<stable safe name>/
    device.json
    results.json
    evidence/<safe command name>.txt
```

The snapshot hashes in `audit_run` tie a historical evaluation to the exact profile and check pack used. A later STIG import never reinterprets an older run.

See [data_model.puml](diagrams/data_model.puml).
