# Feature-Preservation Inventory

## Purpose

This inventory is the change-control baseline for STIG Audit Pro v0.2. It maps
customer-visible behavior to its implementation, durable data, and regression
coverage. Refinements must preserve these capabilities unless a release note
explicitly documents a compatible replacement.

Baseline recorded on 2026-09-11: clean `main`, 64 bundled checks, and 182 tests
passing before this refinement.

## Non-negotiable boundary

STIG Audit Pro is read-only toward network devices. The authoritative
`CommandPolicy` exact-match registry is used by external check validation,
preflight, command planning, and Netmiko runtime execution. The application
does not enter configuration mode, apply DISA fix text, write memory, copy a
configuration, reload, or erase a device. Credentials remain session-only.

| Capability | Current implementation | Durable customer data | Regression coverage |
|---|---|---|---|
| CustomTkinter desktop GUI and first-run workflow | `gui/main_window.py`, `overview_tab.py`, `audit_wizard.py` | UI preference file in application data | full import/startup smoke plus GUI service tests |
| Device targets, bulk selection, CSV preview, and groups | `gui/targets_tab.py`, `storage/device_groups.py` | device-group files under application data | `test_device_groups.py`, security import tests |
| Site Profiles and inheritance | `core/models.py`, `core/yaml_loader.py`, `gui/profiles_tab.py` | profile YAML and timestamped edit backups | YAML validation and check-engine tests |
| Scan presets without credentials | `storage/scan_presets.py`, Audit UI | scan preset files under application data | `test_scan_presets.py` |
| L2 and NDM YAML check libraries | `data/checks/iosxe_l2.yaml`, `iosxe_ndm.yaml` | local check YAML and timestamped edit backups | YAML, parser, engine, and interface-policy tests |
| Visual check editing and advanced YAML | `gui/checks_tab.py`, `gui/yaml_editor.py` | validated local check files; originals backed up before overwrite | YAML and command-policy tests |
| Sample, offline, and live SSH assessments | `application/audit_service.py`, `run_service.py` | first-class Audit Runs, results, snapshots, and evidence | audit service/run/orchestrator tests |
| Concurrent multi-device operation, cancellation, and retry | `application/scan_orchestrator.py`, Audit UI | retry is a distinct linked/described run; original failures remain | `test_scan_orchestrator.py`, service tests, benchmark harness |
| Strict read-only command safety | `core/command_policy.py`, `command_planner.py`, `infrastructure/ssh/netmiko_runner.py` | generated command reference | `test_command_policy.py`, YAML and security tests |
| SQLite audit history and forward migration | `infrastructure/persistence/` | `%LOCALAPPDATA%/STIG Audit Pro/data/stig-audit-pro.sqlite3` by default | database and migration tests |
| Immutable per-run evidence and SHA-256 verification | `infrastructure/evidence/evidence_store.py` | `work/runs/<uuid>/...` under application data | evidence store/hash/security tests |
| Finding-to-evidence traceability and manual decisions | `core/result_model.py`, `run_service.py`, Results/Evidence views | result/evidence link rows and immutable raw files | run, database, evidence, and report tests |
| Paged historical run browsing, deletion, and evidence-only purge | `gui/history_tab.py`, `run_service.py` | structured history remains until explicit deletion | database/evidence/run tests |
| Portable historical audit export/import | `application/audit_package_service.py`, History view | verified archive and imported run classified as historical | enterprise/run-service/security tests |
| Versioned STIG ZIP/XML import | `stig/xccdf_importer.py`, `stig_repository.py`, STIG Update Center | coexisting benchmark/rule releases and source hashes | importer/repository/security tests |
| Normalized STIG release difference and YAML impact | `stig/stig_diff.py`, `application/stig_lifecycle_service.py` | benchmark/rule fingerprints and review state | synthetic diff and YAML-impact tests |
| Starter manual checks and deliberate automation review | `stig/check_generator.py`, STIG Update Center | generated release-specific YAML; no automated check is silently rewritten | generator/diff/repository tests |
| Automation confidence and fixture execution | `core/automation_confidence.py`, `application/check_fixture_service.py` | fixture files and review fingerprints | automation-confidence tests |
| TXT and CSV reports | `reports/audit_report.py` | operator-selected report files | `test_audit_report.py` |
| Stable JSON and professional XLSX reports | `reports/json_writer.py`, `excel_writer.py` | operator-selected report files | JSON/Excel/security tests |
| CKL and Viewer 3-style CKLB workflows | `stig/ckl_writer.py`, `cklb_writer.py` | operator-selected checklist files | CKL and representative CKLB tests |
| Offline licensing and free/paid enforcement | `licensing/`, License UI | signed license file and public verification keys; never a private signing key | licensing and license-admin tests |
| Support bundle, health checks, backup, and activity trail | `application/support_bundle_service.py`, `backup_service.py`, Administration view | sanitized bundle/backups and schema-v2+ activity rows | enterprise and security tests |
| PyInstaller Windows packaging | `stig-audit-pro.spec`, `scripts/package_smoke_test.py` | installed application data remains outside the executable | packaging input validation/smoke process |

## Data-protection invariants

- Existing profiles and checks are validated before save and backed up before
  overwrite.
- Imported STIG releases are additive; a newer release never overwrites an old
  release or reinterprets a completed Audit Run.
- Every Audit Run receives a UUID and its own evidence directory. A later run
  against the same IP cannot replace earlier evidence.
- Profile and check snapshots plus SHA-256 fingerprints preserve the exact
  evaluation context.
- Presets, manifests, database rows, logs, support bundles, activity records,
  and portable packages exclude passwords and enable secrets.
- Database upgrades create a timestamped safety copy before forward migration.
- Destructive GUI actions require explicit confirmation and use exact run,
  profile, group, or release identifiers.

## Advanced access remains available

The guided Audit and STIG Update Center workflows are the primary operator
paths. Advanced YAML editing, technical exception details, fingerprints,
database diagnostics, raw evidence, check IDs, and schema metadata remain
available to administrators and engineers without appearing as prerequisites
for a normal assessment.
