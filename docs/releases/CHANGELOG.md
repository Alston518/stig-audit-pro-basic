# Changelog

## 0.2.0 — 2026-09-04

### Enterprise-readiness refinement — 2026-09-10

#### Historical fidelity and upgrade safety — 2026-09-11

- Added a numbered operator workspace under `Documents\STIG Audit Pro` with
  predictable folders for STIG packages, blank CKLs, device/offline imports,
  completed CKLs, reports, audit packages, backups, support bundles, and STIG
  comparison exports.
- Added one-click Administration actions for the operator workspace, editable
  checks, Site Profiles, and all protected application data; relevant import
  and export dialogs now begin in their matching workspace folder.
- Added clearly labeled **New Profile** and **Delete Profile** actions directly
  to the primary Profiles screen instead of hiding creation in the legacy
  combined setup view.
- Added schema version 3 so historical results retain the exact STIG title
  shown during the original assessment; existing databases receive a safety
  backup and an additive migration.
- Added verified, atomic portable audit-package import with SQLite history
  reconstruction, evidence-link remapping, duplicate protection, and explicit
  **Imported historical audit** classification.
- Moved runtime-editable checks, profiles, groups, presets, and STIG working
  files to an upgrade-safe application-data working copy. Bundled defaults are
  added only when missing and never overwrite customer changes.
- Added the feature-preservation inventory and regression tests for historical
  package round trips, migration fidelity, and application-data bootstrap.
- Added SQLite-backed Audit History search and 100-row paging so large history
  collections are not materialized into Tk widgets at once.
- Added confirmed in-place restore with archive hash and SQLite validation,
  automatic safety backup, exact-destination publication, and rollback on
  partial failure.
- Suppressed third-party SSH INFO logging and sanitize historical Paramiko,
  Netmiko, and SCP diagnostic lines from support bundles so device banners and
  session detail remain outside normal application logs.

- Added a first-run welcome page, guided Devices → STIG → Site Profile → Readiness workflow, and a structured preflight service that blocks invalid audits before SSH.
- Added plain-language finding explanations, DISA guidance actions, CAT/status search filters, bounded large-result/history views, CSV import preview, and linked failed-device retry runs.
- Added an Administration health page, sanitized support bundles, local data backup, activity logging, and portable integrity-verifiable audit-package export.
- Added explicit automation confidence states and a standardized per-check fixture runner surfaced from the Check editor. Existing check automation is never marked reviewed automatically.
- Added schema version 2 with an activity log and automatic pre-migration database safety copy.
- Hardened ZIP/XML/CKL/CKLB imports against traversal, malformed content, and resource limits; neutralized formula-like CSV/XLSX values.
- Added deterministic “why it matters” language to STIG release differences and clearer automation-impact terminology.
- Added a synthetic scale benchmark and expanded security, readiness, migration, support-bundle, backup, audit-package, and confidence tests.

### Architecture and safety

- Introduced application-service, core/domain, and infrastructure boundaries while preserving the CustomTkinter desktop and existing parsers/check engine.
- Replaced broad command-prefix approval with one exact-match, fail-closed `CommandPolicy` used by YAML validation, planning, runtime SSH, tests, and generated documentation.
- Modernized externally editable models to Pydantic 2 validators and strict `extra="forbid"` schemas; versioned bundled check libraries.
- Kept network behavior strictly read-only. No configuration, save, reload, or remediation path was added.

### Audit runs and evidence

- Added UUID-based audit/run-device models and complete lifecycle states.
- Added an embedded SQLAlchemy 2.0 SQLite history database with foreign keys, indexed tables, repositories, and schema versioning.
- Added per-run atomic evidence storage, exact UTF-8 SHA-256 metadata, immutable context snapshots, manifests, integrity verification, and explicit raw-evidence purge.
- Added offline evidence import labeling and session-only credential handling.

### Scanning and operator experience

- Added bounded concurrent multi-device scanning (default five, configurable one–twenty), isolated connections/failures, cancellation, status events, and main-thread GUI consumption.
- Added reusable credential-free scan presets, typed profile editing, simple check-string editing, and retained advanced YAML editing.
- Added per-device audit progress, finding-to-evidence traceability, Evidence and History views, historical report generation, and run-to-run comparison/export.

### STIG lifecycle

- Added versioned coexistence of imported STIG releases with normalized field/rule fingerprints.
- Added stable-identifier release comparison with added/removed/changed/unchanged and field-level changes, including ambiguity handling.
- Added YAML impact recommendations, automation review fingerprints/state, coverage metrics, missing manual starter generation, side-by-side check/fix details, and JSON/CSV/XLSX difference exports.

### Reports

- Preserved TXT, CSV, and CKL behavior.
- Added schema-versioned JSON, professional multi-sheet XLSX, and native STIG Viewer 3-style CKLB import/population/export.
- Centralized report generation behind `ReportService` and evidence references rather than embedding raw configurations by default.

### Engineering

- Added critical unit/fixture coverage for command safety, persistence, evidence, concurrency, STIG differences/impact/repository, run comparison, JSON/XLSX, and CKLB.
- Added generated command and STIG traceability documents, structured documentation, PlantUML sources, and GitHub Actions validation.
- Updated dependency ranges and PyInstaller inputs for the v0.2 modules and resources.

## 0.1.0

Initial development release with CustomTkinter workflows, targets/groups, inherited site profiles, YAML-driven L2/NDM checks, sample and Netmiko scans, licensing, STIG ZIP/XML metadata import, and TXT/CSV reporting.
