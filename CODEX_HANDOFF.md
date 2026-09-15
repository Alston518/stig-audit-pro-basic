# STIG Audit Pro v0.2.0 — Developer Handoff

## Current state

The repository is an incremental evolution of the original CustomTkinter
application, not a rewrite. It remains a read-only Cisco IOS-XE auditing tool.
The product version is `0.2.0`.

Implemented in v0.2:

- Application services for audits, concurrent orchestration, persisted runs,
  reports, and STIG lifecycle operations.
- Exact-match `CommandPolicy`; unsafe/unknown YAML commands fail before SSH.
- SQLite audit history and versioned STIG library using SQLAlchemy 2.x.
- Per-run evidence storage, immutable-style manifests, SHA-256 verification,
  evidence/result links, and offline evidence import.
- Bounded multi-device Netmiko scanning (one connection per worker), progress
  events, failure isolation, and cancellation.
- STIG import coexistence, normalized release diffs, YAML impact analysis,
  coverage metrics, review-state persistence, and manual starter generation.
- CKLB, JSON, and Excel reporting while preserving TXT, CSV, and CKL paths.
- Evidence, History, Results, STIG Library, Profiles, Checks, Reports, and
  Audit Run GUI workflows.

Enterprise-readiness refinement implemented on 2026-09-10:

- First-run welcome, guided assessment wizard, structured blocking/warning
  preflight, plain-language error guidance, and improved finding explanations.
- Failed-device retry as a separate linked run, bounded History/Results views,
  validated CSV import preview, and user-friendly STIG impact language.
- Check fixture runner and explicit `VERIFIED`, `REVIEW_REQUIRED`, `UNTESTED`,
  `MANUAL`, `MISSING`, and `RETIRED` automation confidence classifications.
- Schema v3 persistence: the v2 activity trail remains, and historical results
  now retain their exact STIG title. On-disk databases are backed up before
  forward migration.
- Administration health view, sanitized support bundle, application-data
  backup, and integrity-verifiable portable audit-package export/import.
- Upgrade-safe application-data working copies for editable checks, profiles,
  groups, presets, and imported STIG content; bundled defaults never overwrite
  existing customer files.
- A numbered `Documents\STIG Audit Pro\Workspace` separates operator-selected
  inputs/outputs from protected application data. Administration provides
  one-click access to the workspace, checks, profiles, and all app data.
- Paramiko/Netmiko/SCP routine logs are suppressed below WARNING, and support
  bundles remove older third-party SSH diagnostic lines that could contain a
  device authentication banner.
- ZIP-slip/resource-limit import controls, CKL/CKLB/XML bounds, spreadsheet
  formula neutralization, expanded security tests, and a synthetic scale harness.

## Architecture and key modules

```text
gui -> application -> core -> infrastructure
                    \-> stig / reports
```

- `stig_audit_pro/application/`: audit/run/report/STIG services plus
  `PreflightService`, support bundle, backup, audit-package, and fixture services.
- `stig_audit_pro/core/command_policy.py`: authoritative approved command
  registry. Never bypass it for YAML or runtime execution.
- `stig_audit_pro/infrastructure/persistence/`: SQLite schema, migrations,
  and repositories.
- `stig_audit_pro/infrastructure/evidence/evidence_store.py`: atomic evidence
  files, manifests, verification, purge/delete helpers.
- `stig_audit_pro/stig/stig_repository.py` and `stig_diff.py`: release storage,
  comparison, YAML impact, and coverage.
- `stig_audit_pro/reports/`: JSON and Excel writers; `stig/cklb_writer.py`
  supports CKLB.

Full diagrams and the data model are in
[docs/architecture](docs/architecture/ARCHITECTURE.md).

## Runtime locations

The default SQLite database is resolved using `platformdirs` under the user
application-data directory (normally `%LOCALAPPDATA%\STIG Audit Pro` on
Windows), as are editable data and the evidence workspace:

```text
work/runs/<run_uuid>/manifest.json
work/runs/<run_uuid>/checks.snapshot.yaml
work/runs/<run_uuid>/profile.snapshot.yaml
work/runs/<run_uuid>/devices/<safe-device>/evidence/
data/checks/
data/profiles/
data/device_groups/
data/stigs/
scan_presets/
```

Operator-selected files default to:

```text
%USERPROFILE%\Documents\STIG Audit Pro\Workspace\
```

See [FILES_AND_FOLDERS.md](docs/operator/FILES_AND_FOLDERS.md) for the complete
numbered layout and the distinction between source, operator files, and
app-managed state.

For development, the database path is logged and described in
[DATABASE_GUIDE.md](docs/developers/DATABASE_GUIDE.md). Tests always use a
temporary SQLite database.

## Run and test

```powershell
cd "C:\Users\AWC\Documents\Stig_audit_pro"
python -m pip install -r requirements.txt
python app.py
python -m pytest
python scripts/generate_command_reference.py --check
python scripts/generate_stig_traceability.py --check
python scripts/validate_docs.py
```

Last verified on 2026-09-11: `190 passed`; generated command/traceability
documents and all 35 required documentation files validated; PyInstaller built
`dist/STIGAuditPro/STIGAuditPro.exe`; both source and packaged GUI processes
remained responsive during launch smoke tests; the migrated application
database reported schema version 3.

## Operator workflows

### Import and compare a STIG

Use **STIG Update Center → STIG Source → Import ZIP/XML**, then choose **Compare Previous** or
select two releases and choose **Compare Selected**. The library retains old
releases; an initial import is a baseline (`NO_PREVIOUS_RELEASE`), not a list
of artificial changes. The difference view shows field-level old/new check and
fix text and the associated YAML impact. Export JSON, CSV, or XLSX from that
view.

### YAML Impact

`AUTOMATION_REVIEW_REQUIRED` means DISA check procedure content changed and an
engineer must deliberately review the mapped YAML. `FIX_GUIDANCE_CHANGED` is
visible without implying remediation. `NEW_CHECK_REQUIRED` generates only a
manual-review starter; it never changes automation. `RETIRE_CHECK_REVIEW`
does not delete historical mappings.

### Reports

Use **Reports** for TXT/CSV and JSON/XLSX. CKL remains available through the
checklist workflow. Use `CKLBWriter`/`ReportService.write_cklb` to build or
export CKLB from internal `CheckResult` models.

### Evidence and history

Historical results can be opened without rescanning. The Evidence panel shows
raw command output, command, hash, and file location. **Verify Evidence**
reports `VALID`, `MISSING`, `MODIFIED`, or `UNREADABLE`. Hashes show integrity
after collection only; they do not authenticate the collector.

## Known limitations and next work

- Only IOS-XE L2/NDM is supported. No NX-OS.
- CKLB compatibility is exercised with representative Viewer 3-style fixtures;
  import/export deliberately remains independent from the check engine.
- Check/profile editing has typed common fields plus advanced YAML; broader
  form coverage can be added without changing the schema.
- No remediation, scheduling, credential vault, web service, PostgreSQL,
  cloud telemetry, or third-party integrations are implemented.
- Review-state marking is stored in the local mapping database; future GUI work
  can add a richer reviewer identity/audit trail without changing fingerprints.

Refinement limitations:

- Audit-package export, verification, and historical import are wired into
  History. Duplicate run UUIDs are deliberately refused.
- Backup and deliberately confirmed restore are wired into Administration.
  Restore validates content hashes and schema, creates a safety backup, rolls
  back partial publication, and closes the application after success.
- Standard fixture tooling and GUI execution exist. Bundled checks have not all
  been migrated into per-Vulnerability good/bad fixture directories, so the
  dashboard must not describe all mappings as `VERIFIED`.
- History uses SQLite-backed search and 100-row paging. Results uses a bounded
  filtered window rather than a fully virtualized SQLite query model.

## Non-negotiable safety rule

Never add a command by using a broad prefix allowlist or by trusting YAML. Add
the minimum fixed command to `CommandPolicy`, update its tests, regenerate the
command reference, and preserve the read-only boundary.
