# Batch Protected Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add lazy multi-report import, IP/type report selection, and explicit one/some/all readable export to the Basic Results tab.

**Architecture:** A focused report-workspace module owns protected-file metadata, grouping, deduplication, and sequential batch export. `BasicApp` owns only widgets, dialogs, preview selection, and operator messaging. Imported paths remain encrypted; preview and export call the existing authenticated artifact store only when needed.

**Tech Stack:** Python 3.12, CustomTkinter/Tkinter, pathlib, dataclasses, pytest, existing `ProtectedArtifactStore`.

**Spec:** `docs/superpowers/specs/2026-11-03-batch-protected-reports-design.md`

## Global Constraints

- Do not alter the `.sapenc` format or vault behavior.
- Do not overwrite existing readable files.
- Do not retain all imported plaintext in memory.
- Preserve the existing single-report workflow and Protected Output default folder.
- Do not modify or package the user's uncommitted profile deletion or backup.
- Publish every new Windows package and ZIP directly under `C:\Users\AWC\Desktop\Current_Working_STIG_TOOL` using a dated package directory.

## Review Focus

- Duplicate paths: exact duplicates appear once and do not create duplicate dropdown entries.
- Same IP/type from different runs: both remain selectable with distinct labels.
- Corrupt encrypted file: preview/export failure is isolated from other imported reports.
- Existing destination: batch export records the conflict and never overwrites it.
- Large batch: export reads and writes one report at a time rather than accumulating plaintext.

---

### Task 1: Protected report workspace model

**Files:**
- Create: `stig_audit_pro/gui/protected_reports.py`
- Create: `tests/test_protected_report_workspace.py`

**Interfaces:**
- Produces: `ProtectedReportRef`, `ImportBatch`, and `ProtectedReportWorkspace` with `add()`, `clear()`, `devices()`, `type_options()`, `resolve()`, and `reports()`.
- Consumes: App-generated report filenames and the supported report suffix contract.

- [x] **Step 1: Write failing tests** for IPv4 grouping, TXT/CKL type options, duplicate paths, legacy filename fallback, and duplicate same-IP/type labels.
- [x] **Step 2: Run** `py -3.12 -m pytest tests/test_protected_report_workspace.py -q` and verify failure because the module does not exist.
- [x] **Step 3: Implement** immutable report metadata and a path-only workspace; no artifact reads occur in `add()`.
- [x] **Step 4: Run the focused tests** and verify they pass.
- [x] **Step 5: Commit** the model and tests.

### Task 2: Sequential batch export

**Files:**
- Modify: `stig_audit_pro/gui/protected_reports.py`
- Modify: `tests/test_protected_report_workspace.py`

**Interfaces:**
- Produces: `ExportBatch` and `export_readable_batch(store, reports, destination)`.
- Consumes: `ProtectedArtifactStore.export(protected_path, destination)` and `ProtectedReportRef.original_name`.

- [x] **Step 1: Write failing tests** proving one-at-a-time export, extension/name preservation, partial success, corrupt-report isolation, and refusal to overwrite.
- [x] **Step 2: Run the focused tests** and verify the expected missing-interface failures.
- [x] **Step 3: Implement** sequential export with per-file results and no plaintext accumulation.
- [x] **Step 4: Run the focused tests** and verify they pass.
- [x] **Step 5: Commit** batch export and tests.

### Task 3: Results-tab integration

**Files:**
- Modify: `stig_audit_pro/basic_app.py`
- Modify: `tests/test_basic_output_reliability.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: `ProtectedReportWorkspace`, `export_readable_batch`, and existing `ProtectedArtifactStore.read/export`.
- Produces: multi-select import, Device/IP and report-type selectors, clear workspace action, export-selection dialog, and batch completion messaging.

- [x] **Step 1: Write failing tests** for `askopenfilenames`, Protected Output defaulting, lazy selected-only preview, workspace clearing, one confirmation per batch, and chosen-report export.
- [x] **Step 2: Run the focused UI tests** and verify failures reflect the missing feature.
- [x] **Step 3: Implement** the Results controls and callbacks, keeping `_display_protected_report()` compatible with latest-report navigation.
- [x] **Step 4: Update** operator documentation for batch import, IP/type switching, and readable batch export.
- [x] **Step 5: Run** the new focused tests plus existing artifact/output tests and verify they pass.
- [x] **Step 6: Commit** the UI, documentation, and tests.

### Task 4: Clean verification and Windows package

**Files:**
- Modify: `stig_audit_pro/build_info.json` or the repository's existing build metadata source as required by the build process.
- Create outside repository: dated package directory and ZIP under `C:\Users\AWC\Desktop\Current_Working_STIG_TOOL`.

**Interfaces:**
- Consumes: committed feature branch and `STIG Audit Basic.spec`.
- Produces: clean tested EXE package with visible build identity and preserved shared validation profiles/device groups.

- [x] **Step 1: Create a clean Git snapshot** that excludes uncommitted profiles/backups.
- [x] **Step 2: Run** `py -3.12 -m pytest -q` in the clean snapshot and require zero failures.
- [x] **Step 3: Build** with `py -3.12 -m PyInstaller --noconfirm "STIG Audit Basic.spec"`.
- [x] **Step 4: Publish** the unpacked build with `Publish-ValidationBuild.ps1` and create the sanitized ZIP.
- [ ] **Step 5: Launch** the published EXE and verify the Results tab opens with the new controls.
- [x] **Step 6: Record** the package path, test count, build identity, and manual checks in the validation documentation.
