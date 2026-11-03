# Batch Protected Reports Design

**Date:** 2026-11-03
**Status:** Approved and implemented
**Applies to:** STIG Audit Basic Results tab

## Intent

Make large audit runs easier to review and deliver without weakening encrypted-at-rest behavior. An operator can import one, several, or all selected `.sapenc` reports, choose a device by IP, switch between that device's TXT and CKL reports, and explicitly export one, some, or all imported reports as readable files.

## Goals

- Preserve the current one-report workflow while adding multi-select import.
- Keep imported reports encrypted on disk and retain only their paths in application state.
- Provide an IP dropdown and a separate TXT/CKL selector when both types exist for a device.
- Allow readable export of one, some, or all imported reports with one explicit security confirmation.
- Keep all import and export dialogs anchored to the configured Protected Output folder.
- Clearly summarize successful, skipped, and failed imports or exports.

## Non-goals

- Do not permanently decrypt imported reports for preview.
- Do not combine multiple reports into one document.
- Do not overwrite an existing readable report.
- Do not change the `.sapenc` format, vault, audit collection, or report-generation behavior.

## Selected approach

The operator selected lazy, on-demand decryption. Import records validated encrypted file paths only. The app decrypts one report into memory when the operator chooses its IP and type. Batch export decrypts and writes each selected report sequentially so the complete batch is never held in readable form in memory.

An eager approach that decrypted all imported reports was rejected because it would keep unnecessary readable data in memory and scale poorly for large batches.

## Results-tab behavior

1. **Import protected reports** opens the existing Protected Output folder and allows Windows multi-selection. Selecting one file continues to work.
2. The app validates supported `.sapenc` filenames, removes exact duplicate paths, and adds valid reports to the current workspace.
3. The **Device/IP** dropdown lists unique device addresses inferred from app-generated protected filenames. If a legacy or externally named file cannot be mapped to an IP without decryption, it appears under a safe filename-based label.
4. The **Report type** selector lists only the types available for the chosen device, such as TXT or CKL.
5. Changing either selector decrypts only that report, verifies it, and displays its preview in memory. A failed report shows a clear error without discarding other imported reports.
6. The workspace shows the imported report count and provides a clear/reset action.
7. **Export readable reports** opens a selection dialog containing the imported reports, with Select all, Clear selection, and individual checkboxes. The operator may export one, some, or all.
8. The operator chooses a destination folder and receives one warning that the selected outputs will be unencrypted. Export starts only after confirmation.
9. Exports retain each original filename and type. Existing readable files are not overwritten. The completion message reports exported, skipped, and failed files and their destination.

## Security and failure handling

- Import does not create readable disk files.
- Preview plaintext exists only in the active textbox/in-memory byte buffer and is replaced when another report is selected or the workspace is cleared.
- Batch export processes one report at a time using the existing authenticated artifact store.
- Invalid or corrupted encrypted reports are isolated; one bad file does not prevent other selected reports from importing, previewing, or exporting.
- Cancellation before confirmation creates no readable files.
- The export warning remains explicit and operator controlled.
- No SSH credentials, vault password, or report plaintext is written to logs.

## Testing

- Multi-select import accepts one and many paths, defaults to Protected Output, and deduplicates paths.
- Device/IP and TXT/CKL grouping is deterministic for current report filenames.
- Selecting a report invokes decryption only for that report.
- Corrupt and unsupported reports do not remove valid imports.
- Batch export supports one, some, and all; asks for one confirmation; preserves extensions; and never overwrites existing readable files.
- Partial export reports successes and failures accurately and leaves no partial readable file after a failed write.
- Existing single-report preview/export tests continue to pass.
