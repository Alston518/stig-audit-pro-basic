# STIG Difference Guide

## Matching and normalization

Rules match by Vuln ID, then Rule ID, then STIG ID. A stable Vuln ID with a changed Rule ID remains the same vulnerability with revised metadata. Multiple possible candidates produce an ambiguous result; the engine does not guess.

Line endings, outer whitespace, safe prose whitespace, empty values, and extracted XML text are normalized before deterministic hashes are created. IOS command content is not normalized in a way that erases command syntax. Every relevant field and the complete canonical rule receive separate SHA-256 fingerprints.

## Rule changes

- `ADDED`: only in the new release.
- `REMOVED`: only in the previous release.
- `UNCHANGED`: meaningful field fingerprints match.
- `CHANGED`: one or more fields differ; the viewer lists severity, title, IDs, check text, and/or fix text explicitly.

## YAML impact

- `NEW_CHECK_REQUIRED`: an added rule has no local mapping; generate a manual starter and assess feasibility.
- `RETIRE_CHECK_REVIEW`: a removed rule has a mapping; retain it for old runs but do not execute it by default for the new release.
- `METADATA_UPDATE`: title, severity, Rule ID, or STIG ID changed without substantive procedure changes.
- `AUTOMATION_REVIEW_REQUIRED`: automated check procedure changed, so existing logic is stale until reviewed.
- `FIX_GUIDANCE_CHANGED`: only remediation prose changed; make it visible but do not invalidate otherwise current audit logic automatically.
- `MANUAL_RULE_REVIEW`: substantive content changed for a manual mapping.
- `NO_LOCAL_CHECK`, `NO_ACTION_REQUIRED`, and `AMBIGUOUS_MAPPING` describe the remaining explicit cases.

The UI and exports show family, Vuln ID, old/new Rule IDs, changed fields, YAML file, check type, automation/review state, impact, and a concrete recommendation. Check/fix prose is displayed side by side rather than as raw XML.

## Coverage

`Automated mappings % = automated mappings / applicable rules × 100`.

`Current reviewed automation % = automated mappings whose reviewed fingerprint equals the installed rule fingerprint / applicable rules × 100`.

Stale automation is not counted as fully current coverage.
