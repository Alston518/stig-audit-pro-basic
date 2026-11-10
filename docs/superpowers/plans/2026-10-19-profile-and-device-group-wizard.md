# Site Profile and Device Group Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add GUI-managed flattened site profiles and reusable device groups to Basic so an operator can select a building and run its audit without editing YAML.

**Architecture:** Add a focused profile materialization/validation module and reuse the existing `DeviceGroupStore`. Extend the Basic GUI with a Profiles & Sites tab and a saved-group selector, keeping the existing audit engine and encrypted artifact store as the execution boundary. Generated files remain ordinary configuration YAML in the existing per-user writable data directory and are written atomically after validation.

**Tech Stack:** Python 3.12, Tk/CustomTkinter, Pydantic, PyYAML, pytest, existing Basic GUI and encrypted artifact store.

**Spec:** `docs/superpowers/specs/2026-10-19-profile-and-device-group-wizard-design.md`

## Global Constraints

- Base profiles are selected only during site-profile creation; saved site profiles are standalone flattened YAML files.
- Recursive mappings merge, scalar values replace, and lists replace the base list.
- SSH credentials must never be stored in profiles, groups, or presets.
- Existing direct device-entry audits and existing YAML files remain compatible.
- Audit reports continue to use the encrypted `.sapenc` output workflow.

## Review Focus

- A site profile that intentionally clears a base list must preserve the empty list rather than inherit the base list.
- A profile or group save failure must not leave a truncated or partially written YAML file.
- Duplicate and malformed device addresses must be rejected before an audit starts.
- Selecting a group must update both the device list and the profile used by the audit.
- A saved flattened profile must still load after its original base profile changes or is removed.

### Task 1: Profile materialization and persistence

**Files:**
- Create: `stig_audit_pro/storage/profile_builder.py`
- Test: `tests/test_profile_builder.py`

**Interfaces:**
- `materialize_profile(base_data: Mapping[str, Any], overrides: Mapping[str, Any], profile_name: str) -> dict[str, Any]`
- `validate_profile_data(data: Mapping[str, Any], profiles_dir: Path) -> SiteProfile`
- `save_profile(path: Path, data: Mapping[str, Any], profiles_dir: Path) -> SiteProfile`

- [ ] Write failing tests for recursive merge, list replacement, empty-list replacement, flattened output, validation, and atomic save.
- [ ] Run the focused tests and confirm they fail because the module is missing.
- [ ] Implement the module with a deep-copy recursive merge, removal of `inherits`, existing loader validation, and temp-file-plus-`os.replace` publication.
- [ ] Run the focused tests and confirm they pass.
- [ ] Commit `feat: add flattened site profile builder`.

### Task 2: Device group safety helpers

**Files:**
- Modify: `stig_audit_pro/storage/device_groups.py`
- Test: `tests/test_device_groups.py`

**Interfaces:**
- Add strict address normalization/duplicate detection used by the GUI while retaining existing `DeviceGroupStore` compatibility.
- Add an atomic group-save path that refuses invalid empty groups and overwrites only after explicit caller approval.

- [ ] Write failing tests for normalization, duplicate rejection, empty-group rejection, and atomic save.
- [ ] Run the focused tests and confirm the new assertions fail.
- [ ] Implement the helpers and keep the YAML schema backward compatible.
- [ ] Run the focused tests and confirm they pass.
- [ ] Commit `feat: validate saved Basic device groups`.

### Task 3: Profiles & Sites GUI

**Files:**
- Create: `stig_audit_pro/gui/site_setup.py`
- Modify: `stig_audit_pro/basic_app.py`
- Test: `tests/test_basic_site_setup.py`

**Interfaces:**
- `SiteSetupPanel` owns profile/group editor state and calls injected callbacks for refresh and selection.
- Editor callbacks return validated profile/group paths and never receive SSH credentials.

- [ ] Write failing GUI-adjacent tests for loading profiles/groups, materializing a site profile, saving a group, and refreshing the selector.
- [ ] Run focused tests and confirm they fail.
- [ ] Implement the panel with typed common fields, read-only YAML preview, profile save/duplicate/delete actions, group save/import actions, and actionable validation errors.
- [ ] Add the tab to `BasicApp`, initialize it from the per-user data directory, and refresh the existing profile/group controls after saves.
- [ ] Run focused tests and confirm they pass.
- [ ] Commit `feat: add GUI site and profile setup`.

### Task 4: Saved group audit selection

**Files:**
- Modify: `stig_audit_pro/basic_app.py`
- Test: `tests/test_basic_site_setup.py`, `tests/test_basic_output_reliability.py`

- [ ] Write a failing test proving group selection populates devices/profile and that `_run` receives the selected profile.
- [ ] Run the focused test and confirm it fails.
- [ ] Add the saved-group selector and review card to the Audit tab; preserve manual entry as an alternative.
- [ ] Make audit startup reject a missing/empty group and use the group profile when selected.
- [ ] Run focused tests and the full suite.
- [ ] Commit `feat: run audits from saved device groups`.

### Task 5: Documentation and release verification

**Files:**
- Modify: `README.md`
- Modify: `docs/00_Documentation_Index.txt`
- Create: `docs/12_Site_Setup_Workflow.md`

- [ ] Document profile creation, flattening/override rules, device groups, storage paths, and the audit workflow.
- [ ] Add a short cyber-review note explaining that generated profiles/groups contain network configuration only and never SSH credentials.
- [ ] Run documentation validation, focused tests, the full test suite, and the packaged smoke test.
- [ ] Review the final diff and commit `docs: document Basic site setup workflow`.
