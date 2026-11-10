# Site Profile and Device Group Wizard Design

## Goal

Allow Basic users to create self-contained building profiles and reusable device groups in the GUI, then select a saved building and start an audit without editing YAML files.

## User workflow

1. Open **Profiles & Sites**.
2. Choose **New site profile**, select a base profile once, and edit the friendly fields.
3. Save the result as a named, standalone profile such as `Building 1`.
4. Create a device group such as `Building 1`, paste or import its device addresses, and select the saved profile.
5. On the Audit tab, choose the saved group. The app loads its device list and profile, displays a review summary, and starts the audit when the operator clicks **Start audit**.

## Profile materialization

Base profiles remain bundled templates. Creating a site profile loads the selected base YAML, applies the user-edited site values, validates the complete result through the existing profile loader, and writes one flattened YAML file. The saved file has no `inherits` dependency, so an audit is reproducible even if the base template changes later.

Merge semantics are explicit:

- mappings merge recursively;
- scalar values replace the base value;
- lists replace the base list as a whole;
- an empty list is an intentional override and is preserved.

Existing building profiles remain unchanged when a base template is edited. A future rebase feature can be added separately.

## GUI components

- **Profiles & Sites tab:** profile creation/editing and device-group creation/editing.
- **Profile editor:** common site values are presented as typed controls; advanced profile data can be reviewed in a read-only YAML preview before saving.
- **Device group editor:** named group, profile selection, multiline addresses, CSV/TXT import, duplicate/invalid-address validation, and checked-device count.
- **Audit tab:** saved group selector plus a clearly visible summary of the selected group, profile, platform, and device count. Selecting a group populates the existing device and profile controls; manual device entry remains available.

## Data and security

- Generated profiles and device groups are stored in the existing per-user writable data directory under `data/profiles` and `data/device_groups`.
- Writes are atomic and validate before publication.
- SSH credentials are never written to profiles, groups, or presets.
- Profile and device-group files contain configuration and network inventory, not secrets. The UI labels this clearly and the operator guide documents the storage location and backup expectations.
- Audit output continues to use the existing encrypted `.sapenc` workflow.

## Validation and failure behavior

- Profile names and group names are required and filesystem-safe.
- IP addresses and hostnames are normalized and duplicates are rejected.
- Profile values are validated using the existing `load_profile`/Pydantic path before a file is published.
- Existing files are not silently overwritten; the UI asks before replacing an existing profile or group.
- Invalid YAML, invalid profile values, and empty device groups produce an actionable message and leave the previous file unchanged.

## Compatibility

Existing YAML profiles and device groups continue to load. The current Audit tab and direct device-entry path remain usable. The feature is implemented in the dedicated Basic repository on top of the reviewed `main` branch.

## Acceptance criteria

- A user can create a profile from a base, override nested values and lists, and save a standalone profile that loads without inheritance.
- A user can create a named device group and associate it with a saved profile.
- Selecting a saved group populates the audit controls and uses the associated profile when the audit starts.
- Invalid values cannot corrupt or partially publish a profile/group file.
- Existing test suite remains green, with focused tests covering merge semantics, validation, persistence, GUI selection, and audit integration.
