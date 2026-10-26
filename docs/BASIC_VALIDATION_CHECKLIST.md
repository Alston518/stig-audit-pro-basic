# Basic App Validation Checklist

**Started:** 2026-10-26  
**Build under test:** `STIG_Audit_Basic_Security_Hardened_2026-10-23-EXPORT-FIX`  
**Source branch:** `codex/profile-wizard`

## Passed

- [x] **1. Startup and vault** — App starts, vault password unlocks data, and incorrect passwords are rejected.
- [x] **2. License** — License loads successfully and the license workflow is usable.
- [x] **4. Sample audit and protected reports** — Sample audit completes, `.sapenc` reports are created, and readable exports work.

## Still to validate

- [ ] **3. Profiles and device groups**
  - [ ] Site profiles are present after reopening the app.
  - [ ] Device groups are present after reopening the app.
  - [ ] Selecting a building loads the expected devices and profile.
  - [ ] Editing and saving a profile preserves unrelated fields.

- [ ] **5. Protected report navigation**
  - [ ] Open protected report folder opens the configured Protected Output folder.
  - [ ] Open protected report starts in that same folder.
  - [ ] Export readable copy defaults to that same folder.

- [ ] **6. Live SSH with host-key verification enabled**
  - [ ] Unknown host keys produce a clear failure message.
  - [ ] Verified/enrolled host keys allow a live audit.
  - [ ] Credentials are not written to reports, profiles, or logs.

- [ ] **7. Live SSH compatibility mode**
  - [ ] Unchecking host-key verification changes the banner visibly.
  - [ ] A controlled test audit works with verification disabled.
  - [ ] Verification is re-enabled afterward.

- [ ] **8. Failure messages**
  - [ ] Wrong SSH password.
  - [ ] Unreachable device.
  - [ ] Missing CKL template.
  - [ ] Invalid profile.
  - [ ] Empty device selection.
  - [ ] Invalid output folder.
  - [ ] Cancelled audit.

- [ ] **9. Security checks**
  - [ ] Reports remain encrypted at rest by default.
  - [ ] No readable report is created unless explicitly exported.
  - [ ] SSH credentials are cleared after a run.
  - [ ] Trusted-host data changes only during intentional enrollment.

- [ ] **10. Build identification**
  - [ ] GUI build date and commit match the package metadata.
  - [ ] The tested EXE is the current `EXPORT-FIX` build.

## Current baseline

- Automated regression suite: **330 passed, 1 skipped**.
- Last source change: readable exports default to the Protected Output folder.
- Feature work should wait until the remaining validation items are complete.
