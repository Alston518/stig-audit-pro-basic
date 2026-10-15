# STIG Audit Pro Basic — encrypted report candidate

This document describes the **draft** encryption work on branch
`security/basic-encrypted-reports`. It is not a security accreditation.

## Vault behavior
- The Basic GUI requests a vault password on its first run and asks for it
  again on subsequent launches. The password is never persisted directly.
- A memory-hard scrypt key derivation creates a 256-bit AES-GCM key.
- Every audit-created TXT and CKL and summary PDF/HTML/CSV is rendered in
  memory and written to disk only as a `.sapenc` ciphertext envelope.
- The vault location is under the current user's per-user application data
  directory (`STIG Audit Pro Basic/secure-outputs`). The vault manifest
  `vault.json` contains key-derivation parameters and verification ciphertext.
- Explicit `Export decrypted vault report` creates plaintext **only with**
  the operator's approval. The exported file is not encrypted.

## Limits (important)
- This vault does **not** encrypt YAML profiles/checks, imported device lists,
  sample inputs, blank templates, user-selected plaintext exports, log files,
  system pagefile/hibernation data, or files written by older releases.
- Protect the host with Windows BitLocker and organization-approved controls.
- Existing plaintext reports remain on disk and must be reviewed and handled
  using organization-approved procedures. This change deliberately does not
  automatically migrate or delete them.
- Password recovery is not available. Back up `vault.json` together with
  all `.sapenc` files and keep your password in an approved password manager.
- Neither encryption nor code signing grants DoD authorization to operate.
- The project has not yet undergone independent security review.

## Release acceptance criteria
- Windows CI passes tests, generates the ZIP and verifies its contents.
- Manually validate fresh first launch, cancel, wrong-password rejection,
  relaunch/unlock, tamper detection, sample/live runs, plaintext export warning,
  and read-only device behavior on a clean Windows 10/11 PC.
- Review produced files for plaintext findings, hostnames, IPs and configs.
- Confirm no extra writable/export paths bypass the vault.
- Only after acceptance publish a **new** release to the public downloads repo.
