# Evidence Handling

Official audit evidence is stored beneath the platform application-data `runs/<UUID>/` directory. Every run has separate immutable-context snapshots and per-device artifact paths; rescanning the same IP creates a different UUID/tree and cannot overwrite prior evidence.

## Write and hash process

1. Encode the captured command output as exact UTF-8 bytes.
2. Write a temporary sibling file, flush and close it.
3. Atomically place it at a previously unused final path.
4. Calculate SHA-256 over the exact bytes written.
5. Persist command, relative path, hash, UTC time, and byte length.

Finalized artifacts are never replaced. Safe device/command path components prevent traversal and normalize platform-sensitive characters.

## Verification

`verify_evidence(run_id)` reads each recorded artifact and classifies it as:

- `VALID`: exact SHA-256 and byte content match.
- `MISSING`: the expected path no longer exists.
- `MODIFIED`: readable bytes produce a different hash.
- `UNREADABLE`: the file exists but cannot be read safely.

SHA-256 provides post-collection integrity detection. It does not prove who collected the file, that the source device was authentic, or chain of custody.

## Sensitive data

Raw device output can be sensitive and belongs only in evidence files, not normal logs. Passwords, enable secrets, authentication material, and private license signing material are never written to evidence metadata, snapshots, or manifests. Operators control retention; there is no automatic expiration. Purge and deletion are explicit confirmed actions.
