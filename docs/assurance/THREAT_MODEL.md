# Threat Model

## Assets

Protected assets include device credentials in memory, raw configuration evidence, audit findings/history, profile/check snapshots, license verification material, and imported STIG content.

## Primary threats and controls

- **Command injection or configuration change:** exact centralized allowlist; newline/control/chaining rejection; YAML and runtime validation; no remediation component.
- **Credential disclosure:** session-only fields, GUI clearing, model `extra=forbid`, redacted structured logging, and exclusion from database/manifests/presets.
- **Historical evidence tampering:** per-run immutable paths, atomic writes, exact-byte SHA-256, persisted metadata, and on-demand verification.
- **Cross-run overwrite:** UUID roots and no replacement of finalized artifacts.
- **False comparison across changed controls:** normalized STIG fingerprints and `NOT_COMPARABLE` when a materially changed rule prevents a valid comparison.
- **Unsafe or malformed content:** strict Pydantic/YAML schemas, supported versions, corrupt-import errors, and ambiguous-match failures.
- **Malicious archives / ZIP slip:** STIG, backup, and audit-package ZIP entries are bounded, validated before use, reject traversal/absolute paths, symbolic links, encryption, excessive expansion, and unsafe compression ratios. Imported filenames never choose arbitrary destinations.
- **Malformed CKL/CKLB/XML:** file-size, structure, schema-version, and rule-count limits fail closed with operator-facing errors.
- **CSV/Excel formula injection:** all untrusted strings beginning with spreadsheet formula markers are escaped before CSV/XLSX output.
- **Evidence path and symlink attacks:** evidence paths are UUID-scoped and root-contained; traversal and symlinked run/device paths are rejected.
- **Log/support-bundle leakage:** structured logs and support archives redact credential-shaped values; support archives exclude raw evidence and configurations by default.
- **Database tampering/upgrades:** foreign keys and schema checks detect incompatible state; an on-disk safety copy is created before forward migration.
- **Resource exhaustion:** imports enforce archive/file/entry/count limits, while GUI history/results use bounded display windows.
- **Malicious profile/check content:** strict schemas reject unknown fields and commands pass the same authoritative policy before connection. Raw check edits are validated and backed up before replacement.
- **Worker/GUI concurrency faults:** isolated connections and a queue boundary; only Tk's main thread updates widgets.
- **Database corruption/orphans:** short transactions, schema-version checks, foreign keys, and explicit failure propagation.

## Trust and limitations

The workstation, Python/runtime dependencies, OS file permissions, operator-selected STIG files, and reachable network are trust dependencies. A source hash detects later changes but is not publisher authentication; signed official check-pack distribution remains future work. Hashes do not provide collector identity. The desktop is single-user and does not provide role-based access control, a server database, vault integration, telemetry, or autonomous scheduling in v0.2.

Routine logging suppresses Paramiko, Netmiko, and SCP below WARNING because
those libraries may emit device authentication banners or session detail.
Support-bundle creation also removes historical third-party SSH diagnostic
lines, protecting bundles created from logs written by older releases.

The application displays DISA fix guidance but never executes it. Operators remain responsible for authorization, source validation, findings review, custody, and any remediation performed outside this product.
