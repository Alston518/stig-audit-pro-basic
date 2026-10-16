# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository when
it is available. Otherwise, contact the repository owner through GitHub before
sharing technical details. Do not open a public issue containing device
configurations, credentials, SSH host keys, license files, customer names,
network addresses, audit reports, or exploit details.

Include the affected version or commit, the security impact, reproducible
steps using sanitized data, and any suggested mitigation. The maintainer can
request additional evidence through an approved private channel.

## Supported code

Security fixes target the latest published release and the current default
branch. Older builds may be asked to upgrade before a report is investigated.

## Current boundaries

- `.sapenc` protects newly created Basic reports at rest. Explicit readable
  exports, logs, licenses, templates, editable YAML, memory, pagefile, crash
  dumps, and external backups require separate organizational controls.
- Live SSH rejects unknown and changed server keys using the current Windows
  account's OpenSSH `known_hosts` file.
- The current executable is unsigned, and the bundled cryptographic module is
  not claimed as FIPS 140-3 validated.
- No cloud AI service receives device configurations or findings.

See `docs/07_Basic_Encryption_SSH_and_Licensing.md` for the full security
design and reviewer procedure.
