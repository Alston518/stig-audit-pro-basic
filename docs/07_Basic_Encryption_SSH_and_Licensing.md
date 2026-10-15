# Basic security update — 9 October 2026

This guide applies to **STIG Audit Basic for IOS and IOS XE**, including its
free single-device mode and signed-license batches. The executable in this
folder is the Basic app. It does not launch the Pro interface.

## Encryption at rest

Basic prompts for an audit-data passphrase when it starts. New passphrases
have no complexity rule or minimum character count; a nonempty passphrase is
still required. Later launches require the same passphrase to unlock protected
reports. Removing the minimum permits weak passphrases, so use a strong one
for real audit data and keep it in an approved password manager. An existing
vault keeps its original passphrase; this update does not change it. There is
no recovery key or reset function.

New per-device TXT and CKL reports and Summary PDF, HTML, and CSV reports are
written as `.sapenc` ciphertext in the selected output folder. The report is
rendered in process memory and encrypted before it is written; the normal
audit path does not stage a readable report on disk. The app uses AES-256-GCM
with a fresh 96-bit nonce and authentication for each file. The passphrase is
processed with scrypt (`N=32768, r=8, p=1`) and HKDF-SHA-256. The vault
metadata at `%LOCALAPPDATA%\STIG Audit Pro Basic\audit-vault.json` contains a
random salt, KDF settings, and an encrypted verifier, but no passphrase or
data key. The file name is authenticated as associated data, so renaming a
protected report makes it unreadable.

Use **Results → Open protected report** to decrypt a TXT, CKL, HTML, or CSV
report into the app's memory and view its text. A protected PDF can be
authenticated and decrypted there, but PDF viewing requires a deliberate
readable export. Use **Results → Export readable copy** to create a normal
TXT, CKL, PDF, HTML, or CSV for another application or assessor. That copy is
**not encrypted by Basic**; handle it under your organization's storage and
transfer policy. The app will not silently overwrite an existing readable
file. For CKL import into STIG Viewer, use this explicit export action.

The Audit run card shows the actual saved-file count and destination. It
distinguishes completed, partial, failed, and cancelled runs; no-file failures
are never reported as successful output. Output names use the full selected
target and a digest plus a run ID, avoiding same-octet and repeat-run
collisions. Protected files are staged as ciphertext and published without
replacing an existing file. If a readable export write fails, Basic removes
the partial plaintext copy when the filesystem allows it and warns if it
cannot remove it.

This protection applies to **new Basic audit report files**. Basic's main
workflow does not maintain a Pro audit-history SQLite database or Pro run
evidence store; those Pro encryption claims do not apply here. Older Basic
reports, existing external backups, deliberately exported readable copies,
editable YAML checks/profiles, blank CKL templates, the template-path settings,
logs, and signed license JSON remain outside this report vault. Moving the
package does not move the vault metadata. Preserve the metadata and passphrase
for recovery; losing either makes protected reports unreadable. Existing
plaintext reports are not retroactively converted. Use endpoint full-disk
encryption and your approved handling process for those files and for memory,
pagefile, crash-dump, and backup exposure. This build does not claim FIPS
140-3 validation of its bundled cryptographic modules.

The Basic diagnostic log is plaintext metadata. It suppresses Netmiko and
Paramiko messages, removes device identifiers from structured context, and
omits exception messages and tracebacks. Treat it as an ordinary support log;
it is not an encrypted evidence store. The Results view also replaces raw
SSH failure text with safe operator guidance.

## SSH server identity

Both Basic Netmiko runners use `ssh_strict=True` and
`system_host_keys=True`. They load the current Windows account's OpenSSH
`%USERPROFILE%\.ssh\known_hosts` entries and reject unknown or changed SSH
server keys before any audit command runs. SSH identity keys and the SSH agent
are disabled for the app's password-based login. The app does not automatically
trust a device key or provide a bypass switch.

Before a live run, obtain the device's SSH host-key fingerprint from an
independent approved source such as the network inventory or device console.
From the **same Windows account** that runs Basic, connect with Windows
OpenSSH, for example `ssh operator@192.0.2.10`. For a nondefault port, use
`ssh -p 2222 operator@192.0.2.10`. Compare the fingerprint displayed by
OpenSSH with the approved fingerprint **before** accepting it. Confirm the
entry with `ssh-keygen -F 192.0.2.10`, or
`ssh-keygen -F '[192.0.2.10]:2222'` for that alternate port. `ssh-keyscan`
alone does not establish trust.

If Basic reports an unknown or changed host key, verify address, port, and
the device's identity independently. Investigate unexpected changes. After
an authorized rotation, remove the old entry with `ssh-keygen -R` using the
same host or `[host]:port` form, then verify and enroll the new fingerprint.
The app skips the affected device rather than sending audit commands.
SSH password and enable-secret entry fields are cleared when a live audit
starts. Credentials must remain in process memory for the duration of that
connection; Basic does not persist them. A close request during an active run
requests cancellation and waits for device work and report saves to finish.

## Licensing impact

Encryption and SSH host-key checking are available in Free Basic and in
licensed Basic. No new entitlement, license schema, product identifier,
public key, or signing key is required. Existing valid Basic licenses remain
compatible. The existing license checks still limit selected devices and
enabled report formats before collection and before encrypted report creation.
Opening an already-created protected file requires its vault passphrase; it
does not create another audit or increase a license's device allowance.
Neither a license nor its signature is encrypted by this report vault.

## Reviewer checks

From the repository root, run `py -3.12 -m pytest tests/test_basic_security_update.py -q`
and `py -3.12 -m pytest -q`. The focused tests verify both SSH runners,
encrypted TXT/CKL output in Free Basic, wrong-passphrase and tamper rejection,
and explicit readable export. The full suite covers the preexisting Basic
audit and license behavior. In a sample-output run, inspect the selected
folder: only `.sapenc` reports should be present, and their bytes should not
contain the sample hostname or finding text. Reopen a report in Results and
verify that a readable copy appears only after **Export readable copy**.
The SSH checks use a simulated connection boundary; a live authorized Cisco
device is still required for an end-to-end network test.
No cloud AI integration is enabled. A future model-based review would require
an approved data flow, authorization boundary, retention policy, and offline
or accredited deployment decision before any device configuration is sent.

## Startup troubleshooting

If the password dialog closes but the Basic window does not open, look for a
visible error dialog. Unexpected vault or main-window failures are logged at
`%LOCALAPPDATA%\STIG Audit Pro Basic\logs\stig-audit-pro.log`. The original vault
metadata is at the Basic path above; do not delete or replace it to fix an
unlock issue, because existing encrypted reports depend on that metadata and
the original passphrase. A wrong passphrase is rejected and can be retried.
