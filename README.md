# STIG Audit Basic

STIG Audit Basic is a Windows desktop application for read-only Cisco IOS and
IOS XE STIG assessment. It collects approved `show` command output, evaluates
the selected L2 and NDM checks, and creates TXT and CKL results. Free Basic
assesses one explicitly selected device per run; signed offline licenses can
enable larger batches and additional allowed features.

This is the dedicated public source repository for the Basic application. It
does not launch the Pro interface and does not contain publisher signing tools,
private signing keys, issued customer licenses, or internal release records.

## Release status

The source contains the 9 October 2026 report, interface, encryption, and SSH
update plus the 15 October public-repository cleanup. The older 5 October
binary release predates these security changes. Build this source for testing
until a new release asset is published from the reviewed commit.

## Current security behavior

- New reports and summary exports are stored as authenticated AES-256-GCM
  `.sapenc` files. The audit-data passphrase unlocks the local report vault.
- Reports are rendered in memory and encrypted before they are published to
  the selected output folder. Creating a readable copy requires an explicit
  export action in the Results tab.
- Live SSH requires a matching server key in the current Windows account's
  OpenSSH `known_hosts` file. Unknown or changed keys stop collection.
- SSH agent and identity-key authentication are disabled. Password and enable
  secret fields are cleared when a live audit begins.
- The app reports completed, partial, failed, and cancelled runs with the
  actual protected-file count and exact output folder.

See [the encryption and SSH guide](docs/07_Basic_Encryption_SSH_and_Licensing.md)
for the security boundary, reviewer checks, and known limitations.

## Run from source

Requirements: Windows, Python 3.12, and the packages in `requirements.txt`.

```powershell
py -3.12 -m pip install -r requirements.txt
py -3.12 app.py
```

The first launch asks for a nonempty audit-data passphrase. Later launches
require the same passphrase. There is no recovery key, so preserve both the
passphrase and `%LOCALAPPDATA%\STIG Audit Pro Basic\audit-vault.json`.

## Test and build

```powershell
py -3.12 -m pytest -q
py -3.12 -m PyInstaller --noconfirm "STIG Audit Basic.spec"
```

`BUILD EXE.cmd` runs the Basic build command. Distribute the entire
`dist\STIG Audit Basic` folder, including `_internal`. The executable is
currently unsigned; package hashes detect changes but do not establish the
publisher's identity.

The repository includes sanitized demonstration data. A live end-to-end test
still requires an authorized Cisco device and an independently verified SSH
host-key fingerprint.

## Documentation

- [Documentation index](docs/00_Documentation_Index.txt)
- [Basic licensing](docs/03_Basic_Licensing.md)
- [Encryption, SSH, and licensing](docs/07_Basic_Encryption_SSH_and_Licensing.md)
- [Report output troubleshooting](docs/08_Report_Output_Troubleshooting.md)
- [Security update verification](docs/09_Security_Update_Verification.txt)
- [Release notes](docs/10_Report_UI_Security_Update_Release_Notes.txt)
- [Public release cleanup](docs/11_Public_Release_Cleanup_Notes.txt)

## Licensing

The application verifies signed licenses using production public keys bundled
with the executable. Publisher signing procedures and private keys are kept
outside this public repository. Existing compatible signed Basic licenses do
not need to be reissued for the report-encryption or SSH changes.

This repository does not grant an open-source license. See
[LICENSE.md](LICENSE.md) and the third-party notices under
`docs/Third Party Notices`. Have the final customer EULA and distribution
terms reviewed by qualified counsel before a production public release.

## Security reports

See [SECURITY.md](SECURITY.md). Do not place device configurations,
credentials, licenses, or customer data in a public issue.
