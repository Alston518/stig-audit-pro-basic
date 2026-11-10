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

This branch contains the source from the tested 10 November 2026 Basic golden
package, with only publication hygiene edits to documentation and test fixtures.
The golden package is `STIG_Audit_Basic_2026-11-10-GOLDEN.zip` (SHA-256
`9e8ecb2d883eba70c9dc0a2674faa58ba1f0d71a2a684ee71cce3bfbe62d81f`).
The source suite passed 386 tests with one skip, and the packaged executable
passed report, summary-export, GUI, and bundle-boundary smoke checks. The
operator also completed live SSH scans on IOS and IOS XE hardware. The IOS
check packs remain marked **unvalidated** pending finding-by-finding review
against representative hardware and the source STIG. The executable is not
part of this source repository; use the separately distributed dated package.

## Current security behavior

- New reports and summary exports are stored as authenticated AES-256-GCM
  `.sapenc` files. The audit-data passphrase unlocks the local report vault.
- Reports are rendered in memory and encrypted before they are published to
  the selected output folder. Creating a readable copy requires an explicit
  export action in the Results tab.
- Live SSH verifies saved SSH host keys by default. Before a batch audit, the
  app discovers new fingerprints without sending credentials and shows them
  together for operator review. One confirmation accepts all listed new keys
  on a first-use basis without entering a note or independent source. The
  source field is optional; an empty field is recorded as unverified first-use
  acceptance. Changed saved
  keys remain blocked. Disabling host-key
  verification requires confirmation and displays a warning banner.
- SSH agent and identity-key authentication are disabled. Password and enable
  secret fields are cleared when a live audit begins.
- Live SSH starts with two credential probes before using up to three workers.
  If authentication fails, it stops filling the batch with new connections;
  two failed probes stop a batch with incorrect shared credentials. Connections
  already in flight can still add a failure in a mixed-device run.
- The app reports completed, partial, failed, and cancelled runs with the
  actual protected-file count and exact output folder.

See [the encryption and SSH guide](docs/07_Basic_Encryption_SSH_and_Licensing.md)
for the security boundary, reviewer checks, and known limitations.

## Guided site setup

Use **Profiles & Sites** to create a standalone profile for each building and a reusable device group. For a new deployment, download the master inventory template, fill in the building and device rows, and import it to create all building groups at once. Choose the saved building on the Audit tab to load its device inventory and profile without editing YAML. See [`docs/12_Site_Setup_Workflow.md`](docs/12_Site_Setup_Workflow.md).

## Reviewing protected reports

On the **Results** tab, choose **Import protected reports** and select one,
several, or all `.sapenc` files from an audit batch. The Device/IP and Report
type selectors let you switch between each device's TXT and CKL results. Only
the active report is verified and decrypted for the in-memory preview.

Choose **Export readable reports** to select one, some, or all imported
reports. The app asks for a destination folder and requires one explicit
confirmation before creating unencrypted copies. Batch export processes one
report at a time and never replaces an existing readable file.

The audit folder also contains an encrypted `.manifest.json.sapenc` file with
the operator, tool version, STIG release, timestamp, and report SHA-256 hashes.
Choose **View encrypted manifest** in Results to read it in memory. If a
manifest is selected through **Import protected reports**, the app opens the
manifest viewer automatically. The manifest is not a TXT or CKL report.

**Summary → Export summary** creates encrypted PDF, HTML, and CSV files for
the current run, plus a separate encrypted manifest. The packaged PDF renderer
uses local data only; remote resources are unavailable in the Basic build.

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
