# Offline licensing operations

STIG Audit Pro verifies licenses entirely offline with Ed25519. The publisher
keeps the private signing key on a separate administration system. The customer
application contains only public keys and verification code.

## Customer behavior

`LicenseManager` is the single customer-side authority for file discovery,
JSON/schema validation, canonicalization, public-key loading, Ed25519
verification, UTC date checks, effective device limits, imports, and feature
checks. No other customer module parses license JSON or performs cryptographic
operations.

Validation is fail closed and follows this order: readable file, JSON, required
objects and types, supported schema, exact product, exact algorithm, known key,
Base64 signature, signature, UTC dates and future issuance, expiration,
positive device count, and supported Boolean features. Values are not made
available as trusted properties until signature verification succeeds.

States are `VALID`, `EXPIRED`, `INVALID`, and `MISSING`; `FREE` is the effective
unlicensed mode. Missing, expired, and invalid licenses use Free-mode policy
without deleting or changing results, reports, source CKLs, or completed CKLs.
Free mode permits one unique normalized IP target per scan and enables no paid
feature flags.

The application reloads the license at startup, after import, before every
scan, and before each paid operation. Feature and device checks are enforced in
the controller/service path as well as represented in the GUI.

Fully offline licensing cannot completely prevent a user with operating-system
administrator control from moving the system clock backward. This first
version intentionally does not add invasive clock-tampering detection.

## Customer license locations

The exact filename on every platform is `stig-audit-pro.license.json`.
`platformdirs` selects the per-user application-data directory:

- Windows: `C:\Users\<user>\AppData\Local\STIG Audit Pro\stig-audit-pro.license.json`
- macOS: `~/Library/Application Support/STIG Audit Pro/stig-audit-pro.license.json`
- Linux: `~/.local/share/STIG Audit Pro/stig-audit-pro.license.json`

Linux honors `XDG_DATA_HOME` when it is set. For managed deployments,
`STIG_AUDIT_PRO_LICENSE_PATH` may point to an explicit file and takes
precedence. The License tab always displays the active location.

The preferred customer workflow is to open **License**, select **Import
License** or **Replace License**, and choose the issued file. STIG Audit Pro
verifies it before an atomic copy into the active application-data location.
An invalid or expired selection is not copied.

For a managed Windows copy followed by application validation:

```powershell
$licenseDir = Join-Path $env:LOCALAPPDATA "STIG Audit Pro"
New-Item -ItemType Directory -Force -Path $licenseDir | Out-Null
Copy-Item -LiteralPath ".\issued-licenses\LIC-2026-A7D42F91.license.json" `
  -Destination (Join-Path $licenseDir "stig-audit-pro.license.json")
python app.py
```

## Install publisher and build dependencies

From a trusted checkout:

```powershell
python -m pip install -r requirements.txt
```

New dependencies are `cryptography` for maintained Ed25519 primitives,
`platformdirs` for customer application-data discovery, and `pyinstaller` for
the explicit customer build.

## Generate the production key pair

Run key generation only on the isolated publisher administration system. A
recommended Linux layout is:

```bash
sudo install -d -m 700 -o "$(id -u)" -g "$(id -g)" /opt/stig-license/keys
python -m tools.license_admin keygen \
  --key-id stig-audit-prod-2026-01 \
  --private-key-output /opt/stig-license/keys/stig-audit-prod-2026-01-private.pem \
  --public-key-output /opt/stig-license/keys/stig-audit-prod-2026-01-public.pem
chmod 600 /opt/stig-license/keys/stig-audit-prod-2026-01-private.pem
```

The generated public key initially appears exactly at the
`--public-key-output` path:

```text
/opt/stig-license/keys/stig-audit-prod-2026-01-public.pem
```

The generated private key remains exactly at the `--private-key-output` path:

```text
/opt/stig-license/keys/stig-audit-prod-2026-01-private.pem
```

The tool refuses to write a private key anywhere inside this repository,
refuses to overwrite an existing key without `--force`, sets owner-only file
mode, prints the SHA-256 public-key fingerprint, and never prints private-key
contents.

## Register the production public key

Copy only the public key into the repository, renaming it to the exact key ID:

```bash
cp /opt/stig-license/keys/stig-audit-prod-2026-01-public.pem \
  stig_audit_pro/resources/licensing/public_keys/stig-audit-prod-2026-01.pem
```

The exact repository path is:

```text
stig_audit_pro/resources/licensing/public_keys/stig-audit-prod-2026-01.pem
```

The mapping is filename-based: license
`signature.key_id = "stig-audit-prod-2026-01"` maps only to
`stig-audit-prod-2026-01.pem`. The PyInstaller spec explicitly includes
`stig_audit_pro/resources`, so this file is bundled in customer builds.

Build on Windows and confirm the exact file:

```powershell
python -m PyInstaller --noconfirm --clean .\stig-audit-pro.spec
Test-Path ".\dist\STIGAuditPro\_internal\stig_audit_pro\resources\licensing\public_keys\stig-audit-prod-2026-01.pem"
```

`Test-Path` must print `True`. Do not release a production build if it prints
`False`.

To rotate keys, generate a new key ID and key pair, add the new `<key_id>.pem`
beside the old public key, rebuild and release the application, and issue new
licenses with the new ID. Keep old public keys bundled until every license they
verify has expired or has been replaced. Public-key rotation never requires
shipping a private key.

## Issue licenses

Generate a short-lived non-production test license:

```bash
python -m tools.license_admin issue \
  --private-key /opt/stig-license/keys/stig-audit-prod-2026-01-private.pem \
  --key-id stig-audit-prod-2026-01 \
  --customer-name "Publisher QA" \
  --edition Pro \
  --expires-at "2026-08-01T23:59:59Z" \
  --max-devices 3 \
  --enable multi_device_scan \
  --enable ckl_export \
  --enable l2_checks \
  --enable ndm_checks \
  --enable saved_presets \
  --enable advanced_reporting \
  --output ./issued-licenses/qa-short-lived.license.json
```

Generate a production license:

```bash
python -m tools.license_admin issue \
  --private-key /opt/stig-license/keys/stig-audit-prod-2026-01-private.pem \
  --key-id stig-audit-prod-2026-01 \
  --customer-name "Example Customer" \
  --edition Pro \
  --expires-at "2027-07-28T23:59:59Z" \
  --max-devices 250 \
  --enable multi_device_scan \
  --enable ckl_export \
  --enable l2_checks \
  --enable ndm_checks \
  --enable saved_presets \
  --enable advanced_reporting \
  --output ./issued-licenses/example-customer.license.json
```

Interactive issuance is also available:

```bash
python -m tools.license_admin issue --interactive
```

Each issuance generates a random `LIC-<UTC year>-<8 hex characters>` ID,
canonicalizes and signs the complete `license` object, writes formatted JSON,
derives the matching public key in memory, and immediately self-verifies the
output. It deletes the output and reports failure if self-verification fails.
No database is required or used in this first version.

Verify an issued license independently:

```bash
python -m tools.license_admin verify \
  --license ./issued-licenses/example-customer.license.json \
  --public-key /opt/stig-license/keys/stig-audit-prod-2026-01-public.pem
```

Inspect parsed but explicitly untrusted content:

```bash
python -m tools.license_admin inspect \
  --license ./issued-licenses/example-customer.license.json
```

## Private-key custody and build checks

The recommended live location is
`/opt/stig-license/keys/stig-audit-prod-2026-01-private.pem`, owned by the
dedicated publisher account with mode `0600`. The issue command locates it only
through the explicit `--private-key` argument. Keep at least two encrypted,
offline backups under separate authorized custody; verify backup recovery on
an isolated host. Prefer an encrypted volume or hardware-backed administrative
system and never synchronize the key into source control or customer build
storage.

Confirm Git has no tracked private key or issued license:

```powershell
$matches = git ls-files | Select-String -Pattern "(?i)(private.*\.pem|\.license\.json$)"
if ($matches) { $matches; throw "Sensitive licensing material is tracked" }
```

Confirm the customer build has neither the admin package nor PEM private-key
text:

```powershell
if (Test-Path ".\dist\STIGAuditPro\_internal\tools") {
  throw "Publisher tools were included"
}
$privateKeyHits = Get-ChildItem ".\dist\STIGAuditPro" -Recurse -File |
  Select-String -SimpleMatch "BEGIN PRIVATE KEY" -ErrorAction SilentlyContinue
if ($privateKeyHits) { $privateKeyHits; throw "Private key material was included" }
python -m PyInstaller.utils.cliutils.archive_viewer -l `
  ".\dist\STIGAuditPro\STIGAuditPro.exe" |
  Select-String -Pattern "tools(\.|\\)license_admin"
```

The final archive command must produce no match.

## Automated tests and customer build

```powershell
python -m pytest
python -m PyInstaller --noconfirm --clean .\stig-audit-pro.spec
```

The tests generate fresh test-only Ed25519 keys under pytest temporary
directories. They never use or require a production private key.

## Manual acceptance test

1. Remove or move aside the application-data license file, start `python
   app.py`, and confirm the License tab says `MISSING (Free mode)` with a
   one-device limit.
2. Issue a short-lived QA license with all features and a known small device
   limit.
3. Use **License > Import License** and confirm status `VALID`, customer,
   license ID, expiration, and device limit.
4. Confirm L2/NDM scanning, CKL export, preset saving, and report export are
   enabled by executing each operation.
5. Keep an untouched copy, edit one signed field in another copy, and attempt
   to import the edited file. Confirm it is rejected and does not replace the
   installed valid license.
6. Restore/import the untouched license.
7. Submit duplicate spellings of the same IP and confirm it counts once; then
   submit one more unique valid IP than `max_devices` and confirm the error
   shows permitted and requested counts.
8. Issue an expired test license with a historical issuance timestamp:

   ```bash
   python -m tools.license_admin issue \
     --private-key /opt/stig-license/keys/stig-audit-prod-2026-01-private.pem \
     --key-id stig-audit-prod-2026-01 \
     --customer-name "Expiration QA" \
     --edition Pro \
     --issued-at "2025-07-01T00:00:00Z" \
     --expires-at "2026-07-27T23:59:59Z" \
     --max-devices 2 \
     --enable multi_device_scan \
     --enable l2_checks \
     --output ./issued-licenses/expired-qa.license.json
   ```

   Copy it into the customer license location (an expired license is
   intentionally rejected by the GUI import action), restart, and confirm
   status `EXPIRED (Free mode)`.
9. Confirm existing Results views and CKL files still open and remain unchanged
   after expiration.
