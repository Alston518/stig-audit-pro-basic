# STIG Audit Pro license administration

This is a publisher-only command-line tool. It generates Ed25519 keys, signs
offline licenses, verifies licenses, and displays untrusted parsed contents.
It is explicitly excluded from the customer PyInstaller build.

Run from the repository root:

```powershell
python -m tools.license_admin --help
python -m tools.license_admin keygen --help
python -m tools.license_admin issue --help
python -m tools.license_admin verify --help
python -m tools.license_admin inspect --help
```

The application and this tool import the same
`stig_audit_pro.licensing.canonicalize.canonicalize_license` function. The
signature covers only those canonical bytes for the complete `license` object.

Store production private keys on the isolated publisher system, preferably at
`/opt/stig-license/keys/<key-id>-private.pem` with mode `0600`. Never put a
private key in this repository. The key-generation command enforces that
boundary.
