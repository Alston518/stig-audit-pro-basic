# Current Limitations

## What this does

This page defines what STIG Audit Pro 0.2 does not claim to provide.

## When you use it

Review it before procurement, deployment, or an assessment authorization decision.

- Cisco IOS-XE switch L2 and NDM are the supported automation families. NX-OS and other vendors are not supported.
- The product is a Windows-focused, single-user/local desktop application. There is no server, RBAC, SSO, central inventory, or REST API.
- It is strictly read-only toward devices. It does not remediate, enter configuration mode, save configuration, or reload equipment.
- Some STIG requirements remain manual because CLI evidence cannot support a defensible deterministic decision.
- Site-specific values must be tailored in a Site Profile before results are meaningful.
- Automated mappings are not equivalent to verified automation. A mapping is current only after review against the installed rule fingerprint and passing fixture coverage.
- Portable audit-package export/import preserves results and evidence links;
  packages use the original run UUID, so importing a duplicate run is refused.
- GUI backups exclude raw evidence by default. The restore workflow supports
  evidence only when it was explicitly included by an advanced/service-level
  backup operation.
- Audit History uses SQLite-backed search and pagination. The Results view uses
  a bounded filtered window rather than a fully virtualized table.
- Check-pack content hashing exists through audit snapshots. Signed commercial check-pack distribution is future work.
- Evidence SHA-256 detects changes after capture; it does not prove the identity of the device or operator that produced the evidence.
