# STIG Audit Pro — Post-v0.2 Roadmap

## Delivered in v0.2

- Concurrent, bounded IOS-XE audits with per-device state and cancellation.
- Persistent audit history, evidence hashes, manifests, and run comparison.
- JSON, XLSX, CKL, and CKLB outputs.
- Scan presets, profile and common check-string editing, evidence/history views.
- Versioned STIG library, normalized release difference engine, YAML impact,
  starter checks, review state, and coverage dashboard.

## Next practical improvements

- Complete per-check compliant/noncompliant fixtures for every automated rule
  and make verified fixture coverage the primary assurance metric.
- Add optional evidence selection and estimated-size preview to the existing
  confirmed backup/restore workflow. Validated audit-package import is now
  available in History.
- Replace the bounded Results window with virtualized, SQLite-backed paging;
  History already uses SQLite search and 100-row pages.
- Expand typed profile/check forms and show all profile-value consumers.
- Add authenticated reviewer identity/change audit history when a server edition exists.
- Add explicit CKLB schema-version fixtures for every supported STIG Viewer
  release and improve asset metadata form support.
- Add visual trend reporting based on persisted run comparisons.
- Improve the STIG Library with a direct mapping-review action and release
  filtering for very large libraries.
- Increase automated coverage only after deliberate engineering and fixture
  validation; never infer audit logic from changed DISA prose.

## Deliberately out of scope

STIG Audit Pro remains read-only. Do not add automatic remediation,
configuration pushes, credential vaults, scheduled autonomous scans, web or
multi-user services, PostgreSQL/Redis, cloud telemetry, NetBox, ServiceNow,
Tenable, CyberArk, HashiCorp Vault, or Cisco NX-OS support without a separate
approved product scope.

Future enterprise-edition architecture may add a centralized service, REST API,
PostgreSQL, multi-user authentication, RBAC, SAML/OIDC SSO, central inventory,
NetBox, ServiceNow, Tenable, vault integrations, scheduled scans, signed official
check-pack distribution, and additional Cisco platforms. None are part of the
local desktop v0.2 implementation.
