# STIG Audit Pro v0.2.0 documentation

The current documentation set begins at [docs/INDEX.md](INDEX.md). Legacy
entry points below are retained so existing links continue to resolve.

## Product and operator documents

- [Product overview](PRODUCT_OVERVIEW.md) - v0.2 product scope and links to current operator/architecture guides.
- [Generated command reference](assurance/COMMAND_REFERENCE.md) - exact executable command inventory.
- [Administrator guide](operator/ADMINISTRATOR_GUIDE.md) - targets, profiles, checks, concurrency, offline evidence, and licensing.
- [Security boundary](assurance/SECURITY_BOUNDARY.md) - read-only assurance and credential/data handling.
- [Offline licensing operations](OFFLINE_LICENSING.md) - customer license locations, publisher key custody, license issuance, build verification, and acceptance tests.
- [Root Guard configuration](ROOT_GUARD_CONFIGURATION.md) - CDP-based Root Guard profile and check behavior.
- [Root Guard setup guide](../ROOT_GUARD_SETUP_GUIDE.md) - repository-level deployment guidance.
- [Tester getting started](../TESTER_GETTING_STARTED.md) - pilot testing workflow.
- [Enterprise roadmap](../ENTERPRISE_ROADMAP.md) - planned product work and release direction.

## Legal and release documents

- [End User License Agreement](EULA.md) - formal draft that requires completion and counsel approval before distribution.
- [Release and legal-readiness checklist](RELEASE_LEGAL_CHECKLIST.md) - product-owner actions required before external release.

## Core assurance statement

The v0.2 product uses the exact generated command registry plus the
non-persistent `terminal length 0` session setting. If an Administrator
supplies an enable secret, the session may enter privileged EXEC mode but never
configuration mode. The product makes zero Target Device changes and provides
no remediation path.
