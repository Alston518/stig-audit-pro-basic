# Release and legal-readiness checklist

This checklist is for the product owner. It is not part of the end-user agreement and is not legal advice.

## Required before external distribution

- [ ] Replace every bracketed item in [EULA](EULA.md), including Licensor identity, effective date, contacts, governing law, venue, cure period, and liability cap.
- [ ] Have qualified counsel approve the EULA for the intended customer type, sales model, jurisdiction, and acceptance mechanism.
- [ ] Decide whether this repository is proprietary, source-available, or open source and add a root license file that matches the commercial and distribution model.
- [ ] Decide whether the EULA applies per user, per device, per organization, per subscription, or under a negotiated enterprise agreement.
- [ ] Add an explicit acceptance flow to the installer or first launch, preserve the accepted EULA version and timestamp, and make the terms available before acceptance.
- [ ] Review government procurement requirements separately. Address data rights, records, disputes, security clauses, accessibility, sovereign immunity, and order-of-precedence in a signed government addendum where applicable.
- [ ] Produce an SBOM and complete third-party notices from the exact release build. Verify every dependency license and required attribution.
- [ ] Confirm rights to distribute bundled check content, sample output, templates, logos, names, and other third-party material.
- [ ] Obtain trademark review for the product name and all uses of `STIG`, `Cisco`, `IOS-XE`, `DoD`, and `DISA`.
- [ ] Approve a privacy/data-handling notice for the actual deployment and support model, including evidence transfer and support-data practices.
- [ ] Publish support, vulnerability-disclosure, maintenance, end-of-life, and version-support contacts.

## Technical claim verification

- [ ] Re-run the complete automated test suite on the release artifact.
- [ ] Review every command reachable through the GUI and every bundled check pack; archive the approved command inventory with the release.
- [ ] Confirm the live runner contains no configuration-mode, configuration-set, save, commit, erase, reload, or remediation path.
- [ ] Confirm sample mode performs no network connection.
- [ ] Confirm credentials are not deliberately written to cached command output, reports, logs, or crash diagnostics.
- [ ] Treat cached command output as unredacted sensitive data and document access-control, encryption, retention, overwrite, and secure-deletion requirements.
- [ ] Validate the implemented per-run isolation, SHA-256 evidence verification, and retention/purge behavior against the release artifact. Evidence remains sensitive and is not automatically redacted.
- [ ] Confirm all outbound network destinations and verify the no-telemetry statement against the packaged artifact.
- [ ] Confirm bundled check counts, automation coverage, source STIG identities, parser versions, and known limitations.
- [ ] Sign the application and any installer, publish cryptographic hashes, and establish a trusted release/update channel before production distribution.

## Command-boundary verification

v0.2 uses an exact allowlist in `CommandPolicy`, not a prefix validator. Check
that the generated command reference matches the packaged registry and that
unsafe YAML fails before connection:

- [ ] run `python scripts/generate_command_reference.py --check`;
- [ ] run command-policy tests, including chaining/control-character attempts;
- [ ] confirm `terminal length 0` is the only session operation; and
- [ ] pair application validation with device-side command authorization on the scan account.

## Documentation consistency

- [ ] Update the product version in the EULA, overview, command reference, installer, package metadata, and About screen.
- [ ] Reconcile README, changelog, roadmap, check counts, and supported-platform statements.
- [ ] Link the EULA, product overview, command reference, Administrator guide, security/data guide, third-party notices, privacy notice, and support policy from the distribution entry point.
- [ ] Record the approver and approval date for legal, security, product, and release engineering review.
