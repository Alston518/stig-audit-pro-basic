# Basic offline licensing

The 9 October 2026 security update does not change the signed license schema,
product identifier, production key IDs, feature flags, or Free Basic's
one-device limit. Report encryption and SSH host-key verification apply to
free and licensed use. Existing compatible signed Basic licenses remain valid.

Free Basic allows one selected device per audit, with IOS and IOS XE L2/NDM
checks, TXT reports, and CKL checklists. The limit applies to the selected
batch, not to the number of addresses that may be kept in the device list.

To use a supplied license, open **License**, select **Import / Replace
License**, and choose the signed `.license.json` file. Review the customer,
enabled features, UTC expiration, and effective device limit shown by the app.
Basic verifies the signature offline. Editing the JSON invalidates it, and an
invalid import does not replace a previously installed valid license.

A missing, expired, or invalid license returns Basic to free one-device mode.
The inventory and existing reports remain available. A selected batch above
the effective limit is rejected rather than silently reduced.

The license is rechecked before collection and before output is written. If a
license expires during a licensed multi-device run, renew it and rerun. The
installed path normally is:

```text
%LOCALAPPDATA%\STIG Audit Pro Basic\stig-audit-pro.license.json
```

`STIG_AUDIT_BASIC_LICENSE_PATH` may override that location for a managed
deployment or test. License verification does not require internet access.

Licenses are issued out of band by the software owner. Keep customer license
files out of source control, support bundles, and public issues. Publisher key
generation and signing procedures are intentionally maintained outside this
public repository. Only public verification keys are included in builds.

See [docs/03_Basic_Licensing.md](docs/03_Basic_Licensing.md) for the operator
guide and [docs/07_Basic_Encryption_SSH_and_Licensing.md](docs/07_Basic_Encryption_SSH_and_Licensing.md)
for the security update's license impact.
