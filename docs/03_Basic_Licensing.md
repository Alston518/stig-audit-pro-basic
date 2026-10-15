# Basic offline licensing

The 9 October 2026 security update does not change the signed license schema,
product identifier, production key IDs, feature flags, or Free Basic's
one-device limit. Report encryption and SSH host-key verification apply to
free and licensed use. Existing compatible signed Basic licenses remain valid.

## Free operation

Free Basic allows one explicitly selected device per audit, with IOS and IOS
XE L2/NDM checks, TXT reports, and CKL checklists. You may keep any number of
addresses in the device box. Choose **Select devices**, select one target, and
then choose **Use selection**. The limit applies to the selected batch, not to
a lifetime device count.

## Import a license

For a larger allowed batch, open **License** and choose **Import / Replace
License**. Select the signed `.license.json` supplied by the software owner.
Confirm the displayed customer, enabled features, UTC expiration, and
effective device limit.

Basic verifies the signature locally. Editing the JSON invalidates it. An
invalid import does not overwrite a previously installed valid license. A
missing, expired, or invalid license returns Basic to free one-device mode;
the inventory and existing protected reports remain available.

A batch above the effective limit is rejected rather than silently reduced.
The license is checked before collection and again before output is written.
If it expires during a licensed multi-device run, renew it and rerun. Each app
window permits one audit job at a time; offline licensing does not coordinate
concurrent installations.

## Storage and handling

The License tab displays the exact installed path. It normally is:

```text
%LOCALAPPDATA%\STIG Audit Pro Basic\stig-audit-pro.license.json
```

`STIG_AUDIT_BASIC_LICENSE_PATH` may override that path for a managed
deployment or test. Signature verification requires no internet connection.
The report-encryption passphrase does not encrypt or unlock the license file.

Licenses are issued out of band by the software owner. Do not edit an issued
license or include it in source control, support bundles, screenshots, or
public issues. Publisher signing procedures and private keys are intentionally
kept outside this public repository. Customer builds contain public
verification keys only.

## Compatibility

The signed product identifier remains unchanged for compatibility with
existing Basic license files. No new entitlement or signing key is required
for encrypted `.sapenc` reports or strict SSH host-key checking. If a license
does not validate, confirm that it was issued for this application, has not
expired, and has not been modified, then request a replacement from the
software owner.
