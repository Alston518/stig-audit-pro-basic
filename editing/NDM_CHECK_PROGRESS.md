# IOS-XE NDM Check Validation Progress

Last updated: 2026-07-29

Status meanings:

- `[x]` Completed for the current implementation: live-tested automation or an explicitly approved temporary result.
- `[ ]` Still needs individual live testing.
- `[~]` Intentionally deferred with a documented temporary result.

Progress: **42 of 42 completed for the current implementation**

## Individual Checks

- [x] V-220518 - Profile-defined concurrent VTY management-session limit
- [x] V-220519 - Archive log configuration auditing for account creation
- [x] V-220520 - Archive log configuration auditing for account modification
- [x] V-220521 - Archive log configuration auditing for account disabling
- [x] V-220522 - Archive log configuration auditing for account removal
- [x] V-220523 - Profile-approved management ACL applied inbound to every VTY section
- [x] V-220524 - Block logins for 900 seconds after three failed attempts within 120 seconds
- [x] V-220525 - Standard Mandatory DoD Notice and Consent text in the login banner
- [x] V-220526 - Administrator activity logging with logging userinfo
- [x] V-220528 - Millisecond localtime log timestamps with timezone and year
- [x] V-220529 - Log-input on deny statements in interface-bound IPv4 ACLs
- [x] V-220530 - Archive log configuration auditing for privileged commands
- [x] V-220531 - Temporarily Not Applicable because logging persistent is not configured
- [x] V-220532 - Temporarily Not Applicable because logging persistent is not configured
- [x] V-220533 - Temporarily Not Applicable because logging persistent is not configured
- [x] V-220534 - Prohibited and unnecessary services are disabled
- [x] V-220535 - One local fallback account using the required password policy and TACACS-first AAA order
- [x] V-220537 - Minimum password length configured under the required common-criteria policy
- [x] V-220538 - Uppercase-character requirement configured under the required policy
- [x] V-220539 - Lowercase-character requirement configured under the required policy
- [x] V-220540 - Numeric-character requirement configured under the required policy
- [x] V-220541 - Special-character requirement configured under the required policy
- [x] V-220542 - Eight password-position changes configured under the required policy
- [x] V-220543 - Service password encryption enabled
- [x] V-220544 - Five-minute inactivity timeout configured under every VTY section
- [x] V-220545 - Archive log configuration auditing for account enabling
- [x] V-220547 - Buffered logging with numeric capacity and valid severity
- [x] V-220548 - Remote logging with a valid named trap severity
- [x] V-220549 - At least two profile-defined authoritative NTP servers
- [x] V-220552 - SNMPv3 SHA/SHA-2 HMAC authentication protocol
- [x] V-220553 - SNMPv3 AES-128/192/256 privacy protocol
- [x] V-220554 - Trusted HMAC-SHA2-256 authentication on every profile-defined NTP server
- [x] V-220555 - Approved SSH HMAC-SHA2 algorithm list
- [x] V-220556 - Approved SSH AES-CTR encryption algorithm list
- [x] V-220559 - Archive log configuration auditing for deleted administrator privileges
- [x] V-220560 - Successful and failed login attempt logging
- [x] V-220561 - Archive log configuration auditing for privileged activities
- [x] V-220565 - Two profile-defined RADIUS servers with ports, keys, and AAA group membership
- [x] V-220566 - Temporarily NotAFinding; backups performed through Cisco Catalyst Center
- [x] V-220567 - Not Applicable; no organization-managed public key certificates are used
- [x] V-220568 - At least two profile-defined central logging servers
- [x] V-220569 - Installed IOS-XE release matches the profile-supported version allowlist

## Combined NDM Testing

- [ ] Run all completed checks together against a known-compliant switch
- [ ] Run all completed checks together against a switch with known findings
- [ ] Run the complete NDM library against multiple representative switches
- [ ] Review Open, Error, and Not_Reviewed results for false positives
- [ ] Confirm final NDM YAML validation and automated test suite
