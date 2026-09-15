# Troubleshooting

## What this does

Provides recovery guidance for common operator problems.

## When you use it

Use it when readiness fails, a device cannot complete, or evidence verification reports a warning.

- **Authentication failed:** verify the SSH username/password, privilege level, and account access.
- **Connection timed out:** verify address, routing, ACLs, and the device SSH service.
- **Command rejected:** validate the check pack. YAML cannot grant command authority; only the central read-only policy can approve a command.
- **Profile needs attention:** open Profiles and supply the required organization-defined value.
- **Evidence modified:** retain the run and investigate. The stored bytes no longer match their capture hash.
- **Evidence missing:** determine whether raw evidence was purged intentionally. Structured history may remain.
- **Application diagnostics:** open **Administration** to verify database/evidence health, create a sanitized support bundle, or back up application data.
- **Restore a backup:** use **Administration → Restore Data**. Review the
  confirmation carefully; a safety backup is created first and the application
  closes after a successful restore.

Support bundles exclude credentials, signing keys, raw evidence, and full running configurations by default.
