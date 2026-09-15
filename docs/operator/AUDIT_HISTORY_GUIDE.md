# Audit History Guide

Each assessment has a UUID and immutable profile/check snapshots. History lists its UTC date, ID, description or preset, STIG families/release, profile, device/result counts, and status.

## Actions

- **Open Run** loads persisted findings and metadata without contacting a device.
- **Compare Runs** classifies each device + Vuln ID as new, resolved, persistent, unchanged pass, changed status/applicability, or not comparable.
- **Export Reports** regenerates supported formats from persisted data.
- **Export Package** creates a portable, integrity-indexed historical audit.
- **Import Package** verifies and opens an audit exported by another STIG Audit
  Pro installation. It is clearly labeled **Imported historical audit** and no
  SSH connection is made.
- **Verify Evidence** recalculates hashes and reports `VALID`, `MISSING`, `MODIFIED`, or `UNREADABLE`.
- **Purge Raw Evidence** removes source files but preserves structured results and their historical context.
- **Delete Run** removes the selected structured history and associated local artifacts when requested.

Destructive actions require confirmation. There is no default automatic expiration.

## Compatibility

Comparison checks rule/STIG fingerprints. When versions differ and a rule materially changed, it is `NOT_COMPARABLE` rather than incorrectly presented as the same test. Hashes detect post-collection file changes; they do not establish collector identity, custody, or device authenticity.

An imported package keeps its original run UUID, timestamps, results, profile
and check snapshots, and evidence hashes. Import refuses an invalid, modified,
unsafe, or duplicate run instead of replacing existing history.
