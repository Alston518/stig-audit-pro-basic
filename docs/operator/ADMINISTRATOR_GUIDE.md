# Administrator Guide

## Targets, groups, and presets

Targets may be entered individually or selected from YAML-backed device groups. A scan preset can reference a group/target scope, STIG families, profile, bounded concurrency, timeouts, and report choices. Presets intentionally cannot contain credentials.

## Profiles and checks

The **Profiles** page offers typed fields for common VLANs, DHCP snooping, ARP inspection, trunk pruning, management networks, RADIUS servers, root-guard inputs, and arbitrary profile variables. The app validates a complete `SiteProfile` before atomically saving YAML.

The **Checks** page provides a simple editor for strings/patterns and an advanced YAML editor. Both paths validate the strict Pydantic schema and central command policy before saving. Unknown keys and unsupported schema versions fail closed.

## Running audits

Live audits use one Netmiko connection per worker. Set concurrency between 1 and 20; five is the default. A device failure does not abort unrelated devices. **Cancel Remaining** stops new submissions, cancels queued work where possible, and signals active workers to stop between commands and disconnect.

Sample and offline evidence workflows evaluate through the same parser/check path. To import restricted-environment evidence, open **Evidence → Import Offline Evidence**, choose a directory containing recognized command-output filenames (such as `show_running_config.txt` and `show_version.txt`), and supply the target identifier. The resulting run is visibly labeled `OFFLINE_IMPORTED`; no SSH connection is made and the application does not imply it collected the files.

## Historical data

Completed runs remain until an operator explicitly deletes them. **Purge Raw Evidence** removes command-output files while retaining structured history. **Delete Run** removes structured history and, when selected, its evidence tree. Both operations require confirmation.

## Backup and restore

Open **Administration → Back Up Data** to create an integrity-indexed archive
of the database, profiles, device groups, checks, STIG working library, and
scan presets. Raw evidence is excluded from the standard GUI backup.

Use **Restore Data** only when replacing the current local application state.
The application validates archive paths, contents, hashes, and the SQLite
schema before showing the destructive confirmation. It creates a timestamped
safety backup, publishes only known STIG Audit Pro destinations, rolls back a
partial publication, and closes after success so the restored database is
reopened cleanly. Credentials are not restored because the product does not
store device credentials.

## Licensing

Free/paid device limits and licensed feature checks remain enforced. License payloads and private signing material are not included in audit metadata.
