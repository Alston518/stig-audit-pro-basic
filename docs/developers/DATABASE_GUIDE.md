# Database Guide

STIG Audit Pro uses an embedded SQLite database through SQLAlchemy 2.0. No server is required. The default location is returned by `default_database_path()` and follows `platformdirs` application-data conventions. Startup logs the resolved path without logging evidence or credentials.

## Initialization and versions

`Database` creates parent directories as needed, enables SQLite foreign keys for every connection, and calls the migration initializer. `schema_version` is a singleton integer record. Schema v2 adds the secret-free `activity_log`; schema v3 preserves the STIG title on historical check results. Before an existing on-disk database is migrated forward, startup creates a timestamped `.bak` beside it. A database newer than the application supports fails closed; upgrades never reset user history.

Editable checks, profiles, device groups, presets, and imported STIG working
files also live beneath the platform application-data directory. Startup copies
missing bundled defaults into that working directory atomically and never
replaces an existing customer-edited file. Repository `data/` remains the
distribution source for defaults, not the runtime edit location.

## Repositories

Application code uses `AuditRunRepository`, `StigPersistenceRepository`, and `ActivityLogRepository` instead of holding ORM sessions. Repository operations open short transactions and return detached records with required relationships eagerly loaded.

## Development and tests

Inject a `tmp_path` database (or the explicitly supported in-memory configuration) into every test. Assert foreign keys are enabled. Deleting an audit run cascades structured child rows; `EvidenceStore` owns raw filesystem deletion/purge as a separate, explicit action.

Do not add passwords, enable secrets, license keys, or full raw command output columns. Evidence metadata belongs in SQLite; evidence bytes belong in the run tree.
