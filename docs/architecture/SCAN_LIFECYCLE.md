# Scan Lifecycle

Every scan begins with a UUID and an `AuditRun` in `CREATED`, then enters `RUNNING`. Profile and check-library snapshots are written before device work. Unsafe YAML or a command-policy violation aborts before an SSH connection is attempted.

Each device progresses through `QUEUED`, `CONNECTING`, `COLLECTING`, `PARSING`, `EVALUATING`, and `COMPLETE`. Terminal states also include `AUTH_FAILED`, `CONNECT_FAILED`, `COLLECTION_FAILED`, `EVALUATION_FAILED`, and `CANCELLED`.

`ScanOrchestrator` uses a `ThreadPoolExecutor` with a default concurrency of five and a configured range of one through twenty. It incrementally submits work, isolates device exceptions, and posts status events to a queue. Cancellation stops new submissions, attempts to cancel queued futures, and signals active workers; each worker checks the signal between approved commands and disconnects cleanly.

For successful collection, exact UTF-8 output is written and hashed once. Parsing and evaluation produce results linked to relevant evidence artifact IDs. Device facts/results are persisted, then counts and terminal run status are calculated:

- `COMPLETE`: every device completed successfully.
- `PARTIAL`: at least one success and at least one failure/cancellation.
- `FAILED`: no device completed and at least one failed.
- `CANCELLED`: the run was cancelled without a mixed successful outcome.

A finalized manifest is generated last. Offline imports use the same evaluation, hash, snapshot, and manifest lifecycle but carry `collection_mode: OFFLINE_IMPORTED`; the application does not claim it collected that source evidence.

See [audit_sequence.puml](diagrams/audit_sequence.puml).
