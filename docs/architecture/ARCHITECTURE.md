# Architecture

STIG Audit Pro uses an incremental layered architecture. Existing parsers and the YAML-driven check engine remain stable domain components; application services now coordinate scans, runs, STIG lifecycle operations, comparison, and reporting without making Tk widgets responsible for those workflows.

## Layers

### GUI

CustomTkinter pages collect operator choices and render events, results, evidence, STIG differences, and history. Worker threads never update widgets directly. The main Tk event loop consumes `ScanEvent` objects from a thread-safe queue with `after()`.

### Application services

- `AuditService` coordinates collection, parsing, and evaluation.
- `ScanOrchestrator` provides bounded per-device concurrency, failure isolation, progress events, and cancellation.
- `RunService` owns persistent run lifecycle, snapshots, evidence metadata, manifests, history, and offline imports.
- `StigLifecycleService` imports versioned benchmarks, compares releases, evaluates YAML impact, and calculates coverage.
- `ReportService` generates reports from internal or persisted result models, never from widget state.

### Core/domain

The check engine, parser engine, result and evidence models, and `CommandPolicy` are infrastructure-independent. `CommandPolicy` is the single authoritative allowlist. YAML validation and live execution both fail closed through that policy.

### Infrastructure

One `NetmikoRunner` is created per device worker and owns exactly one connection. SQLite persistence uses SQLAlchemy 2.x with foreign keys enabled. `EvidenceStore` writes immutable per-run UTF-8 artifacts using a temporary file and atomic replace into a previously unused final path.

### STIG and reports

The STIG library stores multiple releases, normalized rules, field hashes, and overall fingerprints. The difference engine matches by Vuln ID, then Rule ID, then STIG ID, reporting ambiguity instead of guessing. Writers adapt independent `CheckResult` models to TXT, CSV, JSON, XLSX, CKL, and CKLB.

## Dependency direction

```text
GUI -> Application -> Core
                  -> Infrastructure adapters
                  -> STIG/report adapters
```

Core does not depend on CustomTkinter, Netmiko, SQLAlchemy, CKL, or CKLB. See [component.puml](diagrams/component.puml) and [audit_sequence.puml](diagrams/audit_sequence.puml).

## Read-only boundary

The architecture intentionally has no remediation service or configuration adapter. Session setup may enter privileged EXEC and issue the registered `terminal length 0` operation. Device commands are otherwise exact-match, read-only inventory commands. Configuration mode, saves, reloads, command chaining, and unregistered YAML commands are rejected before connection.
