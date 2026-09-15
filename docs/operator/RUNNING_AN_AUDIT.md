# Running an Audit

## What this does

Describes preflight, concurrent evidence collection, cancellation, and recovery.

## When you use it

Use this for every live or offline assessment.

The guided workflow is Devices → STIG → Site Profile → Readiness. Preflight validates targets, duplicates, addresses, profile values, STIG/check selection, command safety, database access, writable evidence/report paths, and disk-space sanity before network access. Blocking issues prevent the audit; warnings do not.

Live audits default to five workers and support one through twenty. Each worker owns one Netmiko connection. Workers publish progress through a queue; only the Tk main thread updates widgets. **Cancel Remaining** stops new work, cancels queued work, and asks active workers to disconnect between commands.

Use **Retry Failed** from History after correcting the cause. Successful devices are not rerun, and the retry is retained as a separate run rather than overwriting the failure.
