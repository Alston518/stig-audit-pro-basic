# STIG Audit Pro Basic

STIG Audit Pro Basic is the simple, offline-friendly edition for running the
existing YAML-driven Cisco IOS-XE checks and producing a DISA CKL and plain
text report. It supports one or many devices, pasted addresses or CSV/TXT
imports, sample fixtures (no network required), and live SSH using only the
central read-only command policy.

## Start

```text
python -m pip install -r requirements.txt
python app.py
```

For a first run choose **Sample outputs**, paste addresses (an address ending
in `.26` uses the bundled non-compliant fixture), select a profile, and click
**Start Audit**. Text reports are written to `Documents/STIG Audit Pro
Basic/Workspace/Reports`. CKLs are written to `Workspace/Completed CKLs` when
you select a DISA CKL template for the corresponding family.

Editable checks and profiles are copied on first launch to the per-user data
directory shown by the application. They are never overwritten by later
launches. Credentials are session-only and are not written to disk.

This project intentionally does not include licensing, STIG comparison,
database/history, complex reports, or remediation. The network boundary is
read-only: configuration mode, writes, reloads, and copy/save commands are not
approved by the command policy.
