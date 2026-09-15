# Getting Started

## Install and launch

Use Python 3.11 or 3.12 on Windows:

```powershell
python -m pip install -r requirements.txt
python app.py
```

On first launch, the app creates `Documents\STIG Audit Pro\Workspace` with numbered folders for STIG packages, blank CKLs, imports, completed CKLs, reports, backups, and exports. See [Files and Folders](FILES_AND_FOLDERS.md).

The database, editable checks/profiles, imported release library, and historical evidence use protected platform application data rather than the current working directory. Open their exact locations from **Administration → Files & Folders**. Bundled defaults and sample output remain under `data/` and `tests/sample_outputs/` in a source checkout.

## First audit

1. Open **Audit Run** and select a saved group or enter targets.
2. Select L2, NDM, or both and choose a profile.
3. For a safe demonstration, use sample output. For devices, choose Live SSH and enter session-only credentials.
4. Select concurrency from 1–20 (default 5), then start.
5. Watch per-device status and open **Results** for findings.
6. Use **Evidence**, **Reports**, or **History** after completion.

Passwords and enable secrets are kept only for the operation and are cleared from GUI variables when practical. They are never stored in presets, runs, manifests, or logs.

## Safety expectation

STIG Audit Pro is assessment-only. It does not enter configuration mode, save configuration, reload equipment, or apply fix text. A command not explicitly registered in `CommandPolicy` is rejected before connection.
