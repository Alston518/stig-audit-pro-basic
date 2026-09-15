# Files and Folders

## What this does

This guide explains where STIG Audit Pro keeps operator files and protected application data.

## When you use it

Use this guide when importing a STIG or device list, selecting a blank CKL, finding a completed checklist/report, backing up the application, or making advanced check/profile edits.

## Operator workspace

STIG Audit Pro creates this easy-to-find folder on Windows:

```text
C:\Users\<you>\Documents\STIG Audit Pro\Workspace
```

Its numbered folders have one purpose each:

| Folder | Put or find this here |
|---|---|
| `01 - STIG Packages` | New DISA STIG ZIP/XML downloads |
| `02 - Blank CKL Templates` | Blank/current L2, NDM, or combined CKLs exported from DISA STIG Viewer |
| `03 - Device Imports` | CSV/TXT device lists; never credentials |
| `04 - Offline Evidence` | Previously collected command-output folders for offline import |
| `05 - Completed CKLs` | CKLs populated by completed live audits |
| `06 - Reports` | TXT, CSV, JSON, and XLSX reports |
| `07 - Audit Packages` | Portable historical-audit ZIP files |
| `08 - Backups` | Application backup ZIP files |
| `09 - Support Bundles` | Sanitized diagnostic ZIP files |
| `10 - STIG Comparisons` | Exported STIG release-difference reports |

File dialogs now begin in the matching folder. Open **Administration → Files & Folders → Open Workspace** at any time.

## App-managed data

The running Windows application protects its working data under:

```text
C:\Users\<you>\AppData\Local\STIG Audit Pro
```

Important locations are:

| Location | Contents |
|---|---|
| `data\checks` | Editable L2/NDM YAML checks and generated manual starters |
| `data\profiles` | Base and Site Profile YAML |
| `data\device_groups` | Saved device groups |
| `data\stigs` | Imported/cached STIG source files |
| `data\stig-audit-pro.sqlite3` | Audit history, results, STIG releases, mappings, and activity records |
| `scan_presets` | Saved scan presets |
| `work\runs` | Per-run manifests, snapshots, results, and immutable raw evidence |
| `logs` | Sanitized application logs |

Use **Administration → Files & Folders** to open the workspace, editable checks, Site Profiles, or all application data directly. Normal operators should use the GUI editors and backup tools instead of manually modifying AppData. Advanced YAML remains available in the Checks and Profiles screens.

## Source checkout

The Git repository is application source code, tests, bundled defaults, and documentation. Its root `data` directory contains defaults shipped with a build; those files are copied into application data only when missing. Customer changes belong to the app-managed copies and are not overwritten on startup.

Do not put credentials in the source checkout, operator workspace, YAML files, presets, reports, or backups. Device credentials remain session-only.
