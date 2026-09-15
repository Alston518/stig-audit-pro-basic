# Your First Audit

## What this does

Walks a new operator from an empty installation to a completed read-only assessment.

## When you use it

Use this after installation or when onboarding a new assessor.

1. Launch `python app.py` and select **Run an Audit** on the welcome page.
2. In **Audit Run**, add switch IP addresses individually, paste a list, import a CSV, or load a saved group. CSV import previews valid, duplicate, and invalid entries.
3. Open **STIG Update Center**, choose L2 or NDM, and import the official DISA ZIP/XML. Older releases remain installed.
4. Open **Profiles**, select or copy a Site Profile, and enter the site values such as management VLAN, unused VLAN, approved management networks, RADIUS servers, NTP servers, and logging servers. Validate before saving.
5. Return to **Audit Run**. Choose Live SSH, enter the session-only username/password and optional enable secret, select STIG families, concurrency, report output, and checklist templates.
6. Open **Start an Assessment** and review Devices, STIG, Site Profile, and Readiness. Blocking issues must be corrected before SSH begins; warnings describe work that can be completed later.
7. Select **Start Audit**. The application makes one connection per active worker and runs only approved read-only commands.
8. Review the device stages. A failed device does not stop other devices. Use History **Retry Failed** after correcting connectivity or credentials; the retry is a separate linked audit description.
9. In **Results**, filter or search findings. Select a result to see why it received that status and which evidence/site settings were used.
10. Complete **Manual Review Required** items using DISA check guidance. Export TXT, CSV, JSON, XLSX, CKL, or CKLB as appropriate.
11. Open **History** to reopen the assessment later, verify evidence integrity, compare audits, or export a portable audit package.

Credentials are held only in memory for the session and cleared after the operation.
