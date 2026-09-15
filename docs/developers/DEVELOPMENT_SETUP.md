# Development Setup

Use Python 3.11 or 3.12 on Windows. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest
python app.py
```

Runtime dependency ranges intentionally stay on Pydantic 2, Netmiko 4, SQLAlchemy 2.0, and openpyxl 3. The app has no database server and no mandatory Internet dependency for auditing.

## Quality commands

```powershell
python -m pytest
python scripts/generate_command_reference.py --check
python scripts/generate_stig_traceability.py --check
python scripts/validate_docs.py
```

Use temporary SQLite paths in tests. Never point tests at the platform application database. Mock or fake SSH workers; tests must not require Cisco hardware.

## Packaging

Build the Windows one-folder distribution with:

```powershell
pyinstaller --clean stig-audit-pro.spec
```

The spec includes application data, CustomTkinter assets, SQLAlchemy modules, and runtime resources. Verify the packaged executable can create its database/evidence directories under application data rather than under the read-only bundle.
