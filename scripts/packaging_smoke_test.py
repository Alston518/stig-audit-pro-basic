#!/usr/bin/env python3
"""Check that the PyInstaller specification covers required runtime assets."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    "app.py", "stig-audit-pro.spec", "data/checks/iosxe_l2.yaml",
    "data/checks/iosxe_ndm.yaml", "data/profiles/base_iosxe_access.yaml",
    "docs/operator/FIRST_AUDIT.md",
)
REQUIRED_SPEC_TEXT = ("sqlalchemy.dialects.sqlite", "openpyxl", 'project_root / "data"', 'project_root / "docs"')


def main() -> int:
    errors = [f"Missing runtime asset: {name}" for name in REQUIRED_PATHS if not (ROOT / name).is_file()]
    spec = (ROOT / "stig-audit-pro.spec").read_text(encoding="utf-8")
    errors.extend(f"Packaging spec is missing: {value}" for value in REQUIRED_SPEC_TEXT if value not in spec)
    if errors:
        print("\n".join(errors))
        return 1
    print("Packaging inputs and hidden runtime dependencies are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
