"""Package a tested local Basic build without modifying its golden source."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("built_app", type=Path)
    parser.add_argument("candidate_dir", type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    built_app = args.built_app.resolve(strict=True)
    target = args.candidate_dir.resolve()
    if target.exists():
        parser.error(f"Candidate already exists: {target}")
    if not (built_app / "STIG Audit Basic.exe").is_file():
        parser.error("Built app does not contain STIG Audit Basic.exe")
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("STIG Audit Basic", "build", ".pytest_cache", "__pycache__", "*.pyc"),
    )
    shutil.copytree(built_app, target / "STIG Audit Basic")
    archive = target.with_suffix(".zip")
    with ZipFile(archive, "w", ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(target.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(target.parent))
    print(archive)


if __name__ == "__main__":
    main()
