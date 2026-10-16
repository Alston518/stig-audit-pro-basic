"""Encrypted audit outputs for the Basic desktop workflow."""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_data_path

from stig_audit_pro.infrastructure.security.at_rest import AtRestVault


PROTECTED_SUFFIX = ".sapenc"
REPORT_SUFFIXES = frozenset({".txt", ".ckl", ".csv", ".html", ".pdf"})


def default_vault_path() -> Path:
    """Keep Basic's passphrase metadata separate from Pro and signed licenses."""

    return user_data_path("STIG Audit Pro Basic", appauthor=False, roaming=False) / "audit-vault.json"


class ProtectedArtifactStore:
    """Write reports as ciphertext; release plaintext only by explicit export."""

    def __init__(self, vault: AtRestVault) -> None:
        self.vault = vault

    @staticmethod
    def _original_name(protected: Path) -> str:
        if protected.suffix.lower() != PROTECTED_SUFFIX:
            raise ValueError("Choose a Basic protected report (.sapenc)")
        original = protected.name[: -len(PROTECTED_SUFFIX)]
        if Path(original).suffix.lower() not in REPORT_SUFFIXES:
            raise ValueError("Unsupported protected report type")
        return original

    @staticmethod
    def _association(original_name: str) -> str:
        return "basic-report/" + original_name

    def save(self, clear_path: str | Path, contents: bytes) -> Path:
        clear = Path(clear_path).expanduser()
        if clear.suffix.lower() not in REPORT_SUFFIXES:
            raise ValueError("Unsupported Basic report type")
        if clear.exists():
            raise FileExistsError(f"Refusing to replace a readable report: {clear}")
        protected = clear.with_name(clear.name + PROTECTED_SUFFIX)
        protected.parent.mkdir(parents=True, exist_ok=True)
        self.vault.write_file(
            protected,
            contents,
            self._association(clear.name),
            replace=False,
        )
        return protected

    def read(self, protected_path: str | Path) -> bytes:
        protected = Path(protected_path).expanduser()
        original_name = self._original_name(protected)
        return self.vault.read_file(protected, self._association(original_name))

    def export(self, protected_path: str | Path, destination: str | Path) -> Path:
        """Create a readable copy after a deliberate operator action."""

        protected = Path(protected_path).expanduser()
        original_name = self._original_name(protected)
        clear = Path(destination).expanduser()
        if clear.suffix.lower() != Path(original_name).suffix.lower():
            raise ValueError("The export must keep the report's original file type")
        plaintext = self.read(protected)
        clear.parent.mkdir(parents=True, exist_ok=True)
        created = False
        try:
            with clear.open("xb") as handle:
                created = True
                handle.write(plaintext)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException as exc:
            # A failed write or sync must not leave a readable partial report.
            # Only remove a destination that this call created; an existing
            # destination makes open("xb") fail without touching its contents.
            if created:
                try:
                    clear.unlink(missing_ok=True)
                except OSError as cleanup_error:
                    raise OSError(
                        f"Export failed and an unencrypted file may remain at {clear}: "
                        f"{cleanup_error}"
                    ) from exc
            raise
        return clear
