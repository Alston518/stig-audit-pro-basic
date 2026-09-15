"""Application logging configured for customer-safe diagnostics."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Mapping

from stig_audit_pro.licensing.paths import log_directory


_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|enable[_ -]?secret|secret)\b\s*[:=]\s*([^\s,;]+)"
)


class SafeContextFilter(logging.Filter):
    """Add structured audit fields and redact common credential renderings."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", rendered)
        record.args = ()
        for name in ("run_id", "device_ip", "hostname", "audit_stage", "error_type"):
            if not hasattr(record, name):
                setattr(record, name, "-")
        return True


class AuditLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter carrying safe audit context without evidence content."""

    def process(self, msg: object, kwargs: dict[str, Any]) -> tuple[object, dict[str, Any]]:
        supplied = kwargs.setdefault("extra", {})
        supplied.update({key: value for key, value in self.extra.items() if value is not None})
        return msg, kwargs


def audit_logger(
    logger: logging.Logger,
    *,
    run_id: str | None = None,
    device_ip: str | None = None,
    hostname: str | None = None,
    audit_stage: str | None = None,
    error_type: str | None = None,
) -> AuditLoggerAdapter:
    return AuditLoggerAdapter(
        logger,
        {
            "run_id": run_id or "-",
            "device_ip": device_ip or "-",
            "hostname": hostname or "-",
            "audit_stage": audit_stage or "-",
            "error_type": error_type or "-",
        },
    )


def configure_logging() -> Path | None:
    """Configure a rotating-free first-version log without failing app startup."""

    # Paramiko emits authentication banners and Netmiko may emit command/session
    # detail at INFO/DEBUG. Those bytes belong in the evidence store, never in
    # routine application diagnostics or a support bundle.
    for logger_name in ("paramiko", "netmiko", "scp"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return None
    safe_filter = SafeContextFilter()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s "
        "run_id=%(run_id)s device=%(device_ip)s hostname=%(hostname)s "
        "stage=%(audit_stage)s error=%(error_type)s: %(message)s"
    )
    stream = logging.StreamHandler()
    stream.addFilter(safe_filter)
    stream.setFormatter(formatter)
    root_logger.addHandler(stream)
    root_logger.setLevel(logging.INFO)
    try:
        directory = log_directory()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "stig-audit-pro.log"
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.addFilter(safe_filter)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        return path
    except OSError:
        logging.getLogger(__name__).warning(
            "Could not create the application log file; continuing with console logging"
        )
        return None


__all__ = ["AuditLoggerAdapter", "SafeContextFilter", "audit_logger", "configure_logging"]
