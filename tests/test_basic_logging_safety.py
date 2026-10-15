"""The Basic diagnostic log must not persist exception-provided text."""

import logging

from stig_audit_pro.logging_config import SafeContextFilter


def test_exception_text_is_not_written_to_plaintext_log(tmp_path):
    log_path = tmp_path / "basic.log"
    logger = logging.getLogger("tests.basic_logging_safety")
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.addFilter(SafeContextFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)

    try:
        try:
            raise RuntimeError("password=training-only arbitrary-device-output-marker")
        except RuntimeError as exc:
            logger.exception("Audit step failed: %s", exc)
    finally:
        logger.removeHandler(handler)
        handler.close()

    written = log_path.read_text(encoding="utf-8")
    assert "RuntimeError" in written
    assert "test_basic_logging_safety" in written
    assert "training-only" not in written
    assert "arbitrary-device-output-marker" not in written


def test_vendor_transport_messages_and_device_identifiers_are_not_logged(tmp_path):
    path = tmp_path / "basic.log"
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.addFilter(SafeContextFilter())
    handler.setFormatter(logging.Formatter("%(device_ip)s %(hostname)s %(message)s"))
    logger = logging.getLogger("tests.basic_safe_context")
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    logger.addHandler(handler)
    vendor = logging.getLogger("netmiko.connection")
    vendor.setLevel(logging.WARNING)
    vendor.propagate = False
    vendor.addHandler(handler)
    try:
        logger.warning("audit stage ready", extra={"device_ip": "192.0.2.10", "hostname": "SENSITIVE-SW"})
        vendor.warning("raw SSH banner SENSITIVE-DEVICE-OUTPUT")
    finally:
        logger.removeHandler(handler)
        vendor.removeHandler(handler)
        handler.close()

    written = path.read_text(encoding="utf-8")
    assert "audit stage ready" in written
    assert "192.0.2.10" not in written
    assert "SENSITIVE-SW" not in written
    assert "SENSITIVE-DEVICE-OUTPUT" not in written
