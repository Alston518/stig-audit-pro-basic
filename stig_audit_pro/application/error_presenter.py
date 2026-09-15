"""Translate technical failures into useful operator messages and guidance."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UserFacingError:
    title: str
    message: str
    guidance: str
    technical_details: str


def explain_error(error: BaseException | str, *, device: str | None = None) -> UserFacingError:
    details = str(error)
    text = f"{type(error).__name__ if isinstance(error, BaseException) else ''} {details}".lower()
    subject = device or "The device"
    if "auth" in text or "password" in text or "permission denied" in text:
        return UserFacingError("Authentication failed", f"Authentication failed for {subject}.", "Verify the SSH username/password, privilege level, and SSH access.", details)
    if "timeout" in text or "timed out" in text:
        return UserFacingError("Connection timed out", f"{subject} did not respond before the connection timeout.", "Verify the address, routing, ACLs, and SSH service.", details)
    if "not approved" in text or "unsafecommand" in text or "command rejected" in text:
        return UserFacingError("Command rejected", "A check requested a command that is not approved by STIG Audit Pro's read-only policy.", "Validate the check pack and replace the command with an approved evidence command.", details)
    if "profile" in text and ("missing" in text or "valid" in text or "required" in text):
        return UserFacingError("Site Profile needs attention", "The selected Site Profile is missing or contains an invalid value.", "Open the Site Profile and complete the required value.", details)
    return UserFacingError("Operation failed", "STIG Audit Pro could not complete the operation.", "Review Technical Details and the application log, then retry.", details)


__all__ = ["UserFacingError", "explain_error"]
