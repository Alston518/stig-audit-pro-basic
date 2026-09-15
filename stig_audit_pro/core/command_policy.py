"""Authoritative, fail-closed policy for commands sent to audited devices.

Only commands registered in :data:`APPROVED_COMMAND_REGISTRY` may be sent by
the application.  Check YAML is input, not authority: declaring a command in a
check pack never adds it to this registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable
import unicodedata


class UnsafeCommandError(ValueError):
    """Raised when a command is malformed, unapproved, or potentially unsafe."""


@dataclass(frozen=True, slots=True)
class ApprovedCommand:
    """One fixed command approved for read-only audit collection."""

    command: str
    purpose: str
    default_collection: bool = False
    session_only: bool = False


# This is the one authoritative runtime command registry.  Report/documentation
# generators should consume it rather than maintain their own command lists.
APPROVED_COMMAND_REGISTRY: Final[tuple[ApprovedCommand, ...]] = (
    ApprovedCommand(
        "terminal length 0",
        "Disable terminal pagination for this SSH session.",
        default_collection=True,
        session_only=True,
    ),
    ApprovedCommand(
        "show running-config",
        "Collect the active configuration for audit evaluation.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show version",
        "Collect software version and platform facts.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show inventory",
        "Collect installed hardware inventory.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show vtp status",
        "Collect VTP operational state.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show vlan brief",
        "Collect the VLAN inventory.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show interfaces status",
        "Collect interface link, VLAN, and operational state.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show interfaces trunk",
        "Collect trunk state and allowed VLANs.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show cdp neighbors detail",
        "Collect directly connected neighbor evidence.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show ip access-lists",
        "Collect IPv4 access-list definitions and counters.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show ip dhcp snooping",
        "Collect DHCP snooping state.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show ip arp inspection",
        "Collect Dynamic ARP Inspection state.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show logging",
        "Collect logging state.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show clock",
        "Collect the device clock value.",
        default_collection=True,
    ),
    ApprovedCommand(
        "show snmp user",
        "Collect SNMPv3 user security settings.",
    ),
    ApprovedCommand(
        "show running-config | include ssh",
        "Collect SSH-related active configuration lines.",
    ),
    ApprovedCommand(
        "show interfaces switchport | include Negotiation of Trunking",
        "Collect interface trunk-negotiation state.",
    ),
)

APPROVED_COMMANDS: Final[tuple[str, ...]] = tuple(
    item.command for item in APPROVED_COMMAND_REGISTRY
)
DEFAULT_AUDIT_COMMANDS: Final[tuple[str, ...]] = tuple(
    item.command for item in APPROVED_COMMAND_REGISTRY if item.default_collection
)


class CommandPolicy:
    """Validate and canonicalize commands against the fixed registry.

    The policy deliberately has no API for callers or YAML files to add fixed
    commands dynamically.  A future parameterized command must be implemented
    here with a command-specific validator before it can be accepted.
    """

    _canonical_by_casefold: Final[dict[str, str]] = {
        item.command.casefold(): item.command for item in APPROVED_COMMAND_REGISTRY
    }

    @staticmethod
    def normalize_whitespace(command: str) -> str:
        """Collapse ordinary spaces after rejecting every control character."""

        if not isinstance(command, str):
            raise UnsafeCommandError("Command must be a string")
        if "\n" in command or "\r" in command:
            raise UnsafeCommandError("Command must contain exactly one line")
        if any(unicodedata.category(character) == "Cc" for character in command):
            raise UnsafeCommandError("Command contains a prohibited control character")
        normalized = " ".join(part for part in command.strip().split(" ") if part)
        if not normalized:
            raise UnsafeCommandError("Command must not be empty")
        return normalized

    @staticmethod
    def _reject_chaining(command: str) -> None:
        # A single IOS output-filter pipe is permitted only when the complete
        # command subsequently exact-matches a registered fixed command.
        if any(token in command for token in (";", "&&", "||", "`", "$(", "<", ">")):
            raise UnsafeCommandError("Command contains a prohibited chaining construct")
        if "&" in command:
            raise UnsafeCommandError("Command contains a prohibited chaining character")

    def validate(self, command: str) -> str:
        """Return the registered canonical command or fail closed."""

        normalized = self.normalize_whitespace(command)
        self._reject_chaining(normalized)
        canonical = self._canonical_by_casefold.get(normalized.casefold())
        if canonical is None:
            if "|" in normalized:
                raise UnsafeCommandError("Unapproved command pipeline")
            raise UnsafeCommandError(f"Command is not approved: {normalized}")
        return canonical

    def validate_many(self, commands: Iterable[str]) -> list[str]:
        """Validate commands and return canonical values in caller order."""

        return [self.validate(command) for command in commands]

    def is_allowed(self, command: str) -> bool:
        try:
            self.validate(command)
        except (TypeError, UnsafeCommandError):
            return False
        return True

    @staticmethod
    def approved_commands() -> tuple[str, ...]:
        return APPROVED_COMMANDS

    @staticmethod
    def registry() -> tuple[ApprovedCommand, ...]:
        return APPROVED_COMMAND_REGISTRY


DEFAULT_COMMAND_POLICY: Final[CommandPolicy] = CommandPolicy()


__all__ = [
    "APPROVED_COMMAND_REGISTRY",
    "APPROVED_COMMANDS",
    "DEFAULT_AUDIT_COMMANDS",
    "DEFAULT_COMMAND_POLICY",
    "ApprovedCommand",
    "CommandPolicy",
    "UnsafeCommandError",
]
