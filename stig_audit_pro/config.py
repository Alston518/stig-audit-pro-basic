"""Application-wide constants for the core audit package."""

from __future__ import annotations

from stig_audit_pro.core.command_policy import DEFAULT_AUDIT_COMMANDS

APP_NAME = "stig-audit-pro"
APP_VERSION = "0.2.0"
LICENSE_FILENAME = "stig-audit-pro.license.json"
DEFAULT_PROFILE_NAME = "base_iosxe_access"

# Backward-compatible name for callers that request the standard collection
# set.  Approval itself lives only in core.command_policy.
DEFAULT_SHOW_COMMANDS: tuple[str, ...] = DEFAULT_AUDIT_COMMANDS

# Retained as an empty compatibility export.  Prefix-based approval was unsafe
# and is intentionally no longer used anywhere in the application.
SAFE_COMMAND_PREFIXES: tuple[str, ...] = ()

SUPPORTED_CHECK_TYPES: tuple[str, ...] = (
    "command_contains",
    "command_not_contains",
    "command_pattern_policy",
    "command_regex",
    "section_contains",
    "section_not_contains",
    "interface_policy",
    "interface_config_policy",
    "management_access_policy",
    "ntp_authentication_policy",
    "trunk_vlan_policy",
    "acl_deny_logging_policy",
    "dhcp_snooping_policy",
    "arp_inspection_policy",
    "dod_banner_policy",
    "radius_server_policy",
    "root_guard_neighbor_policy",
    "vty_session_limit_policy",
    "manual_review",
)

VALID_STATUSES: tuple[str, ...] = (
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
)
