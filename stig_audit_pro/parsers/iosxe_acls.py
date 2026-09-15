"""Parsers for IOS-XE IPv4 ACL output and running-config ACL sections."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class AclStatement:
    acl_name: str
    acl_type: str
    action: str
    text: str
    sequence: int | None = None
    source: str = ""

    @property
    def is_deny(self) -> bool:
        return self.action == "deny"

    @property
    def has_log_input(self) -> bool:
        return bool(re.search(r"\blog-input\b", self.text, flags=re.IGNORECASE))


@dataclass(slots=True)
class AclParseResult:
    statements: list[AclStatement] = field(default_factory=list)

    @property
    def deny_statements(self) -> list[AclStatement]:
        return [statement for statement in self.statements if statement.is_deny]


def _infer_numbered_acl_type(name: str) -> str:
    if not name.isdigit():
        return "extended"
    number = int(name)
    if 1 <= number <= 99 or 1300 <= number <= 1999:
        return "standard"
    if 100 <= number <= 199 or 2000 <= number <= 2699:
        return "extended"
    return "extended"


def _parse_statement_line(acl_name: str, acl_type: str, line: str, source: str) -> AclStatement | None:
    stripped = line.strip()
    if not stripped:
        return None
    parts = stripped.split()
    sequence: int | None = None
    if parts and parts[0].isdigit() and len(parts) > 1:
        sequence = int(parts.pop(0))
    if not parts:
        return None
    action = parts[0].lower()
    if action == "remark":
        return None
    if action not in {"permit", "deny"}:
        return None
    text = " ".join([action, *parts[1:]])
    return AclStatement(
        acl_name=acl_name,
        acl_type=acl_type,
        action=action,
        text=text,
        sequence=sequence,
        source=source,
    )


def _parse_show_ip_access_lists(text: str) -> list[AclStatement]:
    statements: list[AclStatement] = []
    current_name: str | None = None
    current_type: str | None = None
    header_re = re.compile(r"^(Standard|Extended) IP access list (.+)$", re.IGNORECASE)
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        header = header_re.match(stripped)
        if header:
            current_type = header.group(1).lower()
            current_name = header.group(2).strip()
            continue
        if current_name and current_type:
            statement = _parse_statement_line(current_name, current_type, stripped, "show_ip_access_lists")
            if statement:
                statements.append(statement)
    return statements


def _parse_running_config_acls(text: str) -> list[AclStatement]:
    statements: list[AclStatement] = []
    current_name: str | None = None
    current_type: str | None = None
    named_re = re.compile(r"^ip access-list (standard|extended) (.+)$", re.IGNORECASE)
    ipv6_re = re.compile(r"^ipv6 access-list (.+)$", re.IGNORECASE)
    global_re = re.compile(r"^access-list\s+(\S+)\s+(.+)$", re.IGNORECASE)

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "!":
            current_name = None
            current_type = None
            continue
        named = named_re.match(stripped)
        if named:
            current_type = named.group(1).lower()
            current_name = named.group(2).strip()
            continue
        ipv6 = ipv6_re.match(stripped)
        if ipv6:
            current_type = "ipv6"
            current_name = ipv6.group(1).strip()
            continue
        global_acl = global_re.match(stripped)
        if global_acl:
            acl_name = global_acl.group(1)
            acl_type = _infer_numbered_acl_type(acl_name)
            statement = _parse_statement_line(
                acl_name, acl_type, global_acl.group(2), "running_config"
            )
            if statement:
                statements.append(statement)
            continue
        if current_name and current_type and raw_line[:1].isspace():
            statement = _parse_statement_line(current_name, current_type, stripped, "running_config")
            if statement:
                statements.append(statement)
    return statements


def parse_acls(show_ip_access_lists: str = "", running_config: str = "") -> AclParseResult:
    collected = [
        *_parse_running_config_acls(running_config),
        *_parse_show_ip_access_lists(show_ip_access_lists),
    ]
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[AclStatement] = []
    for statement in collected:
        key = (statement.acl_name, statement.acl_type, statement.action, statement.text.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(statement)
    return AclParseResult(statements=unique)
