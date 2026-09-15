from __future__ import annotations

from tests.conftest import load_outputs
from stig_audit_pro.parsers.iosxe_acls import parse_acls


def test_acl_parser_ignores_remarks_and_finds_deny_log_input():
    outputs = load_outputs("compliant")
    parsed = parse_acls(
        show_ip_access_lists=outputs["show ip access-lists"],
        running_config=outputs["show running-config"],
    )

    deny_text = [statement.text for statement in parsed.deny_statements]
    assert "remark" not in "\n".join(deny_text).lower()
    assert len(parsed.deny_statements) == 2
    assert all(statement.has_log_input for statement in parsed.deny_statements)


def test_acl_parser_detects_deny_without_log_input():
    outputs = load_outputs("noncompliant")
    parsed = parse_acls(
        show_ip_access_lists=outputs["show ip access-lists"],
        running_config=outputs["show running-config"],
    )

    missing = [statement for statement in parsed.deny_statements if not statement.has_log_input]
    assert len(missing) == 2
    assert {statement.acl_name for statement in missing} == {"USER-IN", "10"}
