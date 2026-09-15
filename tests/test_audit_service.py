from __future__ import annotations

from dataclasses import dataclass

from stig_audit_pro.application.audit_service import AuditService
from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.core.ssh_runner import DeviceCommandRun, DeviceCredentials


@dataclass
class Target:
    ip: str


def test_audit_service_uses_one_runner_per_device_and_traces_results():
    runners: list[object] = []

    class FakeRunner:
        def __init__(self):
            runners.append(self)

        def run_commands(self, target, _credentials, commands, **_kwargs):
            assert "show version" in commands
            return DeviceCommandRun(
                target.ip, "scanned",
                {"show version": "Cisco IOS XE Software\nhostname SW-TEST"},
            )

    check = CheckDefinition(
        vuln_id="V-TEST", rule_id="SV-TEST", stig_id="CISC-TEST",
        title="Version evidence is present", stig_family="IOSXE_NDM",
        severity="cat2", check_type="command_contains",
        commands=["show version"], conditions={"contains": "Cisco IOS XE"},
    )
    run_id = "00000000-0000-4000-8000-000000000042"
    result = AuditService(runner_factory=FakeRunner).run_live(
        run_id=run_id,
        targets=[Target(f"192.0.2.{index}") for index in range(1, 6)],
        credentials=DeviceCredentials("user", "password"),
        checks=[check], profile_provider=lambda _target: SiteProfile(profile_name="test"),
        concurrency=5,
    )

    assert len(runners) == 5
    assert len({id(runner) for runner in runners}) == 5
    assert len(result.results) == 5
    assert all(item.status == "NotAFinding" for item in result.results)
    assert all(item.run_id == run_id for item in result.results)
    assert all(item.rule_id == "SV-TEST" for item in result.results)
    assert all(item.check_type == "command_contains" for item in result.results)
