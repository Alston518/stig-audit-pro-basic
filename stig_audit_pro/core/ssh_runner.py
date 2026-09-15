"""Single-device Netmiko SSH runner for safe IOS-XE show commands."""

from __future__ import annotations

from dataclasses import dataclass

from stig_audit_pro.core.command_planner import normalize_safe_commands
from stig_audit_pro.core.command_policy import DEFAULT_COMMAND_POLICY
from stig_audit_pro.core.output_cache import CommandOutputCache


@dataclass(slots=True)
class DeviceTarget:
    ip: str
    device_type: str = "cisco_xe"
    port: int = 22
    timeout: int = 30


@dataclass(slots=True)
class DeviceCredentials:
    username: str
    password: str
    secret: str | None = None


@dataclass(slots=True)
class DeviceCommandRun:
    ip: str
    status: str
    outputs: dict[str, str]
    error_message: str | None = None


class NetmikoSshRunner:
    """Run a safe command set against one IOS-XE device."""

    def __init__(self, cache: CommandOutputCache | None = None) -> None:
        self.cache = cache

    def run_commands(
        self,
        target: DeviceTarget,
        credentials: DeviceCredentials,
        commands: list[str],
    ) -> DeviceCommandRun:
        # Policy validation intentionally happens before importing Netmiko or
        # attempting a connection.  Unsafe YAML/caller input therefore cannot
        # reach the network boundary.
        approved_commands = normalize_safe_commands(commands)
        pagination_command = DEFAULT_COMMAND_POLICY.validate("terminal length 0")
        try:
            from netmiko import ConnectHandler  # type: ignore
        except ImportError as exc:
            raise RuntimeError("netmiko is required for live SSH scans") from exc

        connection_params = {
            "device_type": target.device_type,
            "host": target.ip,
            "username": credentials.username,
            "password": credentials.password,
            "port": target.port,
            "timeout": target.timeout,
            "banner_timeout": target.timeout,
            "auth_timeout": target.timeout,
        }
        if credentials.secret:
            connection_params["secret"] = credentials.secret

        outputs: dict[str, str] = {}
        try:
            with ConnectHandler(**connection_params) as connection:
                if credentials.secret:
                    connection.enable()
                if pagination_command not in approved_commands:
                    connection.send_command(pagination_command)
                for command in approved_commands:
                    output = connection.send_command(command, read_timeout=target.timeout)
                    outputs[command] = output
            if self.cache:
                self.cache.save_device_outputs(target.ip, outputs)
            return DeviceCommandRun(ip=target.ip, status="scanned", outputs=outputs)
        except Exception as exc:  # Netmiko exposes several transport/auth exception types.
            return DeviceCommandRun(
                ip=target.ip,
                status="skipped",
                outputs=outputs,
                error_message=str(exc),
            )
