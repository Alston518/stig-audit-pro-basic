"""Cancellation-aware Netmiko adapter for approved read-only commands."""

from __future__ import annotations

import threading
from collections.abc import Callable

from stig_audit_pro.core.command_policy import DEFAULT_COMMAND_POLICY
from stig_audit_pro.core.ssh_runner import (
    DeviceCommandRun,
    DeviceCredentials,
    DeviceTarget,
)


class NetmikoRunner:
    """Open exactly one connection and collect an approved command set.

    An instance carries no live connection and is safe to construct per worker.
    The connection object itself never crosses a worker boundary.
    """

    def run_commands(
        self,
        target: DeviceTarget,
        credentials: DeviceCredentials,
        commands: list[str],
        *,
        cancel_event: threading.Event | None = None,
        command_timeout: int | None = None,
        on_command: Callable[[str], None] | None = None,
    ) -> DeviceCommandRun:
        approved = DEFAULT_COMMAND_POLICY.validate_many(commands)
        pagination = DEFAULT_COMMAND_POLICY.validate("terminal length 0")
        cancellation = cancel_event or threading.Event()
        try:
            from netmiko import ConnectHandler  # type: ignore
        except ImportError as exc:
            raise RuntimeError("netmiko is required for live SSH scans") from exc

        params: dict[str, object] = {
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
            params["secret"] = credentials.secret

        outputs: dict[str, str] = {}
        try:
            with ConnectHandler(**params) as connection:
                if credentials.secret:
                    connection.enable()
                if pagination not in approved and not cancellation.is_set():
                    connection.send_command(
                        pagination,
                        read_timeout=command_timeout or target.timeout,
                    )
                for command in approved:
                    if cancellation.is_set():
                        return DeviceCommandRun(
                            ip=target.ip,
                            status="cancelled",
                            outputs=outputs,
                            error_message="Scan cancelled",
                        )
                    if on_command:
                        on_command(command)
                    outputs[command] = connection.send_command(
                        command,
                        read_timeout=command_timeout or target.timeout,
                    )
            return DeviceCommandRun(target.ip, "scanned", outputs)
        except Exception as exc:
            # Do not include connection parameters in the exception: they hold
            # session-only credentials.  Netmiko exception text is retained.
            return DeviceCommandRun(target.ip, "skipped", outputs, str(exc))


__all__ = ["NetmikoRunner"]
