"""SSH infrastructure adapters.

The adapter is loaded lazily so the shared host-key trust module can be used
by the core runner without creating an import cycle during package startup.
"""

__all__ = ["NetmikoRunner"]


def __getattr__(name: str):
    if name == "NetmikoRunner":
        from stig_audit_pro.infrastructure.ssh.netmiko_runner import NetmikoRunner

        return NetmikoRunner
    raise AttributeError(name)
