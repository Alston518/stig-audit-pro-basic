"""GUI package with lazy access to the optional Pro window."""

from importlib import import_module

__all__ = ["StigAuditProApp", "run_gui"]


def __getattr__(name: str):
    if name in __all__:
        return getattr(import_module("stig_audit_pro.gui.main_window"), name)
    raise AttributeError(name)
