"""The packaged PDF compatibility hook cannot open network URLs."""

from __future__ import annotations

import runpy
import sys
import urllib
from pathlib import Path

import pytest


def test_reportlab_runtime_hook_blocks_remote_requests():
    previous_module = sys.modules.get("urllib.request")
    previous_attribute = getattr(urllib, "request", None)
    hook = Path(__file__).resolve().parents[1] / "scripts" / "reportlab_offline_runtime.py"
    try:
        sys.modules.pop("urllib.request", None)
        if hasattr(urllib, "request"):
            del urllib.request
        runpy.run_path(str(hook))
        from urllib.request import Request, urlopen

        with pytest.raises(ValueError, match="unavailable"):
            urlopen("https://example.invalid")
        with pytest.raises(ValueError, match="unavailable"):
            Request("https://example.invalid")
    finally:
        if previous_module is None:
            sys.modules.pop("urllib.request", None)
        else:
            sys.modules["urllib.request"] = previous_module
        if previous_attribute is None:
            del urllib.request
        else:
            urllib.request = previous_attribute
