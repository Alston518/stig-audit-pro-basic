"""Provide ReportLab's optional URL symbols without shipping a URL client.

Basic renders summaries from in-memory text and local fonts. ReportLab imports
``urllib.request`` at module load even when no remote resource is requested.
The Basic bundle excludes that network-capable standard-library module, so a
frozen PDF export needs these fail-closed symbols before ReportLab is imported.
"""

from __future__ import annotations

import sys
import types
import urllib


def _network_unavailable(*_args, **_kwargs):
    raise ValueError("External resources are unavailable in the Basic PDF renderer")


offline_request = types.ModuleType("urllib.request")
offline_request.urlopen = _network_unavailable
offline_request.Request = _network_unavailable
sys.modules["urllib.request"] = offline_request
urllib.request = offline_request
