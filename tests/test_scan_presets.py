from __future__ import annotations

import pytest
from pydantic import ValidationError

from stig_audit_pro.storage.scan_presets import ScanPreset, ScanPresetStore


def test_scan_preset_round_trip_never_accepts_credentials(tmp_path):
    store = ScanPresetStore(tmp_path)
    preset = ScanPreset(
        preset_name="Quarterly", device_group="access-switches",
        stig_families=["IOSXE_L2", "IOSXE_NDM"], profile_name="site",
        concurrency=5,
    )
    path = store.save(preset)
    assert "password" not in path.read_text(encoding="utf-8").lower()
    assert store.load("Quarterly") == preset
    assert store.list_presets() == ["Quarterly"]
    assert store.delete("Quarterly") is True

    with pytest.raises(ValidationError):
        ScanPreset.model_validate({
            "preset_name": "Unsafe", "profile_name": "site", "password": "secret"
        })
