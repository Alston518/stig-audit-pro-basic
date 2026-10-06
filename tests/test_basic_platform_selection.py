from pathlib import Path

import pytest

from stig_audit_pro.basic_app import can_use_sample_outputs, default_profile_name, family_results, library_names, report_stem, template_paths, template_slot_path, save_template_selection, existing_template_selections
from stig_audit_pro.core.command_policy import DEFAULT_COMMAND_POLICY
from stig_audit_pro.core.yaml_loader import load_check_library, load_profile


@pytest.mark.parametrize(
    ("platform", "selection", "expected"),
    [
        ("IOS XE", "L2", ["iosxe_l2"]),
        ("IOS XE", "NDM", ["iosxe_ndm"]),
        ("IOS XE", "L2 + NDM", ["iosxe_l2", "iosxe_ndm"]),
        ("IOS", "L2", ["ios_l2"]),
        ("IOS", "NDM", ["ios_ndm"]),
        ("IOS", "L2 + NDM", ["ios_l2", "ios_ndm"]),
    ],
)
def test_platform_and_family_choose_expected_libraries(platform, selection, expected):
    assert library_names(platform, selection) == expected


def test_platform_selection_rejects_unknown_choice():
    with pytest.raises(ValueError):
        library_names("IOS", "unknown")


def test_ios_cannot_use_iosxe_sample_outputs():
    assert can_use_sample_outputs("IOS XE")
    assert not can_use_sample_outputs("IOS")


@pytest.mark.parametrize(
    ("platform", "families", "expected"),
    [
        ("IOS XE", ["iosxe_l2"], {"iosxe_l2": "xe-l2.ckl", "combined": "xe-both.ckl"}),
        ("IOS XE", ["iosxe_ndm"], {"iosxe_ndm": "xe-ndm.ckl", "combined": "xe-both.ckl"}),
        ("IOS XE", ["iosxe_l2", "iosxe_ndm"], {"iosxe_l2": "xe-l2.ckl", "iosxe_ndm": "xe-ndm.ckl", "combined": "xe-both.ckl"}),
        ("IOS", ["ios_l2"], {"ios_l2": "ios-l2.ckl", "combined": "ios-both.ckl"}),
        ("IOS", ["ios_ndm"], {"ios_ndm": "ios-ndm.ckl", "combined": "ios-both.ckl"}),
        ("IOS", ["ios_l2", "ios_ndm"], {"ios_l2": "ios-l2.ckl", "ios_ndm": "ios-ndm.ckl", "combined": "ios-both.ckl"}),
    ],
)
def test_template_paths_keep_platform_and_family_separate(platform, families, expected):
    paths = {
        "IOS XE": {"L2": "xe-l2.ckl", "NDM": "xe-ndm.ckl", "L2 + NDM": "xe-both.ckl"},
        "IOS": {"L2": "ios-l2.ckl", "NDM": "ios-ndm.ckl", "L2 + NDM": "ios-both.ckl"},
    }
    assert template_paths(platform, families, paths) == expected


def test_blank_templates_are_kept_in_separate_workspace_slots(tmp_path):
    workspace = tmp_path / "CKL Templates"
    ios = tmp_path / "ios.ckl"
    iosxe = tmp_path / "iosxe.xml"
    ios.write_text("<ios />", encoding="utf-8")
    iosxe.write_text("<iosxe />", encoding="utf-8")
    ios_slot = template_slot_path(workspace, "IOS", "L2")
    iosxe_slot = template_slot_path(workspace, "IOS XE", "L2")
    assert ios_slot != iosxe_slot
    assert save_template_selection(ios, ios_slot) == ios_slot
    assert save_template_selection(iosxe, iosxe_slot) == iosxe_slot
    assert ios_slot.read_text(encoding="utf-8") == "<ios />"
    assert iosxe_slot.read_text(encoding="utf-8") == "<iosxe />"
    assert existing_template_selections(workspace)["IOS"]["L2"] == str(ios_slot)
    assert existing_template_selections(workspace)["IOS XE"]["L2"] == str(iosxe_slot)
    assert existing_template_selections(workspace)["IOS"]["NDM"] == ""


def test_reselecting_template_replaces_saved_workspace_copy(tmp_path):
    workspace = tmp_path / "CKL Templates"
    slot = template_slot_path(workspace, "IOS", "NDM")
    first = tmp_path / "first.ckl"
    second = tmp_path / "second.ckl"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    save_template_selection(first, slot)
    save_template_selection(second, slot)
    assert slot.read_text(encoding="utf-8") == "second"
    assert save_template_selection(slot, slot) == slot


def test_single_family_ckl_receives_results_with_uppercase_stig_family():
    from types import SimpleNamespace

    results = [SimpleNamespace(stig_family="IOS_L2"), SimpleNamespace(stig_family="IOS_NDM")]
    assert family_results(results, "ios_l2") == [results[0]]
    assert family_results(results, "ios_ndm") == [results[1]]


def test_ios_starters_load_from_basic_app_data_directory():
    data = Path(__file__).resolve().parents[1] / "data"
    assert default_profile_name("IOS") == "base_ios_switch_access"
    assert default_profile_name("IOS XE") == "base_iosxe_access"
    profile = load_profile(data / "profiles" / "base_ios_switch_access.yaml")
    assert profile.profile_name == "base_ios_switch_access"
    for family, count in (("ios_l2", 22), ("ios_ndm", 35)):
        library = load_check_library(data / "checks" / f"{family}.yaml")
        assert len(library.checks) == count
        assert all(check.stig_family == family.upper() for check in library.checks)
        assert all(
            DEFAULT_COMMAND_POLICY.is_allowed(command)
            for check in library.checks
            for command in check.commands
        )


def test_ios_report_name_identifies_platform():
    class Asset:
        management_ip = "192.0.2.10"

    from datetime import datetime

    assert report_stem(Asset(), "192.0.2.10", ["ios_l2", "ios_ndm"], datetime(2026, 9, 23)) == "10_IOS_L2_NDM_23SEP2026"
    assert report_stem(Asset(), "192.0.2.10", ["iosxe_l2"], datetime(2026, 9, 23)) == "10_IOSXE_L2_23SEP2026"
