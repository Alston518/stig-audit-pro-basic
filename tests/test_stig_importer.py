from __future__ import annotations

import zipfile

import pytest

from tests.conftest import PROJECT_ROOT
from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file


def test_parse_xccdf_metadata():
    metadata = parse_xccdf_file(PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml", family="IOSXE_L2")

    assert metadata.family == "IOSXE_L2"
    assert metadata.title.startswith("Cisco IOS-XE Switch L2S")
    assert metadata.version == "V1R1"
    assert metadata.release_date == "2026-07-04"
    assert metadata.benchmark_release_date == "04 Jul 2026"
    assert metadata.rule_count == 1
    rule = metadata.rules[0]
    assert rule.vuln_id == "V-123456"
    assert rule.rule_id == "SV-123456r1_rule"
    assert rule.stig_id == "CISC-L2-000210"
    assert rule.severity == "medium"
    assert "Review disabled" in rule.check_text


def test_stig_source_manager_imports_zip_and_caches_metadata(tmp_path):
    xml_path = PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml"
    zip_path = tmp_path / "U_Cisco_IOSXE_L2_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(xml_path, "U_SAMPLE-xccdf.xml")

    manager = StigSourceManager(tmp_path / "cache")
    metadata = manager.import_source(zip_path, family="IOSXE_L2")
    cached = manager.load_cached_metadata()

    assert metadata.rule_count == 1
    assert metadata.source_filename == zip_path.name
    assert len(cached) == 1
    assert cached[0].rules[0].stig_id == "CISC-L2-000210"


def test_stig_source_manager_selects_family_xccdf_from_combined_zip(tmp_path):
    xml_path = PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml"
    zip_path = tmp_path / "U_Cisco_IOS-XE_Switch_Y26M04_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(
            xml_path,
            "U_Cisco_IOS-XE_Switch_L2S_V3R2_Manual_STIG/"
            "U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml",
        )
        archive.write(
            xml_path,
            "U_Cisco_IOS-XE_Switch_NDM_V3R6_Manual_STIG/"
            "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml",
        )

    manager = StigSourceManager(tmp_path / "cache")
    manager.import_source(zip_path, family="IOSXE_NDM")

    assert (
        tmp_path
        / "cache"
        / "IOSXE_NDM"
        / "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual-xccdf.xml"
    ).exists()


def test_stig_source_manager_download_from_local_path(tmp_path):
    xml_path = PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml"
    zip_path = tmp_path / "U_Cisco_IOSXE_L2_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(xml_path, "U_SAMPLE-xccdf.xml")

    manager = StigSourceManager(tmp_path / "cache")
    metadata = manager.download_from_url(str(zip_path), family="IOSXE_L2")

    assert metadata.rule_count == 1
    assert metadata.source_filename == zip_path.name


def test_discover_downloads_uses_cyber_catalog_records(tmp_path):
    manager = StigSourceManager(tmp_path / "cache")
    manager._call_cyber_apex = lambda *_args, **_kwargs: [  # type: ignore[method-assign]
        {
            "FileName": "U_Cisco_IOS-XE_Switch_NDM_STIG_V3R6_Manual.zip",
            "DownloadType": "STIG",
            "DocumentLibrary": "STIGs",
            "UploadDate": "2026-04-27",
            "Classification": "Unclassified",
            "DownloadLink": "https://dl.dod.cyber.mil/example/U_Cisco_IOS-XE_Switch_NDM_STIG.zip",
        }
    ]

    candidates = manager.discover_downloads(["cisco", "ios", "xe", "switch", "ndm"])

    assert len(candidates) == 1
    assert candidates[0].source == "cyber.mil catalog"
    assert candidates[0].url.endswith("U_Cisco_IOS-XE_Switch_NDM_STIG.zip")


def test_discover_downloads_falls_back_to_direct_quarterly_bundle(tmp_path):
    manager = StigSourceManager(tmp_path / "cache")
    manager._discover_downloads_from_catalog = lambda _terms: []  # type: ignore[method-assign]
    manager._read_url_text = lambda _url: "<html><title>Welcome to LWC Communities!</title></html>"  # type: ignore[method-assign]
    manager._quarterly_release_codes = lambda: [("26", "07"), ("26", "04")]  # type: ignore[method-assign]
    manager._url_exists = lambda url: "Y26M04" in url  # type: ignore[method-assign]

    candidates = manager.discover_downloads(["cisco", "ios", "xe", "switch", "l2"])

    assert len(candidates) == 1
    assert candidates[0].source == "direct Cyber.mil package"
    assert candidates[0].url.endswith("U_Cisco_IOS-XE_Switch_Y26M04_STIG.zip")


def test_dynamic_cyber_exchange_shell_gets_actionable_error(tmp_path):
    manager = StigSourceManager(tmp_path / "cache")
    manager._discover_downloads_from_catalog = lambda _terms: []  # type: ignore[method-assign]
    manager._read_url_text = lambda _url: "<html><title>Welcome to LWC Communities!</title></html>"  # type: ignore[method-assign]
    manager._guess_direct_package_candidates = lambda _terms: []  # type: ignore[method-assign]

    with pytest.raises(StigSourceError, match="direct ZIP/XML"):
        manager.discover_downloads(["cisco", "ios", "xe"])
