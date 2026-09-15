"""XCCDF metadata importer for DISA STIG sources."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from stig_audit_pro.stig.stig_metadata import (
    StigBenchmarkMetadata,
    StigRuleMetadata,
    extract_release,
    normalize_procedure_text,
    sha256_bytes,
)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _first_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _child_text(element: ET.Element, name: str) -> str:
    child = _first_child(element, name)
    if child is None:
        return ""
    return " ".join("".join(child.itertext()).split())


def _element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def _procedure_text(element: ET.Element | None) -> str:
    """Extract meaningful XCCDF prose without flattening IOS command layout."""

    if element is None:
        return ""
    return normalize_procedure_text("".join(element.itertext()))


def _find_descendant(element: ET.Element, name: str) -> ET.Element | None:
    for candidate in element.iter():
        if _local_name(candidate.tag) == name:
            return candidate
    return None


def _find_all(element: ET.Element, name: str) -> list[ET.Element]:
    return [candidate for candidate in element.iter() if _local_name(candidate.tag) == name]


def _status_date(root: ET.Element) -> str:
    status = _first_child(root, "status")
    if status is None:
        return ""
    return status.attrib.get("date", "")


def _plain_text(root: ET.Element, plain_id_contains: str) -> str:
    needle = plain_id_contains.lower()
    for element in _find_all(root, "plain-text"):
        if needle in element.attrib.get("id", "").lower():
            return _element_text(element)
    return ""


def _extract_vuln_id(group: ET.Element) -> str:
    group_id = group.attrib.get("id", "")
    if group_id:
        return group_id
    title = _child_text(group, "title")
    match = re.search(r"\bV-\d+\b", title)
    return match.group(0) if match else ""


def parse_xccdf_root(
    root: ET.Element,
    *,
    source_path: str = "",
    source_filename: str = "",
    family: str = "",
) -> StigBenchmarkMetadata:
    """Build STIG metadata from an already-parsed XCCDF Benchmark element."""

    benchmark_id = root.attrib.get("id", "")
    version = _child_text(root, "version")
    release_info = _plain_text(root, "release")
    metadata = StigBenchmarkMetadata(
        source_path=source_path,
        source_filename=source_filename,
        family=family,
        benchmark_id=benchmark_id,
        title=_child_text(root, "title"),
        version=version,
        release=extract_release(release_info, version),
        release_info=release_info,
        release_date=_status_date(root),
        rules=[],
    )

    for group in _find_all(root, "Group"):
        rule = _first_child(group, "Rule")
        if rule is None:
            continue
        vuln_id = _extract_vuln_id(group)
        rule_metadata = StigRuleMetadata(
            vuln_id=vuln_id,
            group_id=group.attrib.get("id", vuln_id),
            rule_id=rule.attrib.get("id", ""),
            stig_id=_child_text(rule, "version"),
            title=_child_text(rule, "title") or _child_text(group, "title"),
            severity=rule.attrib.get("severity", ""),
            discussion=_element_text(_first_child(rule, "description")),
            identifiers=[
                text
                for element in rule
                if _local_name(element.tag) == "ident"
                if (text := _element_text(element))
            ],
            check_text=_procedure_text(_find_descendant(rule, "check-content")),
            fix_text=_procedure_text(_first_child(rule, "fixtext")),
        )
        metadata.rules.append(rule_metadata)
    return metadata.calculate_fingerprints()


def parse_xccdf_file(path: str | Path, family: str = "") -> StigBenchmarkMetadata:
    xml_path = Path(path)
    try:
        if not xml_path.is_file() or xml_path.stat().st_size > 25 * 1024 * 1024:
            raise ValueError("XCCDF XML is missing or exceeds the supported 25 MB limit")
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError, ValueError) as exc:
        raise ValueError(f"Could not safely parse XCCDF {xml_path}: {exc}") from exc
    metadata = parse_xccdf_root(
        root,
        source_path=str(xml_path),
        source_filename=xml_path.name,
        family=family,
    )
    metadata.source_sha256 = sha256_bytes(xml_path.read_bytes())
    return metadata.calculate_fingerprints()
