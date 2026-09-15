"""Populate DISA checklist files from automated audit results."""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.parsers.iosxe_running_config import parse_running_config


class CklError(ValueError):
    """Raised when a checklist cannot be read or populated safely."""


@dataclass(slots=True, frozen=True)
class CklAsset:
    """Device identity written to the CKL ASSET section."""

    scan_ip: str
    hostname: str
    management_ip: str
    fqdn: str = ""


@dataclass(slots=True, frozen=True)
class CklWriteSummary:
    path: Path
    updated_vuln_ids: tuple[str, ...]
    unmatched_result_ids: tuple[str, ...]


CKL_STATUS_MAP = {
    "NotAFinding": "NotAFinding",
    "Open": "Open",
    "Not_Applicable": "Not_Applicable",
    "Not_Reviewed": "Not_Reviewed",
    "Error": "Not_Reviewed",
    "Skipped": "Not_Reviewed",
}


def extract_ckl_asset(
    outputs: dict[str, str],
    scan_ip: str,
    management_vlan: int = 300,
) -> CklAsset:
    """Extract hostname, FQDN, and the IPv4 address on the management SVI."""

    running = parse_running_config(outputs.get("show running-config", ""))
    hostname = (running.hostname or "unknown").strip()
    management_ip = _interface_ipv4(running.sections, management_vlan) or scan_ip
    domain = _domain_name(running.global_lines)
    fqdn = hostname
    if hostname != "unknown" and "." not in hostname and domain:
        fqdn = f"{hostname}.{domain}"
    return CklAsset(
        scan_ip=scan_ip,
        hostname=hostname,
        management_ip=management_ip,
        fqdn=fqdn,
    )


def checklist_vuln_ids(path: str | Path) -> set[str]:
    root = _parse_ckl(path).getroot()
    return {
        vuln_id
        for vuln in _elements(root, "VULN")
        if (vuln_id := _vuln_id(vuln))
    }


def write_completed_ckl(
    source_path: str | Path,
    destination_path: str | Path,
    results: list[CheckResult],
    asset: CklAsset,
    *,
    append_comments: bool = True,
) -> CklWriteSummary:
    """Copy a CKL template and populate asset and vulnerability result fields."""

    tree = _parse_ckl(source_path)
    root = tree.getroot()
    if _local_name(root.tag) != "CHECKLIST":
        raise CklError("The selected file is not a DISA CHECKLIST/CKL document.")

    asset_element = _first(root, "ASSET")
    if asset_element is None:
        raise CklError("The selected CKL does not contain an ASSET section.")
    _set_child_text(asset_element, "HOST_NAME", asset.hostname)
    _set_child_text(asset_element, "HOST_IP", asset.management_ip)
    _set_child_text(asset_element, "HOST_FQDN", asset.fqdn or asset.hostname)

    results_by_vuln = {
        result.vuln_id: result
        for result in results
        if result.vuln_id.startswith("V-")
    }
    updated: list[str] = []
    for vuln in _elements(root, "VULN"):
        vuln_id = _vuln_id(vuln)
        result = results_by_vuln.get(vuln_id)
        if result is None:
            continue
        _set_child_text(vuln, "STATUS", CKL_STATUS_MAP.get(result.status, "Not_Reviewed"))
        _set_child_text(vuln, "FINDING_DETAILS", _finding_details(result))
        generated_comment = _generated_comment(result, asset)
        comments = _direct_child(vuln, "COMMENTS")
        existing = comments.text.strip() if comments is not None and comments.text else ""
        if append_comments and existing:
            generated_comment = f"{existing}\n\n{generated_comment}"
        _set_child_text(vuln, "COMMENTS", generated_comment)
        updated.append(vuln_id)

    destination = Path(destination_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(tree, space="  ")
        tree.write(destination, encoding="utf-8", xml_declaration=True)
    except OSError as exc:
        raise CklError(f"Could not write completed CKL {destination}: {exc}") from exc

    unmatched = sorted(set(results_by_vuln) - set(updated))
    return CklWriteSummary(
        path=destination,
        updated_vuln_ids=tuple(sorted(updated)),
        unmatched_result_ids=tuple(unmatched),
    )


def safe_device_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._") or "unknown-device"


def _parse_ckl(path: str | Path) -> ET.ElementTree:
    source = Path(path)
    if not source.is_file():
        raise CklError(f"Could not read CKL file: {source}")
    if source.stat().st_size > 25 * 1024 * 1024:
        raise CklError("CKL exceeds the supported 25 MB size limit")
    try:
        return ET.parse(source)
    except (ET.ParseError, OSError) as exc:
        raise CklError(f"Could not parse CKL file {source}: {exc}") from exc


def _interface_ipv4(sections: dict[str, list[str]], vlan: int) -> str | None:
    wanted = f"interface vlan{vlan}".lower()
    for header, lines in sections.items():
        if header.lower().replace(" ", "") != wanted.replace(" ", ""):
            continue
        for line in lines:
            match = re.match(r"ip address\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)", line)
            if not match:
                continue
            try:
                return str(ipaddress.ip_address(match.group(1)))
            except ValueError:
                continue
    return None


def _domain_name(global_lines: list[str]) -> str:
    for line in global_lines:
        for prefix in ("ip domain name ", "ip domain-name "):
            if line.startswith(prefix):
                return line.removeprefix(prefix).strip().rstrip(".")
    return ""


def _vuln_id(vuln: ET.Element) -> str:
    for stig_data in _elements(vuln, "STIG_DATA"):
        attribute = _direct_child(stig_data, "VULN_ATTRIBUTE")
        data = _direct_child(stig_data, "ATTRIBUTE_DATA")
        if (
            attribute is not None
            and (attribute.text or "").strip().lower() == "vuln_num"
            and data is not None
        ):
            return (data.text or "").strip()
    return ""


def _finding_details(result: CheckResult) -> str:
    if result.finding_details.strip():
        return result.finding_details.strip()
    if result.failed_objects:
        return "\n".join(
            f"{obj.object_type} {obj.object_name}: {obj.details}".rstrip(": ")
            for obj in result.failed_objects
        )
    return result.comments.strip()


def _generated_comment(result: CheckResult, asset: CklAsset) -> str:
    lines = [
        "STIG Audit Pro automated result",
        f"Status: {result.status}",
        f"Device: {asset.hostname}",
        f"Management IP: {asset.management_ip}",
        f"Scan target: {asset.scan_ip}",
    ]
    if result.comments.strip():
        lines.extend(["", result.comments.strip()])
    if result.status in {"Error", "Skipped"} and result.error_message:
        lines.extend(["", f"Automation error: {result.error_message}"])
    return "\n".join(lines)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _elements(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [element for element in parent.iter() if _local_name(element.tag) == local_name]


def _first(parent: ET.Element, local_name: str) -> ET.Element | None:
    return next(
        (element for element in parent.iter() if _local_name(element.tag) == local_name),
        None,
    )


def _direct_child(parent: ET.Element, local_name: str) -> ET.Element | None:
    return next(
        (child for child in list(parent) if _local_name(child.tag) == local_name),
        None,
    )


def _set_child_text(parent: ET.Element, local_name: str, value: str) -> None:
    child = _direct_child(parent, local_name)
    if child is None:
        namespace = parent.tag.rsplit("}", 1)[0] + "}" if "}" in parent.tag else ""
        child = ET.SubElement(parent, f"{namespace}{local_name}")
    child.text = value
