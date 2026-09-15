"""DISA STIG Viewer 3 CKLB 1.0 JSON import, population, and export."""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.stig.ckl_writer import CklAsset
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata


class CklbError(ValueError):
    """Raised when a CKLB document is malformed or cannot be populated."""


@dataclass(slots=True, frozen=True)
class CklbWriteSummary:
    path: Path
    updated_vuln_ids: tuple[str, ...]
    unmatched_result_ids: tuple[str, ...]


CKLB_STATUS_MAP = {
    "NotAFinding": "not_a_finding", "Open": "open",
    "Not_Applicable": "not_applicable", "Not_Reviewed": "not_reviewed",
    "Error": "not_reviewed", "Skipped": "not_reviewed",
}
INTERNAL_STATUS_MAP = {
    "not_a_finding": "NotAFinding", "open": "Open",
    "not_applicable": "Not_Applicable", "not_reviewed": "Not_Reviewed",
}


def load_cklb(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        if not source.is_file() or source.stat().st_size > 25 * 1024 * 1024:
            raise CklbError("CKLB is missing or exceeds the supported 25 MB size limit")
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, CklbError) as exc:
        raise CklbError(f"Could not read CKLB file {source}: {exc}") from exc
    validate_cklb(payload)
    return payload


# Import-oriented alias used by application adapters.
read_cklb = load_cklb


def validate_cklb(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise CklbError("CKLB root must be a JSON object")
    if str(payload.get("cklb_version", "")) != "1.0":
        raise CklbError("Only CKLB schema version 1.0 is supported")
    if not isinstance(payload.get("target_data"), dict):
        raise CklbError("CKLB target_data must be an object")
    stigs = payload.get("stigs")
    if not isinstance(stigs, list):
        raise CklbError("CKLB stigs must be an array")
    if len(stigs) > 100:
        raise CklbError("CKLB contains too many STIG entries")
    for stig in stigs:
        if not isinstance(stig, dict) or not isinstance(stig.get("rules"), list):
            raise CklbError("Each CKLB STIG must contain a rules array")
        if len(stig["rules"]) > 20_000:
            raise CklbError("CKLB contains too many rules")
        for rule in stig["rules"]:
            if not isinstance(rule, dict):
                raise CklbError("Each CKLB rule must be an object")
            if not (_rule_vuln_id(rule) or rule.get("rule_id") or rule.get("rule_id_src")):
                raise CklbError("Each CKLB rule must have a vulnerability or rule identifier")


def create_cklb_template(
    benchmark: StigBenchmarkMetadata, asset: CklAsset, *, title: str | None = None,
) -> dict[str, Any]:
    stig_uuid = str(uuid.uuid4())
    rules: list[dict[str, Any]] = []
    for rule in benchmark.rules:
        rules.append({
            "group_id_src": rule.vuln_id,
            "group_tree": [{"id": rule.vuln_id, "title": rule.title,
                            "description": "<GroupDescription></GroupDescription>"}],
            "group_id": rule.vuln_id, "severity": rule.severity,
            "group_title": rule.title, "rule_id_src": rule.rule_id,
            "rule_id": rule.rule_id.removesuffix("_rule"),
            "rule_version": rule.stig_id, "rule_title": rule.title,
            "fix_text": rule.fix_text, "weight": "10.0",
            "check_content": rule.check_text,
            "check_content_ref": {"name": "M", "href": ""},
            "classification": "Unclassified", "discussion": rule.discussion,
            "false_positives": "", "false_negatives": "", "documentable": "false",
            "security_override_guidance": "", "potential_impacts": "",
            "third_party_tools": "", "ia_controls": "", "responsibility": "",
            "mitigations": "", "mitigation_control": "",
            "legacy_ids": list(rule.identifiers), "ccis": [],
            "reference_identifier": "", "uuid": str(uuid.uuid4()),
            "stig_uuid": stig_uuid, "status": "not_reviewed", "overrides": {},
            "comments": "", "finding_details": "", "srg_id": rule.group_id,
        })
    return {
        "title": title or f"{asset.hostname} {benchmark.display_name}",
        "id": str(uuid.uuid4()),
        "stigs": [{
            "stig_name": benchmark.title, "display_name": benchmark.display_name,
            "stig_id": benchmark.benchmark_id, "release_info": benchmark.release_info,
            "version": benchmark.version, "uuid": stig_uuid,
            "reference_identifier": "", "size": len(rules), "rules": rules,
        }],
        "active": False, "mode": 1, "has_path": True,
        "target_data": _target_data(asset), "cklb_version": "1.0",
    }


def populate_cklb(
    template: dict[str, Any], results: Iterable[CheckResult], asset: CklAsset,
    *, append_comments: bool = True,
) -> tuple[dict[str, Any], tuple[str, ...], tuple[str, ...]]:
    validate_cklb(template)
    payload = copy.deepcopy(template)
    payload["target_data"].update(_target_data(asset))
    result_by_vuln = {result.vuln_id: result for result in results if result.vuln_id}
    updated: list[str] = []
    for stig in payload["stigs"]:
        for rule in stig["rules"]:
            vuln_id = _rule_vuln_id(rule)
            result = result_by_vuln.get(vuln_id)
            if result is None:
                continue
            rule["status"] = CKLB_STATUS_MAP.get(result.status, "not_reviewed")
            rule["finding_details"] = result.finding_details or result.error_message or ""
            generated = _generated_comment(result, asset)
            existing = str(rule.get("comments") or "").strip()
            rule["comments"] = f"{existing}\n\n{generated}" if append_comments and existing else generated
            updated.append(vuln_id)
    unmatched = sorted(set(result_by_vuln) - set(updated))
    return payload, tuple(sorted(set(updated))), tuple(unmatched)


def write_completed_cklb(
    source: str | Path | dict[str, Any] | StigBenchmarkMetadata,
    destination_path: str | Path, results: Iterable[CheckResult], asset: CklAsset,
    *, append_comments: bool = True,
) -> CklbWriteSummary:
    if isinstance(source, StigBenchmarkMetadata):
        template = create_cklb_template(source, asset)
    elif isinstance(source, (str, Path)):
        template = load_cklb(source)
    else:
        template = source
    payload, updated, unmatched = populate_cklb(
        template, results, asset, append_comments=append_comments
    )
    destination = Path(destination_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return CklbWriteSummary(destination, updated, unmatched)


def import_cklb_results(path: str | Path) -> list[CheckResult]:
    payload = load_cklb(path)
    target = payload["target_data"]
    ip = str(target.get("ip_address") or "unknown")
    hostname = str(target.get("host_name") or "unknown")
    results: list[CheckResult] = []
    for stig in payload["stigs"]:
        family = str(stig.get("stig_id") or stig.get("stig_name") or "UNKNOWN")
        for rule in stig["rules"]:
            results.append(CheckResult(
                ip=ip, hostname=hostname, vuln_id=_rule_vuln_id(rule),
                rule_id=str(rule.get("rule_id_src") or rule.get("rule_id") or "") or None,
                stig_id=str(rule.get("rule_version") or "") or None,
                stig_family=family,
                title=str(rule.get("rule_title") or rule.get("group_title") or ""),
                severity=str(rule.get("severity") or "unknown"),
                status=INTERNAL_STATUS_MAP.get(str(rule.get("status")), "Not_Reviewed"),
                finding_details=str(rule.get("finding_details") or ""),
                comments=str(rule.get("comments") or ""),
            ))
    return results


def _rule_vuln_id(rule: dict[str, Any]) -> str:
    return str(rule.get("group_id_src") or rule.get("group_id") or "")


def _target_data(asset: CklAsset) -> dict[str, Any]:
    return {
        "target_type": "Computing", "host_name": asset.hostname,
        "ip_address": asset.management_ip, "mac_address": "",
        "fqdn": asset.fqdn or asset.hostname,
        "comments": f"Scan target: {asset.scan_ip}", "role": "None",
        "is_web_database": False, "technology_area": "Network",
        "web_db_site": "", "web_db_instance": "", "classification": None,
    }


def _generated_comment(result: CheckResult, asset: CklAsset) -> str:
    lines = [
        "STIG Audit Pro automated result", f"Status: {result.status}",
        f"Device: {asset.hostname}", f"Management IP: {asset.management_ip}",
        f"Scan target: {asset.scan_ip}",
    ]
    if result.comments.strip():
        lines.extend(["", result.comments.strip()])
    if result.error_message:
        lines.extend(["", f"Automation error: {result.error_message}"])
    return "\n".join(lines)


__all__ = [
    "CKLB_STATUS_MAP", "CklbError", "CklbWriteSummary", "create_cklb_template",
    "import_cklb_results", "load_cklb", "read_cklb", "populate_cklb", "validate_cklb",
    "write_completed_cklb",
]
