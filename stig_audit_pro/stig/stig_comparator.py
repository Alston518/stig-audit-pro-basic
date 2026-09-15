"""Compare old and new XCCDF STIG sources and map changes to local YAML."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from stig_audit_pro.config import DEFAULT_PROFILE_NAME
from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file, parse_xccdf_root


ChangeKind = Literal["Added", "Changed", "Removed"]

RULE_FIELDS: tuple[tuple[str, str], ...] = (
    ("stig_id", "STIG ID"),
    ("vuln_id", "Vulnerability ID"),
    ("rule_id", "Rule ID"),
    ("group_id", "Group ID"),
    ("title", "Title"),
    ("severity", "Severity"),
    ("discussion", "Discussion"),
    ("identifiers", "Identifiers / CCIs"),
    ("check_text", "Check text"),
    ("fix_text", "Fix text"),
)

PROFILE_TOKEN = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_.]*)")
PROFILE_KEY_NAMES = {
    "profile_key",
    "upstream_profile_key",
    "maximum_sessions_profile_key",
    "radius_group_profile_key",
    "radius_servers_profile_key",
    "radius_addresses_profile_key",
    "ntp_servers_profile_key",
}
SITE_PROFILE_ROOTS = {
    "arp_inspection",
    "comments",
    "dhcp_snooping",
    "disabled_port_policy",
    "endpoint_authentication",
    "management_access",
    "management_vlan",
    "native_vlan",
    "root_guard",
    "trunk_policy",
    "unused_vlan",
    "variables",
}
IMPLICIT_PROFILE_KEYS: dict[str, tuple[str, ...]] = {
    "management_access_policy": (
        "management_access.acl_name",
        "management_access.networks",
    ),
    "dhcp_snooping_policy": ("dhcp_snooping.vlans",),
    "arp_inspection_policy": ("arp_inspection.vlans",),
}
CONDITIONAL_PROFILE_DEFAULTS: dict[str, tuple[tuple[str, str], ...]] = {
    "ntp_authentication_policy": (
        ("ntp_servers_profile_key", "variables.ntp_servers"),
    ),
    "radius_server_policy": (
        ("radius_group_profile_key", "endpoint_authentication.radius_group"),
        ("radius_servers_profile_key", "endpoint_authentication.radius_servers"),
        ("radius_addresses_profile_key", "endpoint_authentication.radius_server_addresses"),
    ),
    "root_guard_neighbor_policy": (
        ("upstream_profile_key", "root_guard.upstream_switches"),
    ),
    "vty_session_limit_policy": (
        ("maximum_sessions_profile_key", "variables.max_concurrent_management_sessions"),
    ),
}


class StigComparisonError(ValueError):
    """Raised when one of the comparison sources cannot be parsed."""


@dataclass(frozen=True, slots=True)
class StigRuleChange:
    kind: ChangeKind
    family: str
    control_id: str
    old_rule: StigRuleMetadata | None
    new_rule: StigRuleMetadata | None
    changed_fields: tuple[str, ...]
    check_path: str = ""
    check_vuln_id: str = ""
    profile_keys: tuple[str, ...] = ()
    base_profile_path: str = ""
    site_profile_paths: tuple[str, ...] = ()

    @property
    def title(self) -> str:
        rule = self.new_rule or self.old_rule
        return rule.title if rule is not None else ""

    @property
    def old_identifier(self) -> str:
        return _rule_identifier(self.old_rule)

    @property
    def new_identifier(self) -> str:
        return _rule_identifier(self.new_rule)

    @property
    def update_target(self) -> str:
        if self.check_path:
            return self.check_path
        if self.kind == "Added":
            return _default_check_path(self.family)
        return "No local check matched"

    def guidance_lines(self) -> list[str]:
        lines: list[str] = []
        if self.kind == "Added":
            lines.append(
                f"Add a check definition for {self.control_id} to "
                f"{_default_check_path(self.family)} and validate the new check/fix text."
            )
            lines.append(
                "If the requirement contains organization- or site-defined values, add a "
                "base default and override it only in the affected site profiles."
            )
        elif self.kind == "Removed":
            target = self.check_path or _default_check_path(self.family)
            lines.append(
                f"Review {target}; retire the local check only after confirming the control "
                "was removed rather than renumbered."
            )
        elif self.check_path:
            changed = ", ".join(self.changed_fields)
            lines.append(
                f"Review {self.check_path} ({self.check_vuln_id}); the STIG changed: {changed}."
            )
            if {"Discussion", "Check text", "Fix text"} & set(self.changed_fields):
                lines.append(
                    "Revalidate the check type, commands, conditions, result text, and evidence "
                    "against the new requirement wording."
                )
            elif {
                "Severity",
                "Title",
                "STIG ID",
                "Vulnerability ID",
                "Rule ID",
                "Group ID",
                "Identifiers / CCIs",
            } & set(self.changed_fields):
                lines.append("Update the corresponding check metadata fields where needed.")
        else:
            lines.append(
                f"No local check matched {self.control_id}. Review "
                f"{_default_check_path(self.family)} and add or remap the control."
            )

        if self.profile_keys:
            lines.append(f"Profile values used by the current check: {', '.join(self.profile_keys)}.")
            if self.base_profile_path:
                lines.append(f"Review the defaults in {self.base_profile_path}.")
            if self.site_profile_paths:
                lines.append(
                    "Review matching site overrides in " + ", ".join(self.site_profile_paths) + "."
                )
            else:
                lines.append("No site file currently overrides those values.")
            if self.kind == "Removed":
                lines.append(
                    "Remove profile values only after confirming no remaining check uses them."
                )
        elif self.kind != "Added":
            lines.append("The matched check does not reference a base/site profile value.")
        return lines


@dataclass(frozen=True, slots=True)
class StigComparisonReport:
    old_source: str
    new_source: str
    old_benchmarks: tuple[StigBenchmarkMetadata, ...]
    new_benchmarks: tuple[StigBenchmarkMetadata, ...]
    changes: tuple[StigRuleChange, ...]
    unchanged_count: int

    @property
    def added_count(self) -> int:
        return sum(change.kind == "Added" for change in self.changes)

    @property
    def changed_count(self) -> int:
        return sum(change.kind == "Changed" for change in self.changes)

    @property
    def removed_count(self) -> int:
        return sum(change.kind == "Removed" for change in self.changes)

    @property
    def summary(self) -> str:
        return (
            f"{self.added_count} added, {self.changed_count} changed, "
            f"{self.removed_count} removed, {self.unchanged_count} unchanged"
        )

    def to_markdown(self) -> str:
        lines = [
            "# STIG Comparison Report",
            "",
            f"- Old source: `{self.old_source}`",
            f"- New source: `{self.new_source}`",
            f"- Result: {self.summary}",
            "",
            "## Benchmarks",
            "",
            "| Source | Family | Benchmark | Version | Release | Rules |",
            "|---|---|---|---|---|---:|",
        ]
        for label, benchmarks in (("Old", self.old_benchmarks), ("New", self.new_benchmarks)):
            for benchmark in benchmarks:
                lines.append(
                    "| "
                    + " | ".join(
                        (
                            label,
                            _markdown_cell(benchmark.family),
                            _markdown_cell(benchmark.display_name),
                            _markdown_cell(benchmark.version),
                            _markdown_cell(benchmark.benchmark_release_date),
                            str(benchmark.rule_count),
                        )
                    )
                    + " |"
                )

        lines.extend(["", "## Required review", ""])
        if not self.changes:
            lines.append("No rule-level differences were found.")
            lines.append("")
            return "\n".join(lines)

        lines.extend(
            [
                "| Change | Family | Control | Fields | Local target |",
                "|---|---|---|---|---|",
            ]
        )
        for change in self.changes:
            fields = ", ".join(change.changed_fields) or "Entire control"
            lines.append(
                "| "
                + " | ".join(
                    _markdown_cell(value)
                    for value in (
                        change.kind,
                        change.family,
                        change.control_id,
                        fields,
                        change.update_target,
                    )
                )
                + " |"
            )

        for change in self.changes:
            lines.extend(["", f"### {change.kind}: {change.control_id}", ""])
            if change.title:
                lines.extend([change.title, ""])
            for guidance in change.guidance_lines():
                lines.append(f"- {guidance}")
            if change.kind == "Changed":
                lines.extend(["", "Changed content:", ""])
                for attribute, label in RULE_FIELDS:
                    if label not in change.changed_fields:
                        continue
                    old_value = getattr(change.old_rule, attribute, "") if change.old_rule else ""
                    new_value = getattr(change.new_rule, attribute, "") if change.new_rule else ""
                    lines.extend(
                        [
                            f"**{label}**",
                            "",
                            f"- Old: {_markdown_value(old_value)}",
                            f"- New: {_markdown_value(new_value)}",
                            "",
                        ]
                    )
        return "\n".join(lines).rstrip() + "\n"

    def write_markdown(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.to_markdown(), encoding="utf-8")
        return destination


def load_stig_benchmarks(
    source_path: str | Path,
    *,
    family: str | None = None,
) -> list[StigBenchmarkMetadata]:
    """Load one XCCDF XML or every XCCDF benchmark in a STIG ZIP package."""

    source = Path(source_path)
    if not source.is_file():
        raise StigComparisonError(f"STIG source was not found: {source}")
    requested_family = family or ""
    benchmarks: list[StigBenchmarkMetadata] = []

    if source.suffix.lower() == ".xml":
        try:
            metadata = parse_xccdf_file(source)
        except (ET.ParseError, OSError) as exc:
            raise StigComparisonError(f"Could not parse XCCDF XML {source.name}: {exc}") from exc
        metadata.family = infer_stig_family(metadata, source.name, requested_family)
        benchmarks = [metadata]
    elif source.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(source) as archive:
                members = sorted(
                    (member for member in archive.infolist() if member.filename.lower().endswith(".xml")),
                    key=lambda member: ("xccdf" not in member.filename.lower(), member.filename.lower()),
                )
                for member in members:
                    try:
                        with archive.open(member) as handle:
                            root = ET.parse(handle).getroot()
                    except (ET.ParseError, OSError):
                        continue
                    if _local_name(root.tag) != "Benchmark":
                        continue
                    metadata = parse_xccdf_root(
                        root,
                        source_path=f"{source}!{member.filename}",
                        source_filename=member.filename,
                    )
                    metadata.family = infer_stig_family(metadata, member.filename, requested_family)
                    if metadata.rule_count:
                        benchmarks.append(metadata)
        except (OSError, zipfile.BadZipFile) as exc:
            raise StigComparisonError(f"Could not read STIG ZIP {source.name}: {exc}") from exc
    else:
        raise StigComparisonError("STIG comparison sources must be XCCDF XML or ZIP files.")

    if requested_family:
        benchmarks = [item for item in benchmarks if item.family == requested_family]
    benchmarks = _deduplicate_benchmarks(benchmarks)
    if not benchmarks:
        family_note = f" for {requested_family}" if requested_family else ""
        raise StigComparisonError(f"No XCCDF Benchmark rules{family_note} were found in {source.name}.")
    return benchmarks


def compare_stig_sources(
    old_source: str | Path,
    new_source: str | Path,
    *,
    family: str | None = None,
    checks: Iterable[CheckDefinition] = (),
    check_sources: Mapping[str, str | Path] | None = None,
    profiles_dir: str | Path | None = None,
    workspace_root: str | Path | None = None,
) -> StigComparisonReport:
    old_benchmarks = load_stig_benchmarks(old_source, family=family)
    new_benchmarks = load_stig_benchmarks(new_source, family=family)
    changes, unchanged_count = compare_stig_metadata(
        old_benchmarks,
        new_benchmarks,
        checks=checks,
        check_sources=check_sources,
        profiles_dir=profiles_dir,
        workspace_root=workspace_root,
    )
    return StigComparisonReport(
        old_source=str(Path(old_source)),
        new_source=str(Path(new_source)),
        old_benchmarks=tuple(old_benchmarks),
        new_benchmarks=tuple(new_benchmarks),
        changes=tuple(changes),
        unchanged_count=unchanged_count,
    )


def compare_stig_metadata(
    old_benchmarks: Iterable[StigBenchmarkMetadata],
    new_benchmarks: Iterable[StigBenchmarkMetadata],
    *,
    checks: Iterable[CheckDefinition] = (),
    check_sources: Mapping[str, str | Path] | None = None,
    profiles_dir: str | Path | None = None,
    workspace_root: str | Path | None = None,
) -> tuple[list[StigRuleChange], int]:
    old_rules = _rules_by_family(old_benchmarks)
    new_rules = _rules_by_family(new_benchmarks)
    check_list = list(checks)
    source_lookup = check_sources or {}
    profile_path = Path(profiles_dir) if profiles_dir is not None else None
    root_path = Path(workspace_root) if workspace_root is not None else None
    changes: list[StigRuleChange] = []
    unchanged_count = 0

    for family_name in sorted(set(old_rules) | set(new_rules)):
        pairs, old_only, new_only = _match_rules(
            old_rules.get(family_name, []),
            new_rules.get(family_name, []),
        )
        for old_rule, new_rule in pairs:
            changed_fields = tuple(
                label
                for attribute, label in RULE_FIELDS
                if getattr(old_rule, attribute) != getattr(new_rule, attribute)
            )
            if not changed_fields:
                unchanged_count += 1
                continue
            changes.append(
                _build_change(
                    "Changed",
                    family_name,
                    old_rule,
                    new_rule,
                    changed_fields,
                    check_list,
                    source_lookup,
                    profile_path,
                    root_path,
                )
            )
        for new_rule in new_only:
            changes.append(
                _build_change(
                    "Added",
                    family_name,
                    None,
                    new_rule,
                    (),
                    check_list,
                    source_lookup,
                    profile_path,
                    root_path,
                )
            )
        for old_rule in old_only:
            changes.append(
                _build_change(
                    "Removed",
                    family_name,
                    old_rule,
                    None,
                    (),
                    check_list,
                    source_lookup,
                    profile_path,
                    root_path,
                )
            )
    kind_order = {"Added": 0, "Changed": 1, "Removed": 2}
    changes.sort(key=lambda item: (kind_order[item.kind], item.family, item.control_id))
    return changes, unchanged_count


def infer_stig_family(
    metadata: StigBenchmarkMetadata,
    filename: str = "",
    fallback: str = "",
) -> str:
    text = " ".join(
        (filename, metadata.source_filename, metadata.benchmark_id, metadata.title)
    ).lower()
    if re.search(r"(?:^|[^a-z0-9])ndm(?:[^a-z0-9]|$)", text):
        return "IOSXE_NDM"
    if re.search(r"(?:^|[^a-z0-9])(?:l2s?|layer[ -]?2)(?:[^a-z0-9]|$)", text):
        return "IOSXE_L2"
    if re.search(r"(?:^|[^a-z0-9])rtr(?:[^a-z0-9]|$)", text):
        return "IOSXE_RTR"
    return fallback or metadata.family or "UNKNOWN"


def _build_change(
    kind: ChangeKind,
    family: str,
    old_rule: StigRuleMetadata | None,
    new_rule: StigRuleMetadata | None,
    changed_fields: tuple[str, ...],
    checks: list[CheckDefinition],
    check_sources: Mapping[str, str | Path],
    profiles_dir: Path | None,
    workspace_root: Path | None,
) -> StigRuleChange:
    matched_check = _find_matching_check(checks, old_rule, new_rule)
    check_path = ""
    check_vuln_id = ""
    profile_keys: tuple[str, ...] = ()
    base_profile_path = ""
    site_profile_paths: tuple[str, ...] = ()
    if matched_check is not None:
        check_vuln_id = matched_check.vuln_id
        source = check_sources.get(matched_check.vuln_id)
        check_path = _display_path(Path(source), workspace_root) if source else _default_check_path(family)
        profile_keys = tuple(sorted(_profile_keys_for_check(matched_check)))
        if profile_keys and profiles_dir is not None:
            base, sites = _profile_impacts(profiles_dir, profile_keys, workspace_root)
            base_profile_path = base
            site_profile_paths = tuple(sites)

    rule = new_rule or old_rule
    control_id = _control_identifier(rule)
    return StigRuleChange(
        kind=kind,
        family=family,
        control_id=control_id,
        old_rule=old_rule,
        new_rule=new_rule,
        changed_fields=changed_fields,
        check_path=check_path,
        check_vuln_id=check_vuln_id,
        profile_keys=profile_keys,
        base_profile_path=base_profile_path,
        site_profile_paths=site_profile_paths,
    )


def _rules_by_family(
    benchmarks: Iterable[StigBenchmarkMetadata],
) -> dict[str, list[StigRuleMetadata]]:
    result: dict[str, list[StigRuleMetadata]] = {}
    for benchmark in benchmarks:
        result.setdefault(benchmark.family or "UNKNOWN", []).extend(benchmark.rules)
    return result


def _match_rules(
    old_rules: list[StigRuleMetadata],
    new_rules: list[StigRuleMetadata],
) -> tuple[
    list[tuple[StigRuleMetadata, StigRuleMetadata]],
    list[StigRuleMetadata],
    list[StigRuleMetadata],
]:
    unmatched_old = set(range(len(old_rules)))
    unmatched_new = set(range(len(new_rules)))
    pairs: list[tuple[StigRuleMetadata, StigRuleMetadata]] = []

    def pair_unique(attribute: str, normalize: Any) -> None:
        old_values: dict[str, list[int]] = {}
        new_values: dict[str, list[int]] = {}
        for index in unmatched_old:
            value = normalize(getattr(old_rules[index], attribute, ""))
            if value:
                old_values.setdefault(value, []).append(index)
        for index in unmatched_new:
            value = normalize(getattr(new_rules[index], attribute, ""))
            if value:
                new_values.setdefault(value, []).append(index)
        for value in sorted(set(old_values) & set(new_values)):
            if len(old_values[value]) != 1 or len(new_values[value]) != 1:
                continue
            old_index = old_values[value][0]
            new_index = new_values[value][0]
            pairs.append((old_rules[old_index], new_rules[new_index]))
            unmatched_old.remove(old_index)
            unmatched_new.remove(new_index)

    pair_unique("stig_id", _normalize_identifier)
    pair_unique("vuln_id", _normalize_identifier)
    pair_unique("title", _normalize_title)
    return (
        pairs,
        [old_rules[index] for index in sorted(unmatched_old)],
        [new_rules[index] for index in sorted(unmatched_new)],
    )


def _find_matching_check(
    checks: Iterable[CheckDefinition],
    old_rule: StigRuleMetadata | None,
    new_rule: StigRuleMetadata | None,
) -> CheckDefinition | None:
    rules = [rule for rule in (new_rule, old_rule) if rule is not None]
    stig_ids = {_normalize_identifier(rule.stig_id) for rule in rules if rule.stig_id}
    vuln_ids = {_normalize_identifier(rule.vuln_id) for rule in rules if rule.vuln_id}
    for check in checks:
        if check.stig_id and _normalize_identifier(check.stig_id) in stig_ids:
            return check
    for check in checks:
        if _normalize_identifier(check.vuln_id) in vuln_ids:
            return check
    return None


def _profile_keys_for_check(check: CheckDefinition) -> set[str]:
    if hasattr(check, "model_dump"):
        payload = check.model_dump()  # type: ignore[attr-defined]
    else:
        payload = check.dict()
    keys: set[str] = set(IMPLICIT_PROFILE_KEYS.get(check.check_type, ()))
    for condition_name, default_key in CONDITIONAL_PROFILE_DEFAULTS.get(check.check_type, ()):
        if condition_name not in check.conditions:
            keys.add(default_key)

    def visit(value: object, parent_key: str = "") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if isinstance(nested, str) and (key in PROFILE_KEY_NAMES or key.endswith("_profile_key")):
                    keys.add(_canonical_profile_key(nested))
                visit(nested, key)
        elif isinstance(value, list):
            for nested in value:
                visit(nested, parent_key)
        elif isinstance(value, str):
            for match in PROFILE_TOKEN.finditer(value):
                token = match.group(1)
                if token not in {"item"}:
                    keys.add(_canonical_profile_key(token))

    visit(payload)
    return {key for key in keys if key}


def _canonical_profile_key(key: str) -> str:
    clean = key.strip().removeprefix("profile.")
    root = clean.split(".", 1)[0]
    if root in SITE_PROFILE_ROOTS:
        return clean
    return f"variables.{clean}"


def _profile_impacts(
    profiles_dir: Path,
    profile_keys: tuple[str, ...],
    workspace_root: Path | None,
) -> tuple[str, list[str]]:
    base_path = profiles_dir / f"{DEFAULT_PROFILE_NAME}.yaml"
    base_display = _display_path(base_path, workspace_root) if base_path.is_file() else ""
    site_paths: list[str] = []
    for path in sorted(profiles_dir.glob("*.yaml")):
        if path == base_path:
            continue
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(payload, dict):
            continue
        if any(_mapping_has_path(payload, key) for key in profile_keys):
            site_paths.append(_display_path(path, workspace_root))
    return base_display, site_paths


def _mapping_has_path(payload: Mapping[str, object], dotted_key: str) -> bool:
    current: object = payload
    for part in dotted_key.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False
        current = current[part]
    return True


def _deduplicate_benchmarks(
    benchmarks: list[StigBenchmarkMetadata],
) -> list[StigBenchmarkMetadata]:
    unique: list[StigBenchmarkMetadata] = []
    seen: set[tuple[str, str, str]] = set()
    for metadata in benchmarks:
        identity = (metadata.family, metadata.benchmark_id, metadata.version)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(metadata)
    return unique


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _normalize_identifier(value: str) -> str:
    return value.strip().upper()


def _normalize_title(value: str) -> str:
    return " ".join(value.casefold().split())


def _control_identifier(rule: StigRuleMetadata | None) -> str:
    if rule is None:
        return "Unknown control"
    return rule.stig_id or rule.vuln_id or rule.rule_id or rule.group_id or "Unknown control"


def _rule_identifier(rule: StigRuleMetadata | None) -> str:
    if rule is None:
        return "-"
    primary = _control_identifier(rule)
    if rule.vuln_id and rule.vuln_id != primary:
        return f"{primary} / {rule.vuln_id}"
    return primary


def _default_check_path(family: str) -> str:
    names = {
        "IOSXE_L2": "data/checks/iosxe_l2.yaml",
        "IOSXE_NDM": "data/checks/iosxe_ndm.yaml",
        "IOSXE_RTR": "data/checks/iosxe_rtr.yaml",
    }
    return names.get(family, "data/checks/<family>.yaml")


def _display_path(path: Path, workspace_root: Path | None) -> str:
    if workspace_root is not None:
        try:
            return path.resolve().relative_to(workspace_root.resolve()).as_posix()
        except ValueError:
            pass
    return str(path)


def _markdown_cell(value: object) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", " ")


def _markdown_value(value: object) -> str:
    text = str(value or "(empty)").replace("\n", " ")
    return text.replace("`", "\\`")
