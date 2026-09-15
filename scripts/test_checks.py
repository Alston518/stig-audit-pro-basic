#!/usr/bin/env python3
"""Run a small YAML check library against an IOS-XE device or saved outputs."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

# Allow this file to be run directly from the repository root without installing
# the package first.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.ssh_runner import DeviceCredentials, DeviceTarget, NetmikoSshRunner
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_check_library, load_profile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and run one or more copied STIG checks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("checks", type=Path, help="YAML file containing library_name and checks")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="IOS-XE hostname or IP address for a live SSH test")
    source.add_argument(
        "--outputs-dir",
        type=Path,
        help="Directory of saved command outputs (filenames use underscores, e.g. show_running_config.txt)",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=REPO_ROOT / "data" / "profiles" / "base_iosxe_access.yaml",
        help="Site profile used to resolve profile variables in checks",
    )
    parser.add_argument("--username", help="SSH username (or set STIG_TEST_USERNAME)")
    parser.add_argument("--password-env", default="STIG_TEST_PASSWORD", help="Environment variable holding SSH password")
    parser.add_argument("--secret-env", default="STIG_TEST_SECRET", help="Environment variable holding enable secret")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--timeout", type=int, default=30, help="SSH command timeout in seconds")
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="VULN_ID",
        help="Run only these vuln_id values from the test YAML",
    )
    parser.add_argument("--json", type=Path, dest="json_path", help="Also save full results as JSON")
    return parser.parse_args()


def command_filename(command: str) -> str:
    """Use the same simple naming convention as tests/sample_outputs."""
    safe = "".join(character if character.isalnum() else "_" for character in command.lower())
    return "_".join(part for part in safe.split("_") if part) + ".txt"


def load_saved_outputs(directory: Path, commands: list[str]) -> dict[str, str]:
    outputs: dict[str, str] = {}
    missing: list[str] = []
    for command in commands:
        if command == "terminal length 0":
            continue
        path = directory / command_filename(command)
        if not path.is_file():
            missing.append(f"{command} -> {path.name}")
            continue
        outputs[command] = path.read_text(encoding="utf-8", errors="replace")
    if missing:
        raise FileNotFoundError(
            "Missing saved output file(s):\n  " + "\n  ".join(missing)
        )
    return outputs


def select_checks(checks: list, vuln_ids: list[str] | None) -> list:
    if not vuln_ids:
        return checks
    requested = set(vuln_ids)
    selected = [check for check in checks if check.vuln_id in requested]
    missing = requested.difference(check.vuln_id for check in selected)
    if missing:
        raise ValueError(f"Unknown --only vuln_id value(s): {', '.join(sorted(missing))}")
    return selected


def result_dict(result: CheckResult) -> dict:
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")  # type: ignore[attr-defined]
    return json.loads(result.json())


def print_results(results: list[CheckResult]) -> None:
    print("\nCHECK RESULTS")
    print("=" * 78)
    for result in results:
        print(f"{result.status:14} {result.vuln_id:12} {result.title}")
        if result.finding_details:
            for line in result.finding_details.splitlines():
                print(f"  {line}")
        if result.comments:
            print(f"  Comment: {result.comments}")
        if result.parser_warnings:
            for warning in result.parser_warnings:
                print(f"  Parser warning: {warning}")
        print()

    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    print(f"Summary: {summary}")


def main() -> int:
    args = parse_args()
    try:
        library = load_check_library(args.checks)
        profile = load_profile(args.profile)
        checks = select_checks(library.checks, args.only)
        if not checks:
            raise ValueError("The test YAML does not contain any checks")
        commands = plan_commands(checks)

        if args.outputs_dir:
            outputs = load_saved_outputs(args.outputs_dir, commands)
            target_ip = "saved-output"
        else:
            username = args.username or os.environ.get("STIG_TEST_USERNAME") or input("SSH username: ")
            password = os.environ.get(args.password_env) or getpass.getpass("SSH password: ")
            secret = os.environ.get(args.secret_env) or None
            run = NetmikoSshRunner().run_commands(
                DeviceTarget(ip=args.host, port=args.port, timeout=args.timeout),
                DeviceCredentials(username=username, password=password, secret=secret),
                commands,
            )
            if run.status != "scanned":
                print(f"SSH scan failed for {args.host}: {run.error_message}", file=sys.stderr)
                return 2
            outputs = run.outputs
            target_ip = args.host

        results = CheckEngine(profile).evaluate_all(checks, outputs=outputs, ip=target_ip)
        print_results(results)
        if args.json_path:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            args.json_path.write_text(
                json.dumps([result_dict(result) for result in results], indent=2),
                encoding="utf-8",
            )
            print(f"Full JSON results saved to {args.json_path}")
        return 1 if any(result.status in {"Open", "Error"} for result in results) else 0
    except (ConfigValidationError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
