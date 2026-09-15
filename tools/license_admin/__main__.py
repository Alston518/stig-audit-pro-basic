"""Command-line entry point for publisher-only offline license administration."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from stig_audit_pro.licensing import LicenseStatus
from stig_audit_pro.licensing.manager import SUPPORTED_FEATURES
from tools.license_admin.issue import issue_license, _parse_utc
from tools.license_admin.keygen import generate_key_pair
from tools.license_admin.verify import (
    inspect_license,
    verification_report,
    verify_license,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.license_admin",
        description=(
            "Publisher-only Ed25519 key and offline license administration. "
            "This package is excluded from customer builds."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate an Ed25519 key pair")
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--private-key-output", required=True, type=Path)
    keygen.add_argument("--public-key-output", required=True, type=Path)
    keygen.add_argument("--force", action="store_true")

    issue = subparsers.add_parser(
        "issue", help="Issue and immediately self-verify a license"
    )
    issue.add_argument("--interactive", action="store_true")
    issue.add_argument("--private-key", type=Path)
    issue.add_argument("--key-id")
    issue.add_argument("--customer-name")
    issue.add_argument("--edition", default="Pro")
    issue.add_argument("--expires-at")
    issue.add_argument(
        "--issued-at",
        help=(
            "Optional historical UTC issuance timestamp for publisher testing "
            "or migration"
        ),
    )
    issue.add_argument("--max-devices", type=int)
    issue.add_argument(
        "--enable",
        action="append",
        default=[],
        choices=sorted(SUPPORTED_FEATURES),
        metavar="FEATURE",
    )
    issue.add_argument("--output", type=Path)
    issue.add_argument("--force", action="store_true")

    verify = subparsers.add_parser(
        "verify", help="Cryptographically verify and summarize a license"
    )
    verify.add_argument("--license", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)

    inspect = subparsers.add_parser(
        "inspect", help="Parse and display a license without trusting it"
    )
    inspect.add_argument("--license", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generated = generate_key_pair(
                key_id=args.key_id,
                private_key_output=args.private_key_output,
                public_key_output=args.public_key_output,
                force=args.force,
            )
            print(f"Generated key_id: {generated.key_id}")
            print(f"Public-key fingerprint: {generated.fingerprint}")
            print(f"Private key: {generated.private_key_path}")
            print(f"Public key: {generated.public_key_path}")
            print(
                "Copy/rename the public key to: "
                f"{generated.repository_public_key_path}"
            )
            print(
                "WARNING: Never commit, log, copy into the repository, or ship "
                "the private signing key."
            )
            return 0

        if args.command == "issue":
            values = _interactive_values(args) if args.interactive else vars(args)
            required = (
                "private_key",
                "key_id",
                "customer_name",
                "expires_at",
                "max_devices",
                "output",
            )
            missing = [name for name in required if values.get(name) is None]
            if missing:
                parser.error(
                    "issue requires "
                    + ", ".join("--" + name.replace("_", "-") for name in missing)
                    + " unless --interactive supplies them"
                )
            issued = issue_license(
                private_key_path=values["private_key"],
                key_id=str(values["key_id"]),
                customer_name=str(values["customer_name"]),
                edition=str(values.get("edition") or "Pro"),
                expires_at=str(values["expires_at"]),
                max_devices=int(values["max_devices"]),
                enabled_features=list(values.get("enable") or []),
                output_path=values["output"],
                issued_at=(
                    _parse_utc(str(values["issued_at"]))
                    if values.get("issued_at")
                    else None
                ),
                force=bool(values.get("force")),
            )
            print("License issued and self-verification succeeded.")
            print(f"License ID: {issued.license_id}")
            print(f"Customer: {issued.customer_name}")
            print(f"Edition: {issued.edition}")
            print(f"Expiration: {issued.expires_at}")
            print(f"Device limit: {issued.max_devices}")
            print(
                "Enabled features: "
                + (
                    ", ".join(issued.enabled_features)
                    if issued.enabled_features
                    else "None"
                )
            )
            print(f"Key ID: {issued.key_id}")
            print(f"Output: {issued.path}")
            return 0

        if args.command == "verify":
            manager = verify_license(
                license_path=args.license,
                public_key_path=args.public_key,
            )
            print(verification_report(manager))
            return (
                0
                if manager.signature_verified
                and manager.status in {LicenseStatus.VALID, LicenseStatus.EXPIRED}
                else 1
            )

        _, report = inspect_license(args.license)
        print(report)
        return 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def _interactive_values(args: argparse.Namespace) -> dict[str, object]:
    defaults = vars(args).copy()
    defaults["customer_name"] = input("Customer name: ").strip()
    defaults["edition"] = input("Edition [Pro]: ").strip() or "Pro"
    defaults["expires_at"] = input(
        "Expiration UTC (for example 2027-07-28T23:59:59Z): "
    ).strip()
    issued_at = input(
        "Historical issuance UTC (blank for current time): "
    ).strip()
    defaults["issued_at"] = issued_at or None
    defaults["max_devices"] = int(input("Maximum device count: ").strip())
    print("Available features: " + ", ".join(sorted(SUPPORTED_FEATURES)))
    enabled = input("Features to enable (comma-separated): ").strip()
    defaults["enable"] = [
        item.strip() for item in enabled.split(",") if item.strip()
    ]
    defaults["private_key"] = Path(input("Private-key location: ").strip())
    defaults["key_id"] = input("Key ID: ").strip()
    defaults["output"] = Path(input("License output location: ").strip())
    return defaults


if __name__ == "__main__":
    raise SystemExit(main())
