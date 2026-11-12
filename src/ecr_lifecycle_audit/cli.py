"""Command line entrypoint.

Exit codes: 0 nothing at or above `--fail-on`, 1 something was found,
2 unreadable or non-ECR input.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from . import __version__
from .checks import all_checks, check_ids, run_checks
from .loader import InputError, load
from .model import AuditConfig, SEVERITIES, meets_floor
from .render import render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2


def _split(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-ecr-lifecycle-audit",
        description=(
            "Audit ECR repositories offline from describe-repositories, "
            "get-lifecycle-policy and describe-images output."
        ),
    )
    parser.add_argument(
        "--input",
        "-i",
        action="append",
        metavar="PATH",
        help="describe-repositories JSON, a directory of them, or - for stdin "
        "(repeatable)",
    )
    parser.add_argument(
        "--policies",
        action="append",
        default=[],
        metavar="PATH",
        help="get-lifecycle-policy JSON file or directory (repeatable)",
    )
    parser.add_argument(
        "--images",
        action="append",
        default=[],
        metavar="PATH",
        help="describe-images JSON file or directory (repeatable)",
    )
    parser.add_argument("--max-untagged", type=int, default=20, metavar="N")
    parser.add_argument("--max-age-days", type=int, default=180, metavar="DAYS")
    parser.add_argument("--price-per-gb", type=float, default=0.10, metavar="USD")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="low",
        help="only run checks at this severity or above (default: low)",
    )
    parser.add_argument("--only", metavar="IDS", help="comma-separated check ids to run")
    parser.add_argument("--skip", metavar="IDS", help="comma-separated check ids to skip")
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "none"),
        default="medium",
        help="lowest severity that makes the exit code 1 (default: medium)",
    )
    parser.add_argument(
        "--now",
        metavar="ISO8601",
        help="treat this instant as now, for reproducible age checks",
    )
    parser.add_argument("--list-checks", action="store_true", help="print checks and exit")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        for check in all_checks():
            print(f"{check.check_id:30} {check.severity:6} {check.summary}")
        return EXIT_OK

    if not args.input and not args.policies and not args.images:
        parser.error("one of --input, --policies or --images is required")

    only = _split(args.only)
    skip = _split(args.skip)
    known = set(check_ids())
    for label, ids in (("--only", only), ("--skip", skip)):
        unknown = ids - known
        if unknown:
            parser.error(f"{label}: unknown check id(s): {', '.join(sorted(unknown))}")

    try:
        now = _parse_now(args.now)
    except ValueError:
        parser.error(f"--now is not an ISO 8601 timestamp: {args.now}")

    cfg = AuditConfig(
        now=now,
        max_untagged=args.max_untagged,
        max_age_days=args.max_age_days,
        price_per_gb=args.price_per_gb,
    )

    try:
        repos = load(args.input or [], args.policies, args.images)
    except InputError as exc:
        print(f"aws-ecr-lifecycle-audit: {exc}", file=sys.stderr)
        return EXIT_INPUT

    findings = run_checks(repos, cfg, only=only, skip=skip, severity_floor=args.severity)
    sys.stdout.write(render(args.format, findings, repos, cfg))

    if args.fail_on == "none":
        return EXIT_OK
    if any(meets_floor(f.severity, args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
