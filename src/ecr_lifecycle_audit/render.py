"""Table, JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json

from .checks import removable_bytes, removable_images
from .model import AuditConfig, Finding, Repository, gib, monthly_cost


def waste_summary(repos: list[Repository], cfg: AuditConfig) -> dict:
    per_repo = {}
    for repo in repos:
        total = removable_bytes(repo, cfg)
        if total:
            per_repo[repo.name] = {
                "images": len(removable_images(repo, cfg)),
                "bytes": total,
            }
    total_bytes = sum(entry["bytes"] for entry in per_repo.values())
    return {
        "repositories": len(per_repo),
        "removable_bytes": total_bytes,
        "removable_gib": round(gib(total_bytes), 2),
        "price_per_gb": cfg.price_per_gb,
        "estimated_monthly_usd": round(monthly_cost(total_bytes, cfg.price_per_gb), 2),
        "per_repository": per_repo,
    }


def _rows(findings: list[Finding]) -> list[list[str]]:
    return [
        [f.severity, f.check, f.repository, f.message, f.detail]
        for f in findings
    ]


HEADER = ["SEVERITY", "CHECK", "REPOSITORY", "FINDING"]


def render_table(findings: list[Finding], repos: list[Repository], cfg: AuditConfig) -> str:
    out = io.StringIO()
    if findings:
        rows = [[f.severity, f.check, f.repository, f.message] for f in findings]
        widths = [
            max(len(HEADER[col]), max(len(row[col]) for row in rows))
            for col in range(len(HEADER))
        ]
        line = "  ".join(HEADER[col].ljust(widths[col]) for col in range(len(HEADER)))
        out.write(line.rstrip() + "\n")
        out.write("  ".join("-" * widths[col] for col in range(len(HEADER))) + "\n")
        for finding, row in zip(findings, rows):
            out.write(
                "  ".join(row[col].ljust(widths[col]) for col in range(len(HEADER))).rstrip()
                + "\n"
            )
            if finding.detail:
                out.write(" " * (widths[0] + 2) + f"  {finding.detail}\n")
    else:
        out.write("No findings.\n")

    waste = waste_summary(repos, cfg)
    out.write("\n")
    out.write(
        f"{len(repos)} repositories audited, {len(findings)} findings.\n"
    )
    out.write(
        "Reclaimable: {gib} GiB across {n} repositories, "
        "est. ${cost}/month at ${price}/GB\n".format(
            gib=waste["removable_gib"],
            n=waste["repositories"],
            cost=f'{waste["estimated_monthly_usd"]:.2f}',
            price=f'{cfg.price_per_gb:g}',
        )
    )
    return out.getvalue()


def render_json(findings: list[Finding], repos: list[Repository], cfg: AuditConfig) -> str:
    payload = {
        "repositories_audited": len(repos),
        "findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "repository": f.repository,
                "message": f.message,
                "detail": f.detail,
                "wasted_bytes": f.wasted_bytes,
            }
            for f in findings
        ],
        "waste": waste_summary(repos, cfg),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_csv(findings: list[Finding], repos: list[Repository], cfg: AuditConfig) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["severity", "check", "repository", "message", "detail", "wasted_bytes"])
    for f in findings:
        writer.writerow(
            [f.severity, f.check, f.repository, f.message, f.detail, f.wasted_bytes]
        )
    return out.getvalue()


RENDERERS = {
    "table": render_table,
    "json": render_json,
    "csv": render_csv,
}


def render(fmt: str, findings: list[Finding], repos: list[Repository], cfg: AuditConfig) -> str:
    return RENDERERS[fmt](findings, repos, cfg)
