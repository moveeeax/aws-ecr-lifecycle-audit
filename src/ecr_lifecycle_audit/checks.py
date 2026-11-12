"""One pure function per check, over exactly one repository.

Every check takes `(Repository, AuditConfig)` and returns findings. No check
reads global state, touches the network or looks at another repository, which
is what keeps the table-driven tests readable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .model import AuditConfig, Finding, Image, LifecycleRule, Repository, gib


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


CheckFn = Callable[[Repository, AuditConfig], list[Finding]]


@dataclass(frozen=True)
class Check:
    check_id: str
    severity: str
    summary: str
    fn: CheckFn


_REGISTRY: dict[str, Check] = {}


def register(check_id: str, severity: str, summary: str):
    def decorate(fn: CheckFn) -> CheckFn:
        _REGISTRY[check_id] = Check(check_id, severity, summary, fn)
        return fn

    return decorate


def all_checks() -> list[Check]:
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]


def check_ids() -> list[str]:
    return sorted(_REGISTRY)


def _f(check_id: str, repo: Repository, message: str, detail: str = "", wasted_bytes: int = 0) -> Finding:
    return Finding(
        check=check_id,
        severity=_REGISTRY[check_id].severity,
        repository=repo.name,
        message=message,
        detail=detail,
        wasted_bytes=wasted_bytes,
    )


def matched_images(repo: Repository, rule: LifecycleRule) -> list[Image]:
    """The images a rule's selection block can act on."""
    if rule.tag_status == "untagged":
        return [i for i in repo.images if i.untagged]
    if rule.tag_status == "tagged":
        tagged = [i for i in repo.images if not i.untagged]
        if not rule.tag_prefix_list:
            return tagged
        return [
            i
            for i in tagged
            if any(tag.startswith(p) for tag in i.tags for p in rule.tag_prefix_list)
        ]
    return list(repo.images)


def stale_images(repo: Repository, cfg: AuditConfig) -> list[Image]:
    out = []
    for image in repo.images:
        age = image.age_days(cfg.now)
        if age is not None and age > cfg.max_age_days:
            out.append(image)
    return out


def removable_images(repo: Repository, cfg: AuditConfig) -> list[Image]:
    """Images a correct lifecycle policy would already have expired.

    Untagged images plus anything past `--max-age-days`, de-duplicated by
    digest so an image that is both is only billed once.
    """
    seen: set[str] = set()
    out: list[Image] = []
    for position, image in enumerate(repo.untagged_images + stale_images(repo, cfg)):
        key = image.digest or f"#{position}"
        if key in seen:
            continue
        seen.add(key)
        out.append(image)
    return out


def removable_bytes(repo: Repository, cfg: AuditConfig) -> int:
    return sum(i.size_bytes for i in removable_images(repo, cfg))


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


@register("MALFORMED_LIFECYCLE_POLICY", "high", "lifecycle policy document could not be parsed")
def malformed_lifecycle_policy(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if not repo.policy_error:
        return []
    return [
        _f(
            "MALFORMED_LIFECYCLE_POLICY",
            repo,
            "lifecycle policy is not usable and nothing is being expired",
            repo.policy_error,
        )
    ]


@register("NO_LIFECYCLE_POLICY", "medium", "no lifecycle policy, so nothing is ever deleted")
def no_lifecycle_policy(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if repo.has_policy or repo.policy_error:
        return []
    detail = "no policy document supplied for this repository"
    if repo.images_known:
        detail = f"{len(repo.images)} images present and no policy to expire any of them"
    return [
        _f(
            "NO_LIFECYCLE_POLICY",
            repo,
            "no lifecycle policy: storage grows with every build",
            detail,
            removable_bytes(repo, cfg),
        )
    ]


@register("UNTAGGED_BLOAT", "medium", "untagged images above the threshold")
def untagged_bloat(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if not repo.images_known:
        return []
    untagged = repo.untagged_images
    if len(untagged) <= cfg.max_untagged:
        return []
    total = sum(i.size_bytes for i in untagged)
    return [
        _f(
            "UNTAGGED_BLOAT",
            repo,
            f"{len(untagged)} untagged images (threshold {cfg.max_untagged})",
            f"{gib(total):.2f} GiB of untagged layers are still billed",
            total,
        )
    ]


@register("UNREACHABLE_RULE", "medium", "a lifecycle rule that can never match an image")
def unreachable_rule(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if not repo.images_known or not repo.rules:
        return []
    findings: list[Finding] = []
    present = repo.all_tags
    for rule in repo.rules:
        matched = matched_images(repo, rule)
        if rule.tag_status == "tagged" and rule.tag_prefix_list and not matched:
            prefixes = ", ".join(rule.tag_prefix_list)
            findings.append(
                _f(
                    "UNREACHABLE_RULE",
                    repo,
                    f"rule priority {rule.priority} matches no image: "
                    f"tagPrefixList [{prefixes}]",
                    f"tags present: {', '.join(sorted(present)) or 'none'}",
                )
            )
            continue
        if (
            rule.count_type == "imageCountMoreThan"
            and rule.count_number is not None
            and len(matched) <= rule.count_number
        ):
            findings.append(
                _f(
                    "UNREACHABLE_RULE",
                    repo,
                    f"rule priority {rule.priority} can never trigger: "
                    f"imageCountMoreThan {rule.count_number} but only "
                    f"{_plural(len(matched), 'image')} match",
                )
            )
    return findings


@register("SHADOWED_RULE", "low", "a rule made unreachable by a higher-priority catch-all")
def shadowed_rule(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    catch_alls = [r for r in repo.rules if r.is_catch_all]
    if not catch_alls:
        return []
    first = min(r.priority for r in catch_alls)
    findings = []
    for rule in repo.rules:
        if rule.priority <= first or rule.is_catch_all:
            continue
        findings.append(
            _f(
                "SHADOWED_RULE",
                repo,
                f"rule priority {rule.priority} is shadowed by the "
                f"tagStatus=any rule at priority {first}",
                "ECR evaluates rules in priority order; a catch-all must come last",
            )
        )
    return findings


@register("TAG_MUTABLE", "medium", "image tags can be repointed under a running deployment")
def tag_mutable(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if repo.tag_mutability != "MUTABLE":
        return []
    return [
        _f(
            "TAG_MUTABLE",
            repo,
            "imageTagMutability is MUTABLE: a pushed tag can be moved to another digest",
        )
    ]


@register("SCAN_ON_PUSH_OFF", "high", "pushed images are never scanned for vulnerabilities")
def scan_on_push_off(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if repo.scan_on_push is not False:
        return []
    return [_f("SCAN_ON_PUSH_OFF", repo, "scanOnPush is false: images are never scanned")]


@register("NO_KMS_ENCRYPTION", "low", "repository uses AES256 instead of a KMS key")
def no_kms_encryption(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if repo.encryption_type != "AES256":
        return []
    return [
        _f(
            "NO_KMS_ENCRYPTION",
            repo,
            "encryptionType is AES256: no customer-managed key",
        )
    ]


@register("STALE_IMAGES", "low", "images older than the age threshold are still stored")
def stale(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if not repo.images_known:
        return []
    old = stale_images(repo, cfg)
    if not old:
        return []
    total = sum(i.size_bytes for i in old)
    oldest = max(old, key=lambda i: i.age_days(cfg.now) or 0.0)
    return [
        _f(
            "STALE_IMAGES",
            repo,
            f"{_plural(len(old), 'image')} older than {cfg.max_age_days} days",
            f"oldest is {int(oldest.age_days(cfg.now) or 0)} days old",
            total,
        )
    ]


@register("EMPTY_REPOSITORY", "low", "repository holds no images at all")
def empty_repository(repo: Repository, cfg: AuditConfig) -> list[Finding]:
    if not repo.images_known or repo.images:
        return []
    return [_f("EMPTY_REPOSITORY", repo, "zero images: probably a dead repository")]


# --------------------------------------------------------------------------- #


def run_checks(
    repos: Iterable[Repository],
    cfg: AuditConfig,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    severity_floor: str = "low",
) -> list[Finding]:
    from .model import meets_floor

    selected = [
        check
        for check in all_checks()
        if (not only or check.check_id in only)
        and (not skip or check.check_id not in skip)
        and meets_floor(check.severity, severity_floor)
    ]
    findings: list[Finding] = []
    for repo in repos:
        for check in selected:
            findings.extend(check.fn(repo, cfg))
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (rank[f.severity], f.repository, f.check, f.message))
    return findings
