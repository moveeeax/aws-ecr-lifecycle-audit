"""The repository model every check reads from.

The three `aws ecr describe-*` shapes get flattened into exactly one
`Repository` per repository name, so a check never has to know which file a
field arrived in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("high", "medium", "low")
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}

BYTES_PER_GIB = 1024 ** 3


@dataclass(frozen=True)
class Image:
    digest: str
    tags: tuple[str, ...] = ()
    size_bytes: int = 0
    pushed_at: datetime | None = None

    @property
    def untagged(self) -> bool:
        return not self.tags

    def age_days(self, now: datetime) -> float | None:
        if self.pushed_at is None:
            return None
        return (now - self.pushed_at).total_seconds() / 86400.0


@dataclass(frozen=True)
class LifecycleRule:
    priority: int
    description: str = ""
    tag_status: str = "any"
    tag_prefix_list: tuple[str, ...] = ()
    count_type: str = ""
    count_number: int | None = None
    count_unit: str = ""
    action_type: str = "expire"

    @property
    def is_catch_all(self) -> bool:
        return self.tag_status == "any" and not self.tag_prefix_list


@dataclass
class Repository:
    name: str
    arn: str = ""
    registry_id: str = ""
    tag_mutability: str = ""
    scan_on_push: bool | None = None
    encryption_type: str = ""
    kms_key: str = ""
    created_at: datetime | None = None
    has_policy: bool = False
    policy_error: str = ""
    rules: list[LifecycleRule] = field(default_factory=list)
    images: list[Image] = field(default_factory=list)
    images_known: bool = False
    in_describe: bool = True

    @property
    def untagged_images(self) -> list[Image]:
        return [i for i in self.images if i.untagged]

    @property
    def all_tags(self) -> set[str]:
        tags: set[str] = set()
        for image in self.images:
            tags.update(image.tags)
        return tags


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    repository: str
    message: str
    detail: str = ""
    wasted_bytes: int = 0


@dataclass(frozen=True)
class AuditConfig:
    """Everything a check is allowed to be configured by."""

    now: datetime
    max_untagged: int = 20
    max_age_days: int = 180
    price_per_gb: float = 0.10


def gib(num_bytes: int) -> float:
    return num_bytes / BYTES_PER_GIB


def monthly_cost(num_bytes: int, price_per_gb: float) -> float:
    """ECR storage is billed per GB-month, so this is deliberately trivial."""
    return gib(num_bytes) * price_per_gb


def meets_floor(severity: str, floor: str) -> bool:
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[floor]
