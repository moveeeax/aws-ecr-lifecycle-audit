import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from ecr_lifecycle_audit.model import AuditConfig

NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)
ACCOUNT = "123456789012"


@pytest.fixture
def cfg():
    return AuditConfig(now=NOW, max_untagged=20, max_age_days=180, price_per_gb=0.10)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def repo_entry(
    name,
    mutability="IMMUTABLE",
    scan_on_push=True,
    encryption="KMS",
):
    return {
        "repositoryArn": f"arn:aws:ecr:eu-central-1:{ACCOUNT}:repository/{name}",
        "registryId": ACCOUNT,
        "repositoryName": name,
        "createdAt": iso(400),
        "imageTagMutability": mutability,
        "imageScanningConfiguration": {"scanOnPush": scan_on_push},
        "encryptionConfiguration": {"encryptionType": encryption},
    }


def image_detail(name, tags, size, days_ago, seed):
    detail = {
        "registryId": ACCOUNT,
        "repositoryName": name,
        "imageDigest": digest(seed),
        "imageSizeInBytes": size,
        "imagePushedAt": iso(days_ago),
    }
    if tags:
        detail["imageTags"] = list(tags)
    return detail


def rule(priority, tag_status, count_type, count_number, prefixes=None, unit=None):
    selection = {"tagStatus": tag_status}
    if prefixes:
        selection["tagPrefixList"] = list(prefixes)
    selection["countType"] = count_type
    if unit:
        selection["countUnit"] = unit
    selection["countNumber"] = count_number
    return {
        "rulePriority": priority,
        "description": f"rule {priority}",
        "selection": selection,
        "action": {"type": "expire"},
    }


def policy_text(rules):
    return json.dumps({"rules": rules})


def write_bundle(tmp_path, bundle, name="bundle.json"):
    path = tmp_path / name
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Named scenarios used by several test modules
# --------------------------------------------------------------------------- #


def clean_bundle():
    """Policy present and reachable, IMMUTABLE, scanned, KMS, no untagged."""
    return {
        "payments-api": {
            "repository": repo_entry("payments-api"),
            "lifecyclePolicyText": policy_text(
                [
                    rule(1, "untagged", "sinceImagePushed", 1, unit="days"),
                    rule(2, "tagged", "imageCountMoreThan", 2, prefixes=["v"]),
                ]
            ),
            "imageDetails": [
                image_detail("payments-api", ["v2.4.1"], 214_000_000, 3, "a"),
                image_detail("payments-api", ["v2.4.0"], 213_000_000, 11, "b"),
                image_detail("payments-api", ["v2.3.9"], 212_000_000, 24, "c"),
            ],
        }
    }


def no_policy_bundle(untagged=900):
    """No lifecycle policy and a pile of untagged images."""
    details = [image_detail("web-frontend", ["v1.8.2"], 96_000_000, 2, "tagged")]
    details += [
        image_detail("web-frontend", [], 10_000_000, 4, f"untagged-{i}")
        for i in range(untagged)
    ]
    return {
        "web-frontend": {
            "repository": repo_entry("web-frontend"),
            "imageDetails": details,
        }
    }


def unreachable_prefix_bundle():
    """tagPrefixList is `release-` while every tag starts with `v`."""
    return {
        "ml-trainer": {
            "repository": repo_entry("ml-trainer"),
            "lifecyclePolicyText": policy_text(
                [rule(1, "tagged", "imageCountMoreThan", 10, prefixes=["release-"])]
            ),
            "imageDetails": [
                image_detail("ml-trainer", ["v0.9.3"], 3_100_000_000, 15, "ml1"),
                image_detail("ml-trainer", ["v0.9.2"], 3_090_000_000, 40, "ml2"),
            ],
        }
    }


def shadowed_bundle():
    """A catch-all at priority 1 in front of a narrower rule at priority 2."""
    return {
        "checkout-worker": {
            "repository": repo_entry("checkout-worker"),
            "lifecyclePolicyText": policy_text(
                [
                    rule(1, "any", "sinceImagePushed", 90, unit="days"),
                    rule(2, "tagged", "imageCountMoreThan", 30, prefixes=["v"]),
                ]
            ),
        }
    }


def malformed_bundle():
    """A broken policy next to a healthy repository."""
    bundle = clean_bundle()
    bundle["broken-policy"] = {
        "repository": repo_entry("broken-policy"),
        "lifecyclePolicyText": '{"rules": [{"rulePriority": 1, "selection": {',
    }
    return bundle
