import pytest

from conftest import (
    clean_bundle,
    image_detail,
    malformed_bundle,
    no_policy_bundle,
    policy_text,
    repo_entry,
    rule,
    shadowed_bundle,
    unreachable_prefix_bundle,
    write_bundle,
)
from ecr_lifecycle_audit.checks import check_ids, removable_bytes, run_checks
from ecr_lifecycle_audit.loader import load
from ecr_lifecycle_audit.model import monthly_cost


def audit(tmp_path, bundle, cfg, **kwargs):
    repos = load([write_bundle(tmp_path, bundle)])
    return repos, run_checks(repos, cfg, **kwargs)


def ids(findings):
    return sorted(f.check for f in findings)


def test_clean_repository_has_no_findings(tmp_path, cfg):
    _, findings = audit(tmp_path, clean_bundle(), cfg)
    assert findings == []


def test_no_policy_with_900_untagged_images(tmp_path, cfg):
    repos, findings = audit(tmp_path, no_policy_bundle(900), cfg)
    by_id = {f.check: f for f in findings}
    assert "NO_LIFECYCLE_POLICY" in by_id
    assert "UNTAGGED_BLOAT" in by_id
    assert by_id["NO_LIFECYCLE_POLICY"].repository == "web-frontend"
    assert by_id["UNTAGGED_BLOAT"].repository == "web-frontend"
    assert "900" in by_id["UNTAGGED_BLOAT"].message
    assert by_id["UNTAGGED_BLOAT"].wasted_bytes == 900 * 10_000_000
    # The one tagged image is not counted as reclaimable.
    assert removable_bytes(repos[0], cfg) == 900 * 10_000_000


def test_untagged_threshold_is_respected(tmp_path, cfg):
    bundle = no_policy_bundle(untagged=5)
    _, findings = audit(tmp_path, bundle, cfg)
    assert "UNTAGGED_BLOAT" not in ids(findings)
    assert "NO_LIFECYCLE_POLICY" in ids(findings)


def test_unreachable_tag_prefix_produces_exactly_one_finding(tmp_path, cfg):
    _, findings = audit(tmp_path, unreachable_prefix_bundle(), cfg)
    unreachable = [f for f in findings if f.check == "UNREACHABLE_RULE"]
    assert len(unreachable) == 1
    assert "priority 1" in unreachable[0].message
    assert "release-" in unreachable[0].message
    assert unreachable[0].repository == "ml-trainer"


def test_rule_whose_count_can_never_be_exceeded(tmp_path, cfg):
    bundle = {
        "api": {
            "repository": repo_entry("api"),
            "lifecyclePolicyText": policy_text(
                [rule(1, "tagged", "imageCountMoreThan", 500, prefixes=["v"])]
            ),
            "imageDetails": [image_detail("api", ["v1"], 10, 1, "x")],
        }
    }
    _, findings = audit(tmp_path, bundle, cfg, only={"UNREACHABLE_RULE"})
    assert len(findings) == 1
    assert "imageCountMoreThan 500" in findings[0].message


def test_shadowed_rule(tmp_path, cfg):
    _, findings = audit(tmp_path, shadowed_bundle(), cfg)
    assert ids(findings) == ["SHADOWED_RULE"]
    assert "priority 2" in findings[0].message
    assert "priority 1" in findings[0].message
    assert findings[0].severity == "low"


def test_malformed_policy_is_a_finding_and_the_rest_is_still_audited(tmp_path, cfg):
    repos, findings = audit(tmp_path, malformed_bundle(), cfg)
    assert [r.name for r in repos] == ["broken-policy", "payments-api"]
    assert ids(findings) == ["MALFORMED_LIFECYCLE_POLICY"]
    assert findings[0].repository == "broken-policy"
    assert findings[0].severity == "high"


def test_hygiene_flags(tmp_path, cfg):
    bundle = {
        "api": {
            "repository": repo_entry("api", "MUTABLE", False, "AES256"),
            "lifecyclePolicyText": policy_text(
                [rule(1, "untagged", "sinceImagePushed", 1, unit="days")]
            ),
            "imageDetails": [image_detail("api", ["v1"], 10, 1, "x")],
        }
    }
    _, findings = audit(tmp_path, bundle, cfg)
    assert ids(findings) == ["NO_KMS_ENCRYPTION", "SCAN_ON_PUSH_OFF", "TAG_MUTABLE"]


def test_stale_images(tmp_path, cfg):
    bundle = {
        "api": {
            "repository": repo_entry("api"),
            "lifecyclePolicyText": policy_text(
                [rule(1, "tagged", "imageCountMoreThan", 1, prefixes=["v"])]
            ),
            "imageDetails": [
                image_detail("api", ["v1"], 1_000, 400, "old"),
                image_detail("api", ["v2"], 2_000, 2, "new"),
            ],
        }
    }
    _, findings = audit(tmp_path, bundle, cfg, only={"STALE_IMAGES"})
    assert len(findings) == 1
    assert findings[0].wasted_bytes == 1_000
    assert "400 days old" in findings[0].detail
    assert findings[0].message == "1 image older than 180 days"


def test_empty_repository(tmp_path, cfg):
    bundle = {
        "legacy-batch": {
            "repository": repo_entry("legacy-batch"),
            "lifecyclePolicyText": policy_text(
                [rule(1, "any", "sinceImagePushed", 30, unit="days")]
            ),
            "imageDetails": [],
        }
    }
    _, findings = audit(tmp_path, bundle, cfg)
    assert ids(findings) == ["EMPTY_REPOSITORY"]


def test_removable_bytes_de_duplicates_untagged_and_stale(tmp_path, cfg):
    bundle = {
        "api": {
            "repository": repo_entry("api"),
            "imageDetails": [image_detail("api", [], 4_000, 900, "both")],
        }
    }
    repos, _ = audit(tmp_path, bundle, cfg)
    assert removable_bytes(repos[0], cfg) == 4_000


def test_only_and_skip_and_severity_compose(tmp_path, cfg):
    bundle = no_policy_bundle(900)
    _, only = audit(tmp_path, bundle, cfg, only={"UNTAGGED_BLOAT"})
    assert ids(only) == ["UNTAGGED_BLOAT"]

    _, skipped = audit(tmp_path, bundle, cfg, skip={"UNTAGGED_BLOAT"})
    assert "UNTAGGED_BLOAT" not in ids(skipped)

    _, floored = audit(tmp_path, bundle, cfg, severity_floor="high")
    assert floored == []

    _, both = audit(tmp_path, bundle, cfg, only={"UNTAGGED_BLOAT"}, skip={"UNTAGGED_BLOAT"})
    assert both == []


def test_findings_are_ordered_high_severity_first(tmp_path, cfg):
    bundle = no_policy_bundle(900)
    bundle["api"] = {
        "repository": repo_entry("api", scan_on_push=False),
        "lifecyclePolicyText": policy_text(
            [rule(1, "untagged", "sinceImagePushed", 1, unit="days")]
        ),
    }
    _, findings = audit(tmp_path, bundle, cfg)
    assert findings[0].check == "SCAN_ON_PUSH_OFF"
    assert findings[0].severity == "high"


def test_every_registered_check_is_documented():
    from ecr_lifecycle_audit.checks import all_checks

    for check in all_checks():
        assert check.summary
        assert check.severity in ("high", "medium", "low")
    assert len(check_ids()) == 10


@pytest.mark.parametrize(
    "num_bytes,price,expected",
    [
        (0, 0.10, 0.0),
        (1024 ** 3, 0.10, 0.10),
        (10 * 1024 ** 3, 0.10, 1.0),
        (1024 ** 3, 0.25, 0.25),
    ],
)
def test_monthly_cost_is_plain_arithmetic(num_bytes, price, expected):
    assert monthly_cost(num_bytes, price) == pytest.approx(expected)
