import json

import pytest

from conftest import ACCOUNT, image_detail, policy_text, repo_entry, rule, write_bundle
from ecr_lifecycle_audit.loader import InputError, load, parse_rules


def test_describe_repositories_is_normalised(tmp_path):
    path = tmp_path / "repos.json"
    path.write_text(
        json.dumps({"repositories": [repo_entry("payments-api", "MUTABLE", False, "AES256")]}),
        encoding="utf-8",
    )
    (repo,) = load([str(path)])
    assert repo.name == "payments-api"
    assert repo.tag_mutability == "MUTABLE"
    assert repo.scan_on_push is False
    assert repo.encryption_type == "AES256"
    assert repo.created_at is not None
    assert repo.images_known is False


def test_three_describe_shapes_merge_into_one_repository(tmp_path):
    repos = tmp_path / "repos.json"
    repos.write_text(json.dumps({"repositories": [repo_entry("api")]}), encoding="utf-8")

    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "api.json").write_text(
        json.dumps(
            {
                "registryId": ACCOUNT,
                "repositoryName": "api",
                "lifecyclePolicyText": policy_text(
                    [rule(1, "untagged", "sinceImagePushed", 1, unit="days")]
                ),
            }
        ),
        encoding="utf-8",
    )

    images = tmp_path / "images"
    images.mkdir()
    (images / "api.json").write_text(
        json.dumps({"imageDetails": [image_detail("api", ["v1"], 10, 1, "x")]}),
        encoding="utf-8",
    )

    (repo,) = load([str(repos)], [str(policies)], [str(images)])
    assert repo.has_policy is True
    assert [r.priority for r in repo.rules] == [1]
    assert repo.images_known is True
    assert repo.images[0].tags == ("v1",)
    assert repo.images[0].size_bytes == 10


def test_bundle_keyed_by_repository_name(tmp_path):
    path = write_bundle(
        tmp_path,
        {
            "api": {
                "repository": repo_entry("api"),
                "lifecyclePolicyText": policy_text([rule(1, "any", "sinceImagePushed", 30, unit="days")]),
                "imageDetails": [image_detail("api", [], 5, 2, "u")],
            }
        },
    )
    (repo,) = load([path])
    assert repo.has_policy and repo.images_known
    assert repo.untagged_images and repo.rules[0].tag_status == "any"


def test_repository_known_only_from_a_policy_file_is_still_audited(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "repositoryName": "ghost",
                "lifecyclePolicyText": policy_text([rule(1, "any", "sinceImagePushed", 1, unit="days")]),
            }
        ),
        encoding="utf-8",
    )
    (repo,) = load([str(path)])
    assert repo.name == "ghost"
    assert repo.in_describe is False


def test_empty_describe_images_marks_the_repository_as_known(tmp_path):
    images = tmp_path / "images"
    images.mkdir()
    (images / "legacy-batch.json").write_text(json.dumps({"imageDetails": []}), encoding="utf-8")
    (repo,) = load([], None, [str(images)])
    assert repo.name == "legacy-batch"
    assert repo.images_known is True
    assert repo.images == []


def test_epoch_and_zulu_timestamps_both_parse(tmp_path):
    path = tmp_path / "images.json"
    path.write_text(
        json.dumps(
            {
                "imageDetails": [
                    {"repositoryName": "api", "imageDigest": "sha256:a", "imagePushedAt": 1700000000},
                    {"repositoryName": "api", "imageDigest": "sha256:b", "imagePushedAt": "2026-01-02T03:04:05Z"},
                    {"repositoryName": "api", "imageDigest": "sha256:c", "imagePushedAt": "not a date"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (repo,) = load([str(path)])
    assert repo.images[0].pushed_at.year == 2023
    assert repo.images[1].pushed_at.month == 1
    assert repo.images[2].pushed_at is None


@pytest.mark.parametrize(
    "document",
    [
        {"rules": [{"rulePriority": 1}]},
        {"rules": [{"rulePriority": "x", "selection": {}}]},
        {"rules": "nope"},
        {"norules": []},
        ["a list"],
        '{"rules": [',
    ],
)
def test_bad_policy_documents_raise_valueerror(document):
    with pytest.raises(ValueError):
        parse_rules(document)


def test_rules_are_sorted_by_priority():
    rules = parse_rules(
        {
            "rules": [
                rule(10, "any", "sinceImagePushed", 5, unit="days"),
                rule(2, "tagged", "imageCountMoreThan", 3, prefixes=["v"]),
            ]
        }
    )
    assert [r.priority for r in rules] == [2, 10]


@pytest.mark.parametrize(
    "payload",
    [{}, {"Rules": []}, {"somethingElse": {"a": 1}}, 42],
)
def test_non_ecr_input_is_rejected(tmp_path, payload):
    path = tmp_path / "junk.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(InputError):
        load([str(path)])


def test_zero_repositories_is_valid_ecr_input(tmp_path):
    path = tmp_path / "repos.json"
    path.write_text(json.dumps({"repositories": []}), encoding="utf-8")
    assert load([str(path)]) == []


def test_unreadable_and_invalid_inputs_raise_inputerror(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(InputError):
        load([str(missing)])

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError):
        load([str(broken)])

    empty = tmp_path / "empty.json"
    empty.write_text("   ", encoding="utf-8")
    with pytest.raises(InputError):
        load([str(empty)])

    empty_dir = tmp_path / "nothing"
    empty_dir.mkdir()
    with pytest.raises(InputError):
        load([str(empty_dir)])
