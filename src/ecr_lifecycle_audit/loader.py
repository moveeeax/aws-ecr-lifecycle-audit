"""Turn `aws ecr describe-*` JSON into `Repository` objects.

No AWS API is ever called. Everything here is pure parsing, which is what
makes the tool runnable in CI with no credentials.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

from .model import Image, LifecycleRule, Repository


class InputError(Exception):
    """Unreadable or non-ECR input. The CLI turns this into exit code 2."""


_REPO_KEYS = ("repositories", "repositoryName", "imageDetails", "lifecyclePolicyText")


def _read_json(path: str) -> Any:
    try:
        if path == "-":
            raw = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if not raw.strip():
        raise InputError(f"{path} is empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc.msg} at line {exc.lineno}") from exc


def _json_files(path: str) -> list[str]:
    """A path is a file, `-` for stdin, or a directory of *.json."""
    if path == "-" or os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        found = sorted(
            os.path.join(path, name)
            for name in os.listdir(path)
            if name.endswith(".json")
        )
        if not found:
            raise InputError(f"no *.json files under {path}")
        return found
    raise InputError(f"no such file or directory: {path}")


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


class RepositoryIndex:
    """Accumulates fragments keyed by repository name."""

    def __init__(self) -> None:
        self._repos: dict[str, Repository] = {}

    def get(self, name: str, *, from_describe: bool = False) -> Repository:
        repo = self._repos.get(name)
        if repo is None:
            repo = Repository(name=name, in_describe=from_describe)
            self._repos[name] = repo
        elif from_describe:
            repo.in_describe = True
        return repo

    def repositories(self) -> list[Repository]:
        return sorted(self._repos.values(), key=lambda r: r.name)

    def __len__(self) -> int:
        return len(self._repos)


def apply_describe_repository(index: RepositoryIndex, entry: dict[str, Any]) -> None:
    name = entry.get("repositoryName")
    if not isinstance(name, str) or not name:
        return
    repo = index.get(name, from_describe=True)
    repo.arn = entry.get("repositoryArn") or repo.arn
    repo.registry_id = str(entry.get("registryId") or repo.registry_id)
    mutability = entry.get("imageTagMutability")
    if isinstance(mutability, str):
        repo.tag_mutability = mutability.upper()
    scan = entry.get("imageScanningConfiguration") or {}
    if isinstance(scan, dict) and "scanOnPush" in scan:
        repo.scan_on_push = bool(scan.get("scanOnPush"))
    enc = entry.get("encryptionConfiguration") or {}
    if isinstance(enc, dict):
        enc_type = enc.get("encryptionType")
        if isinstance(enc_type, str):
            repo.encryption_type = enc_type.upper()
        if isinstance(enc.get("kmsKey"), str):
            repo.kms_key = enc["kmsKey"]
    created = _parse_time(entry.get("createdAt"))
    if created is not None:
        repo.created_at = created


def parse_rules(document: Any) -> list[LifecycleRule]:
    """Normalise an ECR lifecycle policy document into rules.

    Raises `ValueError` when the document is structurally wrong; the caller
    records that as a finding rather than letting it escape.
    """
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ValueError(f"lifecyclePolicyText is not valid JSON: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError("policy document is not a JSON object")
    raw_rules = document.get("rules")
    if raw_rules is None:
        raise ValueError("policy document has no 'rules' key")
    if not isinstance(raw_rules, list):
        raise ValueError("'rules' is not a list")

    rules: list[LifecycleRule] = []
    for position, raw in enumerate(raw_rules, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"rule #{position} is not an object")
        priority = _as_int(raw.get("rulePriority"))
        if priority is None:
            raise ValueError(f"rule #{position} has no numeric rulePriority")
        selection = raw.get("selection")
        if not isinstance(selection, dict):
            raise ValueError(f"rule {priority} has no selection object")
        prefixes = selection.get("tagPrefixList") or []
        if not isinstance(prefixes, list):
            raise ValueError(f"rule {priority} has a non-list tagPrefixList")
        action = raw.get("action")
        action_type = ""
        if isinstance(action, dict):
            action_type = str(action.get("type") or "")
        rules.append(
            LifecycleRule(
                priority=priority,
                description=str(raw.get("description") or ""),
                tag_status=str(selection.get("tagStatus") or "any").lower(),
                tag_prefix_list=tuple(str(p) for p in prefixes),
                count_type=str(selection.get("countType") or ""),
                count_number=_as_int(selection.get("countNumber")),
                count_unit=str(selection.get("countUnit") or ""),
                action_type=action_type,
            )
        )
    rules.sort(key=lambda r: r.priority)
    return rules


def apply_policy(index: RepositoryIndex, name: str, document: Any) -> None:
    repo = index.get(name)
    repo.has_policy = True
    try:
        repo.rules = parse_rules(document)
        repo.policy_error = ""
    except ValueError as exc:
        repo.rules = []
        repo.policy_error = str(exc)


def apply_images(index: RepositoryIndex, name: str, details: Iterable[Any]) -> None:
    repo = index.get(name)
    repo.images_known = True
    for detail in details:
        if not isinstance(detail, dict):
            continue
        tags = detail.get("imageTags") or []
        if not isinstance(tags, list):
            tags = []
        size = _as_int(detail.get("imageSizeInBytes")) or 0
        repo.images.append(
            Image(
                digest=str(detail.get("imageDigest") or ""),
                tags=tuple(str(t) for t in tags),
                size_bytes=size,
                pushed_at=_parse_time(detail.get("imagePushedAt")),
            )
        )


def _ingest_document(index: RepositoryIndex, doc: Any, source: str) -> bool:
    """Absorb one parsed JSON document. Returns True if it looked like ECR."""
    if not isinstance(doc, dict):
        return False
    recognised = False

    repositories = doc.get("repositories")
    if isinstance(repositories, list):
        recognised = True
        for entry in repositories:
            if isinstance(entry, dict):
                apply_describe_repository(index, entry)

    # A bare describe-repositories entry, or a get-lifecycle-policy response.
    name = doc.get("repositoryName")
    if isinstance(name, str) and name:
        recognised = True
        if "lifecyclePolicyText" in doc:
            apply_policy(index, name, doc.get("lifecyclePolicyText"))
        elif "lifecyclePolicy" in doc:
            apply_policy(index, name, doc.get("lifecyclePolicy"))
        else:
            apply_describe_repository(index, doc)

    details = doc.get("imageDetails")
    if isinstance(details, list):
        recognised = True
        grouped: dict[str, list[Any]] = {}
        if not details:
            # An empty describe-images output still proves the repository is
            # empty, so fall back to the file name to know whose it is.
            fallback = (name if isinstance(name, str) and name else _stem(source))
            if fallback:
                grouped[fallback] = []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            owner = detail.get("repositoryName")
            key = owner if isinstance(owner, str) and owner else _stem(source)
            grouped.setdefault(key, []).append(detail)
        for repo_name, items in grouped.items():
            if repo_name:
                apply_images(index, repo_name, items)

    if recognised:
        return True
    return _ingest_bundle(index, doc)


def _ingest_bundle(index: RepositoryIndex, doc: dict[str, Any]) -> bool:
    """A bundle maps repository name -> {repository, lifecyclePolicy, imageDetails}."""
    bundle_keys = {"repository", "lifecyclePolicy", "lifecyclePolicyText", "imageDetails"}
    entries = [
        (key, value)
        for key, value in doc.items()
        if isinstance(value, dict) and bundle_keys & set(value)
    ]
    if not entries:
        return False
    for name, value in entries:
        repo_entry = value.get("repository")
        if isinstance(repo_entry, dict):
            merged = dict(repo_entry)
            merged.setdefault("repositoryName", name)
            apply_describe_repository(index, merged)
        else:
            index.get(name, from_describe=True)
        if "lifecyclePolicyText" in value:
            apply_policy(index, name, value.get("lifecyclePolicyText"))
        elif "lifecyclePolicy" in value:
            apply_policy(index, name, value.get("lifecyclePolicy"))
        details = value.get("imageDetails")
        if isinstance(details, list):
            apply_images(index, name, details)
    return True


def _stem(source: str) -> str:
    base = os.path.basename(source)
    for suffix in (".json",):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def load(
    inputs: list[str],
    policies: list[str] | None = None,
    images: list[str] | None = None,
) -> list[Repository]:
    """Load every path into one repository list.

    `policies` and `images` are separate only as a convenience for the three
    AWS CLI calls; all of them go through the same ingest, so passing a
    describe-images file to `--input` works too.
    """
    index = RepositoryIndex()
    recognised = False
    for group in (inputs, policies or [], images or []):
        for path in group:
            for file_path in _json_files(path):
                doc = _read_json(file_path)
                if _ingest_document(index, doc, file_path):
                    recognised = True
                elif isinstance(doc, list):
                    # A bare list of describe-repositories entries.
                    for entry in doc:
                        if isinstance(entry, dict) and entry.get("repositoryName"):
                            apply_describe_repository(index, entry)
                            recognised = True
    if not recognised:
        raise InputError(
            "input does not look like ECR output: expected one of "
            + ", ".join(_REPO_KEYS)
        )
    return index.repositories()
