# aws-ecr-lifecycle-audit

[![ci](https://github.com/moveeeax/aws-ecr-lifecycle-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-ecr-lifecycle-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audits Amazon ECR repositories **offline**, from JSON the AWS CLI already prints. It names
the repositories with no lifecycle policy, the lifecycle rules that can never match an image,
the untagged-image bloat you are still paying for every month, and the hygiene flags nobody
sets. No AWS API call, no credentials, so it runs in CI next to `terraform plan`.

Nobody deletes container images. Every CI build pushes a layer set, the previous tag becomes
untagged, and untagged images are billed at the same per-GB-month rate as the ones actually
running. The problem is invisible in the console unless you click into every repository.

## Install

```sh
pip install git+https://github.com/moveeeax/aws-ecr-lifecycle-audit
```

Python 3.11+, standard library only.

## Usage

Dump what you have, then audit it:

```sh
aws ecr describe-repositories > repos.json

for r in $(jq -r '.repositories[].repositoryName' repos.json); do
  aws ecr get-lifecycle-policy --repository-name "$r" > "policies/$r.json" 2>/dev/null
  aws ecr describe-images --repository-name "$r" > "images/$r.json"
done

aws-ecr-lifecycle-audit --input repos.json --policies policies/ --images images/
```

A run against the fixtures in `examples/`:

```console
$ aws-ecr-lifecycle-audit \
    --input examples/describe-repositories.json \
    --policies examples/policies \
    --images examples/images \
    --now 2026-11-12T00:00:00Z
SEVERITY  CHECK                       REPOSITORY       FINDING
--------  --------------------------  ---------------  --------------------------------------------------------------------------------
high      MALFORMED_LIFECYCLE_POLICY  broken-policy    lifecycle policy is not usable and nothing is being expired
            lifecyclePolicyText is not valid JSON: Expecting property name enclosed in double quotes
high      SCAN_ON_PUSH_OFF            web-frontend     scanOnPush is false: images are never scanned
medium    UNREACHABLE_RULE            checkout-worker  rule priority 2 can never trigger: imageCountMoreThan 30 but only 1 image match
medium    UNREACHABLE_RULE            ml-trainer       rule priority 1 matches no image: tagPrefixList [release-]
            tags present: v0.9.2, v0.9.3
medium    NO_LIFECYCLE_POLICY         web-frontend     no lifecycle policy: storage grows with every build
            28 images present and no policy to expire any of them
medium    TAG_MUTABLE                 web-frontend     imageTagMutability is MUTABLE: a pushed tag can be moved to another digest
medium    UNTAGGED_BLOAT              web-frontend     26 untagged images (threshold 20)
            2.28 GiB of untagged layers are still billed
low       SHADOWED_RULE               checkout-worker  rule priority 2 is shadowed by the tagStatus=any rule at priority 1
            ECR evaluates rules in priority order; a catch-all must come last
low       EMPTY_REPOSITORY            legacy-batch     zero images: probably a dead repository
low       NO_KMS_ENCRYPTION           legacy-batch     encryptionType is AES256: no customer-managed key
low       NO_KMS_ENCRYPTION           web-frontend     encryptionType is AES256: no customer-managed key
low       STALE_IMAGES                web-frontend     17 images older than 180 days
            oldest is 531 days old

6 repositories audited, 12 findings.
Reclaimable: 2.28 GiB across 1 repositories, est. $0.23/month at $0.1/GB

$ echo $?
1
```

`payments-api` is in that registry too, with a working policy, immutable tags, `scanOnPush`
on and a KMS key. It produces nothing, which is the point.

Other shapes:

```sh
# one bundle file keyed by repository name
aws-ecr-lifecycle-audit --input bundle.json --format json --fail-on high

# stdin
aws ecr describe-repositories | aws-ecr-lifecycle-audit --input -

# a subset of checks, with a looser untagged threshold
aws-ecr-lifecycle-audit --input bundle.json \
  --only NO_LIFECYCLE_POLICY,UNTAGGED_BLOAT --max-untagged 50
```

## Checks

| id | severity | what it means |
| --- | --- | --- |
| `MALFORMED_LIFECYCLE_POLICY` | high | the policy document does not parse, so nothing is expired |
| `SCAN_ON_PUSH_OFF` | high | `scanOnPush` is false and pushed images are never scanned |
| `NO_LIFECYCLE_POLICY` | medium | no policy at all: storage grows with build count |
| `UNTAGGED_BLOAT` | medium | untagged images above `--max-untagged`, with their summed size |
| `UNREACHABLE_RULE` | medium | a `tagPrefixList` that matches nothing, or a `countNumber` that can never be exceeded |
| `TAG_MUTABLE` | medium | `imageTagMutability` is `MUTABLE`, so a tag can be repointed under a running deployment |
| `SHADOWED_RULE` | low | a rule sitting behind a higher-priority `tagStatus: any` catch-all |
| `STALE_IMAGES` | low | images older than `--max-age-days` are still stored |
| `NO_KMS_ENCRYPTION` | low | `AES256` instead of a customer-managed KMS key |
| `EMPTY_REPOSITORY` | low | zero images, probably a dead repository |

`aws-ecr-lifecycle-audit --list-checks` prints the same list with its one-line summaries.

## How it works

Three `describe-*` shapes are normalised into exactly one repository model — name, tag
mutability, scan config, encryption, lifecycle rules sorted by priority, and the image
inventory with tags, sizes and push timestamps. Each check is then a pure function over one
repository, so a check never needs to know which file a field arrived in.

Two of the checks need the image inventory to say anything at all. `UNREACHABLE_RULE` compares
each rule's selection block against the tags actually present: a rule with
`tagPrefixList: ["release-"]` in a repository where every tag starts with `v` can never fire,
and a rule with `countType: imageCountMoreThan` whose `countNumber` is at or above the number
of matching images will never trigger either. Without `--images` those checks stay quiet rather
than guess.

The waste estimate is deliberately boring arithmetic: untagged images plus anything past
`--max-age-days`, de-duplicated by digest, summed over `imageSizeInBytes`, divided by a GiB and
multiplied by `--price-per-gb` (default `0.10`).

## Options

| flag | default | meaning |
| --- | --- | --- |
| `--input PATH` | — | describe-repositories JSON, a directory, or `-` for stdin (repeatable) |
| `--policies PATH` | — | get-lifecycle-policy JSON file or directory (repeatable) |
| `--images PATH` | — | describe-images JSON file or directory (repeatable) |
| `--max-untagged N` | `20` | untagged count that trips `UNTAGGED_BLOAT` |
| `--max-age-days N` | `180` | age that trips `STALE_IMAGES` |
| `--price-per-gb USD` | `0.10` | GB-month price used for the estimate |
| `--format` | `table` | `table`, `json` or `csv` |
| `--severity` | `low` | only run checks at this severity or above |
| `--only IDS` / `--skip IDS` | — | comma-separated check ids |
| `--fail-on` | `medium` | lowest severity that makes the exit code `1`; `none` always exits `0` |
| `--now ISO8601` | now | freeze the clock for reproducible age checks |

Exit codes: `0` nothing at or above `--fail-on`, `1` something was found, `2` unreadable or
non-ECR input. A broken policy document is a finding, not a crash — the remaining repositories
are still audited.

## In CI

```yaml
- name: Audit ECR
  run: |
    aws ecr describe-repositories > repos.json
    aws-ecr-lifecycle-audit --input repos.json --fail-on high
```

With no `--images` the tool still catches missing policies, mutable tags, scanning and
encryption. Add the image inventory when you want the cost number.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

## License

MIT
