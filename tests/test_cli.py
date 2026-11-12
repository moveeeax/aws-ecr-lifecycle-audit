import json
import os
import subprocess
import sys

import pytest

from conftest import (
    NOW,
    clean_bundle,
    malformed_bundle,
    no_policy_bundle,
    shadowed_bundle,
    unreachable_prefix_bundle,
    write_bundle,
)
from ecr_lifecycle_audit.cli import main

FROZEN = ["--now", NOW.isoformat()]
EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def run(args, capsys):
    code = main(FROZEN + args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_repository_exits_zero(tmp_path, capsys):
    path = write_bundle(tmp_path, clean_bundle())
    code, out, _ = run(["--input", path], capsys)
    assert code == 0
    assert "No findings." in out


def test_no_policy_and_untagged_bloat_exits_one(tmp_path, capsys):
    path = write_bundle(tmp_path, no_policy_bundle(900))
    code, out, _ = run(["--input", path], capsys)
    assert code == 1
    assert "NO_LIFECYCLE_POLICY" in out
    assert "UNTAGGED_BLOAT" in out
    assert "web-frontend" in out


def test_table_footer_reports_the_waste_estimate(tmp_path, capsys):
    path = write_bundle(tmp_path, no_policy_bundle(900))
    _, out, _ = run(["--input", path, "--price-per-gb", "0.10"], capsys)
    # 900 * 10 MB = 9,000,000,000 bytes = 8.38 GiB -> $0.84/month
    assert "8.38 GiB" in out
    assert "$0.84/month" in out
    assert "$0.1/GB" in out


def test_price_per_gb_scales_the_estimate(tmp_path, capsys):
    path = write_bundle(tmp_path, no_policy_bundle(900))
    _, out, _ = run(["--input", path, "--price-per-gb", "1.00", "--format", "json"], capsys)
    payload = json.loads(out)
    assert payload["waste"]["estimated_monthly_usd"] == pytest.approx(8.38, abs=0.01)


def test_unreachable_rule_names_the_rule_priority(tmp_path, capsys):
    path = write_bundle(tmp_path, unreachable_prefix_bundle())
    code, out, _ = run(["--input", path, "--format", "json"], capsys)
    payload = json.loads(out)
    findings = [f for f in payload["findings"] if f["check"] == "UNREACHABLE_RULE"]
    assert len(findings) == 1
    assert "priority 1" in findings[0]["message"]
    assert code == 1


def test_malformed_policy_does_not_stop_the_audit(tmp_path, capsys):
    path = write_bundle(tmp_path, malformed_bundle())
    code, out, _ = run(["--input", path, "--format", "json"], capsys)
    payload = json.loads(out)
    assert payload["repositories_audited"] == 2
    assert [f["check"] for f in payload["findings"]] == ["MALFORMED_LIFECYCLE_POLICY"]
    assert payload["findings"][0]["repository"] == "broken-policy"
    assert code == 1


def test_unreadable_input_exits_two_with_one_line(tmp_path, capsys):
    code, out, err = run(["--input", str(tmp_path / "missing.json")], capsys)
    assert code == 2
    assert out == ""
    assert len(err.strip().splitlines()) == 1
    assert "Traceback" not in err


def test_non_ecr_input_exits_two(tmp_path, capsys):
    path = tmp_path / "junk.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    code, _, err = run(["--input", str(path)], capsys)
    assert code == 2
    assert "does not look like ECR output" in err


def test_fail_on_controls_the_exit_code(tmp_path, capsys):
    path = write_bundle(tmp_path, shadowed_bundle())
    # SHADOWED_RULE is low severity, so the default medium floor exits 0.
    code, out, _ = run(["--input", path], capsys)
    assert code == 0
    assert "SHADOWED_RULE" in out

    code, _, _ = run(["--input", path, "--fail-on", "low"], capsys)
    assert code == 1

    code, _, _ = run(["--input", path, "--fail-on", "none"], capsys)
    assert code == 0


def test_severity_floor_hides_lower_checks(tmp_path, capsys):
    path = write_bundle(tmp_path, shadowed_bundle())
    _, out, _ = run(["--input", path, "--severity", "medium"], capsys)
    assert "SHADOWED_RULE" not in out
    assert "No findings." in out


def test_only_and_skip(tmp_path, capsys):
    path = write_bundle(tmp_path, no_policy_bundle(900))
    _, out, _ = run(
        ["--input", path, "--only", "NO_LIFECYCLE_POLICY,UNTAGGED_BLOAT", "--max-untagged", "50"],
        capsys,
    )
    assert "UNTAGGED_BLOAT" in out and "NO_LIFECYCLE_POLICY" in out

    _, out, _ = run(["--input", path, "--skip", "untagged_bloat"], capsys)
    assert "UNTAGGED_BLOAT" not in out


def test_unknown_check_id_is_a_usage_error(tmp_path, capsys):
    path = write_bundle(tmp_path, clean_bundle())
    with pytest.raises(SystemExit) as excinfo:
        main(["--input", path, "--only", "NOPE"])
    assert excinfo.value.code == 2


def test_csv_output_has_a_header_and_one_row_per_finding(tmp_path, capsys):
    path = write_bundle(tmp_path, no_policy_bundle(900))
    _, out, _ = run(["--input", path, "--format", "csv"], capsys)
    lines = out.strip().splitlines()
    assert lines[0].startswith("severity,check,repository")
    assert len(lines) == 3


def test_list_checks(capsys):
    code, out, _ = run(["--list-checks"], capsys)
    assert code == 0
    assert "UNTAGGED_BLOAT" in out
    assert len(out.strip().splitlines()) == 10


def test_no_input_at_all_is_a_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_stdin_is_accepted(tmp_path, monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(clean_bundle())))
    code, out, _ = run(["--input", "-"], capsys)
    assert code == 0
    assert "No findings." in out


def test_shipped_examples_reproduce_the_documented_run(capsys):
    code, out, _ = run(
        [
            "--input",
            os.path.join(EXAMPLES, "describe-repositories.json"),
            "--policies",
            os.path.join(EXAMPLES, "policies"),
            "--images",
            os.path.join(EXAMPLES, "images"),
            "--format",
            "json",
        ],
        capsys,
    )
    payload = json.loads(out)
    found = {(f["check"], f["repository"]) for f in payload["findings"]}
    assert ("MALFORMED_LIFECYCLE_POLICY", "broken-policy") in found
    assert ("NO_LIFECYCLE_POLICY", "web-frontend") in found
    assert ("UNTAGGED_BLOAT", "web-frontend") in found
    assert ("UNREACHABLE_RULE", "ml-trainer") in found
    assert ("SHADOWED_RULE", "checkout-worker") in found
    assert ("EMPTY_REPOSITORY", "legacy-batch") in found
    assert ("TAG_MUTABLE", "web-frontend") in found
    assert ("SCAN_ON_PUSH_OFF", "web-frontend") in found
    assert not any(repo == "payments-api" for _, repo in found)
    assert code == 1


def test_module_is_runnable_with_dash_m(tmp_path):
    path = write_bundle(tmp_path, clean_bundle())
    result = subprocess.run(
        [sys.executable, "-m", "ecr_lifecycle_audit", "--input", path] + FROZEN,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "No findings." in result.stdout
