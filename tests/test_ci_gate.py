"""
Unit tests for CI Gate module in web_security_guard.
Verifies automated threshold checking, reporters, and CLI automation.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import pytest

from web_security_guard.ci_gate import run_security_check, main
from web_security_guard.remediator import SecurityRemediator


@pytest.fixture
def perfect_headers_file(tmp_path):
    f = tmp_path / "_headers"
    remediator = SecurityRemediator()
    f.write_text(remediator.generate_netlify_headers())
    return f


@pytest.fixture
def insecure_html_file(tmp_path):
    f = tmp_path / "insecure.html"
    content = """<!DOCTYPE html>
<html>
<head><title>Insecure Site</title></head>
<body>
  <h1>System Warning: 3 viruses detected! Call Microsoft support now!</h1>
  <form action="http://insecure-phish.com/login">
    <input type="password" name="p">
  </form>
</body>
</html>
"""
    f.write_text(content)
    return f


def test_ci_gate_pass_perfect_headers(perfect_headers_file):
    passed, res, text_out = run_security_check(
        str(perfect_headers_file),
        min_score=85,
        fail_on_critical=True,
        output_format="text",
    )
    assert passed is True
    assert res["score"] == 100
    assert res["grade"] == "A+"
    assert "PASSED" in text_out
    assert "100 / 100" in text_out


def test_ci_gate_fail_insecure(insecure_html_file):
    passed, res, text_out = run_security_check(
        str(insecure_html_file),
        min_score=85,
        fail_on_critical=True,
        output_format="text",
    )
    assert passed is False
    assert res["score"] < 85
    assert res["ci_gate"]["has_critical"] is True
    assert "FAILED" in text_out


def test_ci_gate_json_output(perfect_headers_file):
    passed, res, json_out = run_security_check(
        str(perfect_headers_file),
        output_format="json",
    )
    parsed = json.loads(json_out)
    assert parsed["score"] == 100
    assert parsed["ci_gate"]["passed"] is True


def test_ci_gate_github_actions_output(insecure_html_file):
    passed, res, gh_out = run_security_check(
        str(insecure_html_file),
        output_format="github",
    )
    assert "::error" in gh_out
    assert "::notice" in gh_out
    assert "Security Gate FAILED" in gh_out


def test_ci_gate_markdown_output(perfect_headers_file):
    passed, res, md_out = run_security_check(
        str(perfect_headers_file),
        output_format="markdown",
    )
    assert "## 🛡️ Web Security Guard CI Gate Summary" in md_out
    assert "PASSED" in md_out


def test_ci_gate_directory_scan(tmp_path):
    # Place _headers inside directory and audit directory
    remediator = SecurityRemediator()
    (tmp_path / "_headers").write_text(remediator.generate_netlify_headers())

    passed, res, out = run_security_check(str(tmp_path))
    assert passed is True
    assert res["score"] == 100


def test_ci_gate_fail_on_critical_flag(insecure_html_file):
    # With min_score=0 and fail_on_critical=False, it should pass score check
    passed, res, out = run_security_check(
        str(insecure_html_file),
        min_score=0,
        fail_on_critical=False,
    )
    assert passed is True

    # With fail_on_critical=True, it must fail
    passed_crit, res_crit, out_crit = run_security_check(
        str(insecure_html_file),
        min_score=0,
        fail_on_critical=True,
    )
    assert passed_crit is False


def test_cli_main_success(perfect_headers_file, tmp_path, capsys):
    out_file = tmp_path / "report.txt"
    rem_dir = tmp_path / "remediation"

    exit_code = main([
        str(perfect_headers_file),
        "--min-score", "80",
        "--format", "text",
        "--output", str(out_file),
        "--remediate-dir", str(rem_dir),
    ])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "PASSED" in captured.out
    assert out_file.exists()
    assert rem_dir.exists()
    assert (rem_dir / "_headers").exists()


def test_cli_main_failure(insecure_html_file, capsys):
    exit_code = main([
        str(insecure_html_file),
        "--min-score", "90",
        "--format", "text",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "FAILED" in captured.out
