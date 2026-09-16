"""
Unit tests for SecurityRemediator module in web_security_guard.
Verifies that generated configuration files achieve 100/100 (A+) ratings.
"""

from pathlib import Path
import json
import pytest

from web_security_guard.auditor import SecurityAuditor, Grade
from web_security_guard.remediator import SecurityRemediator


@pytest.fixture
def auditor():
    return SecurityAuditor()


@pytest.fixture
def remediator():
    return SecurityRemediator()


def test_netlify_headers_generation_and_audit(remediator, auditor):
    headers_content = remediator.generate_netlify_headers()
    assert "Strict-Transport-Security" in headers_content
    assert "Content-Security-Policy" in headers_content
    assert "X-Frame-Options: DENY" in headers_content

    # Feed generated config directly into auditor
    result = auditor.audit_content(headers_content, source_name="_headers")
    assert result.score == 100
    assert result.grade == Grade.A_PLUS
    assert result.passed_ci_default


def test_vercel_json_generation_and_audit(remediator, auditor):
    vercel_content = remediator.generate_vercel_json()
    data = json.loads(vercel_content)
    assert "headers" in data
    assert len(data["headers"][0]["headers"]) >= 8

    result = auditor.audit_content(vercel_content, source_name="vercel.json")
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_nginx_conf_generation_and_audit(remediator, auditor):
    nginx_content = remediator.generate_nginx_conf()
    assert "add_header Strict-Transport-Security" in nginx_content
    assert "add_header Content-Security-Policy" in nginx_content

    result = auditor.audit_content(nginx_content, source_name="nginx.conf")
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_caddyfile_generation_and_audit(remediator, auditor):
    caddy_content = remediator.generate_caddyfile()
    assert "header {" in caddy_content
    assert "Strict-Transport-Security" in caddy_content

    result = auditor.audit_content(caddy_content, source_name="Caddyfile")
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_next_config_generation(remediator):
    next_content = remediator.generate_next_config()
    assert "nextConfig" in next_content
    assert "async headers()" in next_content
    assert "Strict-Transport-Security" in next_content


def test_astro_config_generation(remediator):
    astro_content = remediator.generate_astro_config()
    assert "defineConfig" in astro_content
    assert "Strict-Transport-Security" in astro_content


def test_apache_htaccess_generation_and_audit(remediator, auditor):
    htaccess_content = remediator.generate_apache_htaccess()
    assert "<IfModule mod_headers.c>" in htaccess_content
    assert "Header always set" in htaccess_content

    result = auditor.audit_content(htaccess_content, source_name=".htaccess")
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_html_meta_generation(remediator, auditor):
    meta_content = remediator.generate_html_meta()
    assert "<meta http-equiv=\"Content-Security-Policy\"" in meta_content
    assert "<meta http-equiv=\"X-Content-Type-Options\"" in meta_content


def test_markdown_report_generation(remediator, auditor):
    # Audit an empty header set to generate findings
    bad_result = auditor.audit_headers({})
    custom_remediator = SecurityRemediator(audit_result=bad_result)
    report = custom_remediator.generate_markdown_report()

    assert "# 🛡️ Web Security Guard - Executive Remediation Plan" in report
    assert "CSP-MISSING" in report
    assert "HSTS-MISSING" in report
    assert "## 🛠️ Automated Copy-Paste Fixes" in report


def test_generate_all_configs(remediator):
    configs = remediator.generate_all_configs()
    assert "_headers" in configs
    assert "vercel.json" in configs
    assert "nginx.conf" in configs
    assert "Caddyfile" in configs
    assert "next.config.js" in configs
    assert "astro.config.mjs" in configs
    assert ".htaccess" in configs
    assert "security-meta.html" in configs
    assert "SECURITY_REMEDIATION_PLAN.md" in configs


def test_write_remediation_bundle(remediator, auditor, tmp_path):
    bundle_dir = tmp_path / "security_bundle"
    created_files = remediator.write_remediation_bundle(bundle_dir)

    assert len(created_files) == 9
    for f in created_files:
        assert f.exists()
        assert f.stat().st_size > 0

    # Test that writing files allows auditing them from disk with 100% score
    netlify_res = auditor.audit_file(bundle_dir / "_headers")
    assert netlify_res.score == 100
    assert netlify_res.grade == Grade.A_PLUS
