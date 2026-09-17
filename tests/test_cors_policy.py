"""Tests for CORS preflight vulnerability auditor and Permissions-Policy generator."""

from web_security_guard.cors_policy import (
    CORSAuditReport,
    CORSVulnerabilityFinding,
    audit_cors_configuration,
    generate_permissions_policy,
    generate_secure_cors_headers,
)


def test_cors_same_origin_default():
    report = audit_cors_configuration({})
    assert isinstance(report, CORSAuditReport)
    assert report.is_secure
    assert report.risk_score == 0.0
    assert len(report.allowed_origins) == 0


def test_cors_wildcard_with_credentials_critical():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, DELETE",
    }
    report = audit_cors_configuration(headers)
    assert not report.is_secure
    assert report.risk_score >= 80.0
    assert any(f.rule_id == "CORS_WILDCARD_CREDENTIALS" for f in report.findings)
    assert any(f.severity == "critical" for f in report.findings)


def test_cors_null_origin_critical():
    headers = {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Methods": "GET, POST",
    }
    report = audit_cors_configuration(headers)
    assert not report.is_secure
    assert any(f.rule_id == "CORS_NULL_ORIGIN_ALLOWED" for f in report.findings)


def test_cors_arbitrary_origin_reflection():
    attacker_origin = "https://evil.attacker.com"
    headers = {
        "Access-Control-Allow-Origin": attacker_origin,
        "Access-Control-Allow-Credentials": "true",
    }
    report = audit_cors_configuration(headers, tested_origin=attacker_origin)
    assert not report.is_secure
    assert any(f.rule_id == "CORS_ARBITRARY_ORIGIN_REFLECTION" for f in report.findings)


def test_generate_secure_cors_headers():
    cors = generate_secure_cors_headers(
        allowed_origins=["https://dashboard.example.com"],
        allow_credentials=True,
        allowed_methods=["GET", "POST", "OPTIONS"],
        max_age=86400,
    )
    assert cors["Access-Control-Allow-Origin"] == "https://dashboard.example.com"
    assert cors["Access-Control-Allow-Credentials"] == "true"
    assert cors["Access-Control-Max-Age"] == "86400"
    assert cors["Vary"] == "Origin"


def test_generate_permissions_policy():
    policy = generate_permissions_policy()
    assert "camera=()" in policy
    assert "microphone=()" in policy
    assert "geolocation=()" in policy
    assert "browsing-topics=()" in policy
    assert "autoplay=(self)" in policy

    custom = generate_permissions_policy({"camera": "(self)", "payment": "(self https://checkout.stripe.com)"})
    assert "camera=(self)" in custom
    assert "payment=(self https://checkout.stripe.com)" in custom
