"""
Unit tests for SecurityAuditor module in web_security_guard.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

from web_security_guard.auditor import (
    SecurityAuditor,
    AuditResult,
    Finding,
    Severity,
    Category,
    Grade,
)


@pytest.fixture
def auditor():
    return SecurityAuditor()


@pytest.fixture
def perfect_headers():
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
            "upgrade-insecure-requests;"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


# =============================================================================
# 1. Content-Security-Policy (CSP) Tests
# =============================================================================

def test_csp_missing(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "CSP-MISSING" in finding_ids
    assert result.score < 100


def test_csp_strict_pass(auditor, perfect_headers):
    result = auditor.audit_headers(perfect_headers)
    csp_findings = [f for f in result.findings if f.category == Category.CSP]
    assert len(csp_findings) == 0
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_csp_unsafe_inline_and_eval(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "CSP-SCRIPT-UNSAFE-INLINE" in finding_ids
    assert "CSP-SCRIPT-UNSAFE-EVAL" in finding_ids


def test_csp_wildcard_script(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Content-Security-Policy"] = "default-src 'self'; script-src *; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "CSP-SCRIPT-WILDCARD" in finding_ids


def test_csp_missing_directives(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Content-Security-Policy"] = "script-src 'self';"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "CSP-OBJECT-SRC-INSECURE" in finding_ids
    assert "CSP-BASE-URI-MISSING" in finding_ids
    assert "CSP-FORM-ACTION-MISSING" in finding_ids


# =============================================================================
# 2. Strict-Transport-Security (HSTS) Tests
# =============================================================================

def test_hsts_missing(auditor):
    result = auditor.audit_headers({}, url="https://example.com")
    finding_ids = [f.id for f in result.findings]
    assert "HSTS-MISSING" in finding_ids


def test_hsts_short_max_age(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Strict-Transport-Security"] = "max-age=3600"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "HSTS-SHORT-MAX-AGE" in finding_ids
    assert "HSTS-MISSING-SUBDOMAINS" in finding_ids
    assert "HSTS-MISSING-PRELOAD" in finding_ids


def test_hsts_max_age_zero(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Strict-Transport-Security"] = "max-age=0"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "HSTS-MAX-AGE-ZERO" in finding_ids


# =============================================================================
# 3. X-Frame-Options (XFO) Tests
# =============================================================================

def test_xfo_missing_without_csp(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "XFO-MISSING" in finding_ids


def test_xfo_missing_with_csp_frame_ancestors(auditor, perfect_headers):
    headers = dict(perfect_headers)
    del headers["X-Frame-Options"]
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "XFO-LEGACY-FALLBACK-MISSING" in finding_ids
    assert "XFO-MISSING" not in finding_ids


def test_xfo_allow_from_deprecated(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["X-Frame-Options"] = "ALLOW-FROM https://partner.com"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "XFO-ALLOW-FROM-DEPRECATED" in finding_ids


# =============================================================================
# 4. X-Content-Type-Options (XCTO) Tests
# =============================================================================

def test_xcto_missing(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "XCTO-MISSING" in finding_ids


def test_xcto_invalid_value(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["X-Content-Type-Options"] = "sniff"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "XCTO-INVALID-VALUE" in finding_ids


# =============================================================================
# 5. Referrer-Policy Tests
# =============================================================================

def test_referrer_policy_missing(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "REFERRER-POLICY-MISSING" in finding_ids


def test_referrer_policy_unsafe_url(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Referrer-Policy"] = "unsafe-url"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "REFERRER-POLICY-UNSAFE-URL" in finding_ids


# =============================================================================
# 6. Permissions-Policy Tests
# =============================================================================

def test_permissions_policy_missing(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "PERMISSIONS-POLICY-MISSING" in finding_ids


def test_permissions_policy_permissive(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Permissions-Policy"] = "camera=*, microphone=*"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "PERMISSIONS-POLICY-PERMISSIVE" in finding_ids


# =============================================================================
# 7. Cross-Origin Policies (COOP, COEP, CORP) Tests
# =============================================================================

def test_cross_origin_missing(auditor):
    result = auditor.audit_headers({})
    finding_ids = [f.id for f in result.findings]
    assert "COOP-MISSING" in finding_ids
    assert "COEP-MISSING" in finding_ids
    assert "CORP-MISSING" in finding_ids


# =============================================================================
# 8. CORS Security Tests
# =============================================================================

def test_cors_wildcard_with_credentials(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Credentials"] = "true"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "CORS-WILDCARD-WITH-CREDENTIALS" in finding_ids
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not result.passed_ci_default


def test_cors_null_origin_with_credentials(auditor, perfect_headers):
    headers = dict(perfect_headers)
    headers["Access-Control-Allow-Origin"] = "null"
    headers["Access-Control-Allow-Credentials"] = "true"
    result = auditor.audit_headers(headers)
    finding_ids = [f.id for f in result.findings]
    assert "CORS-NULL-ORIGIN-WITH-CREDENTIALS" in finding_ids


def test_cors_origin_reflection(auditor, perfect_headers):
    result = auditor.audit_headers(perfect_headers, cors_reflection_detected=True)
    finding_ids = [f.id for f in result.findings]
    assert "CORS-ORIGIN-REFLECTION-VULN" in finding_ids
    assert not result.passed_ci_default


# =============================================================================
# 9. Cookie Security Flags Tests
# =============================================================================

def test_cookie_missing_flags(auditor, perfect_headers):
    cookies = ["session=abc123xyz; Path=/"]
    result = auditor.audit_headers(perfect_headers, cookies=cookies)
    finding_ids = [f.id for f in result.findings]
    assert "COOKIE-MISSING-SECURE" in finding_ids
    assert "COOKIE-MISSING-HTTPONLY" in finding_ids
    assert "COOKIE-MISSING-SAMESITE" in finding_ids


def test_cookie_samesite_none_without_secure(auditor, perfect_headers):
    cookies = ["auth_token=xyz; SameSite=None"]
    result = auditor.audit_headers(perfect_headers, cookies=cookies, metadata={"is_https": False})
    finding_ids = [f.id for f in result.findings]
    assert "COOKIE-SAMESITE-NONE-INSECURE" in finding_ids


def test_cookie_prefix_violations(auditor, perfect_headers):
    cookies = [
        "__Host-sess=abc; Domain=example.com; Secure; Path=/",
        "__Secure-token=123; HttpOnly",  # Missing Secure
    ]
    result = auditor.audit_headers(perfect_headers, cookies=cookies)
    finding_ids = [f.id for f in result.findings]
    assert "COOKIE-PREFIX-HOST-VIOLATION" in finding_ids
    assert "COOKIE-PREFIX-SECURE-VIOLATION" in finding_ids


def test_cookie_secure_pass(auditor, perfect_headers):
    cookies = ["__Host-id=secret; Secure; HttpOnly; SameSite=Strict; Path=/"]
    result = auditor.audit_headers(perfect_headers, cookies=cookies)
    cookie_findings = [f for f in result.findings if f.category == Category.COOKIES]
    assert len(cookie_findings) == 0


# =============================================================================
# 10. Dark Pattern & Phishing Heuristics Tests
# =============================================================================

def test_dark_pattern_fake_urgency(auditor, perfect_headers):
    html = '<div class="alert">Hurry! Only 2 items left in stock! Deal ends in 04:59</div>'
    result = auditor.audit_headers(perfect_headers, html=html)
    finding_ids = [f.id for f in result.findings]
    assert "DARK-PATTERN-FAKE-URGENCY" in finding_ids


def test_dark_pattern_prechecked_consent(auditor, perfect_headers):
    html = '<input type="checkbox" name="newsletter_subscribe" checked> Subscribe to weekly promo emails'
    result = auditor.audit_headers(perfect_headers, html=html)
    finding_ids = [f.id for f in result.findings]
    assert "DARK-PATTERN-PRECHECKED-CONSENT" in finding_ids


def test_dark_pattern_confirmshaming(auditor, perfect_headers):
    html = '<button>No thanks, I prefer paying full price</button>'
    result = auditor.audit_headers(perfect_headers, html=html)
    finding_ids = [f.id for f in result.findings]
    assert "DARK-PATTERN-CONFIRMSHAMING" in finding_ids


def test_deceptive_ui_fake_alert(auditor, perfect_headers):
    html = '<div><h1>System Warning: 3 viruses detected! Call Microsoft support now!</h1></div>'
    result = auditor.audit_headers(perfect_headers, html=html)
    finding_ids = [f.id for f in result.findings]
    assert "DECEPTIVE-UI-FAKE-ALERT" in finding_ids
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_phishing_insecure_auth_form(auditor, perfect_headers):
    html = '<form action="http://insecure-login.com/login"><input type="password" name="pwd"></form>'
    result = auditor.audit_headers(perfect_headers, html=html)
    finding_ids = [f.id for f in result.findings]
    assert "PHISHING-INSECURE-AUTH-SUBMIT" in finding_ids
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


# =============================================================================
# 11. Configuration File Parsing & Auto-detection
# =============================================================================

def test_parse_netlify_headers_file(auditor, tmp_path):
    netlify_content = """
/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  Cross-Origin-Resource-Policy: same-origin
"""
    headers_file = tmp_path / "_headers"
    headers_file.write_text(netlify_content)

    result = auditor.audit_file(headers_file)
    assert result.score == 100
    assert result.grade == Grade.A_PLUS
    assert result.passed_ci_default


def test_parse_vercel_json_file(auditor, tmp_path):
    vercel_content = """
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {"key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload"},
        {"key": "X-Frame-Options", "value": "DENY"},
        {"key": "X-Content-Type-Options", "value": "nosniff"},
        {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
        {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"},
        {"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"},
        {"key": "Cross-Origin-Opener-Policy", "value": "same-origin"},
        {"key": "Cross-Origin-Embedder-Policy", "value": "require-corp"},
        {"key": "Cross-Origin-Resource-Policy", "value": "same-origin"}
      ]
    }
  ]
}
"""
    vercel_file = tmp_path / "vercel.json"
    vercel_file.write_text(vercel_content)

    result = auditor.audit_file(vercel_file)
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_parse_nginx_conf_file(auditor, tmp_path):
    nginx_content = """
server {
    listen 443 ssl;
    server_name example.com;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
}
"""
    nginx_file = tmp_path / "nginx.conf"
    nginx_file.write_text(nginx_content)

    result = auditor.audit_file(nginx_file)
    assert result.score == 100
    assert result.grade == Grade.A_PLUS


def test_file_not_found(auditor):
    result = auditor.audit_file("/nonexistent/file/path")
    assert result.score <= 50
    assert any(f.id == "FILE-NOT-FOUND" for f in result.findings)


# =============================================================================
# 12. Grade Boundaries & Serialization
# =============================================================================

def test_grades_and_serialization(auditor, perfect_headers):
    result = auditor.audit_headers(perfect_headers)
    assert result.grade == Grade.A_PLUS
    assert result.score == 100

    json_str = result.to_json()
    assert '"score": 100' in json_str
    assert '"grade": "A+"' in json_str

    # Test degraded score grade mapping
    empty_result = auditor.audit_headers({})
    assert empty_result.grade in (Grade.F, Grade.D, Grade.C)
    assert not empty_result.passed_ci_default
