"""Comprehensive Unit Tests for Secret Leakage Detector & Supply Chain Integrity Auditor."""

from __future__ import annotations

import json
from web_security_guard.mcp_server import MCPServer
from web_security_guard.secret_scanner import (
    SecretAuditReport,
    SecretLeakFinding,
    mask_secret,
    scan_secrets,
    shannon_entropy,
)
from web_security_guard.supply_chain_auditor import (
    SupplyChainReport,
    SupplyChainRisk,
    audit_supply_chain,
    classify_domain,
)
from web_security_guard.cli import main as cli_main


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    # High entropy string
    ent = shannon_entropy("aB8$kP9#mZ2!xQ4&")
    assert ent >= 3.5


def test_mask_secret():
    assert mask_secret("") == ""
    assert mask_secret("short") == "sh...rt"
    assert mask_secret("12") == "***"
    secret = "sk_" + "live_" + "1234567890abcdef12345678"
    masked = mask_secret(secret)
    assert masked.startswith("sk_l...")
    assert masked.endswith("5678")
    assert "abcdef" not in masked


def test_scan_secrets_clean_code():
    code = """
    function greet(name) {
        console.log("Hello, " + name);
    }
    const endpoint = "/api/v1/users";
    """
    report = scan_secrets(code, target_name="app.js")
    assert report.clean is True
    assert report.total_findings == 0
    assert report.risk_score == 0.0
    assert "Clean" in report.format_markdown()
    assert "PASSED" in report.format_text()


def test_scan_secrets_aws_and_github():
    code = """
    export const AWS_KEY = "AKIA1234567890ABCDEF";
    const token = "ghp_1234567890abcdefghijklmnopqrstuv";
    """
    report = scan_secrets(code, target_name="env.js")
    assert report.clean is False
    assert report.total_findings == 2
    detector_ids = {f.detector_id for f in report.findings}
    assert "aws-access-key" in detector_ids
    assert "github-pat-classic" in detector_ids
    assert report.risk_score > 50.0


def test_scan_secrets_stripe_and_openai():
    st_tok = "sk_" + "live_" + "51Abcdef1234567890Ghijklmnop"
    code = f"""
    const stripe = require('stripe')('{st_tok}');
    const openaiKey = "sk-proj-1234567890abcdef1234567890abcdef12345678";
    """
    report = scan_secrets(code, target_name="server.js")
    assert report.clean is False
    assert report.total_findings >= 2
    detector_ids = {f.detector_id for f in report.findings}
    assert "stripe-secret-key" in detector_ids
    assert "openai-api-key" in detector_ids


def test_scan_secrets_private_key_and_database_uri():
    code = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Yw...
    -----END RSA PRIVATE KEY-----
    const DB = "postgres://admin:SuperSecretPassword123@db.example.com:5432/prod";
    """
    report = scan_secrets(code, target_name="config.py")
    assert report.clean is False
    detector_ids = {f.detector_id for f in report.findings}
    assert "private-key" in detector_ids
    assert "database-connection-uri" in detector_ids
    md = report.format_markdown()
    assert "CAUTION" in md
    assert "Remediation Details" in md


def test_scan_secrets_ignore_placeholders():
    code = """
    const key = "your_api_key_here";
    const dummy = "placeholder_secret_value";
    """
    report = scan_secrets(code, target_name="test.js")
    assert report.clean is True
    assert report.total_findings == 0


def test_classify_domain():
    cat, trusted = classify_domain("cdnjs.cloudflare.com")
    assert cat == "Trusted CDN"
    assert trusted is True

    cat2, trusted2 = classify_domain("evil-tracker.info")
    assert cat2 == "Third-Party Domain"
    assert trusted2 is False

    cat3, trusted3 = classify_domain("localhost")
    assert trusted3 is True


def test_audit_supply_chain_clean_html():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Secure Portal</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css"
              integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js"
                integrity="sha384-NXUkGwe15M6p31G0U3kY4z2W0F1eB" crossorigin="anonymous"></script>
    </head>
    <body>
        <a href="https://example.com" target="_blank" rel="noopener noreferrer">Docs</a>
    </body>
    </html>
    """
    report = audit_supply_chain(html, target_name="index.html")
    assert report.supply_chain_score == 100.0
    assert report.grade == "A+"
    assert report.missing_sri_count == 0
    assert report.mixed_content_count == 0
    assert report.reverse_tabnabbing_count == 0
    assert "Grade A+" in report.format_markdown()


def test_audit_supply_chain_vulnerabilities_detected():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdn.example.com/unpinned/app.js"></script>
        <script src="http://insecure.com/script.js"></script>
        <link rel="stylesheet" href="http://insecure.com/style.css">
    </head>
    <body>
        <iframe src="http://insecure-widget.com/embed"></iframe>
        <form action="http://auth.example.com/login"></form>
        <a href="https://external.com" target="_blank">External Without Rel</a>
    </body>
    </html>
    """
    report = audit_supply_chain(html, target_name="vulnerable.html", page_is_https=True)
    assert report.total_resources_scanned >= 5
    assert report.missing_sri_count >= 1
    assert report.mixed_content_count >= 3
    assert report.reverse_tabnabbing_count >= 1
    assert report.supply_chain_score < 50.0
    assert report.grade in ("D", "F")

    categories = {r.category for r in report.risks}
    assert "MISSING_SRI" in categories
    assert "MIXED_CONTENT" in categories
    assert "INSECURE_FORM" in categories
    assert "REVERSE_TABNABBING" in categories


def test_mcp_sec_scan_secrets_tool():
    server = MCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "sec_scan_secrets",
            "arguments": {
                "content": 'const token = "ghp_abcdef1234567890abcdef1234567890abcd";'
            },
        },
    }
    resp = server.handle_request(req)
    assert resp["result"]["isError"] is False
    res_data = resp["result"]["content"][0]["text"]
    parsed = json.loads(res_data)
    assert parsed["clean"] is False
    assert parsed["total_findings"] >= 1
    assert parsed["findings"][0]["detector_id"] == "github-pat-classic"


def test_mcp_sec_audit_supply_chain_tool():
    server = MCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {
            "name": "sec_audit_supply_chain",
            "arguments": {
                "html_content": '<script src="http://evil.com/payload.js"></script>'
            },
        },
    }
    resp = server.handle_request(req)
    assert resp["result"]["isError"] is False
    res_data = resp["result"]["content"][0]["text"]
    parsed = json.loads(res_data)
    assert parsed["mixed_content_count"] >= 1
    assert parsed["missing_sri_count"] >= 1


def test_cli_secrets_command_clean_and_dirty(capsys):
    # Dirty input
    tok = "sk_" + "live_" + "1234567890abcdef1234567890"
    code = f'const s = "{tok}";'
    ret_dirty = cli_main(["secrets", "--content", code, "--json"])
    assert ret_dirty == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["clean"] is False

    # Clean input
    clean_code = 'console.log("Safe");'
    ret_clean = cli_main(["secrets", "--content", clean_code, "--json"])
    assert ret_clean == 0
    captured_clean = capsys.readouterr()
    data_clean = json.loads(captured_clean.out)
    assert data_clean["clean"] is True


def test_cli_supply_command(tmp_path, capsys):
    html = '<html><head><script src="https://cdn.example.com/tracker.js"></script></head><body></body></html>'
    test_file = tmp_path / "page.html"
    test_file.write_text(html, encoding="utf-8")
    ret = cli_main(["supply", str(test_file), "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["missing_sri_count"] >= 1
    assert data["supply_chain_score"] < 100.0
