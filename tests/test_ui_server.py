"""Unit tests for Web Security Studio UI Server, REST API, and core engines."""

import io
import json
import threading
import time
import urllib.request
import urllib.parse
import zipfile
from pathlib import Path

import pytest

from web_security_guard.ui_server import (
    create_server,
    WCAGContrastEngine,
    SRIEngine,
    CSPBuilderEngine,
    SecurityAuditEngine,
    HardeningExporter,
    MCPEngine,
    SSLEngine,
    PostureDiffEngine,
    ProjectPatcherEngine,
)


# ==============================================================================
# WCAG Contrast Engine Tests
# ==============================================================================

class TestWCAGContrastEngine:
    """Tests for WCAG 2.2 color contrast and color vision simulation."""

    def test_parse_color_hex(self):
        assert WCAGContrastEngine.parse_color("#000") == (0, 0, 0)
        assert WCAGContrastEngine.parse_color("#fff") == (255, 255, 255)
        assert WCAGContrastEngine.parse_color("#1a73e8") == (26, 115, 232)
        assert WCAGContrastEngine.parse_color("#ff0000ff") == (255, 0, 0)

    def test_parse_color_rgb_and_named(self):
        assert WCAGContrastEngine.parse_color("rgb(10, 20, 30)") == (10, 20, 30)
        assert WCAGContrastEngine.parse_color("rgba(100, 150, 200, 0.5)") == (100, 150, 200)
        assert WCAGContrastEngine.parse_color("white") == (255, 255, 255)
        assert WCAGContrastEngine.parse_color("google-blue") == (26, 115, 232)
        assert WCAGContrastEngine.parse_color("invalid") == (0, 0, 0)

    def test_relative_luminance(self):
        black_lum = WCAGContrastEngine.relative_luminance((0, 0, 0))
        white_lum = WCAGContrastEngine.relative_luminance((255, 255, 255))
        assert black_lum == pytest.approx(0.0, abs=1e-4)
        assert white_lum == pytest.approx(1.0, abs=1e-4)

    def test_contrast_ratio_extremes(self):
        black = (0, 0, 0)
        white = (255, 255, 255)
        ratio_max = WCAGContrastEngine.contrast_ratio(black, white)
        assert ratio_max == 21.0

        ratio_same = WCAGContrastEngine.contrast_ratio(white, white)
        assert ratio_same == 1.0

    def test_wcag_evaluate_google_blue_on_white(self):
        res = WCAGContrastEngine.evaluate("#1a73e8", "#ffffff")
        assert res["ratio"] >= 4.5  # Google Blue passes AA normal
        assert res["wcag_aa_normal"] is True
        assert res["wcag_aa_large"] is True
        assert res["wcag_aa_ui"] is True
        assert "simulations" in res
        assert "protanopia" in res["simulations"]
        assert "deuteranopia" in res["simulations"]
        assert "tritanopia" in res["simulations"]
        assert "achromatopsia" in res["simulations"]

    def test_color_blindness_simulation(self):
        rgb = (26, 115, 232)
        sim_p = WCAGContrastEngine.simulate_color_blindness(rgb, "protanopia")
        assert len(sim_p) == 3
        assert all(0 <= x <= 255 for x in sim_p)

        sim_ach = WCAGContrastEngine.simulate_color_blindness(rgb, "achromatopsia")
        assert sim_ach[0] == sim_ach[1] == sim_ach[2]


# ==============================================================================
# SRI Engine Tests
# ==============================================================================

class TestSRIEngine:
    """Tests for Subresource Integrity hashing and HTML injection."""

    def test_compute_hashes(self):
        data = b"console.log('Hello, world!');"
        hashes = SRIEngine.compute_hashes(data)
        assert hashes["sha256"].startswith("sha256-")
        assert hashes["sha384"].startswith("sha384-")
        assert hashes["sha512"].startswith("sha512-")

    def test_hash_content(self):
        res = SRIEngine.hash_content_or_url(content="var a = 123;")
        assert "sha384" in res
        assert "script_tag" in res
        assert "integrity=" in res["script_tag"]
        assert 'crossorigin="anonymous"' in res["script_tag"]

    def test_inject_sri_into_html(self):
        html = """<html>
<head>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
</head>
<body>
  <script src="https://cdn.example.com/app.js"></script>
</body>
</html>"""
        injected = SRIEngine.inject_sri_into_html(html)
        assert injected["injected_count"] == 2
        assert "integrity=" in injected["transformed_html"]
        assert 'crossorigin="anonymous"' in injected["transformed_html"]


# ==============================================================================
# CSP Builder Engine Tests
# ==============================================================================

class TestCSPBuilderEngine:
    """Tests for CSP Level 3 policy synthesis and framework exporters."""

    def test_build_strict_nonce_preset(self):
        res = CSPBuilderEngine.generate({"preset": "strict_nonce", "nonce": "abc123xyz=="})
        csp = res["csp"]
        assert "'strict-dynamic'" in csp
        assert "'nonce-abc123xyz=='" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_framework_exports(self):
        res = CSPBuilderEngine.generate({"preset": "strict_nonce", "nonce": "rAnd0m=="})
        fw = res["frameworks"]
        assert "nextjs" in fw
        assert "nginx" in fw
        assert "vercel" in fw
        assert "netlify_headers" in fw
        assert "netlify_toml" in fw
        assert "cloudflare" in fw
        assert "apache" in fw
        assert "express" in fw
        assert "html_meta" in fw

        # Validate Next.js export has middleware structure
        assert "export function middleware" in fw["nextjs"]
        assert "x-nonce" in fw["nextjs"]

        # Validate Nginx has add_header
        assert "add_header Content-Security-Policy" in fw["nginx"]

        # Validate Vercel JSON format
        vercel_parsed = json.loads(fw["vercel"])
        assert "headers" in vercel_parsed


# ==============================================================================
# Security Audit Engine Tests
# ==============================================================================

class TestSecurityAuditEngine:
    """Tests for header and cookie security auditing."""

    def test_audit_perfect_headers(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-xyz' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none';",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "X-XSS-Protection": "0",
        }
        res = SecurityAuditEngine.audit_headers(headers, None, "https://example.com")
        assert res["score"] >= 95
        assert res["grade"] == "A+"
        assert len(res["missing_headers"]) == 0

    def test_audit_missing_headers_and_leakage(self):
        headers = {
            "Server": "Apache/2.4.51 (Unix) OpenSSL/1.1.1",
            "X-Powered-By": "PHP/8.1.0",
        }
        res = SecurityAuditEngine.audit_headers(headers, None, "http://insecure-site.com")
        assert res["score"] < 40
        assert res["grade"] == "F"
        assert len(res["missing_headers"]) > 5
        assert len(res["dark_patterns"]) >= 2
        assert any("Server" in w for w in res["warnings"])

    def test_cookie_analysis(self):
        cookie_headers = [
            "session=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Strict",
            "tracking_id=999; Path=/",  # Insecure
            "__Host-auth=token123; Path=/; Secure; HttpOnly; SameSite=Lax",
        ]
        cookies = SecurityAuditEngine.parse_cookies(cookie_headers)
        assert len(cookies) == 3

        # First cookie is secure
        assert cookies[0]["secure"] is True
        assert cookies[0]["httponly"] is True
        assert cookies[0]["status"] == "Secure"

        # Second cookie has issues
        assert cookies[1]["secure"] is False
        assert cookies[1]["httponly"] is False
        assert len(cookies[1]["issues"]) >= 2

        # Third cookie has host prefix
        assert cookies[2]["host_prefix"] is True


# ==============================================================================
# Hardening Exporter & MCP Engine Tests
# ==============================================================================

class TestHardeningAndMCPEngines:
    """Tests for ZIP archive generation and MCP configurations."""

    def test_generate_zip_bytes(self):
        zip_bytes = HardeningExporter.generate_zip_bytes()
        assert len(zip_bytes) > 0

        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            namelist = zf.namelist()
            assert "nextjs-app-router/middleware.ts" in namelist
            assert "vercel-headers/vercel.json" in namelist
            assert "netlify-headers/_headers" in namelist
            assert "netlify-headers/netlify.toml" in namelist
            assert "nginx-hardening/nginx.conf" in namelist
            assert "apache/.htaccess" in namelist
            assert "README.md" in namelist

    def test_mcp_client_configs(self):
        configs = MCPEngine.get_client_configs()
        assert "claude_desktop" in configs
        assert "cursor" in configs
        assert "cline" in configs
        assert "zed" in configs
        assert "tools" in configs
        assert len(configs["tools"]) == 9


# ==============================================================================
# SSL, Posture Diff & Project Patcher Engine Tests
# ==============================================================================

class TestSSLEngine:
    """Tests for TLS certificate and cipher suite inspection engine."""

    def test_inspect_ssl_invalid_domain(self):
        res = SSLEngine.inspect_ssl("invalid.nonexistent.domain.xyz12345", timeout=2.0)
        assert res["is_valid"] is False
        assert res["status"] in ("CONNECTION_FAILED", "UNTRUSTED_OR_INVALID", "ERROR")
        assert len(res["recommendations"]) > 0

    def test_inspect_ssl_mock_connection(self):
        from unittest.mock import MagicMock, patch
        mock_cert = {
            "subject": ((("commonName", "test.example.com"),), (("organizationName", "Example Corp"),), (("countryName", "US"),)),
            "issuer": ((("commonName", "DigiCert Global Root CA"),), (("organizationName", "DigiCert Inc"),), (("countryName", "US"),)),
            "version": 3,
            "serialNumber": "0123456789ABCDEF",
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "test.example.com"), ("DNS", "*.example.com")),
            "OCSP": ("http://ocsp.digicert.com",),
        }

        mock_sslsock = MagicMock()
        mock_sslsock.version.return_value = "TLSv1.3"
        mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sslsock.selected_alpn_protocol.return_value = "h2"
        mock_sslsock.getpeercert.return_value = mock_cert

        mock_sock = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sslsock

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                res = SSLEngine.inspect_ssl("test.example.com", port=443)
                assert res["is_valid"] is True
                assert res["tls_version"] == "TLSv1.3"
                assert res["cipher_suite"]["name"] == "TLS_AES_256_GCM_SHA384"
                assert res["cipher_suite"]["bits"] == 256
                assert res["alpn_protocol"] == "h2"
                assert "test.example.com" in res["certificate"]["sans"]
                assert res["certificate"]["subject"]["commonName"] == "test.example.com"


class TestPostureDiffEngine:
    """Tests for side-by-side security posture differential engine."""

    def test_compare_synthetic(self):
        insecure_html = "<html><body><script>eval('x=1');</script></body></html>"
        hardened_html = "<html><head><meta http-equiv='Content-Security-Policy' content=\"default-src 'self'\"></head><body><h1>Safe</h1></body></html>"
        res = PostureDiffEngine.compare(insecure_html, hardened_html)
        assert res["score_delta"] > 0
        assert len(res["fixed_findings"]) > 0
        assert res["status"] == "IMPROVED"


class TestProjectPatcherEngine:
    """Tests for local repository security patcher."""

    def test_patcher_netlify(self, tmp_path):
        cfg = tmp_path / "netlify.toml"
        cfg.write_text("[build]\n  publish = 'public'\n")

        # Dry run
        res_dry = ProjectPatcherEngine.patch(str(tmp_path), platform="netlify", dry_run=True)
        assert res_dry["platform"] == "netlify"
        assert res_dry["applied"] is False
        assert len(res_dry["patched_files"]) > 0
        assert "[[headers]]" in res_dry["patched_files"][0]["content"]

        # Apply
        res_apply = ProjectPatcherEngine.patch(str(tmp_path), platform="netlify", dry_run=False)
        assert res_apply["applied"] is True
        assert "[[headers]]" in cfg.read_text()

    def test_patcher_auto_detect_vercel(self, tmp_path):
        cfg = tmp_path / "vercel.json"
        cfg.write_text('{"rewrites": []}')

        res = ProjectPatcherEngine.patch(str(tmp_path), platform="auto", dry_run=False)
        assert res["platform"] == "vercel"
        assert res["applied"] is True
        assert "headers" in cfg.read_text()


# ==============================================================================
# HTTP Server & REST API Integration Tests
# ==============================================================================

class TestHTTPServerIntegration:
    """Spins up an ephemeral HTTP server instance and tests all REST endpoints."""

    @pytest.fixture(scope="class")
    def test_server(self):
        server = create_server(host="127.0.0.1", port=0)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        base_url = f"http://127.0.0.1:{port}"
        yield base_url
        server.shutdown()
        server.server_close()

    def _post_json(self, url: str, data: dict):
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def _get(self, url: str):
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.headers, resp.read()

    def test_get_index_html(self, test_server):
        status, headers, content = self._get(f"{test_server}/")
        assert status == 200
        assert b"Web Security Studio" in content
        assert "text/html" in headers.get("Content-Type", "")

    def test_get_api_health(self, test_server):
        status, headers, content = self._get(f"{test_server}/api/health")
        assert status == 200
        data = json.loads(content.decode("utf-8"))
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_get_api_mcp_config(self, test_server):
        status, headers, content = self._get(f"{test_server}/api/mcp/config")
        assert status == 200
        data = json.loads(content.decode("utf-8"))
        assert "claude_desktop" in data

    def test_get_api_export_zip(self, test_server):
        status, headers, content = self._get(f"{test_server}/api/export-zip")
        assert status == 200
        assert "application/zip" in headers.get("Content-Type", "")
        with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
            assert "nextjs-app-router/middleware.ts" in zf.namelist()

    def test_post_api_audit_with_headers(self, test_server):
        payload = {
            "url": "https://test.local",
            "headers": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff"
            }
        }
        status, data = self._post_json(f"{test_server}/api/audit", payload)
        assert status == 200
        assert "score" in data
        assert "grade" in data
        assert "categories" in data

    def test_post_api_csp_generate(self, test_server):
        payload = {"preset": "strict_nonce", "nonce": "testnonce123=="}
        status, data = self._post_json(f"{test_server}/api/csp/generate", payload)
        assert status == 200
        assert "csp" in data
        assert "frameworks" in data
        assert "'nonce-testnonce123=='" in data["csp"]

    def test_post_api_sri_hash(self, test_server):
        payload = {"content": "function initSecurity() { return true; }"}
        status, data = self._post_json(f"{test_server}/api/sri/hash", payload)
        assert status == 200
        assert "sha384" in data
        assert data["sha384"].startswith("sha384-")

    def test_post_api_sri_inject(self, test_server):
        payload = {
            "html": '<script src="https://cdn.example.com/test.js"></script>',
            "algorithm": "sha384"
        }
        status, data = self._post_json(f"{test_server}/api/sri/inject", payload)
        assert status == 200
        assert "integrity=" in data["transformed_html"]

    def test_post_api_wcag_contrast(self, test_server):
        payload = {"fg": "#1a73e8", "bg": "#ffffff"}
        status, data = self._post_json(f"{test_server}/api/wcag/contrast", payload)
        assert status == 200
        assert data["ratio"] >= 4.5
        assert data["wcag_aa_normal"] is True

    def test_post_api_remediate(self, test_server):
        payload = {
            "target": "nginx",
            "headers": {"Server": "nginx"},
            "url": "https://example.com"
        }
        status, data = self._post_json(f"{test_server}/api/remediate", payload)
        assert status == 200
        assert "snippet" in data
        assert "add_header" in data["snippet"]

    def test_post_api_ssl_inspect(self, test_server):
        payload = {"domain": "invalid.local.domain.xyz", "port": 443}
        status, data = self._post_json(f"{test_server}/api/ssl/inspect", payload)
        assert status == 200
        assert "is_valid" in data
        assert data["is_valid"] is False

    def test_get_api_ssl_inspect(self, test_server):
        status, headers, content = self._get(f"{test_server}/api/ssl/inspect?domain=invalid.local.domain.xyz&port=443")
        assert status == 200
        data = json.loads(content.decode("utf-8"))
        assert "is_valid" in data

    def test_post_api_diff_compare(self, test_server):
        payload = {
            "target_a": "https://example.com",
            "target_b": "https://google.com"
        }
        status, data = self._post_json(f"{test_server}/api/diff/compare", payload)
        assert status == 200
        assert "score_delta" in data
        assert "status" in data

    def test_post_api_patch_apply(self, test_server, tmp_path):
        html_file = tmp_path / "index.html"
        html_file.write_text("<!DOCTYPE html><html><head><title>App</title></head><body>Hello</body></html>")

        payload = {
            "project_dir": str(tmp_path),
            "platform": "html",
            "dry_run": True
        }
        status, data = self._post_json(f"{test_server}/api/patch/apply", payload)
        assert status == 200
        assert data["platform"] == "html"
        assert data["applied"] is False

    def test_post_api_secrets(self, test_server):
        payload = {
            "content": 'const token = "ghp_1234567890abcdefghijklmnopqrstuv";'
        }
        status, data = self._post_json(f"{test_server}/api/secrets", payload)
        assert status == 200
        assert "clean" in data
        assert data["clean"] is False
        assert data["total_findings"] >= 1

    def test_post_api_supply_chain(self, test_server):
        payload = {
            "html": '<script src="https://cdn.example.com/bundle.js"></script>'
        }
        status, data = self._post_json(f"{test_server}/api/supply-chain", payload)
        assert status == 200
        assert "missing_sri_count" in data
        assert data["missing_sri_count"] >= 1
        assert "grade" in data

