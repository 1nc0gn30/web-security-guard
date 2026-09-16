#!/usr/bin/env python3
"""Comprehensive unit and integration tests for MCP Server and Security Engine."""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from web_security_guard.mcp_server import (
    MCP_TOOLS_DEFINITIONS,
    SERVER_NAME,
    SERVER_VERSION,
    MCPServer,
    audit_security,
    calculate_contrast,
    diff_security_postures,
    generate_csp_policy,
    generate_mcp_client_config,
    generate_remediation_configs,
    generate_sri_hash,
    inject_sri_into_html,
    inspect_ssl,
    parse_color,
    patch_project,
    relative_luminance,
)


class TestColorContrastEngine(unittest.TestCase):
    """Test WCAG 2.2 color contrast and luminance algorithms."""

    def test_parse_color_formats(self):
        # Hex formats
        self.assertEqual(parse_color("#000000"), (0, 0, 0))
        self.assertEqual(parse_color("#ffffff"), (255, 255, 255))
        self.assertEqual(parse_color("#fff"), (255, 255, 255))
        self.assertEqual(parse_color("#ffff"), (255, 255, 255))
        self.assertEqual(parse_color("#38bdf8"), (56, 189, 248))
        self.assertEqual(parse_color("#38bdf8ff"), (56, 189, 248))

        # Named colors
        self.assertEqual(parse_color("black"), (0, 0, 0))
        self.assertEqual(parse_color("white"), (255, 255, 255))
        self.assertEqual(parse_color("red"), (255, 0, 0))
        self.assertEqual(parse_color("blue"), (0, 0, 255))

        # RGB & RGBA formats
        self.assertEqual(parse_color("rgb(255, 0, 128)"), (255, 0, 128))
        self.assertEqual(parse_color("rgba(10, 20, 30, 0.5)"), (10, 20, 30))
        self.assertEqual(parse_color("100, 150, 200"), (100, 150, 200))

        # Invalid formats
        with self.assertRaises(ValueError):
            parse_color("not-a-color-xyz")
        with self.assertRaises(ValueError):
            parse_color("#12")

    def test_relative_luminance(self):
        self.assertAlmostEqual(relative_luminance(0, 0, 0), 0.0, places=3)
        self.assertAlmostEqual(relative_luminance(255, 255, 255), 1.0, places=3)

    def test_calculate_contrast_black_and_white(self):
        res = calculate_contrast("#000000", "#ffffff")
        self.assertEqual(res["contrast_ratio"], 21.0)
        self.assertEqual(res["formatted_ratio"], "21.0:1")
        self.assertTrue(res["compliance"]["passes_target"])
        self.assertTrue(res["compliance"]["wcag_2_2_aa"]["normal_text"]["passed"])
        self.assertTrue(res["compliance"]["wcag_2_2_aaa"]["normal_text"]["passed"])

    def test_calculate_contrast_low_contrast_failure(self):
        res = calculate_contrast("#777777", "#888888", target_level="AA")
        self.assertLess(res["contrast_ratio"], 3.0)
        self.assertFalse(res["compliance"]["passes_target"])
        self.assertFalse(res["compliance"]["wcag_2_2_aa"]["normal_text"]["passed"])
        self.assertGreater(len(res["suggestions"]), 0)

    def test_calculate_contrast_large_text_threshold(self):
        # Color pair that passes AA large (>= 3.0:1) but fails AA normal (< 4.5:1)
        res = calculate_contrast("#767676", "#ffffff", font_size_pt=18.0, is_bold=False)
        self.assertTrue(res["typography"]["is_large_text"])
        self.assertTrue(res["compliance"]["passes_target"])


class TestSRIEngine(unittest.TestCase):
    """Test Subresource Integrity generation and HTML injection."""

    def test_generate_sri_hash(self):
        data = b"function test() { return 42; }"
        res256 = generate_sri_hash(data, "sha256")
        self.assertEqual(res256["algorithm"], "sha256")
        self.assertTrue(res256["integrity"].startswith("sha256-"))

        res384 = generate_sri_hash(data, "sha384")
        self.assertEqual(res384["algorithm"], "sha384")
        self.assertTrue(res384["integrity"].startswith("sha384-"))

        res512 = generate_sri_hash(data, "sha512")
        self.assertEqual(res512["algorithm"], "sha512")
        self.assertTrue(res512["integrity"].startswith("sha512-"))

        with self.assertRaises(ValueError):
            generate_sri_hash(data, "md5")

    def test_inject_sri_into_html_local_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            js_file = os.path.join(tmpdir, "bundle.js")
            with open(js_file, "w", encoding="utf-8") as f:
                f.write("console.log('test bundle');")

            css_file = os.path.join(tmpdir, "style.css")
            with open(css_file, "w", encoding="utf-8") as f:
                f.write("body { margin: 0; }")

            html_file = os.path.join(tmpdir, "index.html")
            raw_html = f"""<!DOCTYPE html>
            <html>
            <head>
                <link rel="stylesheet" href="{css_file}">
            </head>
            <body>
                <script src="{js_file}"></script>
            </body>
            </html>"""
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(raw_html)

            res = inject_sri_into_html(html_file, algorithm="sha384", save_to_file=True)
            self.assertEqual(res["injected_count"], 2)
            self.assertEqual(len(res["modified_resources"]), 2)

            with open(html_file, "r", encoding="utf-8") as f:
                injected_content = f.read()
            self.assertIn('integrity="sha384-', injected_content)
            self.assertIn('crossorigin="anonymous"', injected_content)


class TestCSPEngine(unittest.TestCase):
    """Test Content Security Policy Level 3 generator."""

    def test_generate_csp_strict_preset(self):
        res = generate_csp_policy(framework="vanilla", preset="strict", nonce="test-nonce")
        self.assertEqual(res["header_name"], "Content-Security-Policy")
        self.assertIn("nonce-test-nonce", res["csp_string"])
        self.assertIn("'strict-dynamic'", res["csp_string"])
        self.assertIn("object-src 'none'", res["csp_string"])
        self.assertIn("frame-ancestors 'none'", res["csp_string"])
        self.assertIn("<meta", res["meta_tag"])
        self.assertIn("add_header", res["nginx_snippet"])
        self.assertIn("Header set", res["apache_snippet"])
        self.assertIn("[[headers]]", res["netlify_snippet"])

    def test_generate_csp_balanced_preset(self):
        res = generate_csp_policy(framework="react", preset="balanced", nonce="bal-nonce")
        self.assertIn("cdnjs.cloudflare.com", res["csp_string"])
        self.assertIn("bal-nonce", res["csp_string"])

    def test_generate_csp_report_only(self):
        res = generate_csp_policy(framework="vanilla", preset="report-only", report_uri="https://api.example.com/csp")
        self.assertEqual(res["header_name"], "Content-Security-Policy-Report-Only")
        self.assertIn("report-uri https://api.example.com/csp", res["csp_string"])

    def test_generate_csp_api_only(self):
        res = generate_csp_policy(preset="api-only")
        self.assertIn("default-src 'none'", res["csp_string"])
        self.assertIn("frame-ancestors 'none'", res["csp_string"])


class TestSecurityAuditEngine(unittest.TestCase):
    """Test static & heuristic security auditing."""

    def test_audit_html_findings(self):
        vulnerable_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Insecure App</title>
        </head>
        <body>
            <a href="https://evil.com" target="_blank">External Link</a>
            <form action="http://insecure.example.com/login" method="POST">
                <input type="password" name="pwd">
                <button type="submit">Log in</button>
            </form>
            <script src="https://cdn.example.com/unhashed.js"></script>
            <script>
                eval("var x = 1;");
            </script>
        </body>
        </html>
        """
        res = audit_security(vulnerable_html, min_score=80)
        self.assertLess(res["score"], 80)
        self.assertIn(res["grade"], ("C", "D", "F"))
        self.assertFalse(res["passed_min_score"])

        finding_ids = [f["id"] for f in res["findings"]]
        self.assertIn("SEC_CSP_MISSING", finding_ids)
        self.assertIn("SEC_INSECURE_FORM_ACTION", finding_ids)
        self.assertIn("SEC_TABNABBING_RISK", finding_ids)
        self.assertIn("SEC_DANGEROUS_JS_SINK", finding_ids)
        self.assertIn("SEC_SRI_MISSING", finding_ids)

    def test_remediation_generation(self):
        res = generate_remediation_configs("test-target", server_type="all")
        self.assertEqual(res["target"], "test-target")
        self.assertIn("netlify.toml", res["files"])
        self.assertIn("nginx.conf", res["files"])
        self.assertIn(".htaccess", res["files"])
        self.assertIn("vercel.json", res["files"])
        self.assertIn("Caddyfile", res["files"])
        self.assertIn("helmet-express.js", res["files"])
        self.assertIn("security-meta.html", res["files"])


class TestSSLEngineMCP(unittest.TestCase):
    """Test SSL / TLS certificate inspection engine in MCP."""

    def test_inspect_ssl_invalid_domain(self):
        res = inspect_ssl("invalid.nonexistent.domain.xyz12345", timeout=2.0)
        self.assertFalse(res["is_valid"])
        self.assertIn(res["status"], ("CONNECTION_FAILED", "UNTRUSTED_OR_INVALID", "ERROR"))
        self.assertGreater(len(res["recommendations"]), 0)

    def test_inspect_ssl_mock_connection(self):
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
                res = inspect_ssl("test.example.com", port=443)
                self.assertTrue(res["is_valid"])
                self.assertEqual(res["tls_version"], "TLSv1.3")
                self.assertEqual(res["cipher_suite"]["name"], "TLS_AES_256_GCM_SHA384")
                self.assertEqual(res["cipher_suite"]["bits"], 256)
                self.assertEqual(res["alpn_protocol"], "h2")
                self.assertIn("test.example.com", res["certificate"]["sans"])
                self.assertIn("*.example.com", res["certificate"]["sans"])
                self.assertEqual(res["certificate"]["subject"]["commonName"], "test.example.com")
                self.assertEqual(res["certificate"]["issuer"]["commonName"], "DigiCert Global Root CA")


class TestPostureDiffEngineMCP(unittest.TestCase):
    """Test side-by-side security posture differential engine."""

    def test_diff_synthetic_html(self):
        insecure_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <a href="https://bad.com" target="_blank">Link</a>
            <form action="http://insecure.com/submit"><button>Submit</button></form>
            <script>eval('x=1');</script>
        </body>
        </html>
        """
        hardened_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none';">
        </head>
        <body>
            <a href="https://good.com" target="_blank" rel="noopener noreferrer">Link</a>
            <form action="https://secure.com/submit"><button>Submit</button></form>
        </body>
        </html>
        """
        res = diff_security_postures(insecure_html, hardened_html)
        self.assertIn("target_a", res)
        self.assertIn("target_b", res)
        self.assertIn("score_delta", res)
        self.assertGreater(res["score_delta"], 0)
        self.assertGreater(len(res["fixed_findings"]), 0)


class TestProjectPatcherEngineMCP(unittest.TestCase):
    """Test 1-click local repository patcher across platforms."""

    def test_patch_project_netlify_dry_run_and_apply(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "netlify.toml")
            with open(config_file, "w", encoding="utf-8") as f:
                f.write("[build]\n  publish = \"dist\"\n")

            # 1. Dry run preview
            res_preview = patch_project(tmpdir, platform="netlify", dry_run=True)
            self.assertEqual(res_preview["platform"], "netlify")
            self.assertTrue(res_preview["dry_run"])
            self.assertFalse(res_preview["applied"])
            self.assertGreater(len(res_preview["patched_files"]), 0)
            self.assertIn("[[headers]]", res_preview["patched_files"][0]["content"])

            # Verify file not touched yet
            with open(config_file, "r", encoding="utf-8") as f:
                content_before = f.read()
            self.assertNotIn("[[headers]]", content_before)

            # 2. Apply patch
            res_applied = patch_project(tmpdir, platform="netlify", dry_run=False)
            self.assertTrue(res_applied["applied"])
            with open(config_file, "r", encoding="utf-8") as f:
                content_after = f.read()
            self.assertIn("[[headers]]", content_after)
            self.assertIn("Strict-Transport-Security", content_after)

    def test_patch_project_auto_detect_vercel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = os.path.join(tmpdir, "vercel.json")
            with open(config_file, "w", encoding="utf-8") as f:
                f.write("{\n  \"rewrites\": []\n}\n")

            res = patch_project(tmpdir, platform="auto", dry_run=False)
            self.assertEqual(res["platform"], "vercel")
            self.assertTrue(res["applied"])

            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("headers", data)

    def test_patch_project_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_file = os.path.join(tmpdir, "index.html")
            with open(html_file, "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE html><html><head><title>App</title></head><body><h1>Hello</h1></body></html>")

            res = patch_project(tmpdir, platform="html", dry_run=False)
            self.assertEqual(res["platform"], "html")
            with open(html_file, "r", encoding="utf-8") as f:
                html_patched = f.read()
            self.assertIn("Content-Security-Policy", html_patched)
            self.assertIn("<meta", html_patched)


class TestMCPClientConfig(unittest.TestCase):
    """Test MCP Client config generation for Claude, Cursor, Cline, Zed, and generic."""

    def test_claude_desktop_config(self):
        cfg = generate_mcp_client_config("claude", python_path="/usr/bin/python3")
        self.assertIn("mcpServers", cfg)
        self.assertIn("web-security-guard", cfg["mcpServers"])
        self.assertEqual(cfg["mcpServers"]["web-security-guard"]["command"], "/usr/bin/python3")

    def test_cursor_config(self):
        cfg = generate_mcp_client_config("cursor")
        self.assertIn("mcpServers", cfg)
        self.assertIn("web-security-guard", cfg["mcpServers"])

    def test_cline_config(self):
        cfg = generate_mcp_client_config("cline")
        self.assertIn("mcpServers", cfg)
        srv = cfg["mcpServers"]["web-security-guard"]
        self.assertFalse(srv["disabled"])
        self.assertIn("sec_audit_site", srv["alwaysAllow"])

    def test_zed_config(self):
        cfg = generate_mcp_client_config("zed")
        self.assertIn("context_servers", cfg)
        self.assertIn("web-security-guard", cfg["context_servers"])

    def test_generic_config(self):
        cfg = generate_mcp_client_config("generic")
        self.assertEqual(cfg["name"], SERVER_NAME)
        self.assertIn("supported_tools", cfg)


class TestMCPServerProtocol(unittest.TestCase):
    """Test JSON-RPC 2.0 and MCP tool execution handlers."""

    def setUp(self):
        self.server = MCPServer()

    def test_initialize(self):
        req = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 101)
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(resp["result"]["serverInfo"]["name"], SERVER_NAME)

    def test_ping(self):
        req = {"jsonrpc": "2.0", "id": 102, "method": "ping"}
        resp = self.server.handle_request(req)
        self.assertEqual(resp["id"], 102)
        self.assertEqual(resp["result"], {})

    def test_tools_list(self):
        req = {"jsonrpc": "2.0", "id": 103, "method": "tools/list"}
        resp = self.server.handle_request(req)
        tools = resp["result"]["tools"]
        self.assertEqual(len(tools), 9)
        tool_names = [t["name"] for t in tools]
        self.assertIn("sec_audit_site", tool_names)
        self.assertIn("sec_generate_csp", tool_names)
        self.assertIn("sec_generate_sri", tool_names)
        self.assertIn("sec_inject_sri", tool_names)
        self.assertIn("sec_check_contrast", tool_names)
        self.assertIn("sec_generate_remediation", tool_names)
        self.assertIn("sec_inspect_ssl", tool_names)
        self.assertIn("sec_diff_postures", tool_names)
        self.assertIn("sec_patch_project", tool_names)

    def test_tools_call_contrast(self):
        req = {
            "jsonrpc": "2.0",
            "id": 104,
            "method": "tools/call",
            "params": {
                "name": "sec_check_contrast",
                "arguments": {"fg_color": "#ffffff", "bg_color": "#000000"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertEqual(data["contrast_ratio"], 21.0)

    def test_tools_call_csp(self):
        req = {
            "jsonrpc": "2.0",
            "id": 105,
            "method": "tools/call",
            "params": {
                "name": "sec_generate_csp",
                "arguments": {"framework": "nextjs", "preset": "strict", "nonce": "abc123xyz"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertIn("abc123xyz", data["csp_string"])

    def test_tools_call_sri(self):
        req = {
            "jsonrpc": "2.0",
            "id": 106,
            "method": "tools/call",
            "params": {
                "name": "sec_generate_sri",
                "arguments": {"target": "console.log('hi');", "algorithm": "sha384"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertEqual(data["algorithm"], "sha384")
        self.assertTrue(data["integrity"].startswith("sha384-"))

    def test_tools_call_remediation(self):
        req = {
            "jsonrpc": "2.0",
            "id": 107,
            "method": "tools/call",
            "params": {
                "name": "sec_generate_remediation",
                "arguments": {"target": "my-site", "server_type": "netlify"},
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertIn("netlify.toml", data["files"])

    def test_tools_call_inspect_ssl(self):
        req = {
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call",
            "params": {
                "name": "sec_inspect_ssl",
                "arguments": {"target": "invalid.local.domain.xyz", "port": 443, "timeout": 1.0},
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertIn("is_valid", data)

    def test_tools_call_diff_postures(self):
        req = {
            "jsonrpc": "2.0",
            "id": 111,
            "method": "tools/call",
            "params": {
                "name": "sec_diff_postures",
                "arguments": {
                    "target_a": "<h1>Baseline</h1>",
                    "target_b": "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"><h1>Hardened</h1>",
                },
            },
        }
        resp = self.server.handle_request(req)
        self.assertFalse(resp["result"]["isError"])
        content_text = resp["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertIn("score_delta", data)

    def test_tools_call_patch_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_file = os.path.join(tmpdir, "index.html")
            with open(html_file, "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE html><html><head><title>App</title></head><body><h1>Hello</h1></body></html>")

            req = {
                "jsonrpc": "2.0",
                "id": 112,
                "method": "tools/call",
                "params": {
                    "name": "sec_patch_project",
                    "arguments": {"project_dir": tmpdir, "platform": "html", "dry_run": True},
                },
            }
            resp = self.server.handle_request(req)
            self.assertFalse(resp["result"]["isError"])
            content_text = resp["result"]["content"][0]["text"]
            data = json.loads(content_text)
            self.assertEqual(data["platform"], "html")
            self.assertTrue(data["dry_run"])

    def test_invalid_tool_name(self):
        req = {
            "jsonrpc": "2.0",
            "id": 108,
            "method": "tools/call",
            "params": {"name": "non_existent_tool", "arguments": {}},
        }
        resp = self.server.handle_request(req)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_invalid_method(self):
        req = {"jsonrpc": "2.0", "id": 109, "method": "invalid/method"}
        resp = self.server.handle_request(req)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()

