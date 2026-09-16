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
    generate_csp_policy,
    generate_mcp_client_config,
    generate_remediation_configs,
    generate_sri_hash,
    inject_sri_into_html,
    parse_color,
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
        self.assertEqual(len(tools), 6)
        tool_names = [t["name"] for t in tools]
        self.assertIn("sec_audit_site", tool_names)
        self.assertIn("sec_generate_csp", tool_names)
        self.assertIn("sec_generate_sri", tool_names)
        self.assertIn("sec_inject_sri", tool_names)
        self.assertIn("sec_check_contrast", tool_names)
        self.assertIn("sec_generate_remediation", tool_names)

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
