#!/usr/bin/env python3
"""Comprehensive unit and integration tests for Web Security Guard CLI & Studio."""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from contextlib import redirect_stdout, redirect_stderr
from http.server import HTTPServer
from unittest.mock import patch, MagicMock

from web_security_guard.cli import (
    build_parser,
    main,
    run_internal_tests,
)



class TestCLIArgumentParsing(unittest.TestCase):
    """Test CLI argument parsing and flags."""

    def setUp(self):
        self.parser = build_parser()

    def test_subcommand_audit_args(self):
        args = self.parser.parse_args(["audit", "https://example.com", "--min-score", "90", "--json"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.target, "https://example.com")
        self.assertEqual(args.min_score, 90)
        self.assertTrue(args.json)

    def test_subcommand_csp_args(self):
        args = self.parser.parse_args(["csp", "--preset", "strict", "--framework", "astro", "--nonce", "xyz"])
        self.assertEqual(args.command, "csp")
        self.assertEqual(args.preset, "strict")
        self.assertEqual(args.framework, "astro")
        self.assertEqual(args.nonce, "xyz")

    def test_subcommand_sri_args(self):
        args = self.parser.parse_args(["sri", "index.html", "--algorithm", "sha512", "--inject"])
        self.assertEqual(args.command, "sri")
        self.assertEqual(args.file_or_url, "index.html")
        self.assertEqual(args.algorithm, "sha512")
        self.assertTrue(args.inject)

    def test_subcommand_contrast_args(self):
        args = self.parser.parse_args(["contrast", "#fff", "#000", "--bold", "--level", "AAA"])
        self.assertEqual(args.command, "contrast")
        self.assertEqual(args.fg, "#fff")
        self.assertEqual(args.bg, "#000")
        self.assertTrue(args.bold)
        self.assertEqual(args.level, "AAA")

    def test_subcommand_check_args(self):
        args = self.parser.parse_args(["check", "dist/index.html", "--min-score", "95"])
        self.assertEqual(args.command, "check")
        self.assertEqual(args.target, "dist/index.html")
        self.assertEqual(args.min_score, 95)


class TestCLIExecutionCommands(unittest.TestCase):
    """Test CLI main() command routing and stdout outputs."""

    def test_run_internal_tests_suite(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = run_internal_tests()
        self.assertEqual(code, 0)
        out = f.getvalue()
        self.assertIn("PASS", out)
        self.assertIn("passed successfully", out)

    def test_cli_test_flag(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["--test"])
        self.assertEqual(code, 0)

    def test_cli_contrast_success(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["contrast", "#ffffff", "#000000", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["contrast_ratio"], 21.0)
        self.assertTrue(data["compliance"]["passes_target"])

    def test_cli_contrast_failure(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["contrast", "#888888", "#777777"])
        self.assertEqual(code, 1)
        out = f.getvalue()
        self.assertIn("FAIL", out)

    def test_cli_csp_generation(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["csp", "--preset", "strict", "--framework", "nextjs", "--nonce", "testnonce999"])
        self.assertEqual(code, 0)
        out = f.getvalue()
        self.assertIn("Content-Security-Policy", out)
        self.assertIn("testnonce999", out)

    def test_cli_csp_json_format(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["csp", "--preset", "balanced", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["preset"], "balanced")
        self.assertIn("csp_string", data)

    def test_cli_sri_hash(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["sri", "console.log('test script');", "--algorithm", "sha256", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["algorithm"], "sha256")
        self.assertTrue(data["integrity"].startswith("sha256-"))

    def test_cli_audit_local_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", mode="w", delete=False) as tf:
            tf.write("""<!DOCTYPE html>
            <html>
            <head><title>Test App</title></head>
            <body>
                <a href="http://example.com" target="_blank">Link</a>
            </body>
            </html>""")
            tf_path = tf.name

        try:
            f = io.StringIO()
            with redirect_stdout(f):
                code = main(["audit", tf_path, "--json"])
            data = json.loads(f.getvalue())
            self.assertIn("score", data)
            self.assertIn("findings", data)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_fix_remediation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = io.StringIO()
            with redirect_stdout(f):
                code = main(["fix", "test-project", "--output-dir", tmpdir, "--json"])
            self.assertEqual(code, 0)
            data = json.loads(f.getvalue())
            self.assertEqual(data["output_directory"], tmpdir)
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "netlify.toml")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "nginx.conf")))

    def test_cli_check_gate(self):
        with tempfile.NamedTemporaryFile(suffix=".html", mode="w", delete=False) as tf:
            tf.write("<!DOCTYPE html><html><body><h1>Safe</h1></body></html>")
            tf_path = tf.name

        try:
            # Low threshold should pass
            code_pass = main(["check", tf_path, "--min-score", "10", "--json"])
            self.assertEqual(code_pass, 0)

            # Max threshold on missing headers should fail
            code_fail = main(["check", tf_path, "--min-score", "99", "--json"])
            self.assertEqual(code_fail, 1)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_cli_mcp_tools_list(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["mcp", "--tools"])
        self.assertEqual(code, 0)
        out = f.getvalue()
        self.assertIn("sec_audit_site", out)
        self.assertIn("sec_generate_csp", out)
        self.assertIn("sec_check_contrast", out)

    def test_cli_mcp_configs(self):
        for client in ("claude", "cursor", "cline", "zed", "generic"):
            f = io.StringIO()
            with redirect_stdout(f):
                code = main(["mcp", "--config", client])
            self.assertEqual(code, 0)
            data = json.loads(f.getvalue())
            self.assertIsInstance(data, dict)

    def test_cli_platform_inspection(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["platform", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["server_name"], "web-security-guard")
        self.assertIn("python_version", data)
        self.assertIn("platform_system", data)


class TestCLIServeCommand(unittest.TestCase):
    """Test CLI serve command."""

    @patch("web_security_guard.ui_server.start_ui_server")
    def test_cmd_serve_invocation(self, mock_start):
        code = main(["serve", "--port", "9090", "--host", "127.0.0.1"])
        self.assertEqual(code, 0)
        mock_start.assert_called_once_with(host="127.0.0.1", port=9090)



if __name__ == "__main__":
    unittest.main()
