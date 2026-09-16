"""
Unit tests for Project Security Patcher Module (web_security_guard.patcher).
"""

import json
from pathlib import Path
import pytest

from web_security_guard.patcher import (
    detect_project_platform,
    patch_project_security,
    ProjectSecurityPatcher,
)


class TestPlatformDetection:
    def test_detect_nextjs_by_config(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text("module.exports = {};", encoding="utf-8")
        assert detect_project_platform(tmp_path) == "nextjs"

    def test_detect_nextjs_by_package_json(self, tmp_path: Path):
        pkg = {"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
        assert detect_project_platform(tmp_path) == "nextjs"

    def test_detect_netlify(self, tmp_path: Path):
        (tmp_path / "netlify.toml").write_text("[build]\npublish = 'dist'", encoding="utf-8")
        assert detect_project_platform(tmp_path) == "netlify"

    def test_detect_vercel(self, tmp_path: Path):
        (tmp_path / "vercel.json").write_text("{}", encoding="utf-8")
        assert detect_project_platform(tmp_path) == "vercel"

    def test_detect_nginx(self, tmp_path: Path):
        (tmp_path / "nginx.conf").write_text("server { listen 80; }", encoding="utf-8")
        assert detect_project_platform(tmp_path) == "nginx"

    def test_detect_static_html(self, tmp_path: Path):
        (tmp_path / "index.html").write_text("<!DOCTYPE html><html><body>Hi</body></html>", encoding="utf-8")
        assert detect_project_platform(tmp_path) == "static_html"


class TestNetlifyPatcher:
    def test_patch_fresh_netlify_project(self, tmp_path: Path):
        res = patch_project_security(tmp_path, target_platform="netlify")
        assert res["success"] is True
        assert res["detected_platform"] == "netlify"
        
        headers_file = tmp_path / "_headers"
        assert headers_file.exists()
        content = headers_file.read_text(encoding="utf-8")
        assert "Strict-Transport-Security" in content
        assert "Content-Security-Policy" in content
        assert "X-Frame-Options: DENY" in content

    def test_patch_existing_netlify_headers_and_idempotency(self, tmp_path: Path):
        headers_file = tmp_path / "_headers"
        headers_file.write_text("/*\n  X-Custom-Header: value\n", encoding="utf-8")

        # First run: updates file and creates backup
        res1 = patch_project_security(tmp_path, target_platform="netlify")
        assert res1["modified_files"][0]["action"] == "updated"
        assert (tmp_path / "_headers.bak").exists()
        
        content = headers_file.read_text(encoding="utf-8")
        assert "X-Custom-Header: value" in content
        assert "Strict-Transport-Security" in content
        assert "Content-Security-Policy" in content

        # Second run: idempotent, returns unchanged
        res2 = patch_project_security(tmp_path, target_platform="netlify")
        assert res2["modified_files"][0]["action"] == "unchanged"


class TestVercelPatcher:
    def test_patch_fresh_vercel_project(self, tmp_path: Path):
        res = patch_project_security(tmp_path, target_platform="vercel")
        assert res["success"] is True
        
        vercel_file = tmp_path / "vercel.json"
        assert vercel_file.exists()
        data = json.loads(vercel_file.read_text(encoding="utf-8"))
        assert "headers" in data
        assert len(data["headers"]) >= 1
        headers_map = {h["key"]: h["value"] for h in data["headers"][0]["headers"]}
        assert "Strict-Transport-Security" in headers_map
        assert "Content-Security-Policy" in headers_map

    def test_patch_existing_vercel_json_preserving_config(self, tmp_path: Path):
        vercel_file = tmp_path / "vercel.json"
        original_config = {
            "cleanUrls": True,
            "rewrites": [{"source": "/api/(.*)", "destination": "/api/index.js"}],
        }
        vercel_file.write_text(json.dumps(original_config), encoding="utf-8")

        res = patch_project_security(tmp_path, target_platform="vercel")
        assert res["modified_files"][0]["action"] == "updated"
        assert (tmp_path / "vercel.json.bak").exists()

        data = json.loads(vercel_file.read_text(encoding="utf-8"))
        assert data["cleanUrls"] is True
        assert len(data["rewrites"]) == 1
        assert "headers" in data

        # Repeated run: unchanged
        res2 = patch_project_security(tmp_path, target_platform="vercel")
        assert res2["modified_files"][0]["action"] == "unchanged"


class TestNextjsPatcher:
    def test_patch_fresh_nextjs_project(self, tmp_path: Path):
        res = patch_project_security(tmp_path, target_platform="nextjs")
        assert res["success"] is True
        
        middleware_file = tmp_path / "middleware.ts"
        assert middleware_file.exists()
        content = middleware_file.read_text(encoding="utf-8")
        assert "export function middleware" in content
        assert "Strict-Transport-Security" in content
        assert "Content-Security-Policy" in content

    def test_patch_nextjs_with_src_directory(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        res = patch_project_security(tmp_path, target_platform="nextjs")
        
        middleware_file = tmp_path / "src" / "middleware.ts"
        assert middleware_file.exists()
        assert not (tmp_path / "middleware.ts").exists()


class TestStaticHtmlPatcher:
    def test_patch_fresh_static_html(self, tmp_path: Path):
        res = patch_project_security(tmp_path, target_platform="static_html")
        assert res["success"] is True
        
        index_file = tmp_path / "index.html"
        assert index_file.exists()
        content = index_file.read_text(encoding="utf-8")
        assert '<meta http-equiv="Content-Security-Policy"' in content
        assert '<meta http-equiv="X-Content-Type-Options"' in content
        assert '<meta http-equiv="Referrer-Policy"' in content

    def test_patch_existing_html_files(self, tmp_path: Path):
        html_file = tmp_path / "index.html"
        html_file.write_text(
            "<!DOCTYPE html>\n<html>\n<head>\n  <title>Test Page</title>\n</head>\n<body>Hello</body></html>",
            encoding="utf-8",
        )

        res1 = patch_project_security(tmp_path, target_platform="static_html")
        assert res1["modified_files"][0]["action"] == "updated"
        assert (tmp_path / "index.html.bak").exists()

        content = html_file.read_text(encoding="utf-8")
        assert '<meta http-equiv="Content-Security-Policy"' in content
        assert "<title>Test Page</title>" in content

        # Second run: idempotent
        res2 = patch_project_security(tmp_path, target_platform="static_html")
        assert res2["modified_files"][0]["action"] == "unchanged"


class TestCustomizationAndOverrides:
    def test_custom_csp_and_headers_override(self, tmp_path: Path):
        custom_csp = "default-src 'self' https://api.mycorp.internal;"
        custom_headers = {"X-Custom-Defense": "Active-v2"}

        res = patch_project_security(
            tmp_path,
            target_platform="netlify",
            custom_csp=custom_csp,
            custom_headers=custom_headers,
        )

        headers_file = tmp_path / "_headers"
        content = headers_file.read_text(encoding="utf-8")
        assert custom_csp in content
        assert "X-Custom-Defense: Active-v2" in content
