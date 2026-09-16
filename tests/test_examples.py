"""Tests validating that all production examples, MCP configs, and docs are valid."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class TestNextjsExample:
    """Validates Next.js 14/15 App Router reference example."""

    def test_middleware_exists_and_valid(self):
        mw_path = REPO_ROOT / "examples" / "nextjs-app-router" / "middleware.ts"
        assert mw_path.exists(), f"Missing {mw_path}"
        content = mw_path.read_text(encoding="utf-8")
        assert "crypto.getRandomValues" in content
        assert "Content-Security-Policy" in content
        assert "x-nonce" in content
        assert "'strict-dynamic'" in content
        assert "Strict-Transport-Security" in content

    def test_layout_exists_and_valid(self):
        layout_path = REPO_ROOT / "examples" / "nextjs-app-router" / "app" / "layout.tsx"
        assert layout_path.exists(), f"Missing {layout_path}"
        content = layout_path.read_text(encoding="utf-8")
        assert "x-nonce" in content
        assert "nonce={nonce}" in content

    def test_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "nextjs-app-router" / "README.md"
        assert readme_path.exists()
        assert len(readme_path.read_text(encoding="utf-8")) > 100


class TestVercelExample:
    """Validates Vercel reference example."""

    def test_vercel_json_valid_and_complete(self):
        v_path = REPO_ROOT / "examples" / "vercel-headers" / "vercel.json"
        assert v_path.exists()
        with open(v_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "headers" in data
        header_keys = [h["key"] for group in data["headers"] for h in group.get("headers", [])]
        assert "Content-Security-Policy" in header_keys
        assert "Strict-Transport-Security" in header_keys
        assert "X-Frame-Options" in header_keys
        assert "X-Content-Type-Options" in header_keys
        assert "Referrer-Policy" in header_keys
        assert "Permissions-Policy" in header_keys

    def test_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "vercel-headers" / "README.md"
        assert readme_path.exists()


class TestNetlifyExample:
    """Validates Netlify reference example."""

    def test_headers_file(self):
        h_path = REPO_ROOT / "examples" / "netlify-headers" / "_headers"
        assert h_path.exists()
        content = h_path.read_text(encoding="utf-8")
        assert "Content-Security-Policy:" in content
        assert "Strict-Transport-Security:" in content
        assert "X-Frame-Options: DENY" in content

    def test_netlify_toml_file(self):
        t_path = REPO_ROOT / "examples" / "netlify-headers" / "netlify.toml"
        assert t_path.exists()
        content = t_path.read_text(encoding="utf-8")
        assert "[[headers]]" in content
        assert "Content-Security-Policy" in content

    def test_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "netlify-headers" / "README.md"
        assert readme_path.exists()


class TestNginxExample:
    """Validates Nginx hardening reference example."""

    def test_nginx_conf(self):
        n_path = REPO_ROOT / "examples" / "nginx-hardening" / "nginx.conf"
        assert n_path.exists()
        content = n_path.read_text(encoding="utf-8")
        assert "server_tokens off;" in content
        assert "ssl_protocols TLSv1.2 TLSv1.3;" in content
        assert "limit_req_zone" in content
        assert "add_header Content-Security-Policy" in content
        assert "add_header Strict-Transport-Security" in content

    def test_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "nginx-hardening" / "README.md"
        assert readme_path.exists()


class TestCdnSriHtmlExample:
    """Validates Subresource Integrity HTML reference example."""

    def test_html_sri_tags(self):
        html_path = REPO_ROOT / "examples" / "cdn-sri-html" / "index.html"
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        assert 'integrity="sha384-' in content
        assert 'crossorigin="anonymous"' in content

    def test_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "cdn-sri-html" / "README.md"
        assert readme_path.exists()


class TestMcpClientConfigs:
    """Validates MCP client config JSON files."""

    def test_claude_desktop_config(self):
        path = REPO_ROOT / "examples" / "mcp-clients" / "claude_desktop_config.json"
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "mcpServers" in data
        assert "web-security-guard" in data["mcpServers"]

    def test_cursor_mcp_config(self):
        path = REPO_ROOT / "examples" / "mcp-clients" / "cursor_mcp.json"
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "mcpServers" in data
        assert "web-security-guard" in data["mcpServers"]

    def test_cline_mcp_config(self):
        path = REPO_ROOT / "examples" / "mcp-clients" / "cline_mcp.json"
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "mcpServers" in data
        assert "web-security-guard" in data["mcpServers"]

    def test_zed_settings_config(self):
        path = REPO_ROOT / "examples" / "mcp-clients" / "zed_settings.json"
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "context_servers" in data
        assert "web-security-guard" in data["context_servers"]

    def test_mcp_readme_exists(self):
        readme_path = REPO_ROOT / "examples" / "mcp-clients" / "README.md"
        assert readme_path.exists()


class TestWorkflowsAndDocs:
    """Validates GitHub Actions workflows and documentation."""

    def test_github_workflows_exist(self):
        ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        rel_path = REPO_ROOT / ".github" / "workflows" / "release.yml"
        sec_path = REPO_ROOT / ".github" / "workflows" / "security-gate.yml"

        assert ci_path.exists()
        assert rel_path.exists()
        assert sec_path.exists()

        ci_content = ci_path.read_text(encoding="utf-8")
        assert "matrix:" in ci_content
        assert "3.13" in ci_content

    def test_documentation_files_exist(self):
        mcp_doc = REPO_ROOT / "docs" / "MCP_GUIDE.md"
        plat_doc = REPO_ROOT / "docs" / "PLATFORMS.md"
        csp_doc = REPO_ROOT / "docs" / "CSP_BEST_PRACTICES.md"
        root_readme = REPO_ROOT / "README.md"
        examples_readme = REPO_ROOT / "examples" / "README.md"

        for doc in [mcp_doc, plat_doc, csp_doc, root_readme, examples_readme]:
            assert doc.exists(), f"Missing {doc}"
            assert len(doc.read_text(encoding="utf-8")) > 200, f"Document {doc} is too short"
