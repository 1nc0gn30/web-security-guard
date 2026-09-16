"""Unit tests for web_security_guard.csp module."""

from __future__ import annotations

import json
import pytest

from web_security_guard.csp import CSPBuilder, _format_source


def test_format_source() -> None:
    # Standard keywords auto-quote
    assert _format_source("self") == "'self'"
    assert _format_source("none") == "'none'"
    assert _format_source("strict-dynamic") == "'strict-dynamic'"
    assert _format_source("unsafe-inline") == "'unsafe-inline'"
    assert _format_source("unsafe-eval") == "'unsafe-eval'"
    assert _format_source("script") == "'script'"

    # Already quoted
    assert _format_source("'self'") == "'self'"
    assert _format_source('"none"') == '"none"'

    # Nonces and hashes
    assert _format_source("nonce-abc123XYZ") == "'nonce-abc123XYZ'"
    assert _format_source("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=") == "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"

    # Schemes and hostnames (unquoted)
    assert _format_source("https:") == "https:"
    assert _format_source("data:") == "data:"
    assert _format_source("blob:") == "blob:"
    assert _format_source("https://cdn.example.com") == "https://cdn.example.com"
    assert _format_source("*.example.com") == "*.example.com"
    assert _format_source("") == ""


def test_csp_builder_init_and_build() -> None:
    builder = CSPBuilder(
        default_src=["'self'"],
        script_src=["'self'", "https://cdn.example.com"],
        script_src_elem=["'self'"],
        script_src_attr=["'none'"],
        style_src=["'self'", "'unsafe-inline'"],
        style_src_elem=["'self'"],
        style_src_attr=["'unsafe-inline'"],
        img_src=["'self'", "data:", "https:"],
        font_src=["'self'", "https://fonts.gstatic.com"],
        connect_src=["'self'", "https://api.example.com"],
        media_src=["'self'"],
        object_src=["'none'"],
        frame_src=["'self'"],
        frame_ancestors=["'none'"],
        form_action=["'self'"],
        base_uri=["'none'"],
        worker_src=["'self'", "blob:"],
        child_src=["'self'", "blob:"],
        manifest_src=["'self'"],
        report_uri="https://api.example.com/csp-report",
        report_to="csp-endpoint",
        upgrade_insecure_requests=True,
        block_all_mixed_content=True,
        require_trusted_types_for="script",
        trusted_types=["default", "my-policy"],
        sandbox=["allow-scripts", "allow-same-origin"],
    )

    policy = builder.build()
    assert "default-src 'self'" in policy
    assert "script-src 'self' https://cdn.example.com" in policy
    assert "script-src-elem 'self'" in policy
    assert "script-src-attr 'none'" in policy
    assert "style-src 'self' 'unsafe-inline'" in policy
    assert "style-src-elem 'self'" in policy
    assert "style-src-attr 'unsafe-inline'" in policy
    assert "object-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "child-src 'self' blob:" in policy
    assert "upgrade-insecure-requests" in policy
    assert "block-all-mixed-content" in policy
    assert "require-trusted-types-for 'script'" in policy
    assert "trusted-types default my-policy" in policy
    assert "sandbox allow-scripts allow-same-origin" in policy
    assert "report-uri https://api.example.com/csp-report" in policy
    assert "report-to csp-endpoint" in policy


def test_csp_builder_extra_directives_kwargs() -> None:
    builder = CSPBuilder(
        prefetch_src=["'self'"],
        fenced_frame_src=["https://trusted.com"],
        custom_flag=True,
    )
    policy = builder.build()
    assert "prefetch-src 'self'" in policy
    assert "fenced-frame-src https://trusted.com" in policy
    assert "custom-flag" in policy


def test_csp_builder_directive_manipulation() -> None:
    builder = CSPBuilder()
    assert not builder.has_directive("script-src")

    # Add directive
    builder.add_directive("script-src", "self", "https://cdn.example.com")
    assert builder.has_directive("script-src")
    assert builder.get_directive("script-src") == ["'self'", "https://cdn.example.com"]

    # Append without duplicate
    builder.add_directive("script-src", "https://cdn.example.com", "https://api.example.com")
    assert builder.get_directive("script-src") == ["'self'", "https://cdn.example.com", "https://api.example.com"]

    # Set directive (replace)
    builder.set_directive("script-src", ["'self'", "'strict-dynamic'"])
    assert builder.get_directive("script-src") == ["'self'", "'strict-dynamic'"]

    # Remove directive
    builder.remove_directive("script-src")
    assert not builder.has_directive("script-src")
    assert builder.get_directive("script-src") == []


def test_csp_builder_copy() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    clone = builder.copy()
    clone.add_directive("script-src", "https://cdn.example.com")

    assert not builder.has_directive("script-src")
    assert clone.has_directive("script-src")


def test_csp_builder_nonces() -> None:
    builder = CSPBuilder(script_src=["'self'"], style_src=["'self'"])
    nonce = builder.add_nonce()

    assert len(nonce) > 10
    assert builder.last_nonce == nonce
    assert f"'nonce-{nonce}'" in builder.get_directive("script-src")
    assert f"'nonce-{nonce}'" in builder.get_directive("style-src")

    # Specific custom nonce
    custom_nonce = "MyStaticNonce123"
    builder.add_nonce(custom_nonce, target_directives=("script-src",))
    assert f"'nonce-{custom_nonce}'" in builder.get_directive("script-src")


def test_csp_builder_script_and_style_hashes() -> None:
    builder = CSPBuilder()
    inline_script = "console.log('Hello, world!');"
    hash_token = builder.add_script_hash(inline_script, algorithm="sha256")

    assert hash_token.startswith("'sha256-")
    assert hash_token.endswith("'")
    assert hash_token in builder.get_directive("script-src")

    inline_style = "body { background: #000; }"
    style_hash = builder.add_style_hash(inline_style, algorithm="sha384")
    assert style_hash.startswith("'sha384-")
    assert style_hash in builder.get_directive("style-src")

    style_hash512 = builder.add_style_hash(inline_style.encode("utf-8"), algorithm="sha512")
    assert style_hash512.startswith("'sha512-")
    assert style_hash512 in builder.get_directive("style-src")

    # Unsupported algorithm error
    with pytest.raises(ValueError, match="Unsupported CSP hash algorithm"):
        builder.add_script_hash("alert(1)", algorithm="md5")


def test_enable_strict_csp() -> None:
    builder = CSPBuilder()
    builder.enable_strict_csp(nonce="testNonce123")

    script_src = builder.get_directive("script-src")
    assert "'nonce-testNonce123'" in script_src
    assert "'strict-dynamic'" in script_src
    assert "'unsafe-inline'" in script_src
    assert "https:" in script_src
    assert "http:" in script_src

    assert builder.get_directive("object-src") == ["'none'"]
    assert builder.get_directive("base-uri") == ["'none'"]


def test_to_header() -> None:
    builder = CSPBuilder(default_src=["'self'"])

    # Raw value
    assert builder.to_header() == "default-src 'self'"
    # With header name
    assert builder.to_header(include_header_name=True) == "Content-Security-Policy: default-src 'self'"
    # Report-Only mode
    assert builder.to_header(report_only=True, include_header_name=True) == "Content-Security-Policy-Report-Only: default-src 'self'"


def test_to_meta_tag() -> None:
    builder = CSPBuilder(default_src=["'self'"], script_src=["'self'"])
    meta = builder.to_meta_tag()
    assert meta.startswith('<meta http-equiv="Content-Security-Policy" content="')
    assert "default-src 'self'" in meta
    assert meta.endswith('">')


def test_to_nginx_directive() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    nginx = builder.to_nginx_directive()
    assert nginx == 'add_header Content-Security-Policy "default-src \'self\'" always;'

    nginx_custom = builder.to_nginx_directive(header_name="X-Custom-CSP", always=False)
    assert nginx_custom == 'add_header X-Custom-CSP "default-src \'self\'";'


def test_to_apache_directive() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    apache = builder.to_apache_directive()
    assert "<IfModule mod_headers.c>" in apache
    assert 'Header set Content-Security-Policy "default-src \'self\'"' in apache
    assert "</IfModule>" in apache


def test_to_cloudflare_workers() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    builder.enable_strict_csp(nonce="placeholderNonce")
    cf = builder.to_cloudflare_workers(nonce_var="customNonce")

    assert "export default {" in cf
    assert "const customNonce = btoa(" in cf
    assert "crypto.getRandomValues(new Uint8Array(16))" in cf
    assert "nonce-${customNonce}" in cf
    assert 'newHeaders.set("Content-Security-Policy", cspHeader);' in cf
    assert 'newHeaders.set("x-nonce", customNonce);' in cf


def test_to_netlify_headers() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    netlify = builder.to_netlify_headers("/admin/*")
    assert netlify.startswith("/admin/*\n")
    assert "Content-Security-Policy: default-src 'self'" in netlify
    assert "X-Content-Type-Options: nosniff" in netlify


def test_to_vercel_json() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    v_dict = builder.to_vercel_json()
    assert "headers" in v_dict
    assert v_dict["headers"][0]["source"] == "/(.*)"
    csp_entry = next(h for h in v_dict["headers"][0]["headers"] if h["key"] == "Content-Security-Policy")
    assert csp_entry["value"] == "default-src 'self'"

    v_str = builder.to_vercel_json_str()
    parsed = json.loads(v_str)
    assert parsed == v_dict


def test_to_nextjs_middleware() -> None:
    builder = CSPBuilder(default_src=["'self'"])
    builder.enable_strict_csp(nonce="myNonceXYZ")
    nextjs = builder.to_nextjs_middleware()

    assert "import { NextRequest, NextResponse } from 'next/server';" in nextjs
    assert "export function middleware(request: NextRequest)" in nextjs
    assert "const nonce = Buffer.from(crypto.randomUUID()).toString('base64');" in nextjs
    assert "nonce-${nonce}" in nextjs
    assert "requestHeaders.set('x-nonce', nonce);" in nextjs
    assert "response.headers.set('Content-Security-Policy', cspHeader);" in nextjs
    assert "export const config = {" in nextjs
    assert "matcher:" in nextjs
