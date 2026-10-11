#!/usr/bin/env python3
"""Web Security Guard - Command-Line Interface & Material 3 Security Studio.

Commands:
  audit     - Audit a live URL or local HTML/config file with 0-100 score & recommendations
  csp       - Interactive & automated Strict CSP Level 3 generator
  sri       - Subresource Integrity (SRI) hasher & HTML injector
  contrast  - WCAG 2.2 Color Contrast Ratio Calculator & Compliance Checker
  fix       - Multi-platform hardening configuration file generator
  check     - CI/CD Quality Gate with exit codes for Pull Requests
  mcp       - Model Context Protocol (MCP) stdio server & client config generator
  serve     - Start Web Security Studio UI (Web Deck)
  platform  - Multi-OS runtime environment inspector
  --test    - Run built-in engine verification test suite
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

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
    patch_project,
    run_mcp_server,
)

# ============================================================================
# ANSI Terminal Colors
# ============================================================================

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)

def bold(text: str) -> str: return _c(text, "1")
def cyan(text: str) -> str: return _c(text, "36")
def green(text: str) -> str: return _c(text, "32")
def yellow(text: str) -> str: return _c(text, "33")
def red(text: str) -> str: return _c(text, "31")
def magenta(text: str) -> str: return _c(text, "35")
def gray(text: str) -> str: return _c(text, "90")


def print_banner() -> None:
    """Print CLI header banner."""
    print(cyan(bold(f"🛡️  Web Security Guard v{SERVER_VERSION}")) + gray(" | Zero-Dependency SecOps & MCP Server"))
    print(gray("─" * 70))


# ============================================================================
# Internal Test Suite Runner (--test)
# ============================================================================

def run_internal_tests() -> int:
    """Run internal engine verification suite."""
    print_banner()
    print(bold("🧪 Running Web Security Guard Engine Verification Suite...\n"))
    passes = 0
    failures = 0

    def test(name: str, fn) -> None:
        nonlocal passes, failures
        try:
            fn()
            print(f"  {green('✔ PASS')} {name}")
            passes += 1
        except Exception as e:
            print(f"  {red('✖ FAIL')} {name}: {str(e)}")
            failures += 1

    # Test 1: WCAG Contrast calculation
    def test_contrast():
        res = calculate_contrast("#000000", "#ffffff")
        assert res["contrast_ratio"] == 21.0
        assert res["compliance"]["passes_target"] is True
        res_low = calculate_contrast("#777777", "#888888")
        assert res_low["compliance"]["passes_target"] is False

    test("WCAG 2.2 Contrast Calculator (Black on White / Low Contrast)", test_contrast)

    # Test 2: SRI Hash computation
    def test_sri():
        content = b"console.log('hello world');"
        res = generate_sri_hash(content, "sha384")
        assert res["algorithm"] == "sha384"
        assert res["integrity"].startswith("sha384-")
        assert len(res["digest_base64"]) > 0

    test("SRI Hash Generator (SHA-384 Base64 Encoding)", test_sri)

    # Test 3: SRI HTML Injection
    def test_sri_injection():
        html = '<html><head><script src="https://cdn.example.com/app.js"></script></head><body></body></html>'
        res = inject_sri_into_html(html, fetch_remote=False)
        assert "html" in res

    test("SRI HTML Injector Engine", test_sri_injection)

    # Test 4: CSP Generation
    def test_csp():
        res = generate_csp_policy(framework="nextjs", preset="strict", nonce="test-nonce-123")
        assert "Content-Security-Policy" in res["header_name"]
        assert "test-nonce-123" in res["csp_string"]
        assert "object-src 'none'" in res["csp_string"]

    test("Strict CSP Level 3 Policy Generator", test_csp)

    # Test 5: Local File Audit
    def test_audit():
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test</title></head>
        <body>
            <a href="https://example.com" target="_blank">Link</a>
            <form action="http://insecure.com/submit"><input type="text"></form>
        </body>
        </html>
        """
        res = audit_security(html)
        assert res["score"] < 100
        assert len(res["findings"]) >= 2
        assert "summary" in res

    test("Security Audit Scanner (Heuristics & Scoring Engine)", test_audit)

    # Test 6: Multi-Platform Hardening Configs
    def test_remediation():
        res = generate_remediation_configs("https://example.com", server_type="all")
        assert "netlify.toml" in res["files"]
        assert "nginx.conf" in res["files"]
        assert ".htaccess" in res["files"]

    test("Multi-Platform Remediation Generator (Netlify/Nginx/Apache/Vercel)", test_remediation)

    # Test 7: MCP Protocol Handlers
    def test_mcp():
        srv = MCPServer()
        init_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert init_resp["result"]["protocolVersion"] == "2024-11-05"
        tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert len(tools_resp["result"]["tools"]) == 12
        call_resp = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "sec_check_contrast",
                "arguments": {"fg_color": "#ffffff", "bg_color": "#000000"}
            }
        })
        assert call_resp["result"]["isError"] is False

    test("MCP Server JSON-RPC 2.0 Protocol Engine", test_mcp)

    # Test 8: MCP Client Configs
    def test_configs():
        cfg_claude = generate_mcp_client_config("claude")
        assert "mcpServers" in cfg_claude
        cfg_zed = generate_mcp_client_config("zed")
        assert "context_servers" in cfg_zed

    test("MCP Client Config Exporter (Claude/Cursor/Cline/Zed)", test_configs)

    # Test 9: SSL Certificate Inspector
    def test_ssl():
        res = inspect_ssl("example.com", port=443, timeout=5.0)
        assert "target" in res
        assert "domain" in res
        assert "is_valid" in res
        assert "certificate" in res

    test("TLS & SSL Certificate Deep Inspector", test_ssl)

    # Test 10: Security Posture Diff
    def test_diff():
        html_a = "<html><head><title>A</title></head><body><form action='http://a.com'></form></body></html>"
        html_b = "<html><head><title>B</title><meta http-equiv='Content-Security-Policy' content=\"default-src 'self'\"></head><body></body></html>"
        res = diff_security_postures(html_a, html_b)
        assert "score_delta" in res
        assert "fixed_findings" in res
        assert "status" in res

    test("Security Posture Diff & Comparison Engine", test_diff)

    # Test 11: Local Project Patcher
    def test_patch():
        res = patch_project(".", platform="netlify", dry_run=True)
        assert res["platform"] == "netlify"
        assert res["dry_run"] is True
        assert len(res["patched_files"]) >= 1

    test("1-Click Local Project Hardening Patcher", test_patch)

    # Test 12: Secret Leak Scanner
    def test_secrets():
        from web_security_guard.secret_scanner import scan_secrets
        k = "sk_" + "live_" + "1234567890abcdef1234567890"
        sample = f'const key = "{k}";'
        rep = scan_secrets(sample, target_name="test.js")
        assert rep.clean is False
        assert rep.total_findings >= 1
        assert rep.findings[0].detector_id == "stripe-secret-key"

    test("High-Fidelity Secret Leakage & API Key Scanner", test_secrets)

    # Test 13: Supply Chain & SRI Auditor
    def test_supply():
        from web_security_guard.supply_chain_auditor import audit_supply_chain
        html = '<html><head><script src="https://cdn.example.com/lib.js"></script></head><body><a href="https://ext.com" target="_blank">Ext</a></body></html>'
        rep = audit_supply_chain(html, target_name="test.html")
        assert rep.missing_sri_count >= 1
        assert rep.reverse_tabnabbing_count >= 1
        assert rep.supply_chain_score < 100.0

    test("Third-Party Supply Chain & Subresource Integrity Auditor", test_supply)

    print("\n" + gray("─" * 70))
    if failures == 0:
        print(green(bold(f"✨ All {passes} verification tests passed successfully!")))
        return 0
    else:
        print(red(bold(f"❌ {failures} test(s) failed out of {passes + failures}.")))
        return 1


# ============================================================================
# CLI Command Handlers
# ============================================================================

def cmd_audit(args: argparse.Namespace) -> int:
    """Audit command handler."""
    target = args.target
    if not args.json:
        print_banner()
        print(f"🔍 Auditing Target: {cyan(bold(target))}\n")

    res = audit_security(target=target, min_score=args.min_score)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res["passed_min_score"] else 1

    score = res["score"]
    grade = res["grade"]
    score_color = green if score >= 85 else (yellow if score >= 65 else red)

    print(f"Score:  {score_color(bold(str(score)))} / 100  (Grade: {score_color(bold(grade))})")
    print(f"Passed Min Score ({args.min_score}): {'✔ Yes' if res['passed_min_score'] else '✖ No'}\n")

    summary = res["summary"]
    print(bold("Findings Summary:"))
    print(f"  • Critical: {red(str(summary['critical']))}")
    print(f"  • High:     {red(str(summary['high']))}")
    print(f"  • Medium:   {yellow(str(summary['medium']))}")
    print(f"  • Low:      {cyan(str(summary['low']))}")
    print(f"  • Info:     {gray(str(summary['info']))}\n")

    if res["findings"]:
        print(bold("Detailed Findings:"))
        for idx, f in enumerate(res["findings"], 1):
            sev_color = red if f["severity"] in ("CRITICAL", "HIGH") else (yellow if f["severity"] == "MEDIUM" else cyan)
            print(f"  [{sev_color(f['severity'])}] {bold(f['title'])}")
            print(f"    Description: {f['description']}")
            print(f"    Remediation: {green(f['remediation'])}\n")
    else:
        print(green("✨ Excellent! No security weaknesses detected."))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(green(f"✔ Audit report saved to '{args.output}'"))

    return 0 if res["passed_min_score"] else 1


def cmd_csp(args: argparse.Namespace) -> int:
    """CSP generator command handler."""
    if not args.preset and not args.framework and sys.stdin.isatty() and not args.format:
        print_banner()
        print(bold("⚡ Interactive Strict CSP Generator\n"))
        print("Choose a preset:")
        print("  1) Strict CSP Level 3 (Recommended - nonces & strict-dynamic)")
        print("  2) Balanced (Strict + trusted CDNs)")
        print("  3) Permissive (HTTPS + blob + inline fallback)")
        print("  4) API Only (default-src 'none')")
        choice = input("Select [1-4, default 1]: ").strip()
        preset_map = {"1": "strict", "2": "balanced", "3": "permissive", "4": "api-only"}
        preset = preset_map.get(choice, "strict")

        framework = input("Target framework (vanilla, nextjs, react, vue, astro, express) [vanilla]: ").strip() or "vanilla"
        nonce = input("Custom nonce token (press enter to auto-generate): ").strip() or None
    else:
        preset = args.preset or "strict"
        framework = args.framework or "vanilla"
        nonce = args.nonce

    domains = [d.strip() for d in args.domains.split(",") if d.strip()] if args.domains else None

    res = generate_csp_policy(
        framework=framework,
        preset=preset,
        nonce=nonce,
        report_uri=args.report_uri,
        domains=domains,
    )

    fmt = (args.format or "header").lower()

    if fmt == "json":
        out = json.dumps(res, indent=2)
    elif fmt == "meta":
        out = res["meta_tag"]
    elif fmt == "nginx":
        out = res["nginx_snippet"]
    elif fmt == "apache":
        out = res["apache_snippet"]
    elif fmt == "netlify":
        out = res["netlify_snippet"]
    elif fmt == "express":
        out = res["express_snippet"]
    else:
        out = f"{res['header_name']}: {res['csp_string']}"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(green(f"✔ CSP saved to '{args.output}'"))
    else:
        print(out)

    return 0


def cmd_sri(args: argparse.Namespace) -> int:
    """SRI command handler."""
    target = args.file_or_url
    algo = args.algorithm or "sha384"

    if args.inject:
        res = inject_sri_into_html(
            html_content_or_path=target,
            algorithm=algo,
            fetch_remote=not args.no_fetch,
            save_to_file=bool(args.output or os.path.isfile(target)),
            output_path=args.output,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_banner()
            print(f"🔒 SRI HTML Injection Complete: {cyan(bold(target))}")
            print(f"  • Resources Injected: {green(str(res['injected_count']))}")
            if res["modified_resources"]:
                for r in res["modified_resources"]:
                    print(f"    - [{r['type']}] {r.get('src') or r.get('href')} -> {green(r['integrity'])}")
            if res.get("saved_to_file"):
                print(f"  • Saved File: {green(res['saved_to_file'])}")
            elif not args.output:
                print("\n" + res["html"])
    else:
        try:
            content, _ = fetch_or_read_content(target)
        except Exception:
            content = target.encode("utf-8")

        res = generate_sri_hash(content, algo)
        res["target"] = target

        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_banner()
            print(f"🔒 Computed Subresource Integrity ({algo}):")
            print(f"  Target:     {cyan(target)}")
            print(f"  Integrity:  {green(bold(res['integrity']))}")
            print(f"  Base64:     {res['digest_base64']}")
            print(f"  Hex:        {res['digest_hex']}")
            print("\n" + bold("Script Tag:"))
            print(f"  {res['script_tag_template'].replace('URL', target)}")
            print("\n" + bold("Style Tag:"))
            print(f"  {res['style_tag_template'].replace('URL', target)}")

    return 0


def cmd_contrast(args: argparse.Namespace) -> int:
    """Contrast command handler."""
    fg = args.fg
    bg = args.bg

    try:
        res = calculate_contrast(
            fg_color=fg,
            bg_color=bg,
            font_size_pt=args.font_size,
            is_bold=args.bold,
            target_level=args.level or "AA",
        )
    except ValueError as e:
        print(red(f"Error parsing colors: {str(e)}"), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(res, indent=2))
        return 0

    print_banner()
    print(bold("🎨 WCAG 2.2 Color Contrast Analysis\n"))
    print(f"Foreground:  {cyan(fg)}  (Hex: {res['foreground']['hex']}, Relative Lum: {res['foreground']['relative_luminance']})")
    print(f"Background:  {cyan(bg)}  (Hex: {res['background']['hex']}, Relative Lum: {res['background']['relative_luminance']})")
    print(f"Ratio:       {green(bold(res['formatted_ratio'])) if res['compliance']['passes_target'] else red(bold(res['formatted_ratio']))}\n")

    comp = res["compliance"]
    aa = comp["wcag_2_2_aa"]
    aaa = comp["wcag_2_2_aaa"]

    def _badge(p: bool) -> str:
        return green("✔ PASS") if p else red("✖ FAIL")

    print(bold("WCAG 2.2 AA Criteria (4.5:1 / 3.0:1):"))
    print(f"  • Normal Text (>= 4.5:1):      {_badge(aa['normal_text']['passed'])}")
    print(f"  • Large Text (>= 3.0:1):       {_badge(aa['large_text']['passed'])}")
    print(f"  • UI Components (>= 3.0:1):    {_badge(aa['ui_components']['passed'])}")

    print(bold("\nWCAG 2.2 AAA Criteria (7.0:1 / 4.5:1):"))
    print(f"  • Normal Text (>= 7.0:1):      {_badge(aaa['normal_text']['passed'])}")
    print(f"  • Large Text (>= 4.5:1):       {_badge(aaa['large_text']['passed'])}")

    if res["suggestions"]:
        print(bold("\nSuggestions:"))
        for s in res["suggestions"]:
            print(f"  • {yellow(s)}")

    return 0 if comp["passes_target"] else 1


def cmd_fix(args: argparse.Namespace) -> int:
    """Fix / Remediation command handler."""
    target = args.target
    out_dir = args.output_dir or "security-hardening"
    server_type = args.server_type or "all"

    res = generate_remediation_configs(
        target=target,
        server_type=server_type,
        include_headers=not args.no_headers,
        include_csp=not args.no_csp,
        include_cors=not args.no_cors,
    )

    os.makedirs(out_dir, exist_ok=True)
    created_files = []

    for fname, content in res["files"].items():
        fpath = os.path.join(out_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)
        created_files.append(fpath)

    if args.json:
        print(json.dumps({"target": target, "output_directory": out_dir, "created_files": created_files}, indent=2))
        return 0

    print_banner()
    print(f"🛠️  Security Hardening Configs Generated for: {cyan(bold(target))}\n")
    print(f"Output Directory: {green(bold(out_dir))}\n")
    print(bold("Created Files:"))
    for f in created_files:
        print(f"  • {green(f)}")

    print("\n" + bold("Instructions:"))
    print(f"  {res['instructions']}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """CI/CD Quality Gate check command handler."""
    target = args.target
    min_score = args.min_score

    res = audit_security(target=target, min_score=min_score)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        score = res["score"]
        passed = res["passed_min_score"]
        status_str = green("PASSED") if passed else red("FAILED")
        print(f"🛡️  Security Gate: {status_str} (Score: {score}/100, Required: {min_score})")

    return 0 if res["passed_min_score"] else 1


def cmd_mcp(args: argparse.Namespace) -> int:
    """MCP command handler."""
    if args.tools:
        print_banner()
        print(bold("🤖 Available Model Context Protocol (MCP) Tools:\n"))
        for t in MCP_TOOLS_DEFINITIONS:
            print(f"  • {cyan(bold(t['name']))}")
            print(f"    {t['description']}")
            props = t["inputSchema"].get("properties", {})
            reqs = t["inputSchema"].get("required", [])
            print(f"    Parameters: {', '.join([f'{k}*' if k in reqs else k for k in props.keys()])}\n")
        return 0

    if args.config:
        cfg = generate_mcp_client_config(
            client_name=args.config,
            python_path=args.python_path or "python3",
            project_root=args.project_root,
        )
        print(json.dumps(cfg, indent=2))
        return 0

    # Start stdio MCP server loop
    run_mcp_server()
    return 0


def cmd_platform(args: argparse.Namespace) -> int:
    """Platform runtime information inspection."""
    if args.json:
        data = {
            "server_name": SERVER_NAME,
            "version": SERVER_VERSION,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "os_name": os.name,
            "platform_system": platform.system(),
            "platform_release": platform.release(),
            "platform_machine": platform.machine(),
            "byte_order": sys.byteorder,
            "path_separator": os.pathsep,
            "dir_separator": os.sep,
            "openssl_version": ssl.OPENSSL_VERSION if hasattr(ssl, "OPENSSL_VERSION") else "N/A",
            "hostname": socket.gethostname(),
        }
        print(json.dumps(data, indent=2))
        return 0

    print_banner()
    print(bold("🖥️  Multi-OS Runtime Environment Diagnostics\n"))
    print(f"  • Web Security Guard:  {green(f'v{SERVER_VERSION}')}")
    print(f"  • Python Interpreter:  {cyan(platform.python_version())} ({platform.python_implementation()})")
    print(f"  • Operating System:    {cyan(platform.system())} {platform.release()} ({platform.machine()})")
    print(f"  • OS Name / Subsystem: {os.name} (DirSep: '{os.sep}', PathSep: '{os.pathsep}')")
    print(f"  • Host Machine Name:   {socket.gethostname()}")
    print(f"  • Byte Order:          {sys.byteorder}-endian")
    print(f"  • OpenSSL / TLS:       {ssl.OPENSSL_VERSION if hasattr(ssl, 'OPENSSL_VERSION') else 'Standard'}")
    print(f"  • Terminal Colors:     {'Supported' if USE_COLOR else 'Disabled / Monocrome'}")
    print(f"  • Protocol Version:    MCP 2024-11-05 (JSON-RPC 2.0 stdio)")
    return 0




def cmd_ssl(args: argparse.Namespace) -> int:
    """Inspect TLS/SSL certificate, cipher suite, SANs, and expiration."""
    target = args.target
    port = args.port or 443
    res = inspect_ssl(target=target, port=port)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res["is_valid"] else 1

    print_banner()
    print(bold(f"🔐 TLS Certificate & Cipher Suite Inspector: {cyan(res['domain'])} (Port {port})\n"))

    if not res["is_valid"]:
        print(red(f"❌ Handshake / Verification Error: {res.get('error', 'Invalid certificate')}"))
        if res.get("recommendations"):
            for r in res["recommendations"]:
                print(f"  • {yellow(r)}")
        return 1

    status_badge = green("VALID") if res["status"] == "VALID" else (yellow("EXPIRING SOON") if res["status"] == "EXPIRING_SOON" else red("EXPIRED"))
    print(f"Status:             {status_badge}")
    print(f"TLS Protocol:       {green(res['tls_version'])} ({'TLS 1.3 Supported ✔' if res['tls_1_3_supported'] else 'TLS 1.2'})")
    print(f"ALPN Protocol:      {cyan(res.get('alpn_protocol', 'N/A'))}")

    cipher = res["cipher_suite"]
    print(f"Cipher Suite:       {cyan(bold(cipher['name']))} ({cipher['bits']} bits)")

    cert = res["certificate"]
    print(f"Subject CN:         {cert.get('common_name', 'N/A')}")
    print(f"Issuer:             {cert.get('issuer_name', 'N/A')}")
    print(f"Valid From:         {cert.get('not_before', 'N/A')}")
    print(f"Valid Until:        {cert.get('not_after', 'N/A')}")

    days = cert.get("days_until_expiration", 0)
    days_color = green if days > 30 else (yellow if days >= 0 else red)
    print(f"Days to Expiry:     {days_color(bold(str(days)))} days\n")

    sans = cert.get("sans", [])
    print(bold(f"Subject Alternative Names (SANs - {len(sans)} entries):"))
    if sans:
        for s in sans[:10]:
            print(f"  • {cyan(s)}")
        if len(sans) > 10:
            print(f"  ... and {len(sans) - 10} more.")
    else:
        print("  (None)")

    if res.get("recommendations"):
        print(bold("\nRecommendations:"))
        for r in res["recommendations"]:
            print(f"  • {yellow(r)}")

    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Side-by-side security posture comparison diff."""
    target_a = args.target_a
    target_b = args.target_b
    res = diff_security_postures(target_a, target_b)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0

    print_banner()
    print(bold("⚖️  Security Posture Side-by-Side Diff\n"))

    score_a = res["score_a"]
    score_b = res["score_b"]
    delta = res["score_delta"]

    col_a = green if score_a >= 85 else (yellow if score_a >= 65 else red)
    col_b = green if score_b >= 85 else (yellow if score_b >= 65 else red)
    delta_color = green if delta > 0 else (red if delta < 0 else gray)
    delta_str = f"+{delta}" if delta > 0 else str(delta)

    print(f"Target A (Baseline): {cyan(target_a)}")
    print(f"  Score:  {col_a(bold(str(score_a)))}/100 (Grade {col_a(res['grade_a'])})")
    print(f"Target B (Hardened): {cyan(target_b)}")
    print(f"  Score:  {col_b(bold(str(score_b)))}/100 (Grade {col_b(res['grade_b'])})")
    print(f"Score Delta:         {delta_color(bold(delta_str))} pts ({delta_color(res['status'])})\n")

    if res["fixed_findings"]:
        print(green(bold(f"✔ Fixed Vulnerabilities ({res['fixed_count']}):")))
        for f in res["fixed_findings"]:
            print(f"  [{green('FIXED')}] {f['title']} (-{f.get('deduction', 0)} pts)")
        print()

    if res["new_findings"]:
        print(red(bold(f"✖ New / Regressed Vulnerabilities ({res['new_count']}):")))
        for f in res["new_findings"]:
            print(f"  [{red('NEW')}] {f['title']}")
        print()

    if res["common_findings"]:
        print(yellow(bold(f"⚠️  Retained Common Findings ({res['common_count']}):")))
        for f in res["common_findings"]:
            print(f"  [{yellow('RETAINED')}] {f['title']}")
        print()

    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    """Auto-patch local repository with hardened headers."""
    project_dir = args.project_dir
    platform_choice = args.platform or "auto"
    dry_run = getattr(args, "dry_run", False)

    res = patch_project(project_dir=project_dir, platform=platform_choice, dry_run=dry_run)

    if args.json:
        print(json.dumps(res, indent=2))
        return 0

    print_banner()
    mode_str = yellow(" [DRY RUN - Simulation Only]") if dry_run else green(" [APPLIED]")
    print(f"⚡ Security Hardening Repository Patcher{mode_str}\n")
    print(f"Project Root:       {cyan(bold(res['project_dir']))}")
    print(f"Target Platform:    {green(bold(res['platform']))}")
    print(f"Files Modified:     {green(str(res['file_count']))}\n")

    print(bold("Patched Configuration Files:"))
    for f in res["patched_files"]:
        action_color = green if f["action"] == "created" else yellow
        print(f"  • [{action_color(f['action'].upper())}] {cyan(f['path'])}")

    print("\n" + green("✔ Security headers and CSP Level 3 policy successfully patched!"))
    return 0


def cmd_isolation(args: argparse.Namespace) -> int:
    """Audit Cross-Origin Isolation (COOP, COEP, CORP) & XS-Leaks risks."""
    from web_security_guard.isolation_guard import audit_cross_origin_isolation

    target = args.target
    headers = None
    html_content = None

    if target:
        from web_security_guard.mcp_server import fetch_or_read_content
        try:
            raw_content, resp_headers = fetch_or_read_content(target)
            headers = resp_headers
            if raw_content:
                html_content = raw_content.decode("utf-8", errors="replace")
        except Exception as e:
            if not args.json:
                print(yellow(f"Warning: Could not fetch '{target}': {e}. Auditing empty baseline."))

    report = audit_cross_origin_isolation(headers=headers, html_content=html_content)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.is_cross_origin_isolated else 1

    print_banner()
    iso_status = green("ENABLED ✔") if report.is_cross_origin_isolated else red("DISABLED ✖")
    print(bold(f"🌐 W3C Cross-Origin Isolation Audit: {iso_status}\n"))
    print(f"Target:                      {cyan(target or 'Baseline Headers')}")
    print(f"COOP (Opener Policy):        {cyan(report.coop_status)}")
    print(f"COEP (Embedder Policy):      {cyan(report.coep_status)}")
    print(f"CORP (Resource Policy):      {cyan(report.corp_status)}")
    print(f"SharedArrayBuffer:           {green('Unlocked ✔') if report.shared_array_buffer_unlocked else red('Locked ✖')}")
    print(f"High-Resolution Timers:      {green('Unlocked ✔') if report.high_res_timers_unlocked else red('Throttled ✖')}")
    print(f"Spectre Risk Score:          {yellow(str(report.spectre_vulnerability_score))}/100")
    print(f"Subresource Breakage Risk:   {cyan(report.subresource_breakage_risk)}\n")

    if report.risks:
        print(bold(f"Identified Risks ({len(report.risks)}):"))
        for r in report.risks:
            sev_color = red if r.severity in ["CRITICAL", "HIGH"] else yellow
            print(f"  [{sev_color(r.severity)}] {bold(r.title)} - {r.attack_vector}")
            print(f"    {r.description}")
            print(f"    Remediation: {green(r.remediation)}\n")

    if getattr(args, "coi_worker", False):
        print(bold("Client-Side Coi ServiceWorker Polyfill (sw.js):"))
        print(gray(report.coi_serviceworker_code))

    return 0 if report.is_cross_origin_isolated else 1


def cmd_secrets(args: argparse.Namespace) -> int:
    """Audit target file, URL, or string for exposed API keys, credentials, and secrets."""
    from web_security_guard.secret_scanner import scan_secrets
    from web_security_guard.mcp_server import fetch_or_read_content

    target = getattr(args, "target", None)
    content = getattr(args, "content", None)
    min_entropy = float(getattr(args, "entropy", 2.5))

    if target:
        try:
            raw_content, _ = fetch_or_read_content(target)
            if raw_content:
                content = raw_content.decode("utf-8", errors="replace")
        except Exception as e:
            if not args.json:
                print(red(f"Error reading target '{target}': {e}"))
            else:
                print(json.dumps({"error": str(e)}, indent=2))
            return 1
    elif not content:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            print(red("Error: Must specify a target file/URL or pipe content."))
            return 1

    report = scan_secrets(content or "", target_name=target or "<input>", min_entropy=min_entropy)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.clean else 1

    if getattr(args, "markdown", False):
        print(report.format_markdown())
        return 0 if report.clean else 1

    print_banner()
    status_str = green("CLEAN ✔") if report.clean else red("SECRETS DETECTED ✖")
    print(bold(f"🔑 Secret Leakage & API Key Audit: {status_str}\n"))
    print(f"Target:                      {cyan(target or '<input>')}")
    print(f"Risk Score:                  {yellow(f'{report.risk_score:.1f}')}/100")
    print(f"Total Findings:              {len(report.findings)}")
    print(f"Severity Breakdown:          Critical: {report.findings_by_severity.get('CRITICAL', 0)}, High: {report.findings_by_severity.get('HIGH', 0)}, Medium: {report.findings_by_severity.get('MEDIUM', 0)}, Low: {report.findings_by_severity.get('LOW', 0)}\n")

    if report.findings:
        print(bold(f"Detected Credentials ({len(report.findings)}):"))
        for f in report.findings:
            sev_color = red if f.severity in ["CRITICAL", "HIGH"] else yellow
            print(f"  [{sev_color(f.severity)}] {bold(f.title)} ({f.detector_id})")
            print(f"    Line {f.line_number}, Col {f.col_offset} | Masked: {f.masked_secret} ({f.entropy:.2f} bits entropy)")
            print(f"    Snippet: {gray(f.snippet)}")
            print(f"    Remediation: {green(f.remediation)}\n")
    else:
        print(green("  ✓ No exposed credentials or high-entropy tokens detected.\n"))

    return 0 if report.clean else 1


def cmd_supply(args: argparse.Namespace) -> int:
    """Audit target HTML or URL for third-party supply chain & SRI risks."""
    from web_security_guard.supply_chain_auditor import audit_supply_chain
    from web_security_guard.mcp_server import fetch_or_read_content

    target = getattr(args, "target", None)
    html_content = None
    page_is_https = True

    if target:
        try:
            raw_content, _ = fetch_or_read_content(target)
            if raw_content:
                html_content = raw_content.decode("utf-8", errors="replace")
            if target.startswith("http://"):
                page_is_https = False
        except Exception as e:
            if not args.json:
                print(red(f"Error reading target '{target}': {e}"))
            else:
                print(json.dumps({"error": str(e)}, indent=2))
            return 1
    else:
        if not sys.stdin.isatty():
            html_content = sys.stdin.read()
        else:
            print(red("Error: Must specify a target HTML file/URL or pipe HTML content."))
            return 1

    report = audit_supply_chain(html_content or "", target_name=target or "<input>", page_is_https=page_is_https)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.supply_chain_score >= 80.0 else 1

    if getattr(args, "markdown", False):
        print(report.format_markdown())
        return 0 if report.supply_chain_score >= 80.0 else 1

    print_banner()
    grade_color = green if report.grade in ["A+", "A"] else (yellow if report.grade in ["B", "C"] else red)
    print(bold(f"📦 Supply Chain & Subresource Integrity Audit: {grade_color(f'Grade {report.grade}')}\n"))
    print(f"Target:                      {cyan(target or '<input>')}")
    print(f"Supply Chain Score:          {grade_color(f'{report.supply_chain_score:.1f}')}/100")
    print(f"Total Resources Scanned:     {report.total_resources_scanned} ({report.scripts_count} scripts, {report.stylesheets_count} CSS, {report.iframes_count} iframes, {report.forms_count} forms)")
    print(f"Missing SRI:                 {yellow(str(report.missing_sri_count))}")
    print(f"Mixed Content (RFC 6797):    {red(str(report.mixed_content_count)) if report.mixed_content_count else green('0')}")
    print(f"Reverse Tabnabbing:          {yellow(str(report.reverse_tabnabbing_count))}\n")

    if report.risks:
        print(bold(f"Supply Chain Vulnerabilities ({len(report.risks)}):"))
        for r in report.risks:
            sev_color = red if r.severity in ["CRITICAL", "HIGH"] else yellow
            print(f"  [{sev_color(r.severity)}] {bold(r.title)} ({r.category})")
            print(f"    Line {r.line_number} | URL: {cyan(r.resource_url)}")
            print(f"    Impact: {r.description}")
            print(f"    Fix: {green(r.remediation)}")
            if r.fixed_snippet:
                print(f"    Suggested Snippet: {gray(r.fixed_snippet)}")
            print("")
    else:
        print(green("  ✓ All external resources have cryptographic integrity pinning & secure transport.\n"))

    return 0 if report.supply_chain_score >= 80.0 else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Start Material 3 Security Studio HTTP server."""
    port = args.port or 8085
    host = args.host or "0.0.0.0"

    from web_security_guard.ui_server import start_ui_server
    start_ui_server(host=host, port=port)
    return 0



# ============================================================================
# Argument Parser & CLI Entrypoint
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="sec-guard",
        description="🛡️ Web Security Guard - Zero-Dependency Web Security Auditing, CSP Generator & MCP Server",
    )
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {SERVER_VERSION}")
    parser.add_argument("--test", action="store_true", help="Run internal engine verification test suite")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: audit
    p_audit = subparsers.add_parser("audit", help="Audit live URL or local HTML/config file")
    p_audit.add_argument("target", help="URL or local path to audit")
    p_audit.add_argument("--min-score", type=int, default=0, help="Minimum score threshold (0-100)")
    p_audit.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_audit.add_argument("--output", "-o", help="Save audit result to JSON file")

    # Subcommand: csp
    p_csp = subparsers.add_parser("csp", help="Generate strict Content Security Policy Level 3")
    p_csp.add_argument("--preset", "-p", choices=["strict", "balanced", "permissive", "report-only", "api-only"], help="CSP preset level")
    p_csp.add_argument("--framework", "-f", help="Target framework (vanilla, nextjs, react, vue, astro, express, django, fastapi)")
    p_csp.add_argument("--nonce", "-n", help="Custom nonce token")
    p_csp.add_argument("--report-uri", help="Reporting endpoint URL")
    p_csp.add_argument("--domains", "-d", help="Comma-separated allowed domains")
    p_csp.add_argument("--format", choices=["header", "meta", "nginx", "apache", "netlify", "express", "json"], help="Output format")
    p_csp.add_argument("--output", "-o", help="Save CSP to file")

    # Subcommand: sri
    p_sri = subparsers.add_parser("sri", help="Compute SRI hash or inject SRI into HTML")
    p_sri.add_argument("file_or_url", help="Script/Style URL, local file path, or HTML file")
    p_sri.add_argument("--algorithm", "-a", choices=["sha256", "sha384", "sha512"], default="sha384", help="Hash algorithm")
    p_sri.add_argument("--inject", action="store_true", help="Inject SRI attributes into HTML tags")
    p_sri.add_argument("--no-fetch", action="store_true", help="Do not fetch remote CDN resources")
    p_sri.add_argument("--output", "-o", help="Save output to file")
    p_sri.add_argument("--json", action="store_true", help="Output JSON format")

    # Subcommand: contrast
    p_contrast = subparsers.add_parser("contrast", help="Evaluate WCAG 2.2 Color Contrast Ratio")
    p_contrast.add_argument("fg", help="Foreground text color (Hex, RGB, or named color)")
    p_contrast.add_argument("bg", help="Background color (Hex, RGB, or named color)")
    p_contrast.add_argument("--font-size", type=float, default=16.0, help="Font size in points (default: 16.0)")
    p_contrast.add_argument("--bold", action="store_true", help="Bold font weight (>= 700)")
    p_contrast.add_argument("--level", choices=["AA", "AAA"], default="AA", help="Target WCAG level")
    p_contrast.add_argument("--json", action="store_true", help="Output JSON format")

    # Subcommand: fix
    p_fix = subparsers.add_parser("fix", help="Generate multi-platform security hardening configs")
    p_fix.add_argument("target", help="URL or project name/path")
    p_fix.add_argument("--output-dir", "-o", default="security-hardening", help="Destination folder for configs")
    p_fix.add_argument("--server-type", choices=["all", "netlify", "nginx", "apache", "vercel", "caddy", "express"], default="all")
    p_fix.add_argument("--no-headers", action="store_true", help="Omit security headers")
    p_fix.add_argument("--no-csp", action="store_true", help="Omit CSP policy")
    p_fix.add_argument("--no-cors", action="store_true", help="Omit CORS configuration")
    p_fix.add_argument("--json", action="store_true", help="Output JSON format")

    # Subcommand: check
    p_check = subparsers.add_parser("check", help="CI/CD Quality Gate check for PRs")
    p_check.add_argument("target", help="URL or file to evaluate")
    p_check.add_argument("--min-score", type=int, default=85, help="Minimum score required to pass gate (default: 85)")
    p_check.add_argument("--json", action="store_true", help="Output JSON format")

    # Subcommand: ssl
    p_ssl = subparsers.add_parser("ssl", help="Inspect TLS version, certificate SANs, expiration days, and cipher suite")
    p_ssl.add_argument("target", help="Domain name or URL to inspect")
    p_ssl.add_argument("--port", type=int, default=443, help="SSL/TLS port (default: 443)")
    p_ssl.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: diff
    p_diff = subparsers.add_parser("diff", help="Side-by-side security posture comparison diff")
    p_diff.add_argument("target_a", help="First target (URL, file, or HTML)")
    p_diff.add_argument("target_b", help="Second target (URL, file, or HTML)")
    p_diff.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: patch
    p_patch = subparsers.add_parser("patch", help="Auto-patch local repository with hardened headers")
    p_patch.add_argument("project_dir", help="Local directory path to patch")
    p_patch.add_argument("--platform", choices=["auto", "netlify", "vercel", "nextjs", "nginx", "html"], default="auto", help="Target platform (default: auto)")
    p_patch.add_argument("--dry-run", action="store_true", help="Simulate without writing files")
    p_patch.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: mcp
    p_mcp = subparsers.add_parser("mcp", help="Model Context Protocol (MCP) server & client config exporter")
    p_mcp.add_argument("--tools", action="store_true", help="List all registered MCP tools")
    p_mcp.add_argument("--config", "-c", choices=["claude", "cursor", "cline", "zed", "generic"], help="Export client configuration JSON")
    p_mcp.add_argument("--python-path", default="python3", help="Python executable path for client configs")
    p_mcp.add_argument("--project-root", help="Custom project root directory for client configs")

    # Subcommand: isolation
    p_iso = subparsers.add_parser("isolation", help="Audit Cross-Origin Isolation (COOP, COEP, CORP) & XS-Leaks risks")
    p_iso.add_argument("target", nargs="?", default=None, help="Target URL, HTML file, or config file to audit")
    p_iso.add_argument("--coi-worker", action="store_true", help="Print client-side Coi ServiceWorker polyfill code")
    p_iso.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: secrets
    p_secrets = subparsers.add_parser("secrets", help="Scan HTML, JS, or code for leaked API keys, tokens, and credentials")
    p_secrets.add_argument("target", nargs="?", default=None, help="Target file or URL to scan")
    p_secrets.add_argument("--content", help="Direct string content to scan")
    p_secrets.add_argument("--entropy", type=float, default=2.5, help="Minimum Shannon entropy threshold (default: 2.5)")
    p_secrets.add_argument("--markdown", action="store_true", help="Output GitHub-flavored markdown report")
    p_secrets.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: supply
    p_supply = subparsers.add_parser("supply", help="Audit third-party scripts, missing SRI, and mixed content")
    p_supply.add_argument("target", nargs="?", default=None, help="Target HTML file or URL to audit")
    p_supply.add_argument("--markdown", action="store_true", help="Output GitHub-flavored markdown report")
    p_supply.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Subcommand: serve
    p_serve = subparsers.add_parser("serve", help="Start Web Security Studio UI (design influenced by Material 3)")
    p_serve.add_argument("--port", "-p", type=int, default=8085, help="Server port (default: 8085)")
    p_serve.add_argument("--host", default="0.0.0.0", help="Server host interface (default: 0.0.0.0)")

    # Subcommand: platform
    p_plat = subparsers.add_parser("platform", help="Inspect multi-OS runtime environment")
    p_plat.add_argument("--json", action="store_true", help="Output JSON format")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI execution router."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.test:
        return run_internal_tests()

    if not args.command:
        parser.print_help()
        return 0

    dispatch_table = {
        "audit": cmd_audit,
        "csp": cmd_csp,
        "sri": cmd_sri,
        "contrast": cmd_contrast,
        "fix": cmd_fix,
        "check": cmd_check,
        "ssl": cmd_ssl,
        "diff": cmd_diff,
        "patch": cmd_patch,
        "isolation": cmd_isolation,
        "secrets": cmd_secrets,
        "supply": cmd_supply,
        "mcp": cmd_mcp,
        "serve": cmd_serve,
        "platform": cmd_platform,
    }

    handler = dispatch_table.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
