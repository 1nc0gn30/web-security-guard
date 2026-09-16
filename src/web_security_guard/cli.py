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
  serve     - Start Google Material 3 Security Studio UI (Web Deck)
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
    generate_csp_policy,
    generate_mcp_client_config,
    generate_remediation_configs,
    generate_sri_hash,
    inject_sri_into_html,
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
        assert len(tools_resp["result"]["tools"]) == 6
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


# ============================================================================
# Material 3 Security Studio Web UI & Server
# ============================================================================

STUDIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web Security Guard | Material 3 Security Studio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --surface-dark: #0f172a;
      --surface-card: #1e293b;
      --surface-hover: #334155;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --secondary: #818cf8;
      --accent: #34d399;
      --danger: #f87171;
      --warning: #fbbf24;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --radius: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: 'Inter', system-ui, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 700;
      font-size: 1.25rem;
      color: var(--text-main);
    }
    .badge {
      background: rgba(56, 189, 248, 0.15);
      color: var(--primary);
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 0.2rem 0.6rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    nav {
      display: flex;
      gap: 0.5rem;
      background: rgba(30, 41, 59, 0.7);
      padding: 0.35rem;
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    nav button {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.5rem 1rem;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.875rem;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    nav button.active, nav button:hover {
      background: var(--primary);
      color: #0f172a;
    }
    main {
      flex: 1;
      max-width: 1200px;
      width: 100%;
      margin: 2rem auto;
      padding: 0 1.5rem;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
    
    .card {
      background: var(--surface-dark);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.75rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
    }
    .card-title {
      font-size: 1.25rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--primary);
    }
    .form-group {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }
    input[type="text"], input[type="number"], select, textarea {
      width: 100%;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      color: var(--text-main);
      font-family: inherit;
      font-size: 0.95rem;
      transition: border 0.2s ease;
    }
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: var(--primary);
    }
    textarea { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
    
    .btn {
      background: var(--primary);
      color: #0f172a;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      font-weight: 700;
      cursor: pointer;
      font-size: 0.95rem;
      transition: background 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    .btn:hover { background: var(--primary-hover); }
    
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
    
    .score-dial {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      background: var(--surface-card);
      border-radius: var(--radius);
      border: 1px solid var(--border);
    }
    .score-number { font-size: 3.5rem; font-weight: 800; }
    .score-grade { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
    
    .finding-item {
      background: var(--surface-card);
      border-left: 4px solid var(--primary);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 0.75rem;
    }
    .finding-item.CRITICAL, .finding-item.HIGH { border-left-color: var(--danger); }
    .finding-item.MEDIUM { border-left-color: var(--warning); }
    .finding-item.LOW { border-left-color: var(--primary); }
    
    pre {
      background: #060911;
      padding: 1rem;
      border-radius: 8px;
      overflow-x: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      color: #38bdf8;
      border: 1px solid #1e293b;
    }
    
    .color-swatch {
      height: 80px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      border: 1px solid var(--border);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      🛡️ Web Security Guard
      <span class="badge">Material 3 Studio</span>
      <span class="badge">Zero-Dep</span>
    </div>
    <nav>
      <button class="active" onclick="showTab('audit')">🛡️ Audit</button>
      <button onclick="showTab('csp')">⚡ CSP Gen</button>
      <button onclick="showTab('sri')">🔒 SRI Hasher</button>
      <button onclick="showTab('contrast')">🎨 WCAG Contrast</button>
      <button onclick="showTab('remediation')">🛠️ Hardening</button>
      <button onclick="showTab('mcp')">🤖 MCP Inspector</button>
    </nav>
  </header>

  <main>
    <!-- TAB 1: AUDIT -->
    <div id="tab-audit" class="tab-content active">
      <div class="card">
        <div class="card-title">🛡️ Web Security Auditor</div>
        <div class="form-group">
          <label>Target URL or Local File Path</label>
          <input type="text" id="audit-target" placeholder="https://example.com or /path/to/index.html" value="https://example.com">
        </div>
        <button class="btn" onclick="runAudit()">🚀 Run Live Security Audit</button>
      </div>

      <div id="audit-results" style="display:none;">
        <div class="grid-2">
          <div class="score-dial">
            <div id="audit-score" class="score-number">100</div>
            <div id="audit-grade" class="score-grade">Grade A+</div>
            <div style="margin-top:0.5rem; color:var(--text-muted);">Security Posture Score</div>
          </div>
          <div class="card" style="margin-bottom:0;">
            <div class="card-title" style="font-size:1rem;">Summary Breakdown</div>
            <div id="audit-summary-text" style="line-height:1.8;"></div>
          </div>
        </div>
        <div class="card" style="margin-top:1.5rem;">
          <div class="card-title">Detailed Vulnerability Findings</div>
          <div id="audit-findings-list"></div>
        </div>
      </div>
    </div>

    <!-- TAB 2: CSP GENERATOR -->
    <div id="tab-csp" class="tab-content">
      <div class="card">
        <div class="card-title">⚡ Strict CSP Level 3 Generator</div>
        <div class="grid-2">
          <div class="form-group">
            <label>Framework</label>
            <select id="csp-framework">
              <option value="vanilla">Vanilla HTML / JS</option>
              <option value="nextjs">Next.js (Vercel)</option>
              <option value="react">React / Vite SPA</option>
              <option value="vue">Vue.js / Nuxt</option>
              <option value="astro">Astro</option>
              <option value="express">Express.js (Helmet)</option>
              <option value="django">Django</option>
              <option value="fastapi">FastAPI</option>
            </select>
          </div>
          <div class="form-group">
            <label>Preset</label>
            <select id="csp-preset">
              <option value="strict">Strict Level 3 (Recommended)</option>
              <option value="balanced">Balanced (CDNs + Nonces)</option>
              <option value="permissive">Permissive (Broad Fallback)</option>
              <option value="api-only">API Only (default-src 'none')</option>
            </select>
          </div>
        </div>
        <button class="btn" onclick="generateCSP()">⚡ Generate Strict CSP Policy</button>
      </div>
      <div id="csp-results" class="card" style="display:none;">
        <div class="card-title">Generated CSP Configuration</div>
        <pre id="csp-output"></pre>
      </div>
    </div>

    <!-- TAB 3: SRI HASHER -->
    <div id="tab-sri" class="tab-content">
      <div class="card">
        <div class="card-title">🔒 Subresource Integrity (SRI) Hasher</div>
        <div class="form-group">
          <label>Resource URL or Source Code</label>
          <input type="text" id="sri-target" placeholder="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        </div>
        <div class="form-group">
          <label>Hash Algorithm</label>
          <select id="sri-algo">
            <option value="sha384">SHA-384 (W3C Recommended)</option>
            <option value="sha512">SHA-512 (High Security)</option>
            <option value="sha256">SHA-256</option>
          </select>
        </div>
        <button class="btn" onclick="generateSRI()">🔒 Calculate SRI Integrity Hash</button>
      </div>
      <div id="sri-results" class="card" style="display:none;">
        <div class="card-title">Computed Integrity Tag</div>
        <pre id="sri-output"></pre>
      </div>
    </div>

    <!-- TAB 4: WCAG CONTRAST -->
    <div id="tab-contrast" class="tab-content">
      <div class="card">
        <div class="card-title">🎨 WCAG 2.2 Color Contrast Calculator</div>
        <div class="grid-2">
          <div class="form-group">
            <label>Foreground Color (Text)</label>
            <input type="text" id="contrast-fg" value="#38bdf8">
          </div>
          <div class="form-group">
            <label>Background Color</label>
            <input type="text" id="contrast-bg" value="#0f172a">
          </div>
        </div>
        <button class="btn" onclick="checkContrast()">🎨 Evaluate Contrast</button>
      </div>
      <div id="contrast-results" class="card" style="display:none;">
        <div class="grid-2" style="margin-bottom:1.5rem;">
          <div id="swatch-preview" class="color-swatch">Preview Sample Text</div>
          <div class="score-dial">
            <div id="contrast-ratio" class="score-number">12.5:1</div>
            <div id="contrast-status" class="score-grade">Passes WCAG AA</div>
          </div>
        </div>
        <pre id="contrast-details"></pre>
      </div>
    </div>

    <!-- TAB 5: REMEDIATION -->
    <div id="tab-remediation" class="tab-content">
      <div class="card">
        <div class="card-title">🛠️ Multi-Platform Hardening Config Generator</div>
        <div class="form-group">
          <label>Target Project Identifier</label>
          <input type="text" id="rem-target" value="production-app">
        </div>
        <button class="btn" onclick="generateHardening()">🛠️ Generate Netlify, Nginx & Apache Configs</button>
      </div>
      <div id="rem-results" class="card" style="display:none;">
        <div class="card-title">Hardening Output Files</div>
        <pre id="rem-output"></pre>
      </div>
    </div>

    <!-- TAB 6: MCP INSPECTOR -->
    <div id="tab-mcp" class="tab-content">
      <div class="card">
        <div class="card-title">🤖 Model Context Protocol (MCP) Tools & Configs</div>
        <div id="mcp-tools-list"></div>
      </div>
    </div>
  </main>

  <script>
    function showTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('nav button').forEach(el => el.classList.remove('active'));
      document.getElementById('tab-' + tabId).classList.add('active');
      event.target.classList.add('active');
    }

    async function runAudit() {
      const target = document.getElementById('audit-target').value;
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
      });
      const data = await res.json();
      document.getElementById('audit-results').style.display = 'block';
      document.getElementById('audit-score').innerText = data.score;
      document.getElementById('audit-grade').innerText = 'Grade ' + data.grade;
      
      const s = data.summary;
      document.getElementById('audit-summary-text').innerHTML = `
        Critical Issues: <b>${s.critical}</b><br>
        High Severity: <b>${s.high}</b><br>
        Medium Severity: <b>${s.medium}</b><br>
        Low / Info: <b>${s.low + s.info}</b>
      `;

      let findingsHtml = '';
      if(data.findings.length === 0) {
        findingsHtml = '<p style="color:var(--accent);">No security vulnerabilities found.</p>';
      } else {
        data.findings.forEach(f => {
          findingsHtml += `
            <div class="finding-item ${f.severity}">
              <div style="font-weight:700; color:var(--text-main); margin-bottom:0.25rem;">[${f.severity}] ${f.title}</div>
              <div style="font-size:0.875rem; color:var(--text-muted);">${f.description}</div>
              <div style="font-size:0.875rem; color:var(--accent); margin-top:0.25rem;"><b>Fix:</b> ${f.remediation}</div>
            </div>
          `;
        });
      }
      document.getElementById('audit-findings-list').innerHTML = findingsHtml;
    }

    async function generateCSP() {
      const fw = document.getElementById('csp-framework').value;
      const pst = document.getElementById('csp-preset').value;
      const res = await fetch('/api/csp', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({framework: fw, preset: pst})
      });
      const data = await res.json();
      document.getElementById('csp-results').style.display = 'block';
      document.getElementById('csp-output').innerText = 
        `# HTTP Header:\\n${data.header_name}: ${data.csp_string}\\n\\n` +
        `# Netlify (netlify.toml):\\n${data.netlify_snippet}\\n\\n` +
        `# Nginx (nginx.conf):\\n${data.nginx_snippet}`;
    }

    async function generateSRI() {
      const target = document.getElementById('sri-target').value;
      const algo = document.getElementById('sri-algo').value;
      const res = await fetch('/api/sri', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target, algorithm: algo})
      });
      const data = await res.json();
      document.getElementById('sri-results').style.display = 'block';
      document.getElementById('sri-output').innerText = JSON.stringify(data, null, 2);
    }

    async function checkContrast() {
      const fg = document.getElementById('contrast-fg').value;
      const bg = document.getElementById('contrast-bg').value;
      const res = await fetch('/api/contrast', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({fg_color: fg, bg_color: bg})
      });
      const data = await res.json();
      document.getElementById('contrast-results').style.display = 'block';
      document.getElementById('contrast-ratio').innerText = data.formatted_ratio;
      document.getElementById('contrast-status').innerText = data.compliance.passes_target ? '✔ Passes WCAG AA' : '✖ Fails WCAG AA';
      
      const swatch = document.getElementById('swatch-preview');
      swatch.style.color = fg;
      swatch.style.backgroundColor = bg;
      
      document.getElementById('contrast-details').innerText = JSON.stringify(data.compliance, null, 2);
    }

    async function generateHardening() {
      const target = document.getElementById('rem-target').value;
      const res = await fetch('/api/fix', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
      });
      const data = await res.json();
      document.getElementById('rem-results').style.display = 'block';
      document.getElementById('rem-output').innerText = JSON.stringify(data.files, null, 2);
    }

    async function loadMCPTools() {
      const res = await fetch('/api/mcp-tools');
      const tools = await res.json();
      let html = '';
      tools.forEach(t => {
        html += `
          <div class="finding-item LOW">
            <div style="font-weight:700; color:var(--primary); font-family:monospace;">${t.name}</div>
            <div style="font-size:0.875rem; color:var(--text-muted); margin-top:0.25rem;">${t.description}</div>
          </div>
        `;
      });
      document.getElementById('mcp-tools-list').innerHTML = html;
    }
    loadMCPTools();
  </script>
</body>
</html>
"""


class StudioHTTPRequestHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP Request Handler for Material 3 Security Studio."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard logs unless debugging
        pass

    def _send_json(self, status_code: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("", "/", "/index.html"):
            body = STUDIO_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/mcp-tools":
            self._send_json(200, MCP_TOOLS_DEFINITIONS)
        elif path == "/api/platform":
            data = {
                "server": SERVER_NAME,
                "version": SERVER_VERSION,
                "python": platform.python_version(),
                "system": platform.system(),
            }
            self._send_json(200, data)
        elif path == "/api/mcp-config":
            query = urllib.parse.parse_qs(parsed_url.query)
            client = query.get("client", ["generic"])[0]
            self._send_json(200, generate_mcp_client_config(client))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else "{}"
        try:
            params = json.loads(body)
        except Exception:
            params = {}

        if path == "/api/audit":
            target = params.get("target", "https://example.com")
            res = audit_security(target=target)
            self._send_json(200, res)
        elif path == "/api/csp":
            fw = params.get("framework", "vanilla")
            pst = params.get("preset", "strict")
            res = generate_csp_policy(framework=fw, preset=pst)
            self._send_json(200, res)
        elif path == "/api/sri":
            target = params.get("target", "")
            algo = params.get("algorithm", "sha384")
            try:
                content, _ = fetch_or_read_content(target)
            except Exception:
                content = target.encode("utf-8")
            res = generate_sri_hash(content, algo)
            self._send_json(200, res)
        elif path == "/api/contrast":
            fg = params.get("fg_color", "#ffffff")
            bg = params.get("bg_color", "#000000")
            res = calculate_contrast(fg, bg)
            self._send_json(200, res)
        elif path == "/api/fix":
            target = params.get("target", "app")
            res = generate_remediation_configs(target)
            self._send_json(200, res)
        else:
            self._send_json(404, {"error": "Not Found"})


def cmd_serve(args: argparse.Namespace) -> int:
    """Start Material 3 Security Studio HTTP server."""
    port = args.port or 8085
    host = args.host or "0.0.0.0"

    print_banner()
    print(bold("🚀 Starting Google Material 3 Security Studio Web UI"))
    print(f"  • Local URL:   {cyan(bold(f'http://localhost:{port}'))}")
    print(f"  • Network URL: {cyan(bold(f'http://{host}:{port}'))}")
    print(gray("  • Press Ctrl+C to terminate the server.\n"))

    server = HTTPServer((host, port), StudioHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n" + yellow("Studio server stopped."))
    finally:
        server.server_close()
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

    # Subcommand: mcp
    p_mcp = subparsers.add_parser("mcp", help="Model Context Protocol (MCP) server & client config exporter")
    p_mcp.add_argument("--tools", action="store_true", help="List all registered MCP tools")
    p_mcp.add_argument("--config", "-c", choices=["claude", "cursor", "cline", "zed", "generic"], help="Export client configuration JSON")
    p_mcp.add_argument("--python-path", default="python3", help="Python executable path for client configs")
    p_mcp.add_argument("--project-root", help="Custom project root directory for client configs")

    # Subcommand: serve
    p_serve = subparsers.add_parser("serve", help="Start Google Material 3 Security Studio UI")
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
