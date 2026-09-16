#!/usr/bin/env python3
"""Web Security Guard - Model Context Protocol (MCP) Server & Security Engine.

Zero external dependencies: Pure Python standard library implementation of:
1. JSON-RPC 2.0 / MCP Server over stdio
2. Web Security Audit Engine (0-100 scoring, headers, cookies, DOM vulnerabilities)
3. Strict Content Security Policy (CSP Level 3) Generator
4. Subresource Integrity (SRI) Hasher & HTML Injector
5. WCAG 2.2 Color Contrast Ratio Calculator
6. Multi-Platform Security Remediation & Hardening Generator
7. MCP Client Config Generator (Claude Desktop, Cursor, Cline, Zed, Generic)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import math
import os
import platform
import re
import secrets
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

# ============================================================================
# Protocol & Engine Constants
# ============================================================================

SERVER_NAME = "web-security-guard"
SERVER_VERSION = "1.0.0"
MCP_PROTOCOL_VERSION = "2024-11-05"

NAMED_COLORS: Dict[str, Tuple[int, int, int]] = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (255, 0, 0),
    "green": (0, 128, 0),
    "blue": (0, 0, 255),
    "yellow": (255, 255, 0),
    "cyan": (0, 255, 255),
    "aqua": (0, 255, 255),
    "magenta": (255, 0, 255),
    "fuchsia": (255, 0, 255),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "silver": (192, 192, 192),
    "maroon": (128, 0, 0),
    "olive": (128, 128, 0),
    "lime": (0, 255, 0),
    "teal": (0, 128, 128),
    "navy": (0, 0, 128),
    "purple": (128, 0, 128),
    "orange": (255, 165, 0),
    "darkblue": (0, 0, 139),
    "darkcyan": (0, 139, 139),
    "darkgray": (169, 169, 169),
    "darkgrey": (169, 169, 169),
    "darkgreen": (0, 100, 0),
    "darkkhaki": (189, 183, 107),
    "darkmagenta": (139, 0, 139),
    "darkolivegreen": (85, 107, 47),
    "darkorange": (255, 140, 0),
    "darkorchid": (153, 50, 204),
    "darkred": (139, 0, 0),
    "darksalmon": (233, 150, 122),
    "darkviolet": (148, 0, 211),
    "deepskyblue": (0, 191, 255),
    "gold": (255, 215, 0),
    "hotpink": (255, 105, 180),
    "indigo": (75, 0, 130),
    "lightcoral": (240, 128, 128),
    "lightcyan": (224, 255, 255),
    "lightgreen": (144, 238, 144),
    "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211),
    "lightyellow": (255, 255, 224),
    "midnightblue": (25, 25, 112),
    "royalblue": (65, 105, 225),
    "transparent": (0, 0, 0),
}


# ============================================================================
# 1. Color Contrast & WCAG 2.2 Analyzer
# ============================================================================

def parse_color(color_str: str) -> Tuple[int, int, int]:
    """Parse color string in Hex (#RGB, #RRGGBB, #RRGGBBAA), RGB/RGBA, or named color."""
    if not isinstance(color_str, str):
        raise ValueError(f"Color must be a string, got {type(color_str)}")

    c = color_str.strip().lower()

    if c in NAMED_COLORS:
        return NAMED_COLORS[c]

    # Hex format
    if c.startswith("#"):
        hex_val = c[1:]
        if len(hex_val) == 3:
            r = int(hex_val[0] * 2, 16)
            g = int(hex_val[1] * 2, 16)
            b = int(hex_val[2] * 2, 16)
            return (r, g, b)
        elif len(hex_val) == 4:
            r = int(hex_val[0] * 2, 16)
            g = int(hex_val[1] * 2, 16)
            b = int(hex_val[2] * 2, 16)
            return (r, g, b)
        elif len(hex_val) == 6 or len(hex_val) == 8:
            r = int(hex_val[0:2], 16)
            g = int(hex_val[2:4], 16)
            b = int(hex_val[4:6], 16)
            return (r, g, b)
        else:
            raise ValueError(f"Invalid hex color format: {color_str}")

    # rgb() or rgba()
    rgb_match = re.match(r"^rgba?\s*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*[\d\.]+)?\s*\)$", c)
    if rgb_match:
        r, g, b = (
            min(255, max(0, int(rgb_match.group(1)))),
            min(255, max(0, int(rgb_match.group(2)))),
            min(255, max(0, int(rgb_match.group(3)))),
        )
        return (r, g, b)

    # 3-tuple comma separated "255, 255, 255"
    parts = [p.strip() for p in c.split(",") if p.strip()]
    if len(parts) in (3, 4) and all(p.replace(".", "", 1).isdigit() for p in parts[:3]):
        r = min(255, max(0, int(float(parts[0]))))
        g = min(255, max(0, int(float(parts[1]))))
        b = min(255, max(0, int(float(parts[2]))))
        return (r, g, b)

    raise ValueError(f"Unable to parse color format: '{color_str}'")


def relative_luminance(r: int, g: int, b: int) -> float:
    """Compute relative luminance according to WCAG 2.2 formula."""
    channels = []
    for val in (r, g, b):
        c = val / 255.0
        if c <= 0.04045:
            c_lin = c / 12.92
        else:
            c_lin = math.pow((c + 0.055) / 1.055, 2.4)
        channels.append(c_lin)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def calculate_contrast(
    fg_color: str,
    bg_color: str,
    font_size_pt: float = 16.0,
    is_bold: bool = False,
    target_level: str = "AA",
) -> Dict[str, Any]:
    """Calculate WCAG 2.2 color contrast ratio and compliance status."""
    fg_rgb = parse_color(fg_color)
    bg_rgb = parse_color(bg_color)

    lum_fg = relative_luminance(*fg_rgb)
    lum_bg = relative_luminance(*bg_rgb)

    l1 = max(lum_fg, lum_bg)
    l2 = min(lum_fg, lum_bg)

    contrast_ratio = (l1 + 0.05) / (l2 + 0.05)
    rounded_ratio = round(contrast_ratio, 2)

    # WCAG 2.2 Thresholds
    # Large text is defined as >= 18pt (24px) or >= 14pt (18.66px) bold
    is_large_text = (font_size_pt >= 18.0) or (font_size_pt >= 14.0 and is_bold)

    aa_normal_pass = rounded_ratio >= 4.5
    aa_large_pass = rounded_ratio >= 3.0
    aa_ui_pass = rounded_ratio >= 3.0

    aaa_normal_pass = rounded_ratio >= 7.0
    aaa_large_pass = rounded_ratio >= 4.5

    level_upper = target_level.upper()
    if level_upper == "AAA":
        overall_pass = aaa_large_pass if is_large_text else aaa_normal_pass
    else:
        overall_pass = aa_large_pass if is_large_text else aa_normal_pass

    # Suggestions if failed
    suggestions = []
    if not overall_pass:
        if lum_bg > 0.5:
            suggestions.append(f"Darken the foreground color '{fg_color}' to increase contrast against the bright background.")
        else:
            suggestions.append(f"Lighten the foreground color '{fg_color}' to increase contrast against the dark background.")
        if not is_large_text and aa_large_pass:
            suggestions.append("Increasing font size to >= 18pt (or >= 14pt bold) would achieve WCAG AA compliance.")

    return {
        "contrast_ratio": rounded_ratio,
        "formatted_ratio": f"{rounded_ratio}:1",
        "foreground": {
            "input": fg_color,
            "rgb": list(fg_rgb),
            "hex": f"#{fg_rgb[0]:02x}{fg_rgb[1]:02x}{fg_rgb[2]:02x}",
            "relative_luminance": round(lum_fg, 4),
        },
        "background": {
            "input": bg_color,
            "rgb": list(bg_rgb),
            "hex": f"#{bg_rgb[0]:02x}{bg_rgb[1]:02x}{bg_rgb[2]:02x}",
            "relative_luminance": round(lum_bg, 4),
        },
        "typography": {
            "font_size_pt": font_size_pt,
            "is_bold": is_bold,
            "is_large_text": is_large_text,
        },
        "compliance": {
            "target_level": level_upper,
            "passes_target": overall_pass,
            "wcag_2_2_aa": {
                "normal_text": {"required": 4.5, "passed": aa_normal_pass},
                "large_text": {"required": 3.0, "passed": aa_large_pass},
                "ui_components": {"required": 3.0, "passed": aa_ui_pass},
            },
            "wcag_2_2_aaa": {
                "normal_text": {"required": 7.0, "passed": aaa_normal_pass},
                "large_text": {"required": 4.5, "passed": aaa_large_pass},
            },
        },
        "suggestions": suggestions,
    }


# ============================================================================
# 2. Subresource Integrity (SRI) Engine
# ============================================================================

def generate_sri_hash(content: Union[str, bytes], algorithm: str = "sha384") -> Dict[str, Any]:
    """Compute Subresource Integrity (SRI) cryptographic hash for scripts/styles."""
    algo_lower = algorithm.lower().strip()
    if algo_lower not in ("sha256", "sha384", "sha512"):
        raise ValueError(f"Unsupported SRI algorithm: {algorithm}. Must be sha256, sha384, or sha512.")

    data = content.encode("utf-8") if isinstance(content, str) else content

    hasher = getattr(hashlib, algo_lower)()
    hasher.update(data)
    digest_bytes = hasher.digest()
    digest_b64 = base64.b64encode(digest_bytes).decode("ascii")
    integrity_string = f"{algo_lower}-{digest_b64}"

    return {
        "integrity": integrity_string,
        "algorithm": algo_lower,
        "digest_hex": hasher.hexdigest(),
        "digest_base64": digest_b64,
        "byte_size": len(data),
        "script_tag_template": f'<script src="URL" integrity="{integrity_string}" crossorigin="anonymous"></script>',
        "style_tag_template": f'<link rel="stylesheet" href="URL" integrity="{integrity_string}" crossorigin="anonymous">',
    }


def fetch_or_read_content(target: str) -> Tuple[bytes, str]:
    """Fetch content from remote URL or read local file path."""
    target_clean = target.strip()

    if target_clean.startswith("http://") or target_clean.startswith("https://"):
        req = urllib.request.Request(
            target_clean,
            headers={
                "User-Agent": f"WebSecurityGuard/{SERVER_VERSION} (Security Auditor; Zero-Dependency Engine)"
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                body = response.read()
                content_type = response.headers.get("Content-Type", "")
                return body, content_type
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP error {e.code} fetching '{target_clean}': {e.reason}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error fetching '{target_clean}': {e.reason}")
        except Exception as e:
            raise RuntimeError(f"Failed to fetch '{target_clean}': {str(e)}")

    # Local file
    if os.path.exists(target_clean):
        with open(target_clean, "rb") as f:
            body = f.read()
        return body, "text/plain"

    # Raw string content passed directly
    return target.encode("utf-8"), "text/plain"


def inject_sri_into_html(
    html_content_or_path: str,
    algorithm: str = "sha384",
    fetch_remote: bool = True,
    save_to_file: bool = False,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect and inject SRI integrity attributes into HTML <script> and <link> tags."""
    algo = algorithm.lower().strip()
    if algo not in ("sha256", "sha384", "sha512"):
        algo = "sha384"

    is_file_path = os.path.isfile(html_content_or_path)
    if is_file_path:
        with open(html_content_or_path, "r", encoding="utf-8", errors="replace") as f:
            html = f.read()
        base_dir = os.path.dirname(os.path.abspath(html_content_or_path))
    else:
        html = html_content_or_path
        base_dir = os.getcwd()

    injected_count = 0
    modified_resources = []
    errors = []

    # Regex patterns for script and stylesheet link tags
    # Replace <script src="..."> tags that lack integrity attribute
    def replace_script(match: re.Match) -> str:
        nonlocal injected_count
        full_tag = match.group(0)
        if "integrity=" in full_tag:
            return full_tag

        src_match = re.search(r'src=["\']([^"\']+)["\']', full_tag)
        if not src_match:
            return full_tag

        src_url = src_match.group(1)
        try:
            if src_url.startswith("http://") or src_url.startswith("https://"):
                if not fetch_remote:
                    return full_tag
                data, _ = fetch_or_read_content(src_url)
            else:
                local_path = os.path.join(base_dir, src_url.lstrip("/"))
                if not os.path.exists(local_path):
                    local_path = os.path.join(base_dir, src_url)
                if not os.path.exists(local_path):
                    return full_tag
                with open(local_path, "rb") as f:
                    data = f.read()

            sri = generate_sri_hash(data, algo)
            integrity_str = sri["integrity"]

            # Add integrity and crossorigin attributes
            tag_no_end = re.sub(r'>\s*$', '', full_tag.strip())
            if "crossorigin" not in full_tag:
                new_tag = f'{tag_no_end} integrity="{integrity_str}" crossorigin="anonymous">'
            else:
                new_tag = f'{tag_no_end} integrity="{integrity_str}">'

            injected_count += 1
            modified_resources.append({
                "type": "script",
                "src": src_url,
                "integrity": integrity_str,
                "algorithm": algo,
                "size_bytes": len(data),
            })
            return new_tag
        except Exception as e:
            errors.append(f"Failed SRI computation for script '{src_url}': {str(e)}")
            return full_tag

    def replace_link(match: re.Match) -> str:
        nonlocal injected_count
        full_tag = match.group(0)
        if "integrity=" in full_tag:
            return full_tag

        rel_match = re.search(r'rel=["\']stylesheet["\']', full_tag, re.IGNORECASE)
        if not rel_match:
            return full_tag

        href_match = re.search(r'href=["\']([^"\']+)["\']', full_tag)
        if not href_match:
            return full_tag

        href_url = href_match.group(1)
        try:
            if href_url.startswith("http://") or href_url.startswith("https://"):
                if not fetch_remote:
                    return full_tag
                data, _ = fetch_or_read_content(href_url)
            else:
                local_path = os.path.join(base_dir, href_url.lstrip("/"))
                if not os.path.exists(local_path):
                    local_path = os.path.join(base_dir, href_url)
                if not os.path.exists(local_path):
                    return full_tag
                with open(local_path, "rb") as f:
                    data = f.read()

            sri = generate_sri_hash(data, algo)
            integrity_str = sri["integrity"]

            tag_no_end = re.sub(r'>\s*$', '', full_tag.strip())
            if "crossorigin" not in full_tag:
                new_tag = f'{tag_no_end} integrity="{integrity_str}" crossorigin="anonymous">'
            else:
                new_tag = f'{tag_no_end} integrity="{integrity_str}">'

            injected_count += 1
            modified_resources.append({
                "type": "stylesheet",
                "href": href_url,
                "integrity": integrity_str,
                "algorithm": algo,
                "size_bytes": len(data),
            })
            return new_tag
        except Exception as e:
            errors.append(f"Failed SRI computation for stylesheet '{href_url}': {str(e)}")
            return full_tag

    # Run replacements
    new_html = re.sub(r'<script\b[^>]*\bsrc=["\'][^"\']+["\'][^>]*>', replace_script, html, flags=re.IGNORECASE)
    new_html = re.sub(r'<link\b[^>]*\bhref=["\'][^"\']+["\'][^>]*>', replace_link, new_html, flags=re.IGNORECASE)

    saved_path = None
    if save_to_file:
        target_file = output_path if output_path else (html_content_or_path if is_file_path else "index.sri.html")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(new_html)
        saved_path = target_file

    return {
        "injected_count": injected_count,
        "modified_resources": modified_resources,
        "errors": errors,
        "saved_to_file": saved_path,
        "html": new_html,
    }


# ============================================================================
# 3. Content Security Policy (CSP Level 3) Generator
# ============================================================================

def generate_csp_policy(
    framework: str = "vanilla",
    preset: str = "strict",
    nonce: Optional[str] = None,
    report_uri: Optional[str] = None,
    domains: Optional[List[str]] = None,
    output_format: str = "header",
) -> Dict[str, Any]:
    """Generate production-grade Content Security Policy Level 3 directives and snippets."""
    fw = framework.lower().strip()
    pst = preset.lower().strip()
    active_nonce = nonce if nonce else secrets.token_urlsafe(16)
    extra_domains = " ".join(domains) if domains else ""

    directives: Dict[str, str] = {}

    if pst == "api-only":
        directives = {
            "default-src": "'none'",
            "frame-ancestors": "'none'",
            "base-uri": "'none'",
            "form-action": "'none'",
        }
    elif pst == "permissive":
        directives = {
            "default-src": f"'self' https: data: blob: {extra_domains}".strip(),
            "script-src": f"'self' 'unsafe-inline' 'unsafe-eval' https: blob: {extra_domains}".strip(),
            "style-src": f"'self' 'unsafe-inline' https: {extra_domains}".strip(),
            "img-src": "'self' data: https: blob:",
            "font-src": "'self' data: https:",
            "connect-src": f"'self' https: wss: {extra_domains}".strip(),
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'self'",
        }
    elif pst == "balanced":
        # Balanced: Strict nonces with common trusted CDNs
        cdn_scripts = f"https://cdnjs.cloudflare.com https://cdn.jsdelivr.net {extra_domains}".strip()
        cdn_styles = "https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com"
        cdn_fonts = "https://fonts.gstatic.com data:"
        directives = {
            "default-src": "'self'",
            "script-src": f"'self' 'nonce-{active_nonce}' {cdn_scripts}".strip(),
            "style-src": f"'self' 'unsafe-inline' {cdn_styles}".strip(),
            "img-src": "'self' data: https:",
            "font-src": f"'self' {cdn_fonts}".strip(),
            "connect-src": f"'self' {extra_domains}".strip(),
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
            "upgrade-insecure-requests": "",
        }
    else:
        # Default: Strict CSP Level 3
        directives = {
            "default-src": "'self'",
            "script-src": f"'self' 'nonce-{active_nonce}' 'strict-dynamic' https: 'unsafe-inline' {extra_domains}".strip(),
            "style-src": f"'self' 'nonce-{active_nonce}' 'unsafe-inline'".strip(),
            "img-src": "'self' data: https:",
            "font-src": "'self' data:",
            "connect-src": f"'self' {extra_domains}".strip(),
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
            "upgrade-insecure-requests": "",
        }

    # Framework adjustments
    if fw in ("nextjs", "next"):
        cur_conn = directives.get('connect-src', "'self'")
        directives["connect-src"] = f"{cur_conn} https://vercel.live".strip()
        cur_img = directives.get('img-src', "'self'")
        directives["img-src"] = f"{cur_img} https://*.githubusercontent.com".strip()
    elif fw in ("astro",):
        directives["script-src"] = f"'self' 'nonce-{active_nonce}' 'strict-dynamic'".strip()
    elif fw in ("vue", "react", "spa"):
        cur_conn = directives.get('connect-src', "'self'")
        directives["connect-src"] = f"{cur_conn} ws: wss:".strip()

    if report_uri:
        directives["report-uri"] = report_uri
        directives["report-to"] = "csp-endpoint"

    # Assemble CSP string
    parts = []
    for k, v in directives.items():
        if v == "":
            parts.append(k)
        else:
            parts.append(f"{k} {v}")
    csp_string = "; ".join(parts)

    header_name = "Content-Security-Policy-Report-Only" if pst == "report-only" else "Content-Security-Policy"

    # Snippets
    meta_tag = f'<meta http-equiv="{header_name}" content="{csp_string}">'
    nginx_snippet = f'add_header {header_name} "{csp_string}" always;'
    apache_snippet = f'Header set {header_name} "{csp_string}"'
    netlify_snippet = f'[[headers]]\n  for = "/*"\n  [headers.values]\n    {header_name} = "{csp_string}"'
    express_snippet = (
        f"// Express.js with Helmet\n"
        f"app.use(helmet.contentSecurityPolicy({{\n"
        f"  directives: {json.dumps(directives, indent=4)}\n"
        f"}}));"
    )

    return {
        "header_name": header_name,
        "csp_string": csp_string,
        "directives": directives,
        "framework": fw,
        "preset": pst,
        "nonce": active_nonce,
        "meta_tag": meta_tag,
        "nginx_snippet": nginx_snippet,
        "apache_snippet": apache_snippet,
        "netlify_snippet": netlify_snippet,
        "express_snippet": express_snippet,
    }


# ============================================================================
# 4. Security Audit Engine (0-100 Score & Categorized Findings)
# ============================================================================

def audit_security(
    target: str,
    min_score: int = 0,
    check_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Audit a live URL or local HTML/config file, producing a 0-100 score and security findings."""
    target_clean = target.strip()
    is_url = target_clean.startswith("http://") or target_clean.startswith("https://")

    score = 100
    findings: List[Dict[str, Any]] = []
    headers_detected: Dict[str, str] = {}
    cookies_detected: List[Dict[str, Any]] = []
    html_body = ""

    if is_url:
        req = urllib.request.Request(
            target_clean,
            headers={"User-Agent": f"WebSecurityGuard/{SERVER_VERSION} (Security Auditor)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                html_body = response.read().decode("utf-8", errors="replace")
                headers_detected = {k: v for k, v in response.headers.items()}
                cookie_headers = response.headers.get_all("Set-Cookie", [])
                for ch in cookie_headers:
                    cookies_detected.append({"raw": ch})
        except urllib.error.HTTPError as e:
            html_body = e.read().decode("utf-8", errors="replace")
            headers_detected = {k: v for k, v in e.headers.items()}
            findings.append({
                "id": "HTTP_ERROR_STATUS",
                "severity": "MEDIUM",
                "title": f"HTTP Status {e.code}",
                "description": f"Target responded with HTTP error status code {e.code}.",
                "remediation": "Check web server routing and authentication configurations.",
            })
            score -= 10
        except Exception as e:
            findings.append({
                "id": "TARGET_UNREACHABLE",
                "severity": "CRITICAL",
                "title": "Target Unreachable",
                "description": f"Failed to connect to target URL: {str(e)}",
                "remediation": "Verify server availability and network connectivity.",
            })
            return {
                "target": target_clean,
                "score": 0,
                "grade": "F",
                "findings": findings,
                "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "recommendations": ["Fix target connectivity before running automated security audits."],
            }
    elif os.path.isfile(target_clean):
        with open(target_clean, "r", encoding="utf-8", errors="replace") as f:
            html_body = f.read()
    elif os.path.isdir(target_clean):
        # Scan directory for index.html or netlify.toml / nginx.conf
        index_file = os.path.join(target_clean, "index.html")
        if os.path.isfile(index_file):
            with open(index_file, "r", encoding="utf-8", errors="replace") as f:
                html_body = f.read()
        else:
            html_body = ""
    else:
        html_body = target_clean

    # Lowercase header map for case-insensitive lookup
    norm_headers = {k.lower(): v for k, v in headers_detected.items()}

    # Check 1: Content Security Policy
    csp_header = norm_headers.get("content-security-policy") or norm_headers.get("content-security-policy-report-only")
    meta_csp_match = re.search(r'<meta\b[^>]*http-equiv=["\']content-security-policy["\'][^>]*content=["\']([^"\']+)["\']', html_body, re.IGNORECASE)

    if not csp_header and not meta_csp_match:
        findings.append({
            "id": "SEC_CSP_MISSING",
            "severity": "HIGH",
            "title": "Missing Content-Security-Policy",
            "description": "No CSP header or meta tag was detected, leaving the application susceptible to Cross-Site Scripting (XSS) and data injection.",
            "remediation": "Deploy a strict CSP Level 3 policy with nonces or hashes (e.g. use 'sec-guard csp').",
        })
        score -= 15
    else:
        csp_val = (csp_header or (meta_csp_match.group(1) if meta_csp_match else "")).lower()
        if "'unsafe-eval'" in csp_val:
            findings.append({
                "id": "SEC_CSP_UNSAFE_EVAL",
                "severity": "MEDIUM",
                "title": "CSP Allows 'unsafe-eval'",
                "description": "CSP policy explicitly allows unsafe-eval which weakens XSS protections.",
                "remediation": "Refactor codebase to eliminate eval() and Function constructor calls.",
            })
            score -= 5
        if "default-src '*'" in csp_val or "script-src '*'" in csp_val:
            findings.append({
                "id": "SEC_CSP_WILDCARD",
                "severity": "HIGH",
                "title": "CSP Contains Insecure Wildcard",
                "description": "CSP allows unrestricted loading of scripts/resources via '*' wildcard.",
                "remediation": "Restrict default-src and script-src to 'self' and explicit origins.",
            })
            score -= 10

    # Check 2: Strict-Transport-Security (HSTS)
    if is_url and target_clean.startswith("https://"):
        hsts = norm_headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "id": "SEC_HSTS_MISSING",
                "severity": "HIGH",
                "title": "Missing Strict-Transport-Security (HSTS)",
                "description": "HTTPS connection does not enforce HSTS, exposing users to SSL-stripping man-in-the-middle attacks.",
                "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
            score -= 10
        elif "max-age" in hsts:
            age_match = re.search(r'max-age=(\d+)', hsts)
            if age_match and int(age_match.group(1)) < 15552000:
                findings.append({
                    "id": "SEC_HSTS_LOW_MAXAGE",
                    "severity": "LOW",
                    "title": "HSTS max-age Below Recommended Duration",
                    "description": f"HSTS max-age is {age_match.group(1)}s (recommended: at least 31536000s / 1 year).",
                    "remediation": "Increase max-age to 31536000 (1 year) or 63072000 (2 years).",
                })
                score -= 3

    # Check 3: X-Content-Type-Options
    if is_url:
        x_content_type = norm_headers.get("x-content-type-options")
        if not x_content_type or "nosniff" not in x_content_type.lower():
            findings.append({
                "id": "SEC_NOSNIFF_MISSING",
                "severity": "MEDIUM",
                "title": "Missing X-Content-Type-Options",
                "description": "X-Content-Type-Options: nosniff is missing, permitting MIME-sniffing attacks.",
                "remediation": "Add header: X-Content-Type-Options: nosniff",
            })
            score -= 5

    # Check 4: X-Frame-Options / Frame Ancestors
    if is_url:
        x_frame = norm_headers.get("x-frame-options")
        has_frame_ancestors = csp_header and "frame-ancestors" in csp_header.lower()
        if not x_frame and not has_frame_ancestors:
            findings.append({
                "id": "SEC_CLICKJACKING_RISK",
                "severity": "MEDIUM",
                "title": "Clickjacking Protection Missing",
                "description": "Neither X-Frame-Options nor CSP frame-ancestors is present to defend against clickjacking.",
                "remediation": "Add header X-Frame-Options: DENY or CSP directive frame-ancestors 'none';",
            })
            score -= 10

    # Check 5: Referrer-Policy
    if is_url:
        ref_policy = norm_headers.get("referrer-policy")
        if not ref_policy:
            findings.append({
                "id": "SEC_REFERRER_POLICY_MISSING",
                "severity": "LOW",
                "title": "Missing Referrer-Policy",
                "description": "No Referrer-Policy specified; URL parameters and sensitive tokens may leak to external referrers.",
                "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            })
            score -= 5

    # Check 6: Permissions-Policy
    if is_url:
        perm_policy = norm_headers.get("permissions-policy")
        if not perm_policy:
            findings.append({
                "id": "SEC_PERMISSIONS_POLICY_MISSING",
                "severity": "LOW",
                "title": "Missing Permissions-Policy",
                "description": "Browser features (camera, microphone, geolocation) are not explicitly restricted.",
                "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            })
            score -= 5

    # Check 7: Server & Technology Banners
    if is_url:
        for leak_header in ("server", "x-powered-by", "x-aspnet-version"):
            val = norm_headers.get(leak_header)
            if val and len(val) > 2:
                findings.append({
                    "id": f"SEC_INFO_LEAK_{leak_header.upper().replace('-', '_')}",
                    "severity": "LOW",
                    "title": f"Technology Banner Leaked ({leak_header})",
                    "description": f"Server emits verbose technology header '{leak_header}: {val}', aiding reconnaissance.",
                    "remediation": f"Disable or mask the '{leak_header}' banner in web server / reverse proxy config.",
                })
                score -= 4

    # Check 8: HTML DOM Analysis - Scripts without SRI
    script_tags = re.findall(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', html_body, re.IGNORECASE)
    for s_tag in script_tags:
        if (s_tag.startswith("http://") or s_tag.startswith("https://") or s_tag.startswith("//")) and "integrity=" not in html_body:
            findings.append({
                "id": "SEC_SRI_MISSING",
                "severity": "MEDIUM",
                "title": "External Script Missing Subresource Integrity (SRI)",
                "description": f"External script '{s_tag}' lacks integrity hash verification.",
                "remediation": "Generate and attach SRI hash (e.g. use 'sec-guard sri <url> --inject').",
            })
            score -= 5
            break  # Deduct once for batch scripts

    # Check 9: HTML DOM Analysis - Insecure target="_blank"
    blank_links = re.findall(r'<a\b[^>]*\btarget=["\']_blank["\'][^>]*>', html_body, re.IGNORECASE)
    unsafe_blanks = [b for b in blank_links if "rel=" not in b.lower() or "noopener" not in b.lower()]
    if unsafe_blanks:
        findings.append({
            "id": "SEC_TABNABBING_RISK",
            "severity": "LOW",
            "title": "Reverse Tabnabbing Vulnerability",
            "description": f"Found {len(unsafe_blanks)} link(s) with target='_blank' lacking rel='noopener noreferrer'.",
            "remediation": "Add rel='noopener noreferrer' to all external links opening in a new tab.",
        })
        score -= 3

    # Check 10: Dangerous JS Sinks in HTML
    if re.search(r'\beval\s*\(', html_body) or re.search(r'document\.write\s*\(', html_body):
        findings.append({
            "id": "SEC_DANGEROUS_JS_SINK",
            "severity": "MEDIUM",
            "title": "Dangerous JavaScript Sink Detected",
            "description": "Inline scripts contain calls to eval() or document.write(), increasing DOM-XSS risk.",
            "remediation": "Replace dynamic code execution with safe parsing methods (JSON.parse).",
        })
        score -= 5

    # Check 11: Insecure HTTP Forms
    if re.search(r'<form\b[^>]*\baction=["\']http://', html_body, re.IGNORECASE):
        findings.append({
            "id": "SEC_INSECURE_FORM_ACTION",
            "severity": "HIGH",
            "title": "Insecure HTTP Form Submission",
            "description": "Form submits data over unencrypted plain HTTP transport.",
            "remediation": "Ensure all form actions use HTTPS or relative paths.",
        })
        score -= 15

    # Check 12: Cookies Security
    for cookie in cookies_detected:
        raw_cookie = cookie.get("raw", "").lower()
        if "secure" not in raw_cookie:
            findings.append({
                "id": "SEC_COOKIE_NOT_SECURE",
                "severity": "MEDIUM",
                "title": "Cookie Missing Secure Flag",
                "description": "Set-Cookie header lacks the 'Secure' attribute, allowing transmission over HTTP.",
                "remediation": "Append '; Secure' to all cookie definitions.",
            })
            score -= 5
        if "httponly" not in raw_cookie:
            findings.append({
                "id": "SEC_COOKIE_NOT_HTTPONLY",
                "severity": "MEDIUM",
                "title": "Cookie Missing HttpOnly Flag",
                "description": "Cookie lacks 'HttpOnly', allowing client-side JavaScript access.",
                "remediation": "Append '; HttpOnly' to session and auth cookies.",
            })
            score -= 5

    # Calculate final score and grade
    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
    }

    recommendations = [f["remediation"] for f in findings if "remediation" in f]

    return {
        "target": target_clean,
        "score": score,
        "grade": grade,
        "findings": findings,
        "summary": summary,
        "recommendations": recommendations,
        "headers_inspected": list(headers_detected.keys()),
        "passed_min_score": score >= min_score,
    }


# ============================================================================
# 5. Multi-Platform Hardening Config Generator
# ============================================================================

def generate_remediation_configs(
    target: str,
    server_type: str = "all",
    include_headers: bool = True,
    include_csp: bool = True,
    include_cors: bool = True,
) -> Dict[str, Any]:
    """Generate ready-to-deploy security configuration files for Netlify, Nginx, Apache, Vercel, etc."""
    csp_data = generate_csp_policy(framework="vanilla", preset="strict")
    csp_header = csp_data["csp_string"]

    files: Dict[str, str] = {}

    # Netlify TOML
    netlify_toml = f"""# Netlify Production Security Hardening Configuration
# Auto-generated by Web Security Guard v{SERVER_VERSION}

[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options = "nosniff"
    X-Frame-Options = "DENY"
    X-XSS-Protection = "0"
    Referrer-Policy = "strict-origin-when-cross-origin"
    Permissions-Policy = "camera=(), microphone=(), geolocation=(), payment=()"
    Cross-Origin-Opener-Policy = "same-origin"
    Cross-Origin-Resource-Policy = "same-origin"
    Content-Security-Policy = "{csp_header}"
"""

    # Nginx Conf
    nginx_conf = f"""# Nginx Security Headers Configuration
# Include in your server {{ ... }} or location / {{ ... }} block

server_tokens off;

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Content-Security-Policy "{csp_header}" always;
"""

    # Apache .htaccess
    apache_htaccess = f"""# Apache .htaccess Security Headers
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "0"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    Header always set Content-Security-Policy "{csp_header}"
    Header unset X-Powered-By
    Header unset Server
</IfModule>
"""

    # Vercel JSON
    vercel_json = json.dumps({
        "headers": [
            {
                "source": "/(.*)",
                "headers": [
                    {"key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload"},
                    {"key": "X-Content-Type-Options", "value": "nosniff"},
                    {"key": "X-Frame-Options", "value": "DENY"},
                    {"key": "X-XSS-Protection", "value": "0"},
                    {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
                    {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()"},
                    {"key": "Content-Security-Policy", "value": csp_header},
                ],
            }
        ]
    }, indent=2)

    # Caddyfile
    caddyfile = f"""# Caddy Server Security Headers
(security_headers) {{
    header {{
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Content-Security-Policy "{csp_header}"
        -Server
    }}
}}
"""

    # Express Helmet Snippet
    express_js = f"""// Express.js Hardening with Helmet & Safe CORS
const helmet = require('helmet');

app.use(helmet({{
  contentSecurityPolicy: {{
    directives: {json.dumps(csp_data["directives"], indent=6)}
  }},
  crossOriginOpenerPolicy: {{ policy: "same-origin" }},
  crossOriginResourcePolicy: {{ policy: "same-origin" }},
  referrerPolicy: {{ policy: "strict-origin-when-cross-origin" }},
  hsts: {{
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }}
}}));
app.disable('x-powered-by');
"""

    # HTML Meta Tags
    meta_tags = f"""<!-- Security Meta Tags -->
<meta http-equiv="Content-Security-Policy" content="{csp_header}">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta name="referrer" content="strict-origin-when-cross-origin">
"""

    st = server_type.lower()
    if st in ("all", "netlify"):
        files["netlify.toml"] = netlify_toml
    if st in ("all", "nginx"):
        files["nginx.conf"] = nginx_conf
    if st in ("all", "apache"):
        files[".htaccess"] = apache_htaccess
    if st in ("all", "vercel"):
        files["vercel.json"] = vercel_json
    if st in ("all", "caddy"):
        files["Caddyfile"] = caddyfile
    if st in ("all", "express", "node"):
        files["helmet-express.js"] = express_js
    if st in ("all", "html", "meta"):
        files["security-meta.html"] = meta_tags

    return {
        "target": target,
        "server_type": server_type,
        "files": files,
        "file_count": len(files),
        "csp_policy": csp_header,
        "instructions": "Place the generated configuration files into your project root or web server config directory.",
    }


# ============================================================================
# 6. TLS / SSL Certificate & Cipher Suite Inspector
# ============================================================================

def inspect_ssl(target: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """Deep TLS certificate, cipher suite, SANs, and expiration inspector."""
    target_clean = target.strip()
    if target_clean.startswith("https://") or target_clean.startswith("http://"):
        parsed = urllib.parse.urlparse(target_clean)
        hostname = parsed.hostname or target_clean
        if parsed.port:
            port = parsed.port
    else:
        parts = target_clean.split("/")[0]
        if ":" in parts:
            host_parts = parts.split(":")
            hostname = host_parts[0]
            try:
                port = int(host_parts[1])
            except ValueError:
                pass
        else:
            hostname = parts

    hostname = hostname.strip()

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                alpn = ssock.selected_alpn_protocol()

                # Extract Subject
                subject_dict: Dict[str, str] = {}
                for rdn in cert.get("subject", ()):
                    for k, v in rdn:
                        subject_dict[k] = v

                # Extract Issuer
                issuer_dict: Dict[str, str] = {}
                for rdn in cert.get("issuer", ()):
                    for k, v in rdn:
                        issuer_dict[k] = v

                # Extract SANs
                sans: List[str] = []
                for typ, val in cert.get("subjectAltName", ()):
                    if typ in ("DNS", "IP Address"):
                        sans.append(val)

                # Parse dates
                not_before_str = cert.get("notBefore", "")
                not_after_str = cert.get("notAfter", "")

                not_after_dt = None
                if not_after_str:
                    try:
                        norm = " ".join(not_after_str.split())
                        not_after_dt = datetime.datetime.strptime(norm, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    except Exception:
                        pass

                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (not_after_dt - now).days if not_after_dt else 0

                if days_remaining > 30:
                    status = "VALID"
                elif days_remaining >= 0:
                    status = "EXPIRING_SOON"
                else:
                    status = "EXPIRED"

                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_proto = cipher[1] if cipher and len(cipher) > 1 else (tls_version or "Unknown")
                cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 0

                recommendations = []
                if tls_version == "TLSv1.2":
                    recommendations.append("Consider upgrading web server / reverse proxy to enable TLSv1.3 for 0-RTT handshakes and forward secrecy.")
                elif tls_version and tls_version < "TLSv1.2":
                    recommendations.append("Deprecated TLS version in use. Upgrade immediately to TLSv1.2 or TLSv1.3.")
                if days_remaining < 30 and days_remaining >= 0:
                    recommendations.append(f"Certificate expires soon ({days_remaining} days remaining). Renew certificate.")
                elif days_remaining < 0:
                    recommendations.append("Certificate has expired! Replace certificate immediately.")
                if cipher_bits < 128:
                    recommendations.append(f"Weak cipher key size ({cipher_bits} bits). Use at least 128-bit or 256-bit ciphers.")

                return {
                    "target": target,
                    "domain": hostname,
                    "port": port,
                    "is_valid": True,
                    "status": status,
                    "tls_version": tls_version,
                    "tls_1_3_supported": tls_version == "TLSv1.3",
                    "cipher_suite": {
                        "name": cipher_name,
                        "protocol": cipher_proto,
                        "bits": cipher_bits,
                    },
                    "alpn_protocol": alpn or "http/1.1",
                    "certificate": {
                        "common_name": subject_dict.get("commonName", hostname),
                        "subject": subject_dict,
                        "issuer": issuer_dict,
                        "issuer_name": issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer",
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "days_until_expiration": days_remaining,
                        "sans": sans,
                        "san_count": len(sans),
                        "serial_number": cert.get("serialNumber", ""),
                        "version": cert.get("version", 3),
                        "ocsp_endpoints": list(cert.get("OCSP", ())),
                        "ca_issuers": list(cert.get("caIssuers", ())),
                    },
                    "recommendations": recommendations,
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "target": target,
            "domain": hostname,
            "port": port,
            "is_valid": False,
            "status": "UNTRUSTED_OR_INVALID",
            "error": str(e),
            "tls_version": "N/A",
            "tls_1_3_supported": False,
            "cipher_suite": {"name": "N/A", "protocol": "N/A", "bits": 0},
            "alpn_protocol": "N/A",
            "certificate": {
                "common_name": hostname,
                "subject": {},
                "issuer": {},
                "issuer_name": "Untrusted / Invalid",
                "not_before": "N/A",
                "not_after": "N/A",
                "days_until_expiration": 0,
                "sans": [],
                "san_count": 0,
                "serial_number": "",
                "version": 0,
                "ocsp_endpoints": [],
                "ca_issuers": [],
            },
            "recommendations": [f"SSL certificate verification failed: {str(e)}. Use a valid CA certificate."],
        }
    except Exception as e:
        return {
            "target": target,
            "domain": hostname,
            "port": port,
            "is_valid": False,
            "status": "CONNECTION_FAILED",
            "error": str(e),
            "tls_version": "N/A",
            "tls_1_3_supported": False,
            "cipher_suite": {"name": "N/A", "protocol": "N/A", "bits": 0},
            "alpn_protocol": "N/A",
            "certificate": {
                "common_name": hostname,
                "subject": {},
                "issuer": {},
                "issuer_name": "Unknown",
                "not_before": "N/A",
                "not_after": "N/A",
                "days_until_expiration": 0,
                "sans": [],
                "san_count": 0,
                "serial_number": "",
                "version": 0,
                "ocsp_endpoints": [],
                "ca_issuers": [],
            },
            "recommendations": [f"Could not complete TLS connection to {hostname}:{port} ({str(e)}). Check domain and port."],
        }


# ============================================================================
# 7. Security Posture Diff Engine
# ============================================================================

def diff_security_postures(target_a: str, target_b: str) -> Dict[str, Any]:
    """Compare two targets or before/after security postures side-by-side."""
    audit_a = audit_security(target_a)
    audit_b = audit_security(target_b)

    score_a = audit_a["score"]
    score_b = audit_b["score"]
    delta = score_b - score_a

    findings_a = {f["id"]: f for f in audit_a.get("findings", [])}
    findings_b = {f["id"]: f for f in audit_b.get("findings", [])}

    fixed_ids = set(findings_a.keys()) - set(findings_b.keys())
    new_ids = set(findings_b.keys()) - set(findings_a.keys())
    common_ids = set(findings_a.keys()) & set(findings_b.keys())

    fixed_findings = [findings_a[k] for k in sorted(fixed_ids)]
    new_findings = [findings_b[k] for k in sorted(new_ids)]
    common_findings = [findings_b[k] for k in sorted(common_ids)]

    headers_a = set(audit_a.get("headers_inspected", []))
    headers_b = set(audit_b.get("headers_inspected", []))

    if delta > 0:
        verdict = f"Security Posture Improved (+{delta} points)"
        status = "IMPROVED"
    elif delta < 0:
        verdict = f"Security Posture Regressed ({delta} points)"
        status = "REGRESSED"
    else:
        verdict = "No Score Change"
        status = "UNCHANGED"

    return {
        "target_a": target_a,
        "target_b": target_b,
        "score_a": score_a,
        "score_b": score_b,
        "score_delta": delta,
        "grade_a": audit_a["grade"],
        "grade_b": audit_b["grade"],
        "status": status,
        "verdict": verdict,
        "fixed_findings": fixed_findings,
        "fixed_count": len(fixed_findings),
        "new_findings": new_findings,
        "new_count": len(new_findings),
        "common_findings": common_findings,
        "common_count": len(common_findings),
        "headers_added": sorted(list(headers_b - headers_a)),
        "headers_removed": sorted(list(headers_a - headers_b)),
        "audit_a": audit_a,
        "audit_b": audit_b,
    }


# ============================================================================
# 8. Local Project Auto-Patcher
# ============================================================================

def patch_project(project_dir: str, platform: str = "auto", dry_run: bool = False) -> Dict[str, Any]:
    """Auto-patch local repository files with hardened security configs."""
    p_dir = os.path.abspath(project_dir.strip()) if project_dir.strip() else os.getcwd()
    plat = platform.lower().strip()

    # Detect platform if auto
    if plat == "auto":
        if os.path.exists(os.path.join(p_dir, "netlify.toml")) or os.path.exists(os.path.join(p_dir, "_headers")):
            plat = "netlify"
        elif os.path.exists(os.path.join(p_dir, "vercel.json")):
            plat = "vercel"
        elif os.path.exists(os.path.join(p_dir, "next.config.js")) or os.path.exists(os.path.join(p_dir, "next.config.mjs")) or os.path.exists(os.path.join(p_dir, "next.config.ts")):
            plat = "nextjs"
        elif os.path.exists(os.path.join(p_dir, "nginx.conf")) or os.path.exists(os.path.join(p_dir, "default.conf")):
            plat = "nginx"
        elif os.path.exists(os.path.join(p_dir, "index.html")):
            plat = "html"
        else:
            plat = "netlify"

    remediation = generate_remediation_configs(target=p_dir, server_type=plat)
    csp_data = generate_csp_policy(framework=plat if plat in ("nextjs", "react", "vue", "astro") else "vanilla", preset="strict")

    patched_files = []

    if plat in ("netlify", "all"):
        toml_path = os.path.join(p_dir, "netlify.toml")
        toml_content = remediation["files"].get("netlify.toml", "")
        if not dry_run:
            os.makedirs(p_dir, exist_ok=True)
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(toml_content)
        patched_files.append({
            "path": toml_path,
            "filename": "netlify.toml",
            "action": "created" if not os.path.exists(toml_path) else "overwritten",
            "content": toml_content,
        })

    if plat in ("vercel", "all"):
        vercel_path = os.path.join(p_dir, "vercel.json")
        vercel_content = remediation["files"].get("vercel.json", "")
        if not dry_run:
            os.makedirs(p_dir, exist_ok=True)
            with open(vercel_path, "w", encoding="utf-8") as f:
                f.write(vercel_content)
        patched_files.append({
            "path": vercel_path,
            "filename": "vercel.json",
            "action": "created" if not os.path.exists(vercel_path) else "overwritten",
            "content": vercel_content,
        })

    if plat in ("nginx", "all"):
        nginx_path = os.path.join(p_dir, "security-headers.conf")
        nginx_content = remediation["files"].get("nginx.conf", "")
        if not dry_run:
            os.makedirs(p_dir, exist_ok=True)
            with open(nginx_path, "w", encoding="utf-8") as f:
                f.write(nginx_content)
        patched_files.append({
            "path": nginx_path,
            "filename": "security-headers.conf",
            "action": "created" if not os.path.exists(nginx_path) else "overwritten",
            "content": nginx_content,
        })

    if plat in ("nextjs", "all"):
        mw_path = os.path.join(p_dir, "middleware.ts")
        mw_content = f"""import {{ NextRequest, NextResponse }} from 'next/server';

export function middleware(request: NextRequest) {{
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const cspHeader = `{csp_data["csp_string"].replace(csp_data["nonce"], "${nonce}")}`;

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeader);

  const response = NextResponse.next({{
    request: {{
      headers: requestHeaders,
    }},
  }});

  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

  return response;
}}

export const config = {{
  matcher: [
    {{
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        {{ type: 'header', key: 'next-router-prefetch' }},
        {{ type: 'header', key: 'purpose', value: 'prefetch' }},
      ],
    }},
  ],
}};
"""
        if not dry_run:
            os.makedirs(p_dir, exist_ok=True)
            with open(mw_path, "w", encoding="utf-8") as f:
                f.write(mw_content)
        patched_files.append({
            "path": mw_path,
            "filename": "middleware.ts",
            "action": "created" if not os.path.exists(mw_path) else "overwritten",
            "content": mw_content,
        })

    if plat in ("html", "all"):
        html_path = os.path.join(p_dir, "index.html")
        meta_snippet = remediation["files"].get("security-meta.html", "")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if "<meta http-equiv=\"Content-Security-Policy\"" not in content:
                if "</head>" in content:
                    content = content.replace("</head>", f"  {meta_snippet}\n</head>")
                else:
                    content = meta_snippet + "\n" + content
                if not dry_run:
                    with open(html_path, "w", encoding="utf-8") as f:
                        f.write(content)
                patched_files.append({
                    "path": html_path,
                    "filename": "index.html",
                    "action": "injected_meta_tags",
                    "content": content,
                })
        else:
            meta_path = os.path.join(p_dir, "security-meta.html")
            if not dry_run:
                os.makedirs(p_dir, exist_ok=True)
                with open(meta_path, "w", encoding="utf-8") as f:
                    f.write(meta_snippet)
            patched_files.append({
                "path": meta_path,
                "filename": "security-meta.html",
                "action": "created",
                "content": meta_snippet,
            })

    return {
        "project_dir": p_dir,
        "platform": plat,
        "dry_run": dry_run,
        "applied": not dry_run,
        "patched_files": patched_files,
        "file_count": len(patched_files),
        "message": f"Successfully patched project for '{plat}' with hardened security headers.",
    }


# ============================================================================
# 9. MCP Client Config Generator (Claude Desktop, Cursor, Cline, Zed, Generic)
# ============================================================================

def generate_mcp_client_config(
    client_name: str,
    python_path: str = "python3",
    project_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate MCP client configuration JSON with cross-platform safe path handling."""
    cl = client_name.lower().strip()

    # Determine absolute project path and source directory
    if project_root:
        abs_root = os.path.abspath(project_root)
    else:
        abs_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    src_dir = os.path.join(abs_root, "src") if os.path.exists(os.path.join(abs_root, "src")) else abs_root

    # Cross-platform safe PYTHONPATH using os.pathsep (';' on Windows, ':' on POSIX)
    pythonpath_env = src_dir

    server_entry = {
        "command": python_path,
        "args": ["-m", "web_security_guard.cli", "mcp"],
        "env": {
            "PYTHONPATH": pythonpath_env,
        },
    }

    all_tool_names = [
        "sec_audit_site",
        "sec_generate_csp",
        "sec_generate_sri",
        "sec_inject_sri",
        "sec_check_contrast",
        "sec_generate_remediation",
        "sec_inspect_ssl",
        "sec_diff_postures",
        "sec_patch_project",
    ]

    if cl in ("claude", "claude_desktop", "claude-desktop"):
        return {
            "mcpServers": {
                "web-security-guard": server_entry
            }
        }
    elif cl in ("cursor",):
        return {
            "mcpServers": {
                "web-security-guard": server_entry
            }
        }
    elif cl in ("cline", "vscode-cline"):
        return {
            "mcpServers": {
                "web-security-guard": {
                    **server_entry,
                    "disabled": False,
                    "alwaysAllow": all_tool_names,
                }
            }
        }
    elif cl in ("zed",):
        return {
            "context_servers": {
                "web-security-guard": {
                    "command": {
                        "path": python_path,
                        "args": ["-m", "web_security_guard.cli", "mcp"],
                        "env": {
                            "PYTHONPATH": pythonpath_env,
                        },
                    }
                }
            }
        }
    else:
        # Generic MCP server descriptor
        return {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "description": "Web Security Guard MCP Server",
            "server": server_entry,
            "transport": "stdio",
            "supported_tools": all_tool_names,
        }


# ============================================================================
# 7. Model Context Protocol (MCP) Server Implementation
# ============================================================================

MCP_TOOLS_DEFINITIONS = [
    {
        "name": "sec_audit_site",
        "description": "Run live URL or local web security audit with 0-100 score, grade, and categorized findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Live URL (https://...) or local file/directory path to audit.",
                },
                "min_score": {
                    "type": "integer",
                    "description": "Minimum acceptable security score (0-100). Default is 0.",
                    "default": 0,
                },
                "check_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific checks to include (headers, cookies, scripts, csp, contrast, forms).",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "sec_generate_csp",
        "description": "Generate strict Content Security Policy (CSP Level 3) with nonces for specified framework.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Target framework (vanilla, nextjs, react, vue, astro, express, django, fastapi).",
                    "default": "vanilla",
                },
                "preset": {
                    "type": "string",
                    "description": "CSP preset (strict, balanced, permissive, report-only, api-only).",
                    "default": "strict",
                },
                "nonce": {
                    "type": "string",
                    "description": "Custom nonce token. If omitted, a secure random token is generated.",
                },
                "report_uri": {
                    "type": "string",
                    "description": "Reporting endpoint URL for violation logs.",
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of allowed external API or CDN origins.",
                },
                "format": {
                    "type": "string",
                    "description": "Output format (header, meta, nginx, apache, netlify, json).",
                    "default": "header",
                },
            },
        },
    },
    {
        "name": "sec_generate_sri",
        "description": "Compute Subresource Integrity (SRI) cryptographic hash for scripts and stylesheets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL, local file path, or raw source string of JavaScript or CSS.",
                },
                "algorithm": {
                    "type": "string",
                    "description": "Hash algorithm (sha256, sha384, sha512).",
                    "default": "sha384",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "sec_inject_sri",
        "description": "Inspect and inject Subresource Integrity (SRI) hashes into HTML files or snippets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "html_content_or_path": {
                    "type": "string",
                    "description": "HTML source code or path to local HTML file.",
                },
                "algorithm": {
                    "type": "string",
                    "description": "Hash algorithm (sha256, sha384, sha512).",
                    "default": "sha384",
                },
                "fetch_remote": {
                    "type": "boolean",
                    "description": "Fetch remote CDN scripts/stylesheets to compute integrity hashes.",
                    "default": True,
                },
                "save_to_file": {
                    "type": "boolean",
                    "description": "Save injected HTML back to file.",
                    "default": False,
                },
                "output_path": {
                    "type": "string",
                    "description": "Custom destination file path if saving.",
                },
            },
            "required": ["html_content_or_path"],
        },
    },
    {
        "name": "sec_check_contrast",
        "description": "Calculate WCAG 2.2 color contrast ratio and evaluate AA / AAA compliance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "fg_color": {
                    "type": "string",
                    "description": "Foreground color (Hex #RGB/#RRGGBB, RGB rgb(r,g,b), or named color).",
                },
                "bg_color": {
                    "type": "string",
                    "description": "Background color (Hex #RGB/#RRGGBB, RGB rgb(r,g,b), or named color).",
                },
                "font_size_pt": {
                    "type": "number",
                    "description": "Font size in points (e.g. 16.0).",
                    "default": 16.0,
                },
                "is_bold": {
                    "type": "boolean",
                    "description": "Whether font weight is bold (>= 700).",
                    "default": False,
                },
                "target_level": {
                    "type": "string",
                    "description": "WCAG target compliance level ('AA' or 'AAA').",
                    "default": "AA",
                },
            },
            "required": ["fg_color", "bg_color"],
        },
    },
    {
        "name": "sec_generate_remediation",
        "description": "Auto-generate multi-platform security hardening configs (Netlify, Nginx, Apache, Vercel, Express).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL or local project path to harden.",
                },
                "server_type": {
                    "type": "string",
                    "description": "Server type (all, netlify, nginx, apache, vercel, caddy, express).",
                    "default": "all",
                },
                "include_headers": {
                    "type": "boolean",
                    "description": "Generate security headers config.",
                    "default": True,
                },
                "include_csp": {
                    "type": "boolean",
                    "description": "Include strict CSP Level 3 policy.",
                    "default": True,
                },
                "include_cors": {
                    "type": "boolean",
                    "description": "Include safe CORS configuration.",
                    "default": True,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "sec_inspect_ssl",
        "description": "Deep TLS certificate, cipher suite, SANs, and expiration days inspector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname, domain, or URL (e.g. google.com or https://example.com).",
                },
                "port": {
                    "type": "integer",
                    "description": "SSL/TLS port (default: 443).",
                    "default": 443,
                },
                "timeout": {
                    "type": "number",
                    "description": "Connection timeout in seconds (default: 10.0).",
                    "default": 10.0,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "sec_diff_postures",
        "description": "Compare two websites or before/after security posture side-by-side with delta scorecards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_a": {
                    "type": "string",
                    "description": "First target URL, HTML snippet, or file path (Baseline / Before).",
                },
                "target_b": {
                    "type": "string",
                    "description": "Second target URL, HTML snippet, or file path (Hardened / After).",
                },
            },
            "required": ["target_a", "target_b"],
        },
    },
    {
        "name": "sec_patch_project",
        "description": "Auto-patch local repository with hardened security headers and server configs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Local project root directory path to patch.",
                },
                "platform": {
                    "type": "string",
                    "description": "Target platform (auto, netlify, vercel, nextjs, nginx, html). Default is auto.",
                    "default": "auto",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, simulates patching without writing files to disk.",
                    "default": False,
                },
            },
            "required": ["project_dir"],
        },
    },
]


class MCPServer:
    """Zero-dependency JSON-RPC 2.0 / Model Context Protocol Server."""

    def __init__(self, name: str = SERVER_NAME, version: str = SERVER_VERSION):
        self.name = name
        self.version = version

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch and execute an MCP tool by name."""
        if tool_name == "sec_audit_site":
            target = arguments.get("target")
            if not target:
                raise ValueError("Missing required argument 'target'")
            min_score = int(arguments.get("min_score", 0))
            check_types = arguments.get("check_types")
            return audit_security(target=target, min_score=min_score, check_types=check_types)

        elif tool_name == "sec_generate_csp":
            return generate_csp_policy(
                framework=arguments.get("framework", "vanilla"),
                preset=arguments.get("preset", "strict"),
                nonce=arguments.get("nonce"),
                report_uri=arguments.get("report_uri"),
                domains=arguments.get("domains"),
                output_format=arguments.get("format", "header"),
            )

        elif tool_name == "sec_generate_sri":
            target = arguments.get("target")
            if not target:
                raise ValueError("Missing required argument 'target'")
            algorithm = arguments.get("algorithm", "sha384")

            # Check if target is URL or file
            try:
                content, _ = fetch_or_read_content(target)
            except Exception:
                content = target.encode("utf-8")

            res = generate_sri_hash(content, algorithm)
            res["target"] = target
            return res

        elif tool_name == "sec_inject_sri":
            html_input = arguments.get("html_content_or_path")
            if not html_input:
                raise ValueError("Missing required argument 'html_content_or_path'")
            return inject_sri_into_html(
                html_content_or_path=html_input,
                algorithm=arguments.get("algorithm", "sha384"),
                fetch_remote=arguments.get("fetch_remote", True),
                save_to_file=arguments.get("save_to_file", False),
                output_path=arguments.get("output_path"),
            )

        elif tool_name == "sec_check_contrast":
            fg = arguments.get("fg_color")
            bg = arguments.get("bg_color")
            if not fg or not bg:
                raise ValueError("Missing required arguments 'fg_color' and 'bg_color'")
            return calculate_contrast(
                fg_color=fg,
                bg_color=bg,
                font_size_pt=float(arguments.get("font_size_pt", 16.0)),
                is_bold=bool(arguments.get("is_bold", False)),
                target_level=arguments.get("target_level", "AA"),
            )

        elif tool_name == "sec_generate_remediation":
            target = arguments.get("target")
            if not target:
                raise ValueError("Missing required argument 'target'")
            return generate_remediation_configs(
                target=target,
                server_type=arguments.get("server_type", "all"),
                include_headers=arguments.get("include_headers", True),
                include_csp=arguments.get("include_csp", True),
                include_cors=arguments.get("include_cors", True),
            )

        elif tool_name == "sec_inspect_ssl":
            target = arguments.get("target")
            if not target:
                raise ValueError("Missing required argument 'target'")
            port = int(arguments.get("port", 443))
            timeout = float(arguments.get("timeout", 10.0))
            return inspect_ssl(target=target, port=port, timeout=timeout)

        elif tool_name == "sec_diff_postures":
            target_a = arguments.get("target_a")
            target_b = arguments.get("target_b")
            if not target_a or not target_b:
                raise ValueError("Missing required arguments 'target_a' and 'target_b'")
            return diff_security_postures(target_a=target_a, target_b=target_b)

        elif tool_name == "sec_patch_project":
            project_dir = arguments.get("project_dir")
            if not project_dir:
                raise ValueError("Missing required argument 'project_dir'")
            platform = arguments.get("platform", "auto")
            dry_run = bool(arguments.get("dry_run", False))
            return patch_project(project_dir=project_dir, platform=platform, dry_run=dry_run)

        else:
            raise KeyError(f"Unknown MCP tool: '{tool_name}'")

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request dictionary."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if not method:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request: missing 'method'"},
            }

        # Notifications without response
        if method == "notifications/initialized" or method == "initialized":
            return None

        # Ping
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # Initialize
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {},
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version,
                    },
                },
            }

        # List Tools
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": MCP_TOOLS_DEFINITIONS,
                },
            }

        # Call Tool
        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                result_data = self.execute_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2),
                            }
                        ],
                        "isError": False,
                    },
                }
            except KeyError as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": str(e)},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing tool '{tool_name}': {str(e)}",
                            }
                        ],
                        "isError": True,
                    },
                }

        # Method Not Found
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: '{method}'"},
        }

    def run_stdio(self) -> None:
        """Run stdio loop reading JSON-RPC from stdin and writing to stdout."""
        # Print startup debug info to stderr so stdout remains pure JSON-RPC stream
        sys.stderr.write(f"[{SERVER_NAME}] MCP stdio server active (v{SERVER_VERSION}, Python {platform.python_version()})\n")
        sys.stderr.flush()

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # Handle Content-Length framing if present (LSP style)
                if line_stripped.startswith("Content-Length:"):
                    length = int(line_stripped.split(":")[1].strip())
                    # Read trailing headers until empty line
                    while True:
                        header_line = sys.stdin.readline().strip()
                        if not header_line:
                            break
                    raw_payload = sys.stdin.read(length)
                    data = json.loads(raw_payload)
                else:
                    data = json.loads(line_stripped)

                response = self.handle_request(data)
                if response is not None:
                    out_json = json.dumps(response)
                    sys.stdout.write(f"{out_json}\n")
                    sys.stdout.flush()

            except json.JSONDecodeError as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                sys.stdout.write(f"{json.dumps(err_resp)}\n")
                sys.stdout.flush()
            except KeyboardInterrupt:
                break
            except Exception as e:
                sys.stderr.write(f"[{SERVER_NAME}] Unexpected error: {str(e)}\n")
                sys.stderr.flush()


def run_mcp_server() -> None:
    """Entrypoint helper to run the stdio MCP server."""
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    run_mcp_server()
