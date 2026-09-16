"""
Web Security Guard - Security Remediator Module
Generates production-grade, zero-trust web server configurations, middleware,
and executive remediation plans to achieve 100/100 (A+) security ratings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import json
import time

from .auditor import AuditResult, Finding, Severity, Category, Grade


class SecurityRemediator:
    """
    Automates the generation of hardened security configurations across all major
    deployment platforms (Netlify, Vercel, Nginx, Caddy, Next.js, Astro, Apache, HTML).
    """

    # Gold-standard security header values for 100/100 (A+) compliance
    STANDARD_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), screen-wake-lock=(), accelerometer=(), gyroscope=(), magnetometer=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests;"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    def __init__(
        self,
        audit_result: Optional[AuditResult] = None,
        custom_csp: Optional[str] = None,
        domain: Optional[str] = None,
        report_uri: Optional[str] = None,
    ):
        self.audit_result = audit_result
        self.custom_csp = custom_csp
        self.domain = domain or "example.com"
        self.report_uri = report_uri

        # Prepare effective headers
        self.headers = dict(self.STANDARD_HEADERS)
        if self.custom_csp:
            self.headers["Content-Security-Policy"] = self.custom_csp
        elif self.report_uri:
            self.headers["Content-Security-Policy"] += f" report-uri {self.report_uri};"

    # -------------------------------------------------------------------------
    # Platform Generators
    # -------------------------------------------------------------------------

    def generate_netlify_headers(self, path_pattern: str = "/*") -> str:
        """Generates Netlify _headers configuration file."""
        lines = [
            "# =============================================================================",
            "# Netlify Security Headers",
            "# Generated automatically by Web Security Guard (100/100 A+ Compliant)",
            "# =============================================================================",
            f"{path_pattern}",
        ]
        for k, v in self.headers.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines) + "\n"

    def generate_vercel_json(self, source_pattern: str = "/(.*)") -> str:
        """Generates Vercel vercel.json headers configuration."""
        header_entries = [{"key": k, "value": v} for k, v in self.headers.items()]
        config = {
            "$schema": "https://openapi.vercel.sh/vercel.json",
            "headers": [
                {
                    "source": source_pattern,
                    "headers": header_entries,
                }
            ],
        }
        return json.dumps(config, indent=2) + "\n"

    def generate_nginx_conf(self, location_block: str = "/") -> str:
        """Generates Nginx add_header directives."""
        lines = [
            "# =============================================================================",
            "# Nginx Security Hardening Directives",
            "# Generated automatically by Web Security Guard",
            "# Include in server {} or location {} block",
            "# =============================================================================",
        ]
        for k, v in self.headers.items():
            lines.append(f'add_header {k} "{v}" always;')
        return "\n".join(lines) + "\n"

    def generate_caddyfile(self, site_address: str = "") -> str:
        """Generates Caddy web server header directives."""
        prefix = f"{site_address} {{\n" if site_address else ""
        suffix = "\n}" if site_address else ""
        indent = "    " if site_address else ""

        lines = [
            f"{indent}# Security Headers (Web Security Guard A+ Standard)",
            f"{indent}header {{",
        ]
        for k, v in self.headers.items():
            lines.append(f'{indent}    {k} "{v}"')
        lines.append(f"{indent}}}")

        return prefix + "\n".join(lines) + suffix + "\n"

    def generate_next_config(self) -> str:
        """Generates Next.js next.config.js security headers configuration."""
        header_objects = []
        for k, v in self.headers.items():
            header_objects.append(f"          {{\n            key: '{k}',\n            value: '{v}',\n          }},")

        headers_str = "\n".join(header_objects)

        return (
            "/**\n"
            " * @type {import('next').NextConfig}\n"
            " * Generated by Web Security Guard (100/100 A+ Rating)\n"
            " */\n"
            "const nextConfig = {\n"
            "  reactStrictMode: true,\n"
            "  poweredByHeader: false,\n"
            "  async headers() {\n"
            "    return [\n"
            "      {\n"
            "        source: '/:path*',\n"
            "        headers: [\n"
            + headers_str + "\n"
            "        ],\n"
            "      },\n"
            "    ];\n"
            "  },\n"
            "};\n\n"
            "module.exports = nextConfig;\n"
        )

    def generate_astro_config(self) -> str:
        """Generates Astro configuration / middleware headers setup."""
        headers_map_entries = []
        for k, v in self.headers.items():
            headers_map_entries.append(f"      '{k}': '{v}',")
        headers_map_str = "\n".join(headers_map_entries)

        return f"""// astro.config.mjs
// Generated by Web Security Guard (100/100 A+ Rating)
import {{ defineConfig }} from 'astro/config';

export default defineConfig({{
  server: {{
    headers: {{
{headers_map_str}
    }},
  }},
}});

// ---------------------------------------------------------------------------
// Astro Middleware Example (src/middleware.ts):
// ---------------------------------------------------------------------------
// import {{ defineMiddleware }} from 'astro:middleware';
//
// export const onRequest = defineMiddleware(async (context, next) => {{
//   const response = await next();
//   const securityHeaders = {{
{headers_map_str}
//   }};
//   Object.entries(securityHeaders).forEach(([k, v]) => response.headers.set(k, v));
//   return response;
// }});
"""

    def generate_apache_htaccess(self) -> str:
        """Generates Apache HTTP Server .htaccess mod_headers configuration."""
        lines = [
            "# =============================================================================",
            "# Apache HTTP Server Security Headers (.htaccess)",
            "# Generated automatically by Web Security Guard",
            "# =============================================================================",
            "<IfModule mod_headers.c>",
        ]
        for k, v in self.headers.items():
            lines.append(f'    Header always set {k} "{v}"')
        lines.append("</IfModule>")
        return "\n".join(lines) + "\n"

    def generate_html_meta(self) -> str:
        """Generates HTML <meta> tag bundle for static hosting fallback."""
        meta_tags = [
            "<!-- Web Security Guard - Security Meta Headers Bundle -->",
            f'<meta http-equiv="Content-Security-Policy" content="{self.headers["Content-Security-Policy"]}">' ,
            f'<meta http-equiv="X-Content-Type-Options" content="{self.headers["X-Content-Type-Options"]}">' ,
            f'<meta http-equiv="Referrer-Policy" content="{self.headers["Referrer-Policy"]}">' ,
        ]
        return "\n".join(meta_tags) + "\n"

    # -------------------------------------------------------------------------
    # Executive Markdown Report
    # -------------------------------------------------------------------------

    def generate_markdown_report(self, audit_result: Optional[AuditResult] = None) -> str:
        """Generates a comprehensive SECURITY_REMEDIATION_PLAN.md executive report."""
        res = audit_result or self.audit_result

        target = res.target if res else self.domain
        score = res.score if res else 0
        grade = res.grade.value if res else "N/A"
        findings = res.findings if res else []

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in findings if f.severity == Severity.INFO)

        badge_color = "brightgreen" if score >= 85 else ("yellow" if score >= 70 else "red")
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(res.timestamp if res else time.time()))

        report_lines = [
            "# 🛡️ Web Security Guard - Executive Remediation Plan",
            "",
            f"> **Target:** `{target}`  ",
            f"> **Audit Date:** `{timestamp_str}`  ",
            f"> **Security Grade:** `[{grade}]` (Score: **{score}/100**)  ",
            f"> **Status:** `{'✅ PASSED' if res and res.passed_ci_default else '❌ ACTION REQUIRED'}`",
            "",
            "---",
            "",
            "## 📊 Executive Summary & Scorecard",
            "",
            "| Metric | Value | Status |",
            "| :--- | :---: | :--- |",
            f"| **Overall Score** | **{score} / 100** | Grade **{grade}** |",
            f"| **Critical Vulnerabilities** | **{critical_count}** | {'🚨 Immediate Action' if critical_count > 0 else '✅ Clear'} |",
            f"| **High Severity Issues** | **{high_count}** | {'⚠️ Fix Required' if high_count > 0 else '✅ Clear'} |",
            f"| **Medium Severity Issues** | **{med_count}** | {'🟡 Attention' if med_count > 0 else '✅ Clear'} |",
            f"| **Low / Info Notes** | **{low_count + info_count}** | ℹ️ Hardening |",
            "",
            "---",
            "",
            "## 🔍 Findings & Root Cause Analysis",
            "",
        ]

        if not findings:
            report_lines.append("🎉 **No vulnerabilities found! Your application demonstrates 100% gold-standard security.**\n")
        else:
            report_lines.extend([
                "| ID | Severity | Category | Finding | Deduction | Remediation |",
                "| :--- | :---: | :--- | :--- | :---: | :--- |",
            ])
            for f in findings:
                sev_icon = "🔴" if f.severity == Severity.CRITICAL else ("🟠" if f.severity == Severity.HIGH else ("🟡" if f.severity == Severity.MEDIUM else "🔵"))
                report_lines.append(
                    f"| `{f.id}` | {sev_icon} **{f.severity.value}** | `{f.category.value}` | **{f.title}**<br>_{f.description}_ | `-{f.deduction} pts` | {f.remediation_hint} |"
                )
            report_lines.append("")

        report_lines.extend([
            "---",
            "",
            "## 🛠️ Automated Copy-Paste Fixes (Achieve 100/100 A+)",
            "",
            "Select your deployment target below to apply the verified security header bundle:",
            "",
            "### 1. Netlify (`_headers`)",
            "Place this file in your publish/public directory:",
            "```http",
            self.generate_netlify_headers().strip(),
            "```",
            "",
            "### 2. Vercel (`vercel.json`)",
            "Add to your project root `vercel.json`:",
            "```json",
            self.generate_vercel_json().strip(),
            "```",
            "",
            "### 3. Nginx (`nginx.conf`)",
            "Add within your `server { ... }` or `location / { ... }` block:",
            "```nginx",
            self.generate_nginx_conf().strip(),
            "```",
            "",
            "### 4. Caddy (`Caddyfile`)",
            "Add to your Caddyfile block:",
            "```caddy",
            self.generate_caddyfile().strip(),
            "```",
            "",
            "### 5. Next.js (`next.config.js`)",
            "```javascript",
            self.generate_next_config().strip(),
            "```",
            "",
            "### 6. Apache (`.htaccess`)",
            "```apache",
            self.generate_apache_htaccess().strip(),
            "```",
            "",
            "### 7. Static HTML Meta Tags",
            "```html",
            self.generate_html_meta().strip(),
            "```",
            "",
            "---",
            "",
            "## 🍪 Cookie Hardening Protocol",
            "1. **Session & Auth Cookies**: Always specify `Secure; HttpOnly; SameSite=Lax; Path=/`",
            "2. **Strict Cookies**: For banking/admin tokens, use `SameSite=Strict`",
            "3. **Domain Prefixes**: Adopt `__Host-session_id=...; Secure; Path=/` to prevent subdomain cookie injection.",
            "",
            "## 🚫 Dark Pattern & Phishing Remediation",
            "1. **Affirmative Consent**: Ensure marketing/subscription checkboxes are unchecked by default.",
            "2. **Honest Scarcity**: Remove ungrounded countdown timers and artificial stock scarcity alerts.",
            "3. **Respectful Opt-Out**: Replace confirmshaming copy ('No thanks, I hate saving') with neutral options ('No, thanks').",
            "",
            "---",
            "Generated with ❤️ by **Web Security Guard**.",
        ])

        return "\n".join(report_lines) + "\n"

    # -------------------------------------------------------------------------
    # Batch & File Generation
    # -------------------------------------------------------------------------

    def generate_all_configs(self) -> Dict[str, str]:
        """Generates all configuration files in memory as a dictionary."""
        return {
            "_headers": self.generate_netlify_headers(),
            "vercel.json": self.generate_vercel_json(),
            "nginx.conf": self.generate_nginx_conf(),
            "Caddyfile": self.generate_caddyfile(),
            "next.config.js": self.generate_next_config(),
            "astro.config.mjs": self.generate_astro_config(),
            ".htaccess": self.generate_apache_htaccess(),
            "security-meta.html": self.generate_html_meta(),
            "SECURITY_REMEDIATION_PLAN.md": self.generate_markdown_report(),
        }

    def write_remediation_bundle(self, target_dir: Union[str, Path]) -> List[Path]:
        """Writes all hardened configuration templates to the target directory."""
        dir_path = Path(target_dir)
        dir_path.mkdir(parents=True, exist_ok=True)

        created_files: List[Path] = []
        configs = self.generate_all_configs()

        for filename, content in configs.items():
            file_path = dir_path / filename
            file_path.write_text(content, encoding="utf-8")
            created_files.append(file_path)

        return created_files
