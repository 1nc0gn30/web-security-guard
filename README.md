# 🛡️ Web Security Guard

<p align="center">
  <strong>Web Security Auditing, CSP Level 3 Synthesis, Subresource Integrity Engine & AI Agent MCP Studio.</strong>
</p>

<p align="center">
  <a href="https://github.com/1nc0gn30/web-security-guard/actions"><img src="https://img.shields.io/badge/CI-15%20Jobs%20Passing-1e8e3e?style=flat-square&logo=githubactions" alt="CI Status"></a>
  <a href="https://pypi.org/project/web-security-guard/"><img src="https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13-1a73e8?style=flat-square&logo=python" alt="Python Versions"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Native%20Server-9334e6?style=flat-square" alt="MCP Compatible"></a>
  <a href="https://www.w3.org/WAI/standards-guidelines/wcag/"><img src="https://img.shields.io/badge/WCAG-2.2%20AA%20%2F%20AAA-f9ab00?style=flat-square" alt="WCAG 2.2"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3c4043?style=flat-square" alt="License"></a>
</p>

---

## 🌟 Overview

**Web Security Guard** (`web-security-guard`) is a zero-dependency, high-performance security automation suite and interactive **Web Security Studio (design influenced by Material 3)**. Built for developers, DevOps engineers, and autonomous AI coding agents, it eliminates the complexity of securing modern web applications against Cross-Site Scripting (XSS), Clickjacking, MIME confusion, and supply chain tampering.

```
                  ┌───────────────────────────────────────────────┐
                  │          Web Security Studio UI               │
                  │   Material 3 Influenced  •  0-100 Grade Gauge │
                  └───────────────────────┬───────────────────────┘
                                          │
        ┌───────────────────┬─────────────┴───────┬───────────────────┐
        ▼                   ▼                     ▼                   ▼
┌───────────────┐   ┌───────────────┐     ┌───────────────┐   ┌───────────────┐
│ Live Auditor  │   │ CSP Level 3   │     │  SRI Engine   │   │   WCAG 2.2    │
│ Headers & SSR │   │ Nonces & Next │     │ Hashes & Tag  │   │ Color Contrast│
│ 10+ Vectors   │   │ Multi-Platform│     │ Auto-Inject   │   │ CB Simulation │
└───────┬───────┘   └───────┬───────┘     └───────┬───────┘   └───────┬───────┘
        │                   │                     │                   │
        └───────────────────┼─────────────────────┼───────────────────┘
                            ▼                     ▼
                  ┌───────────────────────────────────────────────┐
                  │        Model Context Protocol (MCP) Hub       │
                  │  Claude Desktop • Cursor • Cline • Zed • CLI  │
                  └───────────────────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. 🛡️ Multi-Vector Security Header Auditor
- Audits live websites or response headers against **OWASP Top 10** and modern web security guidelines.
- Computes an animated **0–100 Security Grade Gauge** ($A+, A, B, C, D, F$).
- Evaluates:
  * `Strict-Transport-Security` (HSTS duration, subdomains, preloading).
  * `Content-Security-Policy` Level 3.
  * `X-Frame-Options` & CSP `frame-ancestors`.
  * `X-Content-Type-Options: nosniff`.
  * `Referrer-Policy`, `Permissions-Policy`, `COOP`, `COEP`, `CORP`.
  * RFC 6265bis Cookie Hardening (`Secure`, `HttpOnly`, `SameSite`, `__Host-` prefixes).
  * Information Leakage detection (`Server`, `X-Powered-By`).

### 2. 🔒 CSP Level 3 Policy Builder & Framework Exporter
- Interactive synthesis of modern `'strict-dynamic'` policies with per-request cryptographic nonces.
- Eliminates vulnerable domain allowlists.
- Generates 1-click drop-in configurations for:
  * **Next.js 14/15 App Router** (`middleware.ts`)
  * **Nginx** (`nginx.conf`)
  * **Vercel** (`vercel.json`)
  * **Netlify** (`_headers` and `netlify.toml`)
  * **Cloudflare Workers**
  * **Apache** (`.htaccess`)
  * **Express.js** (`helmet`)

### 3. 🧬 Subresource Integrity (SRI) Hasher & HTML Injector
- Computes SHA-256, SHA-384, and SHA-512 base64 digests for local files or remote CDN bundles.
- Automated HTML Batch Injector parses raw HTML and inserts `integrity` and `crossorigin="anonymous"` tags to protect against supply-chain attacks.

### 4. 🎨 WCAG 2.2 Color Contrast & Color Blindness Simulator
- Exact relative luminance ($L = 0.2126 R + 0.7152 G + 0.0722 B$) calculation.
- Live compliance validation for **WCAG AA Normal (4.5:1)**, **AA Large (3:1)**, **UI Components (3:1)**, and **AAA Normal (7:1)**.
- Integrated matrix transformation simulation for **Protanopia**, **Deuteranopia**, **Tritanopia**, and **Achromatopsia**.

### 5. 🔑 High-Fidelity Secret Leakage & API Key Scanner
- Audits HTML, JS, JSON, and source bundles for 25+ exposed credential types.
- Detects AWS keys, GitHub PATs, Stripe keys, OpenAI/Anthropic tokens, Slack webhooks, Twilio SIDs, SendGrid keys, private RSA/EC keys, database connection strings, and JWTs.
- Computes Shannon entropy per token to filter false positives and auto-redacts sensitive substrings (`sk_live_...4a2f`).

### 6. 📦 Supply Chain, Script Integrity & Mixed Content Auditor
- Scans web documents for third-party `<script>`, `<link>`, `<iframe>`, `<form>`, and `<a>` elements.
- Detects missing Subresource Integrity (`integrity="sha384-..."`) on external CDNs.
- Blocks Mixed Content (RFC 6797) HTTP assets on HTTPS origins and alerts on unpinned CDN releases (`@latest`).
- Flags Reverse Tabnabbing (`target="_blank"` without `rel="noopener noreferrer"`) and insecure form POST endpoints.

### 7. 🤖 AI Agent Model Context Protocol (MCP) Hub
- Out-of-the-box MCP server compatible with **Claude Desktop**, **Cursor AI**, **Cline**, **Roo Code**, and **Zed Editor**.
- 12 registered tools including `sec_scan_secrets`, `sec_audit_supply_chain`, `sec_audit_isolation`, `sec_audit_site`, `sec_generate_csp`, and `sec_check_contrast`.

### 8. ⚡ Multi-Platform Hardening Exporter
- 1-click `.zip` bundle export containing pre-configured security files for your entire infrastructure stack.

---

## 📦 Installation & Quickstart

### Option A: Run via `uvx` (Zero Install)
```bash
# Start the Web Security Studio UI
uvx web-security-guard serve --port 8080 --open

# Audit a live URL directly from CLI
uvx web-security-guard audit https://example.com
```

### Option B: Install via `pip`
```bash
pip install web-security-guard
```

---

## 💻 CLI Usage

```bash
# 1. Audit a live website with interactive report
web-sec-guard audit https://google.com

# 2. Audit and output machine-readable JSON
web-sec-guard audit https://example.com --format json

# 3. Generate Level 3 CSP for Next.js App Router
web-sec-guard csp --preset strict_nonce --export nextjs

# 4. Compute Subresource Integrity for CDN script
web-sec-guard sri https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js

# 5. Check WCAG 2.2 Color Contrast
web-sec-guard contrast --fg "#1a73e8" --bg "#ffffff"

# 6. Scan files or bundles for leaked API keys, tokens & credentials
web-sec-guard secrets ./dist/bundle.js

# 7. Audit third-party script supply chain, SRI & mixed content
web-sec-guard supply ./index.html

# 8. Launch Web Security Studio Web UI
web-sec-guard serve --host 127.0.0.1 --port 8080 --open
```

---

## 🐍 Python SDK

```python
from web_security_guard import (
    SecurityAuditEngine,
    CSPBuilderEngine,
    SRIEngine,
    WCAGContrastEngine,
)

# 1. Run live audit
audit = SecurityAuditEngine.fetch_and_audit("https://example.com")
print(f"Grade: {audit['grade']} (Score: {audit['score']}/100)")

# 2. Build CSP Level 3 policy
csp_data = CSPBuilderEngine.generate({"preset": "strict_nonce"})
print("Next.js Middleware:\n", csp_data["frameworks"]["nextjs"])

# 3. Compute SRI hash
sri = SRIEngine.hash_content_or_url(url="https://cdn.example.com/app.js")
print("SRI Tag:", sri["script_tag"])

# 4. Evaluate WCAG 2.2 Contrast
contrast = WCAGContrastEngine.evaluate("#1a73e8", "#ffffff")
print(f"Ratio: {contrast['ratio_formatted']} | AA: {contrast['wcag_aa_normal']}")

# 5. Scan assets for leaked API keys & credentials
from web_security_guard import scan_secrets
secret_report = scan_secrets('const key = "sk-ant-api03-1234567890abcdef1234567890abcdef";')
print(f"Secrets Found: {secret_report.total_findings}, Clean: {secret_report.clean}")

# 6. Audit supply chain & subresource integrity
from web_security_guard import audit_supply_chain
supply_report = audit_supply_chain('<script src="http://insecure.com/script.js"></script>')
print(f"Supply Chain Grade: {supply_report.grade}, Score: {supply_report.supply_chain_score}/100")
```

---

## 🤖 MCP Client Configuration for AI Agents

Add `web-security-guard` to your AI editor or Claude Desktop config:

```json
{
  "mcpServers": {
    "web-security-guard": {
      "command": "uvx",
      "args": ["web-security-guard", "mcp"]
    }
  }
}
```

Detailed guides for **Cursor**, **Cline**, **Zed**, and **Claude Desktop** are available in [`docs/MCP_GUIDE.md`](./docs/MCP_GUIDE.md).

---

## 📚 Documentation & Reference Examples

- 🔒 **[CSP Level 3 Best Practices](./docs/CSP_BEST_PRACTICES.md)**: Deep dive into `'strict-dynamic'`, nonces, and bypassing allowlist pitfalls.
- 📋 **[Multi-Platform Deployment Matrix](./docs/PLATFORMS.md)**: Framework configurations for Next.js, Vercel, Netlify, Nginx, Cloudflare, Express, and Apache.
- 🤖 **[MCP Integration Guide](./docs/MCP_GUIDE.md)**: Complete tool signatures and prompt scenarios for LLM agents.
- 📁 **[Production Reference Examples](./examples/)**:
  * [`nextjs-app-router/`](./examples/nextjs-app-router/): Next.js 14/15 edge middleware with crypto nonces.
  * [`vercel-headers/`](./examples/vercel-headers/): Hardened `vercel.json`.
  * [`netlify-headers/`](./examples/netlify-headers/): Production `_headers` and `netlify.toml`.
  * [`nginx-hardening/`](./examples/nginx-hardening/): TLS 1.3, rate-limiting, and security headers `nginx.conf`.
  * [`cdn-sri-html/`](./examples/cdn-sri-html/): HTML5 document with SHA-384 Subresource Integrity.
  * [`mcp-clients/`](./examples/mcp-clients/): Agent configs for Claude, Cursor, Cline, and Zed.

---

## 🧪 Testing & CI

```bash
# Run unit tests with pytest
PYTHONPATH=src pytest tests/ -v
```

All 15 GitHub Actions test matrix jobs run on Python 3.9 through 3.13 on Ubuntu, macOS, and Windows.

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for details.
