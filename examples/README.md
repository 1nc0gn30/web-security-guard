# Web Security Guard — Production Hardening Examples Catalog

This directory provides battle-tested, zero-trust reference implementations demonstrating how to configure modern web security headers, CSP Level 3 policies, Subresource Integrity, and AI Agent integrations.

---

## 📚 Examples Directory Matrix

| Example Directory | Target Platform / Technology | Key Security Capabilities | Status |
| :--- | :--- | :--- | :--- |
| [`nextjs-app-router/`](./nextjs-app-router/) | Next.js 14/15 (App Router) | Dynamic 128-bit cryptographic nonces, `'strict-dynamic'` CSP, Server Component header forwarding | ✅ Production Ready |
| [`vercel-headers/`](./vercel-headers/) | Vercel Serverless & CDN Edge | Comprehensive `vercel.json` with HSTS preloading, Permissions-Policy, CORP/COOP isolation | ✅ Production Ready |
| [`netlify-headers/`](./netlify-headers/) | Netlify CDN Edge | `_headers` & `netlify.toml` with strict CSP, immutable caching, and XSS defense | ✅ Production Ready |
| [`nginx-hardening/`](./nginx-hardening/) | Nginx Web Server | Mozilla Modern TLS 1.3 profile, dual rate-limiting zones, buffer overflow defense, security headers | ✅ Production Ready |
| [`cdn-sri-html/`](./cdn-sri-html/) | Static HTML5 / CDNs | Subresource Integrity (SRI) with `sha384-...` digests against CDN supply-chain attacks | ✅ Production Ready |
| [`mcp-clients/`](./mcp-clients/) | AI Coding Agents | Ready-to-copy configurations for Claude Desktop, Cursor AI, Cline, Zed, and Windsurf | ✅ Production Ready |

---

## ⚡ Quick Verification

You can audit any local or remote deployment against the Google Security Guard suite:

```bash
# Audit a local Next.js dev server
web-sec-guard audit http://localhost:3000

# Audit a staging or production URL
web-sec-guard audit https://example.com --format json
```
