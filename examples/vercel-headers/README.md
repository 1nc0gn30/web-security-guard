# Vercel Production Security Headers Reference

This configuration provides an edge-optimized, production-ready `vercel.json` file designed to secure applications hosted on Vercel's global CDN network.

---

## 🔒 Configured Headers

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Content-Security-Policy` | `default-src 'self' ...` | Prevents XSS, unauthorized data exfiltration, and script injection. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Enforces HTTPS and enables HSTS browser preloading. |
| `X-Frame-Options` | `DENY` | Prevents clickjacking in framing environments. |
| `X-Content-Type-Options` | `nosniff` | Disables MIME type sniffing. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects sensitive URL path parameters from leaking to third parties. |
| `Permissions-Policy` | `camera=(), microphone=(), ...` | Blocks unauthorized hardware API access. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates window contexts to mitigate Spectre-class attacks. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Limits asset consumption to first-party origins. |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Enforces cross-origin isolation. |

---

## 🚀 Deployment Instructions

1. Place `vercel.json` in the root of your project directory.
2. Deploy using the Vercel CLI:
   ```bash
   npx vercel --prod
   ```
3. Verify headers using `web-security-guard`:
   ```bash
   web-sec-guard audit https://your-project.vercel.app
   ```
