# Netlify Security Hardening Reference

This directory contains production-grade configuration files for deploying single-page apps (SPAs), Vite projects, and static sites to Netlify with full defense-in-depth header protection.

---

## 📁 Included Files

1. `_headers`: Placed in the `public/` or publish directory to inject headers on Netlify CDN edges.
2. `netlify.toml`: Unified build and headers configuration file placed in the repository root.

---

## 🛡️ Security Posture Highlights

- **A+ Grade Security**: Configured to score 95–100% on `web-security-guard` audit checks.
- **HSTS Preload Ready**: Includes `max-age=31536000; includeSubDomains; preload` for full HTTPS enforcement.
- **Strict Framing**: `X-Frame-Options: DENY` combined with CSP `frame-ancestors 'none'`.
- **Browser API Lockdown**: `Permissions-Policy` disables unnecessary hardware and device APIs.

---

## 🚀 Deployment Instructions

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy to preview
netlify deploy

# Deploy to production
netlify deploy --prod

# Verify your headers with Web Security Guard
web-sec-guard audit https://your-site.netlify.app
```
