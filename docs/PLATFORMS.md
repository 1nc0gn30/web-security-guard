# Multi-Platform Security Headers Deployment Matrix

This document provides drop-in configurations and platform-specific nuances for deploying defense-in-depth security headers across all major modern web frameworks and hosting architectures.

---

## 📋 Comprehensive Platform Matrix

| Platform / Framework | Configuration Mechanism | Supports Dynamic Nonce | HSTS Preload | Notes & Caveats |
| :--- | :--- | :---: | :---: | :--- |
| **Next.js 14/15 (App Router)** | `middleware.ts` | ✅ Yes | ✅ Yes | Nonces can be generated on Edge runtime and passed via `x-nonce` header. |
| **Next.js (Pages / Static)** | `next.config.js` | ❌ No | ✅ Yes | Uses static `headers()` block in config. |
| **Vercel Edge** | `vercel.json` | ❌ No | ✅ Yes | Best suited for static sites or serverless functions without SSR nonces. |
| **Netlify Edge** | `_headers` / `netlify.toml` | ❌ No | ✅ Yes | Ensure multi-header merging does not duplicate CSP headers. |
| **Cloudflare Workers** | `worker.js` / Pages Functions | ✅ Yes | ✅ Yes | High performance Edge execution; can inject nonces into HTML stream. |
| **Nginx** | `nginx.conf` (`add_header`) | ⚠️ Partial (`$request_id`) | ✅ Yes | **Warning**: Nginx `add_header` in nested blocks overwrites parent headers unless re-declared. |
| **Apache HTTP Server** | `.htaccess` (`mod_headers`) | ⚠️ Partial (`%{UNIQUE_ID}e`) | ✅ Yes | Requires `mod_headers` and `mod_ssl` enabled. |
| **Caddy 2** | `Caddyfile` (`header`) | ❌ No | ✅ Yes | Automatic HTTPS with zero-config TLS certificates. |
| **Express.js / Node** | `helmet` middleware | ✅ Yes | ✅ Yes | Use `res.locals.nonce = crypto.randomBytes(16).toString('base64')`. |
| **FastAPI / Starlette** | Custom Middleware | ✅ Yes | ✅ Yes | Use `BaseHTTPMiddleware` to inject response headers. |
| **Django (Python)** | `django-csp` / SecurityMiddleware | ✅ Yes | ✅ Yes | Configure `SECURE_HSTS_SECONDS = 31536000` in `settings.py`. |
| **Ruby on Rails** | `config/initializers/content_security_policy.rb` | ✅ Yes | ✅ Yes | Native Rails 6+ CSP DSL with automatic nonce binding. |

---

## 🔧 Code Snippets by Platform

### 1. Next.js 14/15 `middleware.ts`
```typescript
import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const cspHeader = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests;`;

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeader);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  return response;
}
```

### 2. Vercel `vercel.json`
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:; object-src 'none'; frame-ancestors 'none';" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }
      ]
    }
  ]
}
```

### 3. Nginx `security-headers.conf`
```nginx
# Drop-in Security Header Include
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests;" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
server_tokens off;
```

### 4. Cloudflare Worker `index.js`
```javascript
export default {
  async fetch(request, env, ctx) {
    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);

    newHeaders.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';");
    newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    newHeaders.set('X-Frame-Options', 'DENY');
    newHeaders.set('X-Content-Type-Options', 'nosniff');
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  }
};
```

### 5. Express.js / Helmet
```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  })
);
```
