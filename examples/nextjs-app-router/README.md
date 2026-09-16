# Next.js 14/15 App Router Security Architecture

This production reference example demonstrates implementing **Google Security best practices** for Next.js 14 and 15 (App Router) using Level 3 Content Security Policy (CSP) with dynamic cryptographic nonces and defense-in-depth headers.

---

## 🔒 Security Features

1. **CSP Level 3 Nonce Generation**:
   - Uses Edge-compatible `crypto.getRandomValues()` to generate a unique 128-bit base64-encoded nonce per HTTP request.
   - Employs `'strict-dynamic'` to trust scripts loaded dynamically by authorized root scripts, eliminating brittle domain allowlists.

2. **Server-Side Nonce Propagation**:
   - The middleware injects the generated nonce into the request header `x-nonce`.
   - Server Components and Root Layout read `await headers()` to apply `nonce={nonce}` onto `<Script>` and `<style>` tags.

3. **Complete Defense-in-Depth Headers**:
   - `Strict-Transport-Security` (HSTS) with 1-year duration, subdomains, and preload flags.
   - `X-Content-Type-Options: nosniff` (MIME sniffing defense).
   - `X-Frame-Options: DENY` (Clickjacking mitigation).
   - `Referrer-Policy: strict-origin-when-cross-origin` (Data privacy).
   - `Permissions-Policy` (Disables unused camera, microphone, geolocation, and payment APIs).
   - `Cross-Origin-Opener-Policy: same-origin` (Browsing context isolation).

---

## 📁 File Structure

- `middleware.ts`: Edge middleware that generates the nonce and injects HTTP response headers.
- `app/layout.tsx`: Root Layout extracting the nonce and binding it to scripts.

---

## 🚀 How to Run and Test

1. Copy `middleware.ts` to the root of your Next.js project.
2. In `app/layout.tsx`, extract `x-nonce` as shown in the example.
3. Test your headers using `web-security-guard`:

```bash
# Start your Next.js app
npm run dev

# Audit localhost in another terminal
web-sec-guard audit http://localhost:3000
```
