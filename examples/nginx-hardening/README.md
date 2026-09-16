# Production Hardened Nginx Configuration Reference

This guide details the hardening measures implemented in `nginx.conf` for achieving maximum security (A+ on SSL Labs and Web Security Guard).

---

## 🔒 Hardening Features

1. **Information Leakage**: `server_tokens off;` prevents Nginx from broadcasting exact version numbers in error pages and headers.
2. **Modern TLS**: Restricted to TLS 1.2 and TLS 1.3 with forward-secret AEAD ciphers (`ECDHE` + `AES-GCM` / `CHACHA20`).
3. **OCSP Stapling**: Speeds up TLS handshakes while preserving user privacy by serving verified revocation certificates.
4. **Buffer Limit Defenses**: Mitigates buffer-overflow attacks with capped `client_body_buffer_size` and `client_header_buffer_size`.
5. **Rate Limiting**: Employs two `limit_req_zone` buckets (20 r/s for general static/dynamic assets, 5 r/s for `/api/` endpoints).
6. **Defense-in-Depth Headers**: Injects full CSP Level 3, HSTS, XFO, CORP, COEP, COOP, and Permissions-Policy.
7. **Hidden File Protection**: Explicitly denies access to dotfiles (`.git`, `.env`, `.aws`).

---

## 🚀 Syntax Testing & Deployment

```bash
# Test Nginx syntax
sudo nginx -t -c /path/to/nginx.conf

# Reload running service
sudo systemctl reload nginx

# Run comprehensive security audit
web-sec-guard audit https://your-server-domain.com
```
