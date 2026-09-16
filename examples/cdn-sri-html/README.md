# Subresource Integrity (SRI) Reference Guide

Subresource Integrity (SRI) is a W3C web security specification that enables browsers to verify that resources fetched from third-party Content Delivery Networks (CDNs) have not been maliciously manipulated or corrupted.

---

## 🔒 Why SRI is Essential

When you include a third-party script like:
```html
<script src="https://cdn.example.com/analytics.js"></script>
```
Your application's security is entirely dependent on that CDN's infrastructure. If an attacker compromises the CDN or injects code via DNS hijacking, every visitor to your site can be exploited.

By specifying the cryptographic digest:
```html
<script 
  src="https://cdn.example.com/analytics.js" 
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" 
  crossorigin="anonymous">
</script>
```
The browser validates the cryptographic hash before execution. If a single byte differs, execution is blocked immediately.

---

## 🛠️ Generating SRI Hashes with Web Security Guard

```bash
# Calculate SRI from remote CDN URL
web-sec-guard sri https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js

# Calculate SRI from local build file
web-sec-guard sri ./dist/bundle.js --algo sha384
```
