"""
Web Security Guard - Security Auditor Module
Zero-dependency automated scanner for web security headers, cookie flags,
CORS misconfigurations, and dark pattern / phishing heuristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set, Tuple
import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    CSP = "Content-Security-Policy"
    HSTS = "Strict-Transport-Security"
    XFO = "X-Frame-Options"
    XCTO = "X-Content-Type-Options"
    REFERRER = "Referrer-Policy"
    PERMISSIONS = "Permissions-Policy"
    CROSS_ORIGIN = "Cross-Origin-Policies"
    CORS = "CORS-Security"
    COOKIES = "Cookie-Security"
    DARK_PATTERNS = "Dark-Patterns-Heuristics"


class Grade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class Finding:
    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    remediation_hint: str
    deduction: int = 0
    evidence: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation_hint": self.remediation_hint,
            "deduction": self.deduction,
            "evidence": self.evidence,
            "references": self.references,
        }


@dataclass
class AuditMetrics:
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    category_scores: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "category_scores": self.category_scores,
        }


@dataclass
class AuditResult:
    target: str
    target_type: str  # "url", "file", "headers", "content"
    timestamp: float
    score: int
    grade: Grade
    passed_ci_default: bool
    findings: List[Finding] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    metrics: AuditMetrics = field(default_factory=AuditMetrics)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "timestamp": self.timestamp,
            "score": self.score,
            "grade": self.grade.value,
            "passed_ci_default": self.passed_ci_default,
            "findings": [f.to_dict() for f in self.findings],
            "raw_headers": self.raw_headers,
            "cookies": self.cookies,
            "metrics": self.metrics.to_dict(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class SecurityAuditor:
    """
    Evaluates web assets and configurations against modern web security standards.
    Supports live URLs, raw headers, HTML files, and web server configurations
    (Netlify _headers, Vercel vercel.json, Nginx nginx.conf, Caddy Caddyfile, Apache .htaccess).
    """

    def __init__(self, user_agent: Optional[str] = None):
        self.user_agent = user_agent or "WebSecurityGuard-Auditor/1.0 (+https://github.com/web-security-guard)"

    # -------------------------------------------------------------------------
    # Public Audit API
    # -------------------------------------------------------------------------

    def audit_url(self, url: str, timeout: float = 10.0, check_cors: bool = True) -> AuditResult:
        """Audits a live URL over HTTP/HTTPS with optional CORS probe."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme.lower() == "https"

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        raw_headers: Dict[str, str] = {}
        cookies_list: List[str] = []
        html_body = ""
        status_code = 200

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if is_https else None) as resp:
                status_code = resp.status
                # Extract headers
                for k, v in resp.headers.items():
                    raw_headers[k.lower()] = v
                # Extract cookies
                cookies_list = resp.headers.get_all("Set-Cookie") or []
                # Read content sample
                content_bytes = resp.read(1024 * 1024)  # 1MB limit
                try:
                    charset = resp.headers.get_content_charset() or "utf-8"
                    html_body = content_bytes.decode(charset, errors="replace")
                except Exception:
                    html_body = content_bytes.decode("utf-8", errors="replace")

        except urllib.error.HTTPError as e:
            status_code = e.code
            for k, v in e.headers.items():
                raw_headers[k.lower()] = v
            cookies_list = e.headers.get_all("Set-Cookie") or []
            try:
                html_body = e.read(512 * 1024).decode("utf-8", errors="replace")
            except Exception:
                html_body = ""
        except Exception as e:
            # Return audit result indicating fetch failure
            f = Finding(
                id="CONN-FETCH-FAILED",
                category=Category.HSTS if is_https else Category.CSP,
                severity=Severity.CRITICAL,
                title="Connection/Fetch Failed",
                description=f"Could not connect to target URL: {str(e)}",
                remediation_hint="Verify host connectivity, DNS resolution, and SSL certificates.",
                deduction=50,
                evidence=str(e),
            )
            return self._build_result(
                target=url,
                target_type="url",
                findings=[f],
                raw_headers={},
                cookies=[],
                metadata={"error": str(e), "status_code": 0},
            )

        cors_reflection_vuln = False
        if check_cors and is_https:
            cors_reflection_vuln = self._probe_cors_reflection(url, timeout)

        return self.audit_headers(
            headers=raw_headers,
            cookies=cookies_list,
            url=url,
            html=html_body,
            metadata={
                "status_code": status_code,
                "is_https": is_https,
                "cors_reflection_detected": cors_reflection_vuln,
            },
            cors_reflection_detected=cors_reflection_vuln,
        )

    def audit_headers(
        self,
        headers: Dict[str, str],
        cookies: Optional[Union[List[str], str]] = None,
        url: Optional[str] = None,
        html: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        cors_reflection_detected: bool = False,
    ) -> AuditResult:
        """Audits a dictionary of HTTP response headers and optional HTML/cookies."""
        norm_headers = {k.lower().strip(): str(v).strip() for k, v in headers.items()}
        parsed_cookies: List[str] = []
        if isinstance(cookies, str):
            parsed_cookies = [cookies]
        elif isinstance(cookies, list):
            parsed_cookies = cookies

        # Also pull Set-Cookie from headers if present
        if "set-cookie" in norm_headers and not parsed_cookies:
            parsed_cookies = [norm_headers["set-cookie"]]

        target = url or "HTTP Headers"
        findings: List[Finding] = []

        is_https = True
        if url and url.startswith("http://") and not url.startswith("https://"):
            is_https = False
        if metadata and "is_https" in metadata:
            is_https = metadata["is_https"]

        # Run 10 evaluations
        findings.extend(self._eval_csp(norm_headers, html))
        findings.extend(self._eval_hsts(norm_headers, is_https))
        findings.extend(self._eval_xfo(norm_headers, findings))
        findings.extend(self._eval_xcto(norm_headers))
        findings.extend(self._eval_referrer(norm_headers))
        findings.extend(self._eval_permissions_policy(norm_headers))
        findings.extend(self._eval_cross_origin(norm_headers))
        findings.extend(self._eval_cors(norm_headers, cors_reflection_detected))
        findings.extend(self._eval_cookies(parsed_cookies, is_https))
        if html:
            findings.extend(self._eval_dark_patterns_and_phishing(html, url))

        structured_cookies = self._parse_cookies_structure(parsed_cookies)

        return self._build_result(
            target=target,
            target_type="url" if url else "headers",
            findings=findings,
            raw_headers=norm_headers,
            cookies=structured_cookies,
            metadata=metadata or {},
        )

    def audit_content(self, content: str, source_name: str = "content", content_type: str = "auto") -> AuditResult:
        """Audits raw file/text content (HTML, Netlify headers, Nginx conf, etc.)."""
        # Auto-detect content type
        if content_type == "auto":
            content_type = self._detect_content_type(content, source_name)

        if content_type == "html":
            meta_headers = self._extract_meta_headers(content)
            return self.audit_headers(headers=meta_headers, html=content, url=source_name)
        elif content_type == "netlify_headers":
            headers = self._parse_netlify_headers(content)
            return self.audit_headers(headers=headers, url=source_name)
        elif content_type == "vercel_json":
            headers = self._parse_vercel_json(content)
            return self.audit_headers(headers=headers, url=source_name)
        elif content_type == "nginx_conf":
            headers = self._parse_nginx_conf(content)
            return self.audit_headers(headers=headers, url=source_name)
        elif content_type == "caddyfile":
            headers = self._parse_caddyfile(content)
            return self.audit_headers(headers=headers, url=source_name)
        elif content_type == "htaccess":
            headers = self._parse_htaccess(content)
            return self.audit_headers(headers=headers, url=source_name)
        else:
            # Fallback: parse as generic headers or HTML
            if "<html" in content.lower() or "<!doctype html" in content.lower():
                meta_headers = self._extract_meta_headers(content)
                return self.audit_headers(headers=meta_headers, html=content, url=source_name)
            headers = self._parse_generic_headers(content)
            return self.audit_headers(headers=headers, url=source_name)

    def audit_file(self, file_path: Union[str, Path]) -> AuditResult:
        """Audits a local file (HTML or server configuration)."""
        path = Path(file_path)
        if not path.exists():
            f = Finding(
                id="FILE-NOT-FOUND",
                category=Category.CSP,
                severity=Severity.CRITICAL,
                title="Configuration File Not Found",
                description=f"File does not exist: {path}",
                remediation_hint="Check file path and accessibility.",
                deduction=100,
                evidence=str(path),
            )
            return self._build_result(
                target=str(path),
                target_type="file",
                findings=[f],
                raw_headers={},
                cookies=[],
                score_override=0,
            )

        content = path.read_text(encoding="utf-8", errors="replace")
        return self.audit_content(content, source_name=str(path))

    # -------------------------------------------------------------------------
    # Category 1: Content-Security-Policy (CSP)
    # -------------------------------------------------------------------------

    def _eval_csp(self, headers: Dict[str, str], html: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []
        csp_header = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")

        if not csp_header and html:
            meta_csp = re.search(
                r'<meta\s+http-equiv=["\']content-security-policy["\']\s+content=["\']([^"\']+)["\']',
                html,
                re.IGNORECASE,
            )
            if meta_csp:
                csp_header = meta_csp.group(1)

        if not csp_header:
            findings.append(
                Finding(
                    id="CSP-MISSING",
                    category=Category.CSP,
                    severity=Severity.HIGH,
                    title="Missing Content-Security-Policy Header",
                    description="No Content-Security-Policy header or meta tag was detected. The application is vulnerable to Cross-Site Scripting (XSS), data injection, and malicious frame execution.",
                    remediation_hint="Add a strict CSP Level 3 header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';",
                    deduction=25,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://csp.withgoogle.com"],
                )
            )
            return findings

        # Parse directives
        directives: Dict[str, List[str]] = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            dir_name = tokens[0].lower()
            dir_values = [t.lower() for t in tokens[1:]]
            directives[dir_name] = dir_values

        # 1. object-src check
        object_src = directives.get("object-src")
        default_src = directives.get("default-src")
        if not object_src and (not default_src or "'none'" not in default_src):
            findings.append(
                Finding(
                    id="CSP-OBJECT-SRC-INSECURE",
                    category=Category.CSP,
                    severity=Severity.LOW,
                    title="CSP Missing 'object-src \\'none\\''",
                    description="Missing `object-src 'none'` allows Flash and plugin execution vulnerabilities.",
                    remediation_hint="Set `object-src 'none';` in your Content-Security-Policy.",
                    deduction=5,
                    evidence=csp_header,
                )
            )
        elif object_src and "'none'" not in object_src:
            findings.append(
                Finding(
                    id="CSP-OBJECT-SRC-PERMISSIVE",
                    category=Category.CSP,
                    severity=Severity.LOW,
                    title="Permissive 'object-src' in CSP",
                    description=f"object-src directive is permissive ({' '.join(object_src)}). Plugins should be disabled.",
                    remediation_hint="Set `object-src 'none';`.",
                    deduction=4,
                    evidence="object-src " + " ".join(object_src),
                )
            )

        # 2. base-uri check
        base_uri = directives.get("base-uri")
        if not base_uri:
            findings.append(
                Finding(
                    id="CSP-BASE-URI-MISSING",
                    category=Category.CSP,
                    severity=Severity.LOW,
                    title="CSP Missing 'base-uri'",
                    description="Missing `base-uri` allows base-tag injection to redirect relative script URLs.",
                    remediation_hint="Add `base-uri 'self';` or `base-uri 'none';` to CSP.",
                    deduction=4,
                    evidence=csp_header,
                )
            )

        # 3. form-action check
        form_action = directives.get("form-action")
        if not form_action:
            findings.append(
                Finding(
                    id="CSP-FORM-ACTION-MISSING",
                    category=Category.CSP,
                    severity=Severity.LOW,
                    title="CSP Missing 'form-action'",
                    description="Missing `form-action` allows form submissions to arbitrary external endpoints.",
                    remediation_hint="Add `form-action 'self';` to restrict form submission targets.",
                    deduction=4,
                    evidence=csp_header,
                )
            )

        # 4. script-src evaluations
        script_src = directives.get("script-src") or directives.get("script-src-elem") or default_src
        if script_src:
            has_nonce_or_hash = any(
                t.startswith("'nonce-") or t.startswith("'sha256-") or t.startswith("'sha384-") or t.startswith("'sha512-")
                for t in script_src
            )
            has_strict_dynamic = "'strict-dynamic'" in script_src

            if "'unsafe-inline'" in script_src and not (has_nonce_or_hash or has_strict_dynamic):
                findings.append(
                    Finding(
                        id="CSP-SCRIPT-UNSAFE-INLINE",
                        category=Category.CSP,
                        severity=Severity.MEDIUM,
                        title="CSP Allows 'unsafe-inline' in Scripts",
                        description="`script-src 'unsafe-inline'` disables XSS protection unless paired with nonces/hashes.",
                        remediation_hint="Remove `'unsafe-inline'` and use cryptographic nonces (`'nonce-...'`) or SHA256 hashes.",
                        deduction=10,
                        evidence="script-src " + " ".join(script_src),
                    )
                )

            if "'unsafe-eval'" in script_src:
                findings.append(
                    Finding(
                        id="CSP-SCRIPT-UNSAFE-EVAL",
                        category=Category.CSP,
                        severity=Severity.MEDIUM,
                        title="CSP Allows 'unsafe-eval'",
                        description="`unsafe-eval` allows strings to be executed as code via eval(), Function(), setTimeout(string).",
                        remediation_hint="Refactor code to eliminate string evaluation and remove `'unsafe-eval'`.",
                        deduction=8,
                        evidence="script-src " + " ".join(script_src),
                    )
                )

            if "*" in script_src or "http:" in script_src or "data:" in script_src:
                findings.append(
                    Finding(
                        id="CSP-SCRIPT-WILDCARD",
                        category=Category.CSP,
                        severity=Severity.HIGH,
                        title="CSP Wildcard or Insecure Scheme in Scripts",
                        description=f"Script source contains wildcard or insecure scheme: {' '.join(script_src)}",
                        remediation_hint="Remove wildcard `*` or `data:` from script-src. Use specific trusted origins or nonces.",
                        deduction=15,
                        evidence="script-src " + " ".join(script_src),
                    )
                )

        # 5. frame-ancestors check
        frame_ancestors = directives.get("frame-ancestors")
        if not frame_ancestors:
            # We record a finding if frame-ancestors is absent in CSP
            findings.append(
                Finding(
                    id="CSP-FRAME-ANCESTORS-MISSING",
                    category=Category.CSP,
                    severity=Severity.HIGH,
                    title="CSP Missing 'frame-ancestors'",
                    description="Missing `frame-ancestors` directive allows UI redressing and clickjacking across parent frames.",
                    remediation_hint="Add `frame-ancestors 'none';` (or `'self'`) to Content-Security-Policy.",
                    deduction=8,
                    evidence=csp_header,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 2: Strict-Transport-Security (HSTS)
    # -------------------------------------------------------------------------

    def _eval_hsts(self, headers: Dict[str, str], is_https: bool) -> List[Finding]:
        findings: List[Finding] = []
        hsts = headers.get("strict-transport-security")

        if not hsts:
            findings.append(
                Finding(
                    id="HSTS-MISSING",
                    category=Category.HSTS,
                    severity=Severity.HIGH if is_https else Severity.MEDIUM,
                    title="Missing Strict-Transport-Security Header",
                    description="HSTS is not configured. Browsers can be downgraded to plaintext HTTP via SSL stripping attacks.",
                    remediation_hint="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    deduction=20,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://hstspreload.org"],
                )
            )
            return findings

        # Parse directives
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not max_age_match:
            findings.append(
                Finding(
                    id="HSTS-INVALID-MAX-AGE",
                    category=Category.HSTS,
                    severity=Severity.HIGH,
                    title="HSTS Missing or Invalid max-age",
                    description=f"HSTS header does not contain a valid max-age directive: '{hsts}'",
                    remediation_hint="Set `max-age=31536000` (at least 1 year in seconds).",
                    deduction=15,
                    evidence=hsts,
                )
            )
        else:
            max_age = int(max_age_match.group(1))
            if max_age == 0:
                findings.append(
                    Finding(
                        id="HSTS-MAX-AGE-ZERO",
                        category=Category.HSTS,
                        severity=Severity.HIGH,
                        title="HSTS max-age is Zero (Disabled)",
                        description="HSTS max-age=0 instructs the browser to clear its HSTS cache, disabling HTTPS enforcement.",
                        remediation_hint="Increase max-age to at least 31536000 seconds.",
                        deduction=18,
                        evidence=hsts,
                    )
                )
            elif max_age < 31536000:
                findings.append(
                    Finding(
                        id="HSTS-SHORT-MAX-AGE",
                        category=Category.HSTS,
                        severity=Severity.MEDIUM,
                        title="HSTS max-age is Too Short (< 1 Year)",
                        description=f"HSTS max-age={max_age} seconds ({round(max_age/86400, 1)} days) is shorter than the recommended 31536000 seconds (1 year).",
                        remediation_hint="Set `max-age=31536000` to satisfy HSTS Preload criteria.",
                        deduction=8,
                        evidence=hsts,
                    )
                )

        if "includesubdomains" not in hsts.lower():
            findings.append(
                Finding(
                    id="HSTS-MISSING-SUBDOMAINS",
                    category=Category.HSTS,
                    severity=Severity.LOW,
                    title="HSTS Missing 'includeSubDomains'",
                    description="HSTS does not include subdomains, leaving subdomains unprotected against man-in-the-middle attacks.",
                    remediation_hint="Append `; includeSubDomains` to your HSTS header.",
                    deduction=4,
                    evidence=hsts,
                )
            )

        if "preload" not in hsts.lower():
            findings.append(
                Finding(
                    id="HSTS-MISSING-PRELOAD",
                    category=Category.HSTS,
                    severity=Severity.INFO,
                    title="HSTS Missing 'preload' Directive",
                    description="HSTS header is missing the `preload` directive required for submission to Chromium's HSTS preload list.",
                    remediation_hint="Append `; preload` after ensuring long-term HTTPS stability.",
                    deduction=2,
                    evidence=hsts,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 3: X-Frame-Options (XFO)
    # -------------------------------------------------------------------------

    def _eval_xfo(self, headers: Dict[str, str], existing_findings: List[Finding]) -> List[Finding]:
        findings: List[Finding] = []
        xfo = headers.get("x-frame-options")
        has_csp_frame_ancestors = not any(f.id == "CSP-FRAME-ANCESTORS-MISSING" or f.id == "CSP-MISSING" for f in existing_findings)

        if not xfo:
            if not has_csp_frame_ancestors:
                findings.append(
                    Finding(
                        id="XFO-MISSING",
                        category=Category.XFO,
                        severity=Severity.HIGH,
                        title="Missing X-Frame-Options Header (Clickjacking Risk)",
                        description="Neither X-Frame-Options nor CSP frame-ancestors is present. Attackers can embed your site in hidden iframes to hijack clicks.",
                        remediation_hint="Set `X-Frame-Options: DENY` or `SAMEORIGIN`.",
                        deduction=10,
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="XFO-LEGACY-FALLBACK-MISSING",
                        category=Category.XFO,
                        severity=Severity.INFO,
                        title="X-Frame-Options Missing (Covered by CSP frame-ancestors)",
                        description="CSP frame-ancestors is configured, but adding X-Frame-Options: DENY provides legacy fallback for older browsers.",
                        remediation_hint="Add `X-Frame-Options: DENY` for defense-in-depth.",
                        deduction=2,
                    )
                )
            return findings

        val = xfo.strip().upper()
        if val in ("DENY", "SAMEORIGIN"):
            # Good
            pass
        elif val.startswith("ALLOW-FROM"):
            findings.append(
                Finding(
                    id="XFO-ALLOW-FROM-DEPRECATED",
                    category=Category.XFO,
                    severity=Severity.LOW,
                    title="Deprecated 'ALLOW-FROM' in X-Frame-Options",
                    description="`ALLOW-FROM` is deprecated and ignored by modern browsers. Use CSP `frame-ancestors` instead.",
                    remediation_hint="Replace with `X-Frame-Options: SAMEORIGIN` and CSP `frame-ancestors <domain>`.",
                    deduction=5,
                    evidence=xfo,
                )
            )
        else:
            findings.append(
                Finding(
                    id="XFO-INVALID-VALUE",
                    category=Category.XFO,
                    severity=Severity.LOW,
                    title="Invalid X-Frame-Options Value",
                    description=f"Unrecognized X-Frame-Options value: '{xfo}'",
                    remediation_hint="Set `X-Frame-Options: DENY` or `SAMEORIGIN`.",
                    deduction=5,
                    evidence=xfo,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 4: X-Content-Type-Options (XCTO)
    # -------------------------------------------------------------------------

    def _eval_xcto(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        xcto = headers.get("x-content-type-options")

        if not xcto:
            findings.append(
                Finding(
                    id="XCTO-MISSING",
                    category=Category.XCTO,
                    severity=Severity.MEDIUM,
                    title="Missing X-Content-Type-Options Header",
                    description="Missing `X-Content-Type-Options: nosniff`. Browsers may try to MIME-sniff response bodies, turning benign user uploads into executable scripts.",
                    remediation_hint="Set `X-Content-Type-Options: nosniff`.",
                    deduction=10,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )
        elif xcto.strip().lower() != "nosniff":
            findings.append(
                Finding(
                    id="XCTO-INVALID-VALUE",
                    category=Category.XCTO,
                    severity=Severity.MEDIUM,
                    title="Invalid X-Content-Type-Options Value",
                    description=f"Value is '{xcto}', expected 'nosniff'.",
                    remediation_hint="Set `X-Content-Type-Options: nosniff`.",
                    deduction=8,
                    evidence=xcto,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 5: Referrer-Policy
    # -------------------------------------------------------------------------

    def _eval_referrer(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        rp = headers.get("referrer-policy")

        valid_safe_policies = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }

        if not rp:
            findings.append(
                Finding(
                    id="REFERRER-POLICY-MISSING",
                    category=Category.REFERRER,
                    severity=Severity.LOW,
                    title="Missing Referrer-Policy Header",
                    description="No Referrer-Policy header found. URL query parameters containing tokens or sensitive paths may leak in Referer headers.",
                    remediation_hint="Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
                    deduction=7,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                )
            )
            return findings

        rp_clean = rp.strip().lower()
        if rp_clean == "unsafe-url":
            findings.append(
                Finding(
                    id="REFERRER-POLICY-UNSAFE-URL",
                    category=Category.REFERRER,
                    severity=Severity.MEDIUM,
                    title="Insecure Referrer-Policy 'unsafe-url'",
                    description="`unsafe-url` sends full URLs (including paths and query strings) over plaintext HTTP and cross-origin requests.",
                    remediation_hint="Replace with `strict-origin-when-cross-origin`.",
                    deduction=10,
                    evidence=rp,
                )
            )
        elif rp_clean not in valid_safe_policies:
            findings.append(
                Finding(
                    id="REFERRER-POLICY-INVALID",
                    category=Category.REFERRER,
                    severity=Severity.LOW,
                    title="Invalid Referrer-Policy Directive",
                    description=f"Unknown Referrer-Policy value: '{rp}'",
                    remediation_hint="Set `Referrer-Policy: strict-origin-when-cross-origin`.",
                    deduction=5,
                    evidence=rp,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 6: Permissions-Policy
    # -------------------------------------------------------------------------

    def _eval_permissions_policy(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        pp = headers.get("permissions-policy") or headers.get("feature-policy")

        if not pp:
            findings.append(
                Finding(
                    id="PERMISSIONS-POLICY-MISSING",
                    category=Category.PERMISSIONS,
                    severity=Severity.LOW,
                    title="Missing Permissions-Policy Header",
                    description="Permissions-Policy is missing. Powerful browser features (camera, microphone, geolocation, usb) are not explicitly restricted.",
                    remediation_hint="Set `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()`",
                    deduction=8,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                )
            )
            return findings

        # Check for overly permissive sensitive features
        sensitive_features = ["camera", "microphone", "geolocation", "payment", "usb"]
        permissive_found = []
        for feat in sensitive_features:
            if f"{feat}=*" in pp.lower() or f"{feat}=( * )" in pp.lower():
                permissive_found.append(feat)

        if permissive_found:
            findings.append(
                Finding(
                    id="PERMISSIONS-POLICY-PERMISSIVE",
                    category=Category.PERMISSIONS,
                    severity=Severity.LOW,
                    title="Overly Permissive Permissions-Policy Directives",
                    description=f"Sensors/features set to wildcard access: {', '.join(permissive_found)}",
                    remediation_hint=f"Restrict sensitive features: {', '.join(f + '=()' for f in permissive_found)}",
                    deduction=5,
                    evidence=pp,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 7: Cross-Origin Policies (COOP, COEP, CORP)
    # -------------------------------------------------------------------------

    def _eval_cross_origin(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        coop = headers.get("cross-origin-opener-policy")
        coep = headers.get("cross-origin-embedder-policy")
        corp = headers.get("cross-origin-resource-policy")

        if not coop:
            findings.append(
                Finding(
                    id="COOP-MISSING",
                    category=Category.CROSS_ORIGIN,
                    severity=Severity.LOW,
                    title="Missing Cross-Origin-Opener-Policy (COOP)",
                    description="COOP is missing. Cross-origin documents opened via window.open can retain references to your window object.",
                    remediation_hint="Set `Cross-Origin-Opener-Policy: same-origin` or `same-origin-allow-popups`.",
                    deduction=4,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"],
                )
            )

        if not coep:
            findings.append(
                Finding(
                    id="COEP-MISSING",
                    category=Category.CROSS_ORIGIN,
                    severity=Severity.LOW,
                    title="Missing Cross-Origin-Embedder-Policy (COEP)",
                    description="COEP is missing. Enables cross-origin isolation necessary for high-resolution timers and SharedArrayBuffer.",
                    remediation_hint="Set `Cross-Origin-Embedder-Policy: require-corp` or `credentialless`.",
                    deduction=3,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
                )
            )

        if not corp:
            findings.append(
                Finding(
                    id="CORP-MISSING",
                    category=Category.CROSS_ORIGIN,
                    severity=Severity.LOW,
                    title="Missing Cross-Origin-Resource-Policy (CORP)",
                    description="CORP is missing. Allows other origins to load your resources (images, scripts, json) cross-origin.",
                    remediation_hint="Set `Cross-Origin-Resource-Policy: same-origin` or `same-site`.",
                    deduction=3,
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"],
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Category 8: CORS Security
    # -------------------------------------------------------------------------

    def _eval_cors(self, headers: Dict[str, str], cors_reflection_detected: bool) -> List[Finding]:
        findings: List[Finding] = []
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")

        allow_credentials = acac is not None and acac.strip().lower() == "true"

        if cors_reflection_detected:
            findings.append(
                Finding(
                    id="CORS-ORIGIN-REFLECTION-VULN",
                    category=Category.CORS,
                    severity=Severity.CRITICAL,
                    title="Arbitrary Origin Reflection with Credentials (CORS)",
                    description="Server dynamically reflects untrusted request Origin in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true. Attackers can steal authenticated user data via cross-origin XHR/fetch.",
                    remediation_hint="Validate Origin against an explicit strict allowlist before reflecting, or disable Access-Control-Allow-Credentials.",
                    deduction=25,
                    references=["https://portswigger.net/web-security/cors"],
                )
            )

        if acao:
            acao_val = acao.strip()
            if acao_val == "*" and allow_credentials:
                findings.append(
                    Finding(
                        id="CORS-WILDCARD-WITH-CREDENTIALS",
                        category=Category.CORS,
                        severity=Severity.CRITICAL,
                        title="Insecure CORS: Wildcard Origin with Credentials",
                        description="`Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` is forbidden by browsers and indicates a dangerous misconfiguration.",
                        remediation_hint="Never combine wildcard `*` with credentials. Specify exact trusted origin.",
                        deduction=25,
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                    )
                )
            elif acao_val.lower() == "null" and allow_credentials:
                findings.append(
                    Finding(
                        id="CORS-NULL-ORIGIN-WITH-CREDENTIALS",
                        category=Category.CORS,
                        severity=Severity.HIGH,
                        title="Insecure CORS: 'null' Origin with Credentials",
                        description="`Access-Control-Allow-Origin: null` with credentials enables sandbox iframe or data-URI exploitation.",
                        remediation_hint="Disallow `null` origin in CORS headers.",
                        deduction=20,
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Category 9: Cookie Security Flags
    # -------------------------------------------------------------------------

    def _eval_cookies(self, cookie_headers: List[str], is_https: bool) -> List[Finding]:
        findings: List[Finding] = []

        for raw_cookie in cookie_headers:
            parts = [p.strip() for p in raw_cookie.split(";")]
            if not parts or not parts[0]:
                continue

            name_val = parts[0].split("=", 1)
            cookie_name = name_val[0].strip()

            lower_attrs = {p.lower().split("=")[0].strip(): p for p in parts[1:]}

            has_secure = "secure" in lower_attrs
            has_httponly = "httponly" in lower_attrs
            samesite_val = None

            for p in parts[1:]:
                if p.lower().startswith("samesite"):
                    kv = p.split("=", 1)
                    if len(kv) == 2:
                        samesite_val = kv[1].strip().lower()
                    else:
                        samesite_val = "lax"

            # 1. Secure flag
            if is_https and not has_secure:
                findings.append(
                    Finding(
                        id="COOKIE-MISSING-SECURE",
                        category=Category.COOKIES,
                        severity=Severity.HIGH,
                        title=f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                        description=f"Cookie '{cookie_name}' transmitted without the 'Secure' attribute can be intercepted in transit over unencrypted connections.",
                        remediation_hint=f"Append `; Secure` to the Set-Cookie definition for '{cookie_name}'.",
                        deduction=10,
                        evidence=raw_cookie,
                    )
                )

            # 2. HttpOnly flag
            if not has_httponly:
                findings.append(
                    Finding(
                        id="COOKIE-MISSING-HTTPONLY",
                        category=Category.COOKIES,
                        severity=Severity.MEDIUM,
                        title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        description=f"Cookie '{cookie_name}' lacks 'HttpOnly', allowing client-side JavaScript access via document.cookie (XSS token theft risk).",
                        remediation_hint=f"Append `; HttpOnly` to '{cookie_name}' unless explicit JavaScript access is required.",
                        deduction=8,
                        evidence=raw_cookie,
                    )
                )

            # 3. SameSite attribute
            if not samesite_val:
                findings.append(
                    Finding(
                        id="COOKIE-MISSING-SAMESITE",
                        category=Category.COOKIES,
                        severity=Severity.MEDIUM,
                        title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                        description=f"Cookie '{cookie_name}' lacks an explicit SameSite attribute, exposing it to Cross-Site Request Forgery (CSRF).",
                        remediation_hint=f"Set `; SameSite=Lax` or `; SameSite=Strict` on '{cookie_name}'.",
                        deduction=8,
                        evidence=raw_cookie,
                    )
                )
            elif samesite_val == "none" and not has_secure:
                findings.append(
                    Finding(
                        id="COOKIE-SAMESITE-NONE-INSECURE",
                        category=Category.COOKIES,
                        severity=Severity.HIGH,
                        title=f"Cookie '{cookie_name}' SameSite=None without Secure",
                        description=f"SameSite=None requires the 'Secure' attribute; modern browsers will reject this cookie.",
                        remediation_hint=f"Add `; Secure` when using `SameSite=None` on '{cookie_name}'.",
                        deduction=10,
                        evidence=raw_cookie,
                    )
                )

            # 4. Cookie prefix validation (__Host-, __Secure-)
            if cookie_name.startswith("__Host-"):
                if not has_secure or "path" not in lower_attrs or "domain" in lower_attrs:
                    findings.append(
                        Finding(
                            id="COOKIE-PREFIX-HOST-VIOLATION",
                            category=Category.COOKIES,
                            severity=Severity.LOW,
                            title=f"Cookie Prefix Violation on '{cookie_name}'",
                            description="`__Host-` cookies must include `Secure`, `Path=/`, and omit the `Domain` attribute.",
                            remediation_hint="Set `Secure; Path=/` and do not set `Domain`.",
                            deduction=4,
                            evidence=raw_cookie,
                        )
                    )
            elif cookie_name.startswith("__Secure-"):
                if not has_secure:
                    findings.append(
                        Finding(
                            id="COOKIE-PREFIX-SECURE-VIOLATION",
                            category=Category.COOKIES,
                            severity=Severity.LOW,
                            title=f"Cookie Prefix Violation on '{cookie_name}'",
                            description="`__Secure-` cookies must include the `Secure` attribute.",
                            remediation_hint="Append `; Secure`.",
                            deduction=4,
                            evidence=raw_cookie,
                        )
                    )

        return findings

    # -------------------------------------------------------------------------
    # Category 10: Dark Pattern & Phishing Heuristics
    # -------------------------------------------------------------------------

    def _eval_dark_patterns_and_phishing(self, html: str, url: Optional[str] = None) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Deceptive UI Cues / Fake System Alerts (CRITICAL)
        fake_alert_patterns = [
            (r"(?:your\s+pc\s+is\s+infected|system\s+warning:\s+\d+\s+viruses|call\s+microsoft\s+support\s+now|windows\s+security\s+alert:\s+trojan|spyware\s+detected|call\s+apple\s+support)", "Fake Malware/System Warning Alert"),
            (r"(?:download\s+(?:now|here|installer)\s*<\/a>[\s\S]{0,100}<a[^>]*class=[\"'][^\"']*fake-btn)", "Disguised Download Button Pattern"),
        ]
        for pattern, title in fake_alert_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        id="DECEPTIVE-UI-FAKE-ALERT",
                        category=Category.DARK_PATTERNS,
                        severity=Severity.CRITICAL,
                        title=f"Deceptive Security Alert: {title}",
                        description=f"Detected deceptive prompt or simulated operating system warning designed to scare users: '{match.group(0)[:100]}...'",
                        remediation_hint="Remove misleading security warnings and scareware UI elements.",
                        deduction=25,
                        evidence=match.group(0)[:200],
                    )
                )

        # 2. Suspicious Phishing Credential Forms (CRITICAL)
        # Form with password field posting to http:// or suspicious external endpoint
        form_matches = re.finditer(r'<form\b([^>]*)>([\s\S]*?)<\/form>', html, re.IGNORECASE)
        for form in form_matches:
            attrs = form.group(1)
            body = form.group(2)
            if re.search(r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE):
                action_match = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                if action_match:
                    action_url = action_match.group(1).strip()
                    if action_url.startswith("http://"):
                        findings.append(
                            Finding(
                                id="PHISHING-INSECURE-AUTH-SUBMIT",
                                category=Category.DARK_PATTERNS,
                                severity=Severity.CRITICAL,
                                title="Password Form Submits Over Insecure Plaintext HTTP",
                                description=f"Form containing password inputs submits credentials to plaintext URL: '{action_url}'",
                                remediation_hint="Ensure all login and credential submission forms submit to HTTPS endpoints.",
                                deduction=25,
                                evidence=f"action='{action_url}'",
                            )
                        )

        # 3. Fake Urgency / Artificial Scarcity Countdowns (MEDIUM)
        urgency_patterns = [
            (r"(?:only\s+\d+\s+(?:items?|left|seats?|tickets?)\s+(?:in\s+stock|available)|hurry[!\s]+offer\s+expires\s+in|deal\s+ends\s+in\s+\d{1,2}:\d{2}|countdown-timer|class=[\"'][^\"']*fake-urgency)", "Fake Urgency Countdown"),
            (r"(?:someone\s+in\s+[a-z\s]+\s+just\s+bought\s+this|claimed\s+\d+%\s+of\s+lightning\s+deal)", "Manufactured Social Proof / Scarcity"),
        ]
        for pattern, title in urgency_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        id="DARK-PATTERN-FAKE-URGENCY",
                        category=Category.DARK_PATTERNS,
                        severity=Severity.MEDIUM,
                        title=f"Dark Pattern: {title}",
                        description=f"Detected artificial scarcity or fake urgency manipulation: '{match.group(0)[:100]}'",
                        remediation_hint="Avoid artificial countdowns or false scarcity claims that manipulate user purchasing decisions.",
                        deduction=10,
                        evidence=match.group(0)[:150],
                        references=["https://www.ftc.gov/news-events/topics/protecting-consumer-privacy-security/dark-patterns"],
                    )
                )

        # 4. Pre-checked Consent / Marketing / Subscription Checkboxes (MEDIUM)
        prechecked_matches = re.finditer(r'<input\b([^>]*type=["\']checkbox["\'][^>]*)>', html, re.IGNORECASE)
        for chk in prechecked_matches:
            attrs = chk.group(1).lower()
            if "checked" in attrs:
                # Check if it relates to marketing, newsletter, insurance, recurring charges
                if any(k in attrs for k in ["newsletter", "promo", "marketing", "subscribe", "insurance", "recurring", "donation", "optin", "upsell", "auto-renew"]):
                    findings.append(
                        Finding(
                            id="DARK-PATTERN-PRECHECKED-CONSENT",
                            category=Category.DARK_PATTERNS,
                            severity=Severity.MEDIUM,
                            title="Dark Pattern: Pre-checked Opt-in / Marketing Checkbox",
                            description=f"Pre-checked checkbox violates GDPR/FTC guidelines for affirmative consent: '{chk.group(0)[:100]}'",
                            remediation_hint="Default checkboxes to unchecked state requiring affirmative opt-in.",
                            deduction=8,
                            evidence=chk.group(0)[:150],
                        )
                    )

        # 5. Confirmshaming / Deceptive Unsubscribe Traps (LOW/MEDIUM)
        confirmshame_patterns = [
            r"(?:no\s+thanks,\s+i\s+(?:hate|prefer\s+paying|don't\s+want\s+to\s+save)|no,\s+i\s+want\s+to\s+miss\s+out|no\s+thanks,\s+i\s+like\s+paying\s+full)",
            r"(?:unsubscribe[\s\S]{0,100}style=[\"'][^\"']*(?:font-size:\s*(?:[1-6]px|0|0\.\d+em)|color:\s*(?:transparent|#fff|#ffffff|rgba\(0,\s*0,\s*0,\s*0\))))",
        ]
        for pattern in confirmshame_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        id="DARK-PATTERN-CONFIRMSHAMING",
                        category=Category.DARK_PATTERNS,
                        severity=Severity.LOW,
                        title="Dark Pattern: Confirmshaming / Hidden Unsubscribe",
                        description=f"Detected manipulative confirmshaming language or disguised opt-out text: '{match.group(0)[:100]}'",
                        remediation_hint="Use neutral, respectful opt-out language and ensure unsubscribe controls are clearly legible.",
                        deduction=7,
                        evidence=match.group(0)[:150],
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Helper & Parser Methods
    # -------------------------------------------------------------------------

    def _probe_cors_reflection(self, url: str, timeout: float) -> bool:
        """Sends a probe request with untrusted Origin to detect reflection + credentials vulnerability."""
        probe_origin = "https://security-audit-probe.example.org"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": self.user_agent,
                    "Origin": probe_origin,
                },
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin")
                acac = resp.headers.get("Access-Control-Allow-Credentials")
                if acao == probe_origin and acac and acac.strip().lower() == "true":
                    return True
        except Exception:
            pass
        return False

    def _parse_cookies_structure(self, cookie_headers: List[str]) -> List[Dict[str, Any]]:
        cookies = []
        for raw in cookie_headers:
            parts = [p.strip() for p in raw.split(";")]
            if not parts or not parts[0]:
                continue
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip()
            val = name_val[1].strip() if len(name_val) > 1 else ""

            attrs: Dict[str, Any] = {"name": name, "value": val, "raw": raw}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    attrs[k.strip().lower()] = v.strip()
                else:
                    attrs[p.strip().lower()] = True
            cookies.append(attrs)
        return cookies

    def _detect_content_type(self, content: str, source_name: str) -> str:
        s_lower = source_name.lower()
        if s_lower.endswith(("_headers", "headers")) or "_headers" in s_lower:
            return "netlify_headers"
        if s_lower.endswith("vercel.json") or '"headers"' in content:
            return "vercel_json"
        if s_lower.endswith("nginx.conf") or "add_header" in content:
            return "nginx_conf"
        if s_lower.endswith("caddyfile") or "header {" in content:
            return "caddyfile"
        if s_lower.endswith(".htaccess") or "<ifmodule mod_headers.c>" in content.lower():
            return "htaccess"
        if s_lower.endswith((".html", ".htm")) or "<!doctype html" in content.lower() or "<html" in content.lower():
            return "html"
        return "generic_headers"

    def _extract_meta_headers(self, html: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        matches = re.finditer(
            r'<meta\s+http-equiv=["\']([^"\']+)["\']\s+content=["\']([^"\']*)["\']',
            html,
            re.IGNORECASE,
        )
        for m in matches:
            headers[m.group(1).lower().strip()] = m.group(2).strip()
        # Also try reverse attribute order (content before http-equiv)
        matches_rev = re.finditer(
            r'<meta\s+content=["\']([^"\']*)["\']\s+http-equiv=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        for m in matches_rev:
            headers[m.group(2).lower().strip()] = m.group(1).strip()
        return headers

    def _parse_netlify_headers(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("/"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def _parse_vercel_json(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        try:
            data = json.loads(content)
            headers_list = data.get("headers", [])
            for entry in headers_list:
                for h in entry.get("headers", []):
                    key = h.get("key")
                    val = h.get("value")
                    if key and val:
                        headers[key.lower().strip()] = str(val).strip()
        except Exception:
            pass
        return headers

    def _parse_nginx_conf(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        pattern = re.compile(
            r'add_header\s+([^\s]+)\s+(?:"([^"]+)"|\'([^\']+)\'|([^;\s]+))(?:\s+always)?\s*;',
            re.IGNORECASE,
        )
        for m in pattern.finditer(content):
            key = m.group(1).lower().strip()
            val = m.group(2) or m.group(3) or m.group(4) or ""
            headers[key] = val.strip()
        return headers

    def _parse_caddyfile(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        pattern = re.compile(
            r'^\s*([A-Za-z0-9-]+)\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s]+))',
            re.MULTILINE,
        )
        for m in pattern.finditer(content):
            k = m.group(1).lower().strip()
            if k not in ("header", "tls", "root", "file_server", "encode", "reverse_proxy", "import", "log", "respond"):
                val = m.group(2) or m.group(3) or m.group(4) or ""
                headers[k] = val.strip()
        return headers

    def _parse_htaccess(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        pattern = re.compile(
            r'Header\s+(?:always\s+)?set\s+([^\s]+)\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s]+))',
            re.IGNORECASE,
        )
        for m in pattern.finditer(content):
            key = m.group(1).lower().strip()
            val = m.group(2) or m.group(3) or m.group(4) or ""
            headers[key] = val.strip()
        return headers

    def _parse_generic_headers(self, content: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    # -------------------------------------------------------------------------
    # Scoring & Result Construction
    # -------------------------------------------------------------------------

    def _build_result(
        self,
        target: str,
        target_type: str,
        findings: List[Finding],
        raw_headers: Dict[str, str],
        cookies: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        score_override: Optional[int] = None,
    ) -> AuditResult:
        # Category deduction caps
        category_caps = {
            Category.CSP: 30,
            Category.HSTS: 20,
            Category.XFO: 10,
            Category.XCTO: 10,
            Category.REFERRER: 10,
            Category.PERMISSIONS: 10,
            Category.CROSS_ORIGIN: 10,
            Category.CORS: 25,
            Category.COOKIES: 20,
            Category.DARK_PATTERNS: 25,
        }

        category_deductions: Dict[Category, int] = {c: 0 for c in Category}
        for f in findings:
            category_deductions[f.category] += f.deduction

        total_deduction = 0
        cat_scores: Dict[str, int] = {}
        for cat, cap in category_caps.items():
            capped_deduction = min(category_deductions[cat], cap)
            total_deduction += capped_deduction
            cat_scores[cat.value] = max(0, 100 - int((capped_deduction / cap) * 100))

        if score_override is not None:
            score = max(0, min(100, score_override))
        else:
            score = max(0, min(100, 100 - total_deduction))

        # Determine Grade
        if score >= 95:
            grade = Grade.A_PLUS
        elif score >= 85:
            grade = Grade.A
        elif score >= 70:
            grade = Grade.B
        elif score >= 55:
            grade = Grade.C
        elif score >= 40:
            grade = Grade.D
        else:
            grade = Grade.F

        # Metrics counting
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in findings if f.severity == Severity.INFO)

        metrics = AuditMetrics(
            total_findings=len(findings),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            category_scores=cat_scores,
        )

        passed_ci = (score >= 85) and (crit_count == 0)

        return AuditResult(
            target=target,
            target_type=target_type,
            timestamp=time.time(),
            score=score,
            grade=grade,
            passed_ci_default=passed_ci,
            findings=findings,
            raw_headers=raw_headers,
            cookies=cookies,
            metrics=metrics,
            metadata=metadata or {},
        )
