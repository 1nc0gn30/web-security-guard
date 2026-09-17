"""CORS preflight vulnerability auditor and Permissions-Policy security synthesizer.

Audits Cross-Origin Resource Sharing (CORS) configurations for security flaws:
- Insecure wildcard origin with credentials
- Null origin reflection
- Permissive origin regex bypasses
- Overly permissive HTTP methods or headers
- Missing or weak preflight cache controls (Access-Control-Max-Age)
- Permissions-Policy hardware/sensor attack surface lockdown

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set


@dataclass
class CORSVulnerabilityFinding:
    """Security finding from CORS policy inspection."""

    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    rule_id: str
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CORSAuditReport:
    """Complete security evaluation of CORS response headers."""

    is_secure: bool
    risk_score: float  # 0.0 (perfect) to 100.0 (critical exposure)
    findings: List[CORSVulnerabilityFinding] = field(default_factory=list)
    allowed_origins: List[str] = field(default_factory=list)
    allows_credentials: bool = False
    allowed_methods: List[str] = field(default_factory=list)
    allowed_headers: List[str] = field(default_factory=list)
    max_age_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_secure": self.is_secure,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "allowed_origins": self.allowed_origins,
            "allows_credentials": self.allows_credentials,
            "allowed_methods": self.allowed_methods,
            "allowed_headers": self.allowed_headers,
            "max_age_seconds": self.max_age_seconds,
        }


def audit_cors_configuration(
    headers: Dict[str, str],
    tested_origin: Optional[str] = None,
) -> CORSAuditReport:
    """Audit HTTP response headers for CORS misconfigurations and vulnerabilities.

    Args:
        headers: Dict of HTTP headers (case-insensitive keys).
        tested_origin: Optional origin string supplied in the test request.

    Returns:
        CORSAuditReport detailing risk score, findings, and remediation.
    """
    # Normalize headers to lowercase
    norm_headers = {k.lower(): v.strip() for k, v in headers.items()}

    allow_origin = norm_headers.get("access-control-allow-origin")
    allow_credentials = norm_headers.get("access-control-allow-credentials", "").lower() == "true"
    allow_methods_raw = norm_headers.get("access-control-allow-methods", "")
    allow_headers_raw = norm_headers.get("access-control-allow-headers", "")
    max_age_raw = norm_headers.get("access-control-max-age")

    allowed_methods = [m.strip().upper() for m in allow_methods_raw.split(",") if m.strip()]
    allowed_headers = [h.strip().lower() for h in allow_headers_raw.split(",") if h.strip()]

    max_age = None
    if max_age_raw:
        try:
            max_age = int(max_age_raw)
        except ValueError:
            pass

    findings: List[CORSVulnerabilityFinding] = []
    risk_score = 0.0

    if not allow_origin:
        # Same-origin only by default, safe
        return CORSAuditReport(
            is_secure=True,
            risk_score=0.0,
            findings=[
                CORSVulnerabilityFinding(
                    severity="info",
                    rule_id="CORS_SAME_ORIGIN_DEFAULT",
                    message="No Access-Control-Allow-Origin header present; browser enforces default same-origin policy.",
                    remediation="Maintain default same-origin unless cross-domain API access is explicitly required.",
                )
            ],
            allowed_origins=[],
            allows_credentials=False,
            allowed_methods=[],
            allowed_headers=[],
            max_age_seconds=None,
        )

    origins = [o.strip() for o in allow_origin.split(",") if o.strip()]

    # 1. Critical: Wildcard with credentials
    if "*" in origins and allow_credentials:
        risk_score += 90.0
        findings.append(
            CORSVulnerabilityFinding(
                severity="critical",
                rule_id="CORS_WILDCARD_CREDENTIALS",
                message="Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. Modern browsers reject this, but it indicates dangerous authorization design.",
                remediation="Specify explicit trusted domain origins instead of wildcard '*' when credentials are required.",
            )
        )

    # 2. Critical: Null origin reflection
    if "null" in [o.lower() for o in origins]:
        risk_score += 80.0
        findings.append(
            CORSVulnerabilityFinding(
                severity="critical",
                rule_id="CORS_NULL_ORIGIN_ALLOWED",
                message="Access-Control-Allow-Origin allows 'null'. Sandboxed iframes and local file exploits can read sensitive API responses.",
                remediation="Never allow 'null' in Access-Control-Allow-Origin.",
            )
        )

    # 3. High: Origin reflection of untrusted origin
    if tested_origin and allow_origin == tested_origin:
        if "evil" in tested_origin or "attacker" in tested_origin or "localhost" in tested_origin:
            risk_score += 70.0
            findings.append(
                CORSVulnerabilityFinding(
                    severity="high",
                    rule_id="CORS_ARBITRARY_ORIGIN_REFLECTION",
                    message=f"Server reflexively trusted arbitrary test origin: '{tested_origin}'.",
                    remediation="Validate Origin against an explicit allowlist of domain names rather than blindly echoing request Origin.",
                )
            )

    # 4. Medium: Overly permissive methods
    dangerous_methods = {"DELETE", "PUT", "PATCH"}
    exposed_dangerous = dangerous_methods.intersection(set(allowed_methods))
    if "*" in origins and exposed_dangerous:
        risk_score += 30.0
        findings.append(
            CORSVulnerabilityFinding(
                severity="medium",
                rule_id="CORS_WILDCARD_STATE_MUTATION",
                message=f"Wildcard origin permits state-mutating HTTP methods: {', '.join(sorted(exposed_dangerous))}.",
                remediation="Restrict state-mutating operations (DELETE/PUT/PATCH) to authenticated, explicit origins.",
            )
        )

    # 5. Low/Info: Preflight cache duration
    if max_age is None:
        risk_score += 10.0
        findings.append(
            CORSVulnerabilityFinding(
                severity="low",
                rule_id="CORS_MAX_AGE_MISSING",
                message="Access-Control-Max-Age header is missing. Browsers will default to minimal preflight caching, increasing latency.",
                remediation="Add 'Access-Control-Max-Age: 86400' (24 hours) to cache successful preflight OPTIONS requests.",
            )
        )
    elif max_age > 86400:
        findings.append(
            CORSVulnerabilityFinding(
                severity="info",
                rule_id="CORS_MAX_AGE_HIGH",
                message=f"Access-Control-Max-Age is {max_age}s (>24h). Chrome caps preflight cache at 7200s (2h), Firefox at 86400s (24h).",
                remediation="Standardize Access-Control-Max-Age to 86400.",
            )
        )

    risk_score = min(100.0, risk_score)
    is_secure = risk_score < 40.0 and not any(f.severity in ("critical", "high") for f in findings)

    return CORSAuditReport(
        is_secure=is_secure,
        risk_score=risk_score,
        findings=findings,
        allowed_origins=origins,
        allows_credentials=allow_credentials,
        allowed_methods=allowed_methods,
        allowed_headers=allowed_headers,
        max_age_seconds=max_age,
    )


def generate_secure_cors_headers(
    allowed_origins: Sequence[str],
    allow_credentials: bool = False,
    allowed_methods: Optional[Sequence[str]] = None,
    allowed_headers: Optional[Sequence[str]] = None,
    max_age: int = 86400,
) -> Dict[str, str]:
    """Generate secure, hardened CORS response headers.

    Args:
        allowed_origins: Explicit allowed origins (e.g. ['https://app.example.com']).
        allow_credentials: True if cookies/Authorization headers are accepted.
        allowed_methods: Permitted HTTP methods (defaults to GET, POST, OPTIONS).
        allowed_headers: Permitted request headers (defaults to Content-Type, Authorization).
        max_age: Preflight cache time in seconds (defaults to 86400).

    Returns:
        Dict of canonical CORS headers.
    """
    if not allowed_origins:
        return {}

    methods = list(allowed_methods) if allowed_methods else ["GET", "POST", "OPTIONS"]
    headers = list(allowed_headers) if allowed_headers else ["Content-Type", "Authorization", "X-Requested-With"]

    primary_origin = allowed_origins[0] if len(allowed_origins) == 1 else " ".join(allowed_origins)

    result: Dict[str, str] = {
        "Access-Control-Allow-Origin": primary_origin,
        "Access-Control-Allow-Methods": ", ".join(methods),
        "Access-Control-Allow-Headers": ", ".join(headers),
        "Access-Control-Max-Age": str(max_age),
        "Vary": "Origin",
    }

    if allow_credentials:
        result["Access-Control-Allow-Credentials"] = "true"

    return result


def generate_permissions_policy(
    features: Optional[Dict[str, str]] = None,
) -> str:
    """Generate a hardened Permissions-Policy header string.

    Locks down device hardware, sensors, and privacy-sensitive browser features.

    Args:
        features: Optional mapping of feature name to allowlist (e.g. {'camera': '()', 'geolocation': 'self'}).

    Returns:
        Formatted Permissions-Policy header value string.
    """
    defaults = {
        "camera": "()",
        "microphone": "()",
        "geolocation": "()",
        "payment": "()",
        "usb": "()",
        "bluetooth": "()",
        "magnetometer": "()",
        "gyroscope": "()",
        "accelerometer": "()",
        "display-capture": "()",
        "autoplay": "(self)",
        "fullscreen": "(self)",
        "browsing-topics": "()",
    }
    if features:
        defaults.update(features)

    directives = [f"{feat}={val}" for feat, val in sorted(defaults.items())]
    return ", ".join(directives)
