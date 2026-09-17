"""Cross-Origin Isolation (COOP / COEP / CORP) & XS-Leaks Defense Suite.

Audits and synthesizes headers required for W3C Cross-Origin Isolation:
- Cross-Origin-Opener-Policy (COOP): Prevents window.opener hijacking and XS-Leaks.
- Cross-Origin-Embedder-Policy (COEP): Enforces no-cors or credentialless resource embedding.
- Cross-Origin-Resource-Policy (CORP): Restricts resource reading to same-origin/same-site.

Unlocks SharedArrayBuffer, WebAssembly threads, and high-resolution performance.now()
while neutralizing Spectre side-channel memory leaks. Generates server headers and
a client-side Coi ServiceWorker polyfill for static hosting (e.g. GitHub Pages).

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Union


class COOPMode(str, Enum):
    """Cross-Origin-Opener-Policy directive values."""

    SAME_ORIGIN = "same-origin"
    SAME_ORIGIN_ALLOW_POPUPS = "same-origin-allow-popups"
    UNSAFE_NONE = "unsafe-none"


class COEPMode(str, Enum):
    """Cross-Origin-Embedder-Policy directive values."""

    REQUIRE_CORP = "require-corp"
    CREDENTIALLESS = "credentialless"
    UNSAFE_NONE = "unsafe-none"


class CORPMode(str, Enum):
    """Cross-Origin-Resource-Policy directive values."""

    SAME_ORIGIN = "same-origin"
    SAME_SITE = "same-site"
    CROSS_ORIGIN = "cross-origin"


@dataclass
class IsolationRisk:
    """Security risk or compatibility obstacle in cross-origin isolation."""

    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    attack_vector: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrossOriginIsolationReport:
    """Complete evaluation of cross-origin isolation posture and server configs."""

    is_cross_origin_isolated: bool
    coop_status: str
    coep_status: str
    corp_status: str
    shared_array_buffer_unlocked: bool
    high_res_timers_unlocked: bool
    subresource_breakage_risk: str  # Low, Medium, High
    spectre_vulnerability_score: float  # 0.0 (Hardened) to 100.0 (Exposed)
    risks: List[IsolationRisk] = field(default_factory=list)
    recommended_headers: Dict[str, str] = field(default_factory=dict)
    server_configs: Dict[str, str] = field(default_factory=dict)
    coi_serviceworker_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_cross_origin_isolated": self.is_cross_origin_isolated,
            "coop_status": self.coop_status,
            "coep_status": self.coep_status,
            "corp_status": self.corp_status,
            "shared_array_buffer_unlocked": self.shared_array_buffer_unlocked,
            "high_res_timers_unlocked": self.high_res_timers_unlocked,
            "subresource_breakage_risk": self.subresource_breakage_risk,
            "spectre_vulnerability_score": round(self.spectre_vulnerability_score, 1),
            "risks": [r.to_dict() for r in self.risks],
            "recommended_headers": self.recommended_headers,
            "server_configs": self.server_configs,
            "coi_serviceworker_code": self.coi_serviceworker_code,
        }


def generate_isolation_headers(
    coop: str = "same-origin",
    coep: str = "credentialless",
    corp: str = "same-origin",
) -> Dict[str, str]:
    """Generate standard W3C Cross-Origin Isolation response headers dictionary."""
    return {
        "Cross-Origin-Opener-Policy": coop,
        "Cross-Origin-Embedder-Policy": coep,
        "Cross-Origin-Resource-Policy": corp,
    }


def generate_coi_serviceworker(scope: str = "./") -> str:
    """Generate self-contained ServiceWorker polyfill for static hosts (e.g. GitHub Pages).

    Intercepts outgoing navigations and fetch requests and injects COOP/COEP headers
    in the client browser to unlock SharedArrayBuffer in environments without custom header control.
    """
    return f"""// coi-serviceworker v0.1.0 - Cross-Origin Isolation Polyfill for Static Hosting
// Injects COOP: same-origin & COEP: credentialless headers transparently
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {{
  if (event.request.cache === "only-if-cached" && event.request.mode !== "same-origin") {{
    return;
  }}

  event.respondWith(
    fetch(event.request)
      .then((response) => {{
        if (response.status === 0) {{
          return response;
        }}

        const newHeaders = new Headers(response.headers);
        newHeaders.set("Cross-Origin-Opener-Policy", "same-origin");
        newHeaders.set("Cross-Origin-Embedder-Policy", "credentialless");
        newHeaders.set("Cross-Origin-Resource-Policy", "same-origin");

        return new Response(response.body, {{
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        }});
      }})
      .catch((err) => console.error("[coi-serviceworker] Fetch error:", err))
  );
}});
"""


def generate_server_isolation_configs(headers: Dict[str, str]) -> Dict[str, str]:
    """Generate ready-to-use configuration files across major deployment platforms."""
    coop = headers.get("Cross-Origin-Opener-Policy", "same-origin")
    coep = headers.get("Cross-Origin-Embedder-Policy", "credentialless")
    corp = headers.get("Cross-Origin-Resource-Policy", "same-origin")

    # 1. Netlify _headers
    netlify_conf = (
        "/*\n"
        f"  Cross-Origin-Opener-Policy: {coop}\n"
        f"  Cross-Origin-Embedder-Policy: {coep}\n"
        f"  Cross-Origin-Resource-Policy: {corp}\n"
    )

    # 2. Vercel vercel.json
    vercel_obj = {
        "headers": [
            {
                "source": "/(.*)",
                "headers": [
                    {"key": "Cross-Origin-Opener-Policy", "value": coop},
                    {"key": "Cross-Origin-Embedder-Policy", "value": coep},
                    {"key": "Cross-Origin-Resource-Policy", "value": corp},
                ],
            }
        ]
    }
    vercel_conf = json.dumps(vercel_obj, indent=2)

    # 3. Nginx nginx.conf
    nginx_conf = (
        "# W3C Cross-Origin Isolation & Spectre Defense\n"
        f'add_header Cross-Origin-Opener-Policy "{coop}" always;\n'
        f'add_header Cross-Origin-Embedder-Policy "{coep}" always;\n'
        f'add_header Cross-Origin-Resource-Policy "{corp}" always;\n'
    )

    # 4. Caddy Caddyfile
    caddy_conf = (
        "# Cross-Origin Isolation Headers\n"
        "header {\n"
        f'    Cross-Origin-Opener-Policy "{coop}"\n'
        f'    Cross-Origin-Embedder-Policy "{coep}"\n'
        f'    Cross-Origin-Resource-Policy "{corp}"\n'
        "}\n"
    )

    # 5. Apache .htaccess
    apache_conf = (
        "<IfModule mod_headers.c>\n"
        f'  Header set Cross-Origin-Opener-Policy "{coop}"\n'
        f'  Header set Cross-Origin-Embedder-Policy "{coep}"\n'
        f'  Header set Cross-Origin-Resource-Policy "{corp}"\n'
        "</IfModule>\n"
    )

    # 6. Next.js next.config.js snippet
    nextjs_conf = f"""// In next.config.js
module.exports = {{
  async headers() {{
    return [
      {{
        source: '/:path*',
        headers: [
          {{ key: 'Cross-Origin-Opener-Policy', value: '{coop}' }},
          {{ key: 'Cross-Origin-Embedder-Policy', value: '{coep}' }},
          {{ key: 'Cross-Origin-Resource-Policy', value: '{corp}' }},
        ],
      }},
    ];
  }},
}};"""

    # 7. Express.js middleware snippet
    express_conf = f"""// Express.js Cross-Origin Isolation Middleware
app.use((req, res, next) => {{
  res.setHeader('Cross-Origin-Opener-Policy', '{coop}');
  res.setHeader('Cross-Origin-Embedder-Policy', '{coep}');
  res.setHeader('Cross-Origin-Resource-Policy', '{corp}');
  next();
}});"""

    return {
        "netlify_headers": netlify_conf,
        "vercel_json": vercel_conf,
        "nginx_conf": nginx_conf,
        "caddy_conf": caddy_conf,
        "apache_htaccess": apache_conf,
        "nextjs_config": nextjs_conf,
        "express_middleware": express_conf,
        "nginx": nginx_conf,
        "apache": apache_conf,
        "caddy": caddy_conf,
        "netlify": netlify_conf,
        "vercel": vercel_conf,
        "express": express_conf,
        "nextjs": nextjs_conf,
    }


def audit_cross_origin_isolation(
    headers: Optional[Dict[str, str]] = None,
    html_content: Optional[str] = None,
) -> CrossOriginIsolationReport:
    """Audit HTTP response headers and HTML for Cross-Origin Isolation and XS-Leaks vulnerabilities."""
    headers = headers or {}
    normalized = {k.lower(): str(v).strip() for k, v in headers.items()}

    coop_val = normalized.get("cross-origin-opener-policy", "")
    coep_val = normalized.get("cross-origin-embedder-policy", "")
    corp_val = normalized.get("cross-origin-resource-policy", "")

    risks: List[IsolationRisk] = []
    spectre_score = 100.0

    # 1. COOP Evaluation
    coop_ok = coop_val in ("same-origin", "same-origin-allow-popups")
    if not coop_val:
        risks.append(
            IsolationRisk(
                title="Missing Cross-Origin-Opener-Policy (COOP)",
                severity="CRITICAL",
                attack_vector="Cross-Site Window Leaks & Window Opener Hijacking",
                description="Without COOP, cross-origin documents opened via window.open() share the same browsing context group, allowing malicious sites to access window.opener or measure execution times.",
                remediation="Add header: 'Cross-Origin-Opener-Policy: same-origin'.",
            )
        )
    elif coop_val == "unsafe-none":
        risks.append(
            IsolationRisk(
                title="Insecure COOP Mode: unsafe-none",
                severity="HIGH",
                attack_vector="Window Context Sharing",
                description="COOP is explicitly set to unsafe-none, permitting other origins to interact with the window object.",
                remediation="Upgrade to 'Cross-Origin-Opener-Policy: same-origin'.",
            )
        )
    else:
        spectre_score -= 40.0

    # 2. COEP Evaluation
    coep_ok = coep_val in ("require-corp", "credentialless")
    if not coep_val:
        risks.append(
            IsolationRisk(
                title="Missing Cross-Origin-Embedder-Policy (COEP)",
                severity="CRITICAL",
                attack_vector="Spectre Side-Channel Cache Probing",
                description="Without COEP, cross-origin resources without explicit CORP headers can be loaded into memory, creating Spectre memory leak attack surfaces.",
                remediation="Add header: 'Cross-Origin-Embedder-Policy: credentialless' (recommended for compatibility) or 'require-corp'.",
            )
        )
    elif coep_val == "unsafe-none":
        risks.append(
            IsolationRisk(
                title="Insecure COEP Mode: unsafe-none",
                severity="HIGH",
                attack_vector="Spectre Cache Probing",
                description="COEP is explicitly disabled, allowing arbitrary cross-origin resources into process memory.",
                remediation="Upgrade to 'Cross-Origin-Embedder-Policy: credentialless'.",
            )
        )
    else:
        spectre_score -= 40.0

    # 3. CORP Evaluation
    if not corp_val:
        risks.append(
            IsolationRisk(
                title="Missing Cross-Origin-Resource-Policy (CORP)",
                severity="MEDIUM",
                attack_vector="Cross-Origin Resource Inclusion",
                description="Without CORP, downstream sites might embed internal assets across origins without protection.",
                remediation="Add header: 'Cross-Origin-Resource-Policy: same-origin'.",
            )
        )
    else:
        spectre_score -= 20.0

    is_isolated = coop_ok and coep_ok
    shared_array_buffer = is_isolated
    high_res_timers = is_isolated

    # 4. Subresource Breakage Analysis on HTML
    breakage_risk = "Low"
    if html_content and coep_val == "require-corp":
        # Check for third-party script or img tags without crossorigin attribute
        third_party_media = re.findall(
            r'<(img|script|link)\s+[^>]*?src=["\'](https?://[^"\']+)["\'][^>]*?>',
            html_content,
            re.IGNORECASE,
        )
        uncredentialed = [tag for tag in third_party_media if "crossorigin" not in tag]
        if len(uncredentialed) > 2:
            breakage_risk = "High"
            risks.append(
                IsolationRisk(
                    title="Subresource Block Risk under COEP: require-corp",
                    severity="WARNING",
                    attack_vector="Resource Loading Failure",
                    description=f"Found {len(uncredentialed)} third-party subresources without 'crossorigin' attributes. Under 'require-corp', these resources will fail to load unless the CDN sends a CORP header.",
                    remediation="Switch to 'Cross-Origin-Embedder-Policy: credentialless' to load third-party resources without blocking, or add crossorigin='anonymous'.",
                )
            )
        elif len(uncredentialed) > 0:
            breakage_risk = "Medium"

    rec_headers = generate_isolation_headers(
        coop="same-origin",
        coep="credentialless",
        corp="same-origin",
    )
    server_confs = generate_server_isolation_configs(rec_headers)
    sw_code = generate_coi_serviceworker()

    return CrossOriginIsolationReport(
        is_cross_origin_isolated=is_isolated,
        coop_status=coop_val or "missing",
        coep_status=coep_val or "missing",
        corp_status=corp_val or "missing",
        shared_array_buffer_unlocked=shared_array_buffer,
        high_res_timers_unlocked=high_res_timers,
        subresource_breakage_risk=breakage_risk,
        spectre_vulnerability_score=max(0.0, spectre_score),
        risks=risks,
        recommended_headers=rec_headers,
        server_configs=server_confs,
        coi_serviceworker_code=sw_code,
    )
