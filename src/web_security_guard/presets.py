"""Pre-configured Security Profiles and CSP Archetypes for web-security-guard.

Provides ready-to-deploy, industry-standard CSP configurations for zero-trust applications,
enterprise SaaS, PCI DSS 4.0 e-commerce, developer portals, API services, and media platforms.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from web_security_guard.csp import CSPBuilder


def create_strict_zero_trust_preset(
    nonce: Optional[str] = None,
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
    trusted_types: Optional[Sequence[str]] = None,
) -> CSPBuilder:
    """Build a Zero-Trust Strict CSP Level 3 policy with maximum hardening.

    Adheres to Google Strict CSP guidelines with cryptographic nonces, 'strict-dynamic',
    complete disabling of object/plugin injection, base-uri lockdown, and Trusted Types enforcement.
    """
    builder = CSPBuilder(
        default_src=["'none'"],
        img_src=["'self'", "data:"],
        font_src=["'self'"],
        connect_src=["'self'"],
        media_src=["'self'"],
        object_src=["'none'"],
        base_uri=["'none'"],
        form_action=["'self'"],
        frame_ancestors=["'none'"],
        upgrade_insecure_requests=True,
        block_all_mixed_content=True,
        require_trusted_types_for="'script'",
        trusted_types=trusted_types or ["default"],
        report_uri=report_uri,
        report_to=report_to,
    )

    builder.enable_strict_csp(
        nonce=nonce,
        enable_strict_dynamic=True,
        unsafe_inline_fallback=True,
        https_fallback=True,
        object_none=True,
        base_uri_none=True,
    )
    # Add nonce to style-src as well for strict zero-trust styling
    if builder.last_nonce:
        builder.set_directive("style-src", [f"'nonce-{builder.last_nonce}'", "'self'"])

    return builder


def create_saas_enterprise_preset(
    nonce: Optional[str] = None,
    api_domains: Optional[Sequence[str]] = None,
    cdn_domains: Optional[Sequence[str]] = None,
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
) -> CSPBuilder:
    """Build an Enterprise SaaS CSP policy balancing security and real-world multi-service integration.

    Supports secure API communication, WebSockets, external fonts (Google Fonts), CDNs, and telemetry.
    """
    apis = list(api_domains) if api_domains else ["https://api.*", "wss:"]
    cdns = list(cdn_domains) if cdn_domains else ["https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"]

    builder = CSPBuilder(
        default_src=["'self'"],
        img_src=["'self'", "data:", "https:", "blob:"],
        font_src=["'self'", "https://fonts.gstatic.com", "data:"],
        style_src=["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        connect_src=["'self'"] + apis,
        media_src=["'self'", "https:"],
        object_src=["'none'"],
        frame_src=["'self'"],
        frame_ancestors=["'self'"],
        form_action=["'self'"],
        base_uri=["'self'"],
        upgrade_insecure_requests=True,
        report_uri=report_uri,
        report_to=report_to,
    )

    script_sources = ["'self'"] + cdns
    if nonce is not None or True:
        assigned_nonce = builder.add_nonce(nonce=nonce, target_directives=("script-src",))
        script_sources.insert(0, f"'nonce-{assigned_nonce}'")
        script_sources.append("'strict-dynamic'")
        script_sources.append("'unsafe-inline'")
        script_sources.append("https:")

    builder.set_directive("script-src", script_sources)
    return builder


def create_ecommerce_pci_preset(
    nonce: Optional[str] = None,
    payment_gateways: Optional[Sequence[str]] = None,
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
) -> CSPBuilder:
    """Build a PCI DSS 4.0 compliant CSP policy (Requirement 6.4.3).

    Specifically designed to neutralize Magecart, formjacking, and client-side payment data exfiltration
    by restricting script execution and network destinations to authorized payment providers.
    """
    gateways = list(payment_gateways) if payment_gateways else [
        "https://js.stripe.com",
        "https://www.paypalobjects.com",
        "https://pay.google.com",
        "https://applepay.cdn-apple.com",
    ]

    api_endpoints = [
        "https://api.stripe.com",
        "https://api.paypal.com",
        "https://pay.google.com",
    ]

    builder = CSPBuilder(
        default_src=["'none'"],
        style_src=["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        font_src=["'self'", "https://fonts.gstatic.com"],
        img_src=["'self'", "data:", "https://*.stripe.com", "https://*.paypal.com"],
        connect_src=["'self'"] + api_endpoints,
        frame_src=["'self'"] + gateways,
        frame_ancestors=["'none'"],
        form_action=["'self'"] + gateways,
        object_src=["'none'"],
        base_uri=["'none'"],
        upgrade_insecure_requests=True,
        report_uri=report_uri,
        report_to=report_to,
    )

    assigned_nonce = builder.add_nonce(nonce=nonce, target_directives=("script-src",))
    script_sources = [f"'nonce-{assigned_nonce}'", "'self'"] + gateways
    builder.set_directive("script-src", script_sources)

    return builder


def create_developer_portal_preset(
    nonce: Optional[str] = None,
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
) -> CSPBuilder:
    """Build a developer documentation and interactive playground CSP policy.

    Permits dynamic code highlighting (Prism, Highlight.js), MathJax/KaTeX rendering, Web Workers,
    and interactive iframe sandboxes.
    """
    builder = CSPBuilder(
        default_src=["'self'"],
        script_src=[
            "'self'",
            "'unsafe-eval'",
            "'unsafe-inline'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com",
        ],
        style_src=[
            "'self'",
            "'unsafe-inline'",
            "https://fonts.googleapis.com",
            "https://cdn.jsdelivr.net",
        ],
        font_src=["'self'", "https://fonts.gstatic.com", "data:"],
        img_src=["'self'", "data:", "https:", "blob:"],
        connect_src=["'self'", "https:"],
        worker_src=["'self'", "blob:"],
        child_src=["'self'", "blob:"],
        object_src=["'none'"],
        frame_ancestors=["'self'"],
        base_uri=["'self'"],
        report_uri=report_uri,
        report_to=report_to,
    )

    if nonce:
        builder.add_nonce(nonce=nonce, target_directives=("script-src", "style-src"))

    return builder


def create_api_service_preset(
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
) -> CSPBuilder:
    """Build an API Backend lockdown CSP policy.

    Ideal for REST/GraphQL microservices that return JSON or binary data and should never execute scripts,
    embed frames, or process HTML forms.
    """
    return CSPBuilder(
        default_src=["'none'"],
        frame_ancestors=["'none'"],
        sandbox=[],  # Empty sandbox directive locks down all capabilities
        base_uri=["'none'"],
        form_action=["'none'"],
        object_src=["'none'"],
        report_uri=report_uri,
        report_to=report_to,
    )


def create_creative_media_preset(
    nonce: Optional[str] = None,
    report_uri: Optional[str] = None,
    report_to: Optional[str] = None,
) -> CSPBuilder:
    """Build a rich creative media CSP policy.

    Supports WebGL, WebAssembly ('wasm-unsafe-eval'), Blob URLs, MediaStreams, Web Workers,
    and audio/video hardware rendering.
    """
    builder = CSPBuilder(
        default_src=["'self'"],
        script_src=["'self'", "'wasm-unsafe-eval'", "blob:"],
        style_src=["'self'", "'unsafe-inline'"],
        img_src=["'self'", "data:", "blob:", "https:"],
        media_src=["'self'", "blob:", "data:", "https:"],
        connect_src=["'self'", "blob:", "data:", "https:", "wss:"],
        worker_src=["'self'", "blob:"],
        child_src=["'self'", "blob:"],
        object_src=["'none'"],
        frame_ancestors=["'self'"],
        base_uri=["'self'"],
        upgrade_insecure_requests=True,
        report_uri=report_uri,
        report_to=report_to,
    )

    if nonce:
        builder.add_nonce(nonce=nonce, target_directives=("script-src",))

    return builder


PRESETS: Dict[str, Dict[str, Any]] = {
    "strict_zero_trust": {
        "factory": create_strict_zero_trust_preset,
        "title": "Strict Zero Trust",
        "description": "Maximum security CSP Level 3 policy using nonces, strict-dynamic, and Trusted Types.",
        "compliance": ["NIST SP 800-53", "OWASP ASVS Level 3", "CSP Level 3"],
        "recommended_for": "Banking, healthcare, authentication portals, and high-security government applications.",
    },
    "saas_enterprise": {
        "factory": create_saas_enterprise_preset,
        "title": "Enterprise SaaS",
        "description": "Production SaaS policy with telemetry, WebSockets, external fonts, and secure CDNs.",
        "compliance": ["SOC 2 Type II", "ISO 27001", "OWASP Top 10"],
        "recommended_for": "B2B SaaS dashboards, cloud management consoles, and modern single-page apps.",
    },
    "ecommerce_pci": {
        "factory": create_ecommerce_pci_preset,
        "title": "E-Commerce PCI DSS 4.0",
        "description": "PCI DSS 4.0 (Req 6.4.3) compliant policy to protect checkout scripts and thwart Magecart.",
        "compliance": ["PCI DSS v4.0 Requirement 6.4.3 & 11.6.1"],
        "recommended_for": "Checkout flows, payment pages, and online storefronts processing credit cards.",
    },
    "developer_portal": {
        "factory": create_developer_portal_preset,
        "title": "Developer Portal & Docs",
        "description": "Documentation profile supporting code highlighting, syntax evaluation, and math engines.",
        "compliance": ["OWASP ASVS Level 2"],
        "recommended_for": "API docs, developer hubs, Markdown blogs, and interactive REPLs.",
    },
    "api_service": {
        "factory": create_api_service_preset,
        "title": "API Microservice Lockdown",
        "description": "Lockdown profile for JSON/gRPC/GraphQL APIs that never render browser DOM.",
        "compliance": ["OWASP API Security Top 10"],
        "recommended_for": "REST API backends, OAuth token endpoints, and webhook receivers.",
    },
    "creative_media": {
        "factory": create_creative_media_preset,
        "title": "Creative Media & WebGL",
        "description": "Rich media profile allowing WebAssembly, WebGL shaders, Blob workers, and audio/video.",
        "compliance": ["OWASP ASVS Level 2"],
        "recommended_for": "Audio/video editors, 3D WebGL games, data visualization canvases, and streaming portals.",
    },
}


def list_presets() -> List[str]:
    """Return a list of all available security preset identifiers."""
    return list(PRESETS.keys())


def get_preset_metadata(name: str) -> Dict[str, Any]:
    """Retrieve metadata, compliance details, and usage description for a named preset.

    Args:
        name: Name of the preset (e.g. 'strict_zero_trust').

    Returns:
        Metadata dictionary.

    Raises:
        KeyError: If the preset name does not exist.
    """
    key = name.lower().strip()
    if key not in PRESETS:
        available = ", ".join(PRESETS.keys())
        raise KeyError(f"Unknown preset '{name}'. Available presets: {available}")

    entry = PRESETS[key]
    return {
        "name": key,
        "title": entry["title"],
        "description": entry["description"],
        "compliance": entry["compliance"],
        "recommended_for": entry["recommended_for"],
    }


def get_preset(name: str, **kwargs: Any) -> CSPBuilder:
    """Instantiate a configured CSPBuilder for the given preset name.

    Args:
        name: Preset identifier (e.g. 'strict_zero_trust', 'saas_enterprise', 'ecommerce_pci').
        **kwargs: Optional arguments passed directly to the preset factory function.

    Returns:
        Configured CSPBuilder instance.

    Raises:
        KeyError: If the preset name is unknown.
    """
    key = name.lower().strip()
    if key not in PRESETS:
        available = ", ".join(PRESETS.keys())
        raise KeyError(f"Unknown preset '{name}'. Available presets: {available}")

    factory: Callable[..., CSPBuilder] = PRESETS[key]["factory"]
    return factory(**kwargs)
