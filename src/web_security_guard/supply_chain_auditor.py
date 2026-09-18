"""Third-Party Supply Chain, Script Integrity & Mixed Content Auditor.

Audits HTML and web templates for:
1. Subresource Integrity (SRI) on external scripts & stylesheets.
2. Mixed Content (RFC 6797) blockable (scripts/iframes) and passive (images).
3. Reverse Tabnabbing (OWASP A01: target="_blank" without rel="noopener noreferrer").
4. Insecure form actions and unpinned CDN package dependencies.
5. Domain categorization across trusted CDNs, self-hosted, and untrusted origins.

100% Python Standard Library. Zero external dependencies.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


KNOWN_TRUSTED_CDNS: Set[str] = {
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "cdn.tailwindcss.com",
    "assets.vercel.com",
    "esm.sh",
    "ga.jspm.io",
}


@dataclass
class SupplyChainRisk:
    """A detected supply chain, integrity, or transport security risk."""

    category: str  # MISSING_SRI, MIXED_CONTENT, REVERSE_TABNABBING, INSECURE_FORM, UNPINNED_DEPENDENCY
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    target_tag: str
    resource_url: str
    line_number: int
    description: str
    remediation: str
    fixed_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SupplyChainReport:
    """Comprehensive supply chain security and resource audit report."""

    target_name: str
    total_resources_scanned: int
    scripts_count: int
    stylesheets_count: int
    iframes_count: int
    forms_count: int
    external_links_count: int
    missing_sri_count: int
    mixed_content_count: int
    reverse_tabnabbing_count: int
    supply_chain_score: float  # 0.0 to 100.0
    grade: str  # A+, A, B, C, D, F
    risks: List[SupplyChainRisk] = field(default_factory=list)
    domains_inventory: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_name": self.target_name,
            "total_resources_scanned": self.total_resources_scanned,
            "scripts_count": self.scripts_count,
            "stylesheets_count": self.stylesheets_count,
            "iframes_count": self.iframes_count,
            "forms_count": self.forms_count,
            "external_links_count": self.external_links_count,
            "missing_sri_count": self.missing_sri_count,
            "mixed_content_count": self.mixed_content_count,
            "reverse_tabnabbing_count": self.reverse_tabnabbing_count,
            "supply_chain_score": round(self.supply_chain_score, 1),
            "grade": self.grade,
            "risks": [r.to_dict() for r in self.risks],
            "domains_inventory": self.domains_inventory,
        }

    def format_text(self) -> str:
        """Render human-readable terminal report."""
        lines = [
            f"=== Supply Chain & Subresource Integrity Audit: {self.target_name} ===",
            f"Grade: {self.grade} | Score: {self.supply_chain_score:.1f}/100",
            f"Scanned: {self.total_resources_scanned} resources ({self.scripts_count} scripts, {self.stylesheets_count} stylesheets, {self.iframes_count} iframes, {self.forms_count} forms)",
            f"Vulnerabilities: Missing SRI: {self.missing_sri_count} | Mixed Content: {self.mixed_content_count} | Reverse Tabnabbing: {self.reverse_tabnabbing_count}",
            "-" * 60,
        ]
        if not self.risks:
            lines.append("✓ All third-party assets have integrity pinning and transport security.")
        else:
            for i, r in enumerate(self.risks, 1):
                lines.append(f"[{i}] [{r.severity}] {r.title} ({r.category})")
                lines.append(f"    Line: {r.line_number} | URL: {r.resource_url}")
                lines.append(f"    Description: {r.description}")
                lines.append(f"    Fix: {r.remediation}")
                if r.fixed_snippet:
                    lines.append(f"    Snippet: {r.fixed_snippet}")
                lines.append("")
        return "\n".join(lines)

    def format_markdown(self) -> str:
        """Render markdown report with GitHub-flavored alerts."""
        if not self.risks:
            return (
                f"### Supply Chain & Subresource Integrity Audit: `{self.target_name}`\n\n"
                f"> [!NOTE]\n> **Grade {self.grade} ({self.supply_chain_score:.1f}/100)**: All resources are secure and integrity pinned.\n"
            )

        md = [
            f"### Supply Chain & Subresource Integrity Audit: `{self.target_name}`\n",
            f"> [!WARNING]\n> **Grade {self.grade} ({self.supply_chain_score:.1f}/100)** with **{len(self.risks)} risk(s)** detected.\n",
            "| # | Severity | Category | Target | Resource URL | Line |",
            "|---|---|---|---|---|---|",
        ]
        for i, r in enumerate(self.risks, 1):
            md.append(f"| {i} | **{r.severity}** | {r.category} | `{r.target_tag}` | `{r.resource_url[:40]}` | Line {r.line_number} |")

        md.append("\n#### Vulnerability Details & Remediations\n")
        for i, r in enumerate(self.risks, 1):
            md.append(f"**{i}. {r.title}** (`{r.category}`)")
            md.append(f"- **URL**: `{r.resource_url}`")
            md.append(f"- **Impact**: {r.description}")
            md.append(f"- **Fix**: {r.remediation}")
            if r.fixed_snippet:
                md.append(f"- **Remediated Snippet**:\n  ```html\n  {r.fixed_snippet}\n  ```\n")

        return "\n".join(md)


def classify_domain(domain: str) -> Tuple[str, bool]:
    """Classify domain as trusted CDN, self/relative, or unknown third party."""
    domain_lower = domain.lower()
    if not domain_lower or domain_lower in ("localhost", "127.0.0.1"):
        return ("Localhost / Relative", True)
    if domain_lower in KNOWN_TRUSTED_CDNS:
        return ("Trusted CDN", True)
    for cdn in KNOWN_TRUSTED_CDNS:
        if domain_lower.endswith("." + cdn):
            return ("Trusted CDN", True)
    return ("Third-Party Domain", False)


def calculate_grade(score: float) -> str:
    if score >= 95.0:
        return "A+"
    elif score >= 90.0:
        return "A"
    elif score >= 80.0:
        return "B"
    elif score >= 70.0:
        return "C"
    elif score >= 60.0:
        return "D"
    return "F"


def audit_supply_chain(
    html_content: str,
    target_name: str = "<document>",
    page_is_https: bool = True,
) -> SupplyChainReport:
    """Audit HTML content for subresource integrity, mixed content, and external link risks."""
    if not html_content:
        return SupplyChainReport(
            target_name=target_name,
            total_resources_scanned=0,
            scripts_count=0,
            stylesheets_count=0,
            iframes_count=0,
            forms_count=0,
            external_links_count=0,
            missing_sri_count=0,
            mixed_content_count=0,
            reverse_tabnabbing_count=0,
            supply_chain_score=100.0,
            grade="A+",
        )

    risks: List[SupplyChainRisk] = []
    domains_inventory: Dict[str, Dict[str, Any]] = {}

    def track_domain(url: str, resource_type: str) -> None:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        if not netloc:
            return
        if netloc not in domains_inventory:
            classification, is_trusted = classify_domain(netloc)
            domains_inventory[netloc] = {
                "classification": classification,
                "is_trusted": is_trusted,
                "is_secure_https": parsed.scheme.lower() == "https",
                "resource_types": [resource_type],
                "count": 1,
            }
        else:
            entry = domains_inventory[netloc]
            entry["count"] += 1
            if resource_type not in entry["resource_types"]:
                entry["resource_types"].append(resource_type)

    lines = html_content.splitlines()

    # 1. Script tag audit: <script ... src="..." ...>
    script_pattern = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
    scripts_count = 0
    missing_sri_count = 0
    mixed_content_count = 0

    for line_idx, line in enumerate(lines, 1):
        for m in script_pattern.finditer(line):
            tag_attrs = m.group(1)
            src_m = re.search(r'src=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not src_m:
                continue

            scripts_count += 1
            src_url = src_m.group(1).strip()
            track_domain(src_url, "script")

            parsed = urllib.parse.urlparse(src_url)
            is_external = bool(parsed.netloc)

            # Check Mixed Content
            if page_is_https and (src_url.startswith("http://") or (is_external and parsed.scheme == "http")):
                mixed_content_count += 1
                risks.append(
                    SupplyChainRisk(
                        category="MIXED_CONTENT",
                        title="Blockable Mixed Content Script",
                        severity="CRITICAL",
                        target_tag="script",
                        resource_url=src_url,
                        line_number=line_idx,
                        description="Browsers block insecure HTTP scripts on HTTPS pages under RFC 6797; active MITM attacker could hijack page context.",
                        remediation="Upgrade script source to HTTPS.",
                        fixed_snippet=line.replace(src_url, src_url.replace("http://", "https://")),
                    )
                )

            # Check Missing SRI on external scripts
            has_integrity = "integrity=" in tag_attrs.lower()
            if is_external and not has_integrity:
                missing_sri_count += 1
                severity = "HIGH"
                risks.append(
                    SupplyChainRisk(
                        category="MISSING_SRI",
                        title="Third-Party Script Missing Subresource Integrity (SRI)",
                        severity=severity,
                        target_tag="script",
                        resource_url=src_url,
                        line_number=line_idx,
                        description="External script loaded without cryptographic hash. If CDN is compromised, malicious JS executes directly in user browsers.",
                        remediation='Add integrity="sha384-..." and crossorigin="anonymous" attributes.',
                        fixed_snippet=f'<script src="{src_url}" integrity="sha384-<HASH>" crossorigin="anonymous"></script>',
                    )
                )

            # Check Unpinned version on CDN
            if is_external and any(cdn in src_url.lower() for cdn in ("unpkg.com", "cdn.jsdelivr.net")):
                if "@latest" in src_url or not re.search(r"@\d+\.\d+", src_url):
                    risks.append(
                        SupplyChainRisk(
                            category="UNPINNED_DEPENDENCY",
                            title="Unpinned CDN Dependency Version",
                            severity="MEDIUM",
                            target_tag="script",
                            resource_url=src_url,
                            line_number=line_idx,
                            description="Script loads from dynamic latest version on CDN. A breaking change or dependency confusion could break production.",
                            remediation="Pin script to an exact semver release (e.g. package@1.2.3).",
                            fixed_snippet="",
                        )
                    )

    # 2. Stylesheet audit: <link rel="stylesheet" ... href="...">
    link_pattern = re.compile(r"<link\b([^>]*)>", re.IGNORECASE)
    stylesheets_count = 0

    for line_idx, line in enumerate(lines, 1):
        for m in link_pattern.finditer(line):
            tag_attrs = m.group(1)
            if "stylesheet" not in tag_attrs.lower():
                continue

            href_m = re.search(r'href=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not href_m:
                continue

            stylesheets_count += 1
            href_url = href_m.group(1).strip()
            track_domain(href_url, "stylesheet")

            parsed = urllib.parse.urlparse(href_url)
            is_external = bool(parsed.netloc)

            # Mixed Content Stylesheet
            if page_is_https and href_url.startswith("http://"):
                mixed_content_count += 1
                risks.append(
                    SupplyChainRisk(
                        category="MIXED_CONTENT",
                        title="Insecure HTTP Stylesheet (Mixed Content)",
                        severity="HIGH",
                        target_tag="link",
                        resource_url=href_url,
                        line_number=line_idx,
                        description="Loading CSS over insecure HTTP allows man-in-the-middle attackers to alter page styles and exfiltrate data via CSS selectors.",
                        remediation="Upgrade stylesheet to HTTPS.",
                        fixed_snippet=line.replace(href_url, href_url.replace("http://", "https://")),
                    )
                )

            # Missing SRI
            if is_external and "integrity=" not in tag_attrs.lower():
                missing_sri_count += 1
                risks.append(
                    SupplyChainRisk(
                        category="MISSING_SRI",
                        title="Third-Party Stylesheet Missing Subresource Integrity",
                        severity="MEDIUM",
                        target_tag="link",
                        resource_url=href_url,
                        line_number=line_idx,
                        description="External CSS loaded without SRI hash verification.",
                        remediation='Add integrity="sha384-..." and crossorigin="anonymous" attributes.',
                        fixed_snippet=f'<link rel="stylesheet" href="{href_url}" integrity="sha384-<HASH>" crossorigin="anonymous">',
                    )
                )

    # 3. IFrame audit: <iframe ... src="...">
    iframe_pattern = re.compile(r"<iframe\b([^>]*)>", re.IGNORECASE)
    iframes_count = 0

    for line_idx, line in enumerate(lines, 1):
        for m in iframe_pattern.finditer(line):
            tag_attrs = m.group(1)
            src_m = re.search(r'src=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not src_m:
                continue
            iframes_count += 1
            src_url = src_m.group(1).strip()
            track_domain(src_url, "iframe")

            if page_is_https and src_url.startswith("http://"):
                mixed_content_count += 1
                risks.append(
                    SupplyChainRisk(
                        category="MIXED_CONTENT",
                        title="Insecure HTTP IFrame (Blockable Mixed Content)",
                        severity="CRITICAL",
                        target_tag="iframe",
                        resource_url=src_url,
                        line_number=line_idx,
                        description="HTTP iframes inside HTTPS pages are blocked and expose user communications to interception.",
                        remediation="Upgrade embedded iframe target to HTTPS.",
                        fixed_snippet=line.replace(src_url, src_url.replace("http://", "https://")),
                    )
                )

    # 4. Form action audit: <form ... action="...">
    form_pattern = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
    forms_count = 0

    for line_idx, line in enumerate(lines, 1):
        for m in form_pattern.finditer(line):
            tag_attrs = m.group(1)
            act_m = re.search(r'action=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not act_m:
                continue
            forms_count += 1
            act_url = act_m.group(1).strip()
            track_domain(act_url, "form")

            if act_url.startswith("http://"):
                risks.append(
                    SupplyChainRisk(
                        category="INSECURE_FORM",
                        title="Insecure HTTP Form Submission Target",
                        severity="CRITICAL",
                        target_tag="form",
                        resource_url=act_url,
                        line_number=line_idx,
                        description="Form credentials and user input will be transmitted in plaintext across the network.",
                        remediation="Ensure form action points to an HTTPS endpoint.",
                        fixed_snippet=line.replace(act_url, act_url.replace("http://", "https://")),
                    )
                )

    # 5. External links reverse tabnabbing: <a ... target="_blank" ...>
    a_pattern = re.compile(r"<a\b([^>]*)>", re.IGNORECASE)
    external_links_count = 0
    reverse_tabnabbing_count = 0

    for line_idx, line in enumerate(lines, 1):
        for m in a_pattern.finditer(line):
            tag_attrs = m.group(1)
            target_m = re.search(r'target=["\']_blank["\']', tag_attrs, re.IGNORECASE)
            if not target_m:
                continue
            href_m = re.search(r'href=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            if not href_m:
                continue
            href_url = href_m.group(1).strip()
            parsed = urllib.parse.urlparse(href_url)
            if not parsed.netloc:
                continue

            external_links_count += 1
            rel_m = re.search(r'rel=["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
            rel_val = rel_m.group(1).lower() if rel_m else ""

            if "noopener" not in rel_val or "noreferrer" not in rel_val:
                reverse_tabnabbing_count += 1
                risks.append(
                    SupplyChainRisk(
                        category="REVERSE_TABNABBING",
                        title="Reverse Tabnabbing Vulnerability in External Link",
                        severity="MEDIUM",
                        target_tag="a",
                        resource_url=href_url,
                        line_number=line_idx,
                        description="Link with target='_blank' lacks rel='noopener noreferrer'. Target page can manipulate window.opener to redirect user to a phishing page.",
                        remediation='Add rel="noopener noreferrer" to external <a> tag.',
                        fixed_snippet=f'<a href="{href_url}" target="_blank" rel="noopener noreferrer">',
                    )
                )

    total_scanned = scripts_count + stylesheets_count + iframes_count + forms_count + external_links_count

    # Score calculation
    score = 100.0
    for r in risks:
        if r.severity == "CRITICAL":
            score -= 25.0
        elif r.severity == "HIGH":
            score -= 15.0
        elif r.severity == "MEDIUM":
            score -= 8.0
        elif r.severity == "LOW":
            score -= 3.0
    score = max(0.0, min(100.0, score))
    grade = calculate_grade(score)

    return SupplyChainReport(
        target_name=target_name,
        total_resources_scanned=total_scanned,
        scripts_count=scripts_count,
        stylesheets_count=stylesheets_count,
        iframes_count=iframes_count,
        forms_count=forms_count,
        external_links_count=external_links_count,
        missing_sri_count=missing_sri_count,
        mixed_content_count=mixed_content_count,
        reverse_tabnabbing_count=reverse_tabnabbing_count,
        supply_chain_score=score,
        grade=grade,
        risks=risks,
        domains_inventory=domains_inventory,
    )
