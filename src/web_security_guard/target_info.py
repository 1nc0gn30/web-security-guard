"""Web Security Guard - Target Information Gathering Module.

Reconnaissance module for DNS, WHOIS, HTTP headers, technologies,
and target fingerprinting using Python stdlib only.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DNSRecord:
    """DNS record information."""
    record_type: str
    value: str
    ttl: Optional[int] = None


@dataclass
class HTTPHeaderInfo:
    """HTTP response header analysis."""
    server: str = ""
    x_powered_by: str = ""
    content_type: str = ""
    strict_transport_security: str = ""
    x_content_type_options: str = ""
    x_frame_options: str = ""
    x_xss_protection: str = ""
    referrer_policy: str = ""
    content_security_policy: str = ""
    cache_control: str = ""
    pragma: str = ""
    expires: str = ""
    set_cookie: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class TechnologyStack:
    """Detected technologies on the target."""
    web_server: str = ""
    programming_language: str = ""
    framework: str = ""
    cms: str = ""
    javascript_libraries: List[str] = field(default_factory=list)
    analytics: List[str] = field(default_factory=list)
    cdns: List[str] = field(default_factory=list)


@dataclass
class TargetInfoReport:
    """Complete target reconnaissance report."""
    target: str
    resolved_ip: str = ""
    resolved_ips: List[str] = field(default_factory=list)
    hostname: str = ""
    dns_records: List[DNSRecord] = field(default_factory=list)
    http_headers: Optional[HTTPHeaderInfo] = None
    tech_stack: Optional[TechnologyStack] = None
    open_ports_summary: str = ""
    ssl_info: Optional[Dict[str, Any]] = None
    technologies: List[str] = field(default_factory=list)
    favicon_hash: str = ""
    page_title: str = ""
    meta_tags: Dict[str, str] = field(default_factory=dict)
    external_resources: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    cookies: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "resolved_ips": self.resolved_ips,
            "hostname": self.hostname,
            "dns_records": [
                {"type": r.record_type, "value": r.value, "ttl": r.ttl}
                for r in self.dns_records
            ],
            "http_headers": (
                {
                    "server": self.http_headers.server,
                    "x_powered_by": self.http_headers.x_powered_by,
                    "content_type": self.http_headers.content_type,
                    "strict_transport_security": self.http_headers.strict_transport_security,
                    "x_content_type_options": self.http_headers.x_content_type_options,
                    "x_frame_options": self.http_headers.x_frame_options,
                    "x_xss_protection": self.http_headers.x_xss_protection,
                    "referrer_policy": self.http_headers.referrer_policy,
                    "content_security_policy": self.http_headers.content_security_policy,
                    "set_cookie_count": len(self.http_headers.set_cookie),
                    "custom_headers_count": len(self.http_headers.custom_headers),
                }
                if self.http_headers else None
            ),
            "tech_stack": (
                {
                    "web_server": self.tech_stack.web_server,
                    "programming_language": self.tech_stack.programming_language,
                    "framework": self.tech_stack.framework,
                    "cms": self.tech_stack.cms,
                    "javascript_libraries": self.tech_stack.javascript_libraries,
                    "analytics": self.tech_stack.analytics,
                    "cdns": self.tech_stack.cdns,
                }
                if self.tech_stack else None
            ),
            "ssl_info": self.ssl_info,
            "technologies": self.technologies,
            "page_title": self.page_title,
            "meta_tags": self.meta_tags,
            "external_resources": self.external_resources,
            "forms": self.forms,
        }

    def format_text(self) -> str:
        lines = [
            f"=== Target Intelligence: {self.target} ===",
            f"Resolved IP: {self.resolved_ip}",
            f"Hostname: {self.hostname}",
            f"DNS Records: {len(self.dns_records)}",
            f"Technologies: {', '.join(self.technologies) if self.technologies else 'Unknown'}",
            f"Page Title: {self.page_title}",
            "-" * 60,
        ]
        if self.http_headers:
            h = self.http_headers
            lines.append(f"Server: {h.server or 'Unknown'}")
            lines.append(f"X-Powered-By: {h.x_powered_by or 'None'}")
            lines.append(f"HSTS: {h.strict_transport_security or 'Not set'}")
            lines.append(f"X-Frame-Options: {h.x_frame_options or 'Not set'}")
            lines.append(f"X-Content-Type-Options: {h.x_content_type_options or 'Not set'}")
            lines.append(f"CSP: {h.content_security_policy or 'Not set'}")
            lines.append(f"Cookies: {len(h.set_cookie)}")
        if self.tech_stack:
            ts = self.tech_stack
            lines.append(f"\nTech Stack:")
            lines.append(f"  Server: {ts.web_server}")
            lines.append(f"  Language: {ts.programming_language}")
            lines.append(f"  Framework: {ts.framework}")
            lines.append(f"  CMS: {ts.cms}")
        return "\n".join(lines)

    def format_markdown(self) -> str:
        md = [
            f"# 🎯 Target Intelligence: `{self.target}`\n",
        ]
        if self.resolved_ip:
            md.append(f"**Resolved IP:** `{self.resolved_ip}`\n")
        if self.hostname:
            md.append(f"**Hostname:** `{self.hostname}`\n")
        if self.page_title:
            md.append(f"**Page Title:** {self.page_title}\n")
        
        if self.http_headers:
            h = self.http_headers
            md.append("## HTTP Headers\n")
            md.append("| Header | Value |")
            md.append("|---|---|")
            if h.server:
                md.append(f"| Server | `{h.server}` |")
            if h.x_powered_by:
                md.append(f"| X-Powered-By | `{h.x_powered_by}` |")
            if h.content_type:
                md.append(f"| Content-Type | `{h.content_type}` |")
            if h.strict_transport_security:
                md.append(f"| Strict-Transport-Security | `{h.strict_transport_security}` |")
            else:
                md.append("| Strict-Transport-Security | **⚠️ Not set** |")
            if h.x_frame_options:
                md.append(f"| X-Frame-Options | `{h.x_frame_options}` |")
            else:
                md.append("| X-Frame-Options | **⚠️ Not set** |")
            if h.x_content_type_options:
                md.append(f"| X-Content-Type-Options | `{h.x_content_type_options}` |")
            else:
                md.append("| X-Content-Type-Options | **⚠️ Not set** |")
            if h.content_security_policy:
                md.append(f"| CSP | `{h.content_security_policy[:80]}...` |")
            else:
                md.append("| CSP | **⚠️ Not set** |")
            md.append(f"| Cookies | {len(h.set_cookie)} |")
            md.append("")
        
        if self.tech_stack:
            ts = self.tech_stack
            md.append("## Technology Stack\n")
            md.append(f"| Component | Detected |")
            md.append(f"|---|---|")
            md.append(f"| Web Server | {ts.web_server or 'Unknown'} |")
            md.append(f"| Language | {ts.programming_language or 'Unknown'} |")
            md.append(f"| Framework | {ts.framework or 'Unknown'} |")
            md.append(f"| CMS | {ts.cms or 'Unknown'} |")
            if ts.javascript_libraries:
                md.append(f"| JS Libraries | {', '.join(ts.javascript_libraries)} |")
            if ts.cdns:
                md.append(f"| CDNs | {', '.join(ts.cdns)} |")
            md.append("")
        
        if self.technologies:
            md.append(f"**Technologies:** {', '.join(self.technologies)}\n")
        
        return "\n".join(md)


# Tech fingerprinting patterns
TECH_PATTERNS: Dict[str, List[str]] = {
    "Nginx": [r"nginx/[\d.]+", r"nginx"],
    "Apache": [r"Apache/[\d.]+", r"Apache"],
    "IIS": [r"Microsoft-IIS/[\d.]+", r"IIS"],
    "Express.js": [r"express", r"X-Powered-By:\s*Express"],
    "Django": [r"django", r"X-Frame-Options:\s*SAMEORIGIN"],
    "Spring Boot": [r"Spring", r"X-Application-Context"],
    "Laravel": [r"laravel", r"X-Laravel-"],
    "WordPress": [r"wordpress", r"wp-content", r"wp-includes"],
    "Drupal": [r"drupal", r"Drupal"],
    "Joomla": [r"joomla", r"Joomla"],
    "React": [r"react", r"_react"],
    "Vue.js": [r"vue.js", r"vue-" ],
    "Angular": [r"angular", r"ng-"],
    "jQuery": [r"jquery", r"jQuery"],
    "Google Analytics": [r"google-analytics", r"googletagmanager", r"UA-\d+"],
    "Cloudflare": [r"cloudflare", r"__cf_bm", r"cf-ray"],
    "AWS CloudFront": [r"cloudfront", r"X-Cache:.*HIT"],
    "Redis": [r"redis", r"X-Redis-"],
    "PHP": [r"php/[\d.]+", r"X-Powered-By:\s*PHP"],
    "Python": [r"wsgi", r"python", r"X-Generator:\s*Django"],
    "Ruby": [r"ruby", r"rack", r"X-Runtime"],
    "Node.js": [r"node\.js", r"express", r"Next.js"],
    "Docker": [r"docker", r"X-Docker-"],
    "Kubernetes": [r"kubernetes", r"X-Kubernetes-"],
    "OpenSSL": [r"OpenSSL/[\d.]+"],
    "Let's Encrypt": [r"Let's Encrypt", r"R3"],
}


def _extract_technologies(headers: Dict[str, str], html: str = "") -> Tuple[List[str], TechnologyStack]:
    """Extract technologies from headers and HTML."""
    detected: List[str] = []
    stack = TechnologyStack()
    
    all_text = " ".join(f"{k}: {v}" for k, v in headers.items()) + " " + html
    
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, all_text, re.IGNORECASE):
                detected.append(tech)
                break
    
    # Identify server
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    
    if server:
        stack.web_server = server
        for tech in detected:
            if tech.lower() in server.lower():
                stack.web_server = tech
                break
    
    if x_powered:
        stack.programming_language = x_powered
        if "php" in x_powered.lower():
            stack.programming_language = "PHP"
        elif "node" in x_powered.lower():
            stack.programming_language = "Node.js"
        elif "python" in x_powered.lower():
            stack.programming_language = "Python"
        elif "ruby" in x_powered.lower():
            stack.programming_language = "Ruby"
        elif "java" in x_powered.lower():
            stack.programming_language = "Java"
    
    # Identify framework from headers
    if "X-Powered-By: Express" in all_text or "express" in all_text.lower():
        stack.framework = "Express.js"
    elif "django" in all_text.lower():
        stack.framework = "Django"
    elif "laravel" in all_text.lower():
        stack.framework = "Laravel"
    elif "spring" in all_text.lower():
        stack.framework = "Spring Boot"
    elif "rails" in all_text.lower():
        stack.framework = "Ruby on Rails"
    elif "flask" in all_text.lower():
        stack.framework = "Flask"
    elif "next.js" in all_text.lower():
        stack.framework = "Next.js"
    
    # Identify CMS
    if "wordpress" in all_text.lower():
        stack.cms = "WordPress"
    elif "drupal" in all_text.lower():
        stack.cms = "Drupal"
    elif "joomla" in all_text.lower():
        stack.cms = "Joomla"
    
    # Detect CDNs
    for cdn in ["Cloudflare", "AWS CloudFront", "Fastly", "Akamai", "CloudFront"]:
        if cdn.lower() in all_text.lower():
            stack.cdns.append(cdn)
    
    # Detect analytics
    for analytic in ["Google Analytics", "Google Tag Manager"]:
        if analytic.lower() in all_text.lower():
            stack.analytics.append(analytic)
    
    return detected, stack


def _extract_meta_tags(html: str) -> Dict[str, str]:
    """Extract meta tags from HTML."""
    tags: Dict[str, str] = {}
    for match in re.finditer(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE):
        tags[match.group(1)] = match.group(2)
    for match in re.finditer(r'<meta[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        tags[match.group(2)] = match.group(1)
    # Open Graph
    for match in re.finditer(r'<meta[^>]*property=["\']og:([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE):
        tags[f"og:{match.group(1)}"] = match.group(2)
    return tags


def _extract_forms(html: str) -> List[Dict[str, Any]]:
    """Extract form elements from HTML."""
    forms = []
    for match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*type=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        forms.append({
            "action": action_match.group(1) if action_match else "",
            "method": (method_match.group(1) if method_match else "get").upper(),
            "input_types": inputs,
        })
    return forms


def _extract_external_resources(html: str) -> List[str]:
    """Extract external resource domains."""
    domains: List[str] = []
    for match in re.finditer(r'(?:src|href)=["\']https?://([^"\'/]+)', html, re.IGNORECASE):
        domain = match.group(1)
        if domain not in domains:
            domains.append(domain)
    return domains


def _fetch_url(url: str, timeout: float = 10.0) -> Tuple[Optional[bytes], Dict[str, str], int]:
    """Fetch URL and return content, headers, and status code."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            headers = dict(resp.info())
            return content, headers, resp.status
    except urllib.error.HTTPError as e:
        content = e.read() if hasattr(e, 'read') else b""
        headers = dict(e.headers) if hasattr(e, 'headers') else {}
        return content, headers, e.code
    except Exception:
        return None, {}, 0


def _resolve_dns(target: str) -> Tuple[str, List[str]]:
    """Resolve DNS for a target."""
    hostname = target
    ips: List[str] = []
    try:
        # Handle URLs
        if target.startswith(("http://", "https://")):
            hostname = urllib.parse.urlparse(target).hostname or target
        
        # Get all A records
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        pass
    
    resolved_ip = ips[0] if ips else ""
    return resolved_ip, ips


def gather_target_info(
    target: str,
    fetch_http: bool = True,
    dns_lookup: bool = True,
    fetch_html: bool = True,
) -> TargetInfoReport:
    """Gather comprehensive target intelligence.
    
    Parameters:
        target: Domain, URL, or IP address
        fetch_http: Fetch HTTP headers
        dns_lookup: Perform DNS resolution
        fetch_html: Fetch and analyze HTML content
    
    Returns:
        TargetInfoReport with all gathered intelligence
    """
    report = TargetInfoReport(target=target)
    
    # DNS Resolution
    if dns_lookup:
        resolved_ip, all_ips = _resolve_dns(target)
        report.resolved_ip = resolved_ip
        report.resolved_ips = all_ips
        report.hostname = target if not target.startswith(("http://", "https://")) else urllib.parse.urlparse(target).hostname or target
    
    # HTTP/HTTPS inspection
    urls_to_try = [target] if target.startswith("http") else [
        f"https://{target}",
        f"http://{target}",
    ]
    
    for url in urls_to_try:
        if fetch_http:
            content, headers, status = _fetch_url(url, timeout=10.0)
            if headers:
                http_info = HTTPHeaderInfo()
                http_info.server = headers.get("server", "")
                http_info.x_powered_by = headers.get("x-powered-by", "")
                http_info.content_type = headers.get("content-type", "")
                http_info.strict_transport_security = headers.get("strict-transport-security", "")
                http_info.x_content_type_options = headers.get("x-content-type-options", "")
                http_info.x_frame_options = headers.get("x-frame-options", "")
                http_info.x_xss_protection = headers.get("x-xss-protection", "")
                http_info.referrer_policy = headers.get("referrer-policy", "")
                http_info.content_security_policy = headers.get("content-security-policy", "")
                http_info.cache_control = headers.get("cache-control", "")
                http_info.pragma = headers.get("pragma", "")
                http_info.expires = headers.get("expires", "")
                http_info.set_cookie = []
                raw_cookies = headers.get("set-cookie", "")
                if raw_cookies:
                    http_info.set_cookie = [
                        c.split(";")[0].strip()
                        for c in raw_cookies.split(",")
                        if c.strip()
                    ]
                
                # Custom headers
                standard_headers = {
                    "server", "x-powered-by", "content-type",
                    "strict-transport-security", "x-content-type-options",
                    "x-frame-options", "x-xss-protection", "referrer-policy",
                    "content-security-policy", "cache-control", "pragma",
                    "expires", "set-cookie", "date", "connection",
                }
                for k, v in headers.items():
                    if k.lower() not in standard_headers:
                        http_info.custom_headers[k] = v
                
                report.http_headers = http_info
                
                # Extract technologies
                html_content = ""
                if fetch_html and content:
                    try:
                        html_content = content.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                
                detected, stack = _extract_technologies(headers, html_content)
                report.technologies = detected
                report.tech_stack = stack
                
                # Parse HTML for deeper analysis
                if html_content:
                    title_match = re.search(
                        r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE
                    )
                    report.page_title = title_match.group(1).strip() if title_match else ""
                
                report.meta_tags = _extract_meta_tags(html_content)
                report.external_resources = _extract_external_resources(html_content)
                report.forms = _extract_forms(html_content)
                
                # Extract cookies from HTML/meta
                cookie_matches = re.findall(
                    r'(?:cookie|Set-Cookie)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    html_content, re.IGNORECASE
                )
                for c in cookie_matches[:10]:
                    report.cookies.append({"value": c[:50]})
                
                # Only use first successful URL
                break
    
    return report