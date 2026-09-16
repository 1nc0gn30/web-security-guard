"""
Web Security Guard - SSL / TLS & Certificate Inspector Module
Zero-dependency TLS scanner and X.509 certificate inspector using Python stdlib ssl and socket.
"""

from __future__ import annotations

import datetime
from enum import Enum
import json
from pathlib import Path
import re
import socket
import ssl
from typing import Dict, List, Optional, Any, Tuple, Union
import urllib.parse


class TLSGrade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


def extract_hostname_and_port(hostname_or_url: str, default_port: int = 443) -> Tuple[str, int]:
    """
    Extracts clean hostname and port from URL or host string.
    Supports:
      - 'https://example.com:8443/path' -> ('example.com', 8443)
      - 'https://example.com'          -> ('example.com', 443)
      - 'example.com:8443'             -> ('example.com', 8443)
      - 'example.com'                  -> ('example.com', 443)
      - '127.0.0.1:9443'               -> ('127.0.0.1', 9443)
    """
    target = hostname_or_url.strip()
    if not target:
        raise ValueError("Target hostname or URL cannot be empty")

    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or "localhost"
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "https":
            port = default_port if default_port != 443 else 443
        elif parsed.scheme == "http":
            port = 80 if default_port == 443 else default_port
        else:
            port = default_port
        return host, port

    # Check for host:port without scheme
    if ":" in target and not target.startswith("["):  # not raw IPv6 without port
        parts = target.split(":", 1)
        # Check if right part is integer
        if parts[1].isdigit():
            return parts[0].strip("/"), int(parts[1])

    # Strip any trailing path or slash
    host = target.split("/")[0]
    return host, default_port


def parse_cert_date(date_str: Optional[str]) -> Optional[datetime.datetime]:
    """
    Parses OpenSSL / Python ssl certificate date string into UTC datetime.
    Example formats:
      - 'May  1 12:00:00 2025 GMT'
      - 'May 12 12:00:00 2025 GMT'
      - '2025-05-12T12:00:00Z'
    """
    if not date_str:
        return None

    # Handle standard OpenSSL format: '%b %d %H:%M:%S %Y %Z'
    # Normalize double spaces in single-digit days
    normalized = re.sub(r"\s+", " ", date_str.strip())
    
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def extract_rdn_dict(rdn_tuples: Any) -> Dict[str, str]:
    """
    Flattens certificate subject/issuer RDN tuples into a clean dict.
    Example input: ((('commonName', 'example.com'),), (('organizationName', 'Example Inc'),))
    Output: {'commonName': 'example.com', 'organizationName': 'Example Inc'}
    """
    res: Dict[str, str] = {}
    if not rdn_tuples:
        return res

    for rdn in rdn_tuples:
        for attr, val in rdn:
            res[attr] = str(val)
    return res


def calculate_tls_grade(
    tls_version: str,
    cipher_name: str,
    cipher_bits: int,
    days_remaining: Optional[int],
    is_expired: bool,
    is_trusted: bool = True,
    error_msg: Optional[str] = None,
) -> Tuple[TLSGrade, int, List[Dict[str, Any]]]:
    """
    Computes TLS security grade (A+, A, B, C, D, F) and score (0-100).
    Evaluation rules:
      - TLSv1.3 with >= 128 bit cipher and cert > 30 days: 100 pts -> A+
      - TLSv1.2 with >= 128 bit cipher and cert > 30 days: 90 pts -> A
      - TLSv1.2 with cert expiring <= 30 days: 75 pts -> B
      - TLSv1.1 or weak cipher (< 128 bits): 50 pts -> C
      - TLSv1.0 (deprecated / vulnerable): 35 pts -> D
      - SSLv3 / SSLv2 / Expired cert / Handshake failure: 0 pts -> F
    """
    findings: List[Dict[str, Any]] = []

    if error_msg or not is_trusted or is_expired:
        if is_expired:
            findings.append({
                "id": "TLS_CERT_EXPIRED",
                "severity": "CRITICAL",
                "title": "SSL/TLS Certificate Expired",
                "description": f"The certificate expired {abs(days_remaining or 0)} days ago. Browsers will block connections.",
                "deduction": 100,
            })
        if error_msg:
            findings.append({
                "id": "TLS_HANDSHAKE_ERROR",
                "severity": "CRITICAL",
                "title": "TLS Handshake / Verification Error",
                "description": error_msg,
                "deduction": 100,
            })
        return TLSGrade.F, 0, findings

    score = 100
    tls_ver_upper = (tls_version or "").upper()

    # TLS Protocol Version Evaluation
    if "1.3" in tls_ver_upper:
        score = 100
    elif "1.2" in tls_ver_upper:
        score = 90
    elif "1.1" in tls_ver_upper:
        score = 50
        findings.append({
            "id": "TLS_DEPRECATED_V1_1",
            "severity": "HIGH",
            "title": "Deprecated TLS Protocol (TLS 1.1)",
            "description": "TLS 1.1 is deprecated by IETF (RFC 8996) and modern browsers. Upgrade to TLS 1.3/1.2.",
            "deduction": 50,
        })
    elif "1.0" in tls_ver_upper:
        score = 30
        findings.append({
            "id": "TLS_DEPRECATED_V1_0",
            "severity": "CRITICAL",
            "title": "Insecure Deprecated Protocol (TLS 1.0)",
            "description": "TLS 1.0 is vulnerable to BEAST/POODLE attacks and violates PCI DSS.",
            "deduction": 70,
        })
    elif "SSL" in tls_ver_upper:
        score = 0
        findings.append({
            "id": "TLS_INSECURE_SSL",
            "severity": "CRITICAL",
            "title": "Critical Insecure Protocol (SSLv2/SSLv3)",
            "description": "SSLv2/SSLv3 protocols are broken and insecure.",
            "deduction": 100,
        })
        return TLSGrade.F, 0, findings
    else:
        score = 70

    # Cipher Suite Evaluation
    cipher_upper = (cipher_name or "").upper()
    if cipher_bits < 128:
        score = min(score, 45)
        findings.append({
            "id": "TLS_WEAK_CIPHER_BITS",
            "severity": "HIGH",
            "title": f"Weak Cipher Encryption Strength ({cipher_bits} bits)",
            "description": f"Cipher suite {cipher_name} has insufficient key length ({cipher_bits} < 128 bits).",
            "deduction": 45,
        })
    elif any(weak in cipher_upper for weak in ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]):
        score = min(score, 30)
        findings.append({
            "id": "TLS_INSECURE_CIPHER_ALGO",
            "severity": "CRITICAL",
            "title": f"Insecure Cipher Algorithm ({cipher_name})",
            "description": "Cipher suite contains known vulnerable algorithms (RC4/3DES/MD5/NULL).",
            "deduction": 60,
        })

    # Certificate Expiration Evaluation
    if days_remaining is not None:
        if days_remaining <= 0:
            score = 0
            findings.append({
                "id": "TLS_CERT_EXPIRED",
                "severity": "CRITICAL",
                "title": "Certificate Expired",
                "description": f"Certificate has expired ({days_remaining} days remaining).",
                "deduction": 100,
            })
            return TLSGrade.F, 0, findings
        elif days_remaining <= 7:
            score -= 30
            findings.append({
                "id": "TLS_CERT_EXPIRING_IMMINENT",
                "severity": "HIGH",
                "title": "Certificate Expiring Imminently (< 7 days)",
                "description": f"Certificate will expire in {days_remaining} day(s). Immediate renewal required.",
                "deduction": 30,
            })
        elif days_remaining <= 30:
            score -= 15
            findings.append({
                "id": "TLS_CERT_EXPIRING_SOON",
                "severity": "MEDIUM",
                "title": "Certificate Expiring Soon (< 30 days)",
                "description": f"Certificate expires in {days_remaining} days. Schedule automated renewal.",
                "deduction": 15,
            })

    score = max(0, min(100, score))

    if score >= 95 and "1.3" in tls_ver_upper and (days_remaining is None or days_remaining > 30):
        grade = TLSGrade.A_PLUS
    elif score >= 85:
        grade = TLSGrade.A
    elif score >= 70:
        grade = TLSGrade.B
    elif score >= 50:
        grade = TLSGrade.C
    elif score >= 30:
        grade = TLSGrade.D
    else:
        grade = TLSGrade.F

    return grade, score, findings


def get_mock_tls_inspection(
    hostname: str = "example.com",
    port: int = 443,
    custom_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generates a realistic mock/offline TLS inspection result for testing or offline environments.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=30)
    valid_until = now + datetime.timedelta(days=60)
    days_remaining = 60

    result: Dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "connected": True,
        "tls_version": "TLSv1.3",
        "cipher": {
            "name": "TLS_AES_256_GCM_SHA384",
            "protocol_version": "TLSv1.3",
            "bits": 256,
        },
        "certificate": {
            "subject": {
                "commonName": hostname,
                "organizationName": "Example Security Corp",
                "countryName": "US",
            },
            "issuer": {
                "commonName": "Let's Encrypt Authority E1",
                "organizationName": "Let's Encrypt",
                "countryName": "US",
            },
            "valid_from": valid_from.isoformat(),
            "valid_until": valid_until.isoformat(),
            "valid_from_formatted": valid_from.strftime("%b %d %H:%M:%S %Y GMT"),
            "valid_until_formatted": valid_until.strftime("%b %d %H:%M:%S %Y GMT"),
            "days_remaining": days_remaining,
            "is_expired": False,
            "expiring_soon": False,
            "subject_alt_names": [hostname, f"*.{hostname}"],
            "serial_number": "04A1B2C3D4E5F60718293A4B5C6D7E8F",
            "version": 3,
            "ocsp": ["http://e1.o.lencr.org"],
            "ca_issuers": ["http://e1.i.lencr.org/"],
        },
        "alpn_protocol": "h2",
        "compression": None,
        "grade": TLSGrade.A_PLUS.value,
        "score": 100,
        "passed": True,
        "findings": [],
        "summary": f"TLSv1.3 / AES-256 (Grade A+) - Certificate valid for {days_remaining} days",
        "mode": "mock",
    }

    if custom_data:
        # Deep merge/override top level
        for k, v in custom_data.items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k].update(v)
            else:
                result[k] = v

        # Recalculate grade if needed
        cert = result.get("certificate", {})
        cipher = result.get("cipher", {})
        grade, score, findings = calculate_tls_grade(
            tls_version=result.get("tls_version", "TLSv1.3"),
            cipher_name=cipher.get("name", "TLS_AES_256_GCM_SHA384"),
            cipher_bits=cipher.get("bits", 256),
            days_remaining=cert.get("days_remaining"),
            is_expired=cert.get("is_expired", False),
            is_trusted=result.get("connected", True),
            error_msg=result.get("error"),
        )
        result["grade"] = grade.value
        result["score"] = score
        result["findings"] = findings
        result["passed"] = score >= 85

    return result


def inspect_tls_and_cert(
    hostname_or_url: str,
    port: int = 443,
    timeout: float = 5.0,
    offline_mode: bool = False,
    mock_cert_data: Optional[Dict[str, Any]] = None,
    verify_hostname: bool = True,
) -> Dict[str, Any]:
    """
    Performs full SSL/TLS handshake and X.509 certificate inspection.
    
    Parameters:
      - hostname_or_url: URL (e.g. 'https://example.com') or hostname ('example.com')
      - port: Destination TLS port (default: 443)
      - timeout: Socket timeout in seconds (default: 5.0)
      - offline_mode: If True, uses mock/offline engine without making real network calls
      - mock_cert_data: Optional dictionary to customize offline mock results
      - verify_hostname: Whether to verify SSL certificate against hostname
      
    Returns:
      Dict containing:
        - hostname, port, connected
        - tls_version, cipher {name, protocol_version, bits}
        - certificate {subject, issuer, valid_from, valid_until, days_remaining, sans, serial_number, version}
        - grade (A+, A, B, C, D, F), score (0-100), findings, summary
    """
    hostname, resolved_port = extract_hostname_and_port(hostname_or_url, default_port=port)

    if offline_mode:
        return get_mock_tls_inspection(hostname=hostname, port=resolved_port, custom_data=mock_cert_data)

    # Prepare SSL context
    ctx = ssl.create_default_context()
    if not verify_hostname:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        with socket.create_connection((hostname, resolved_port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version() or "UNKNOWN"
                cipher_tuple = ssock.cipher()  # (name, ssl_version, bits)
                cipher_name = cipher_tuple[0] if cipher_tuple else "UNKNOWN"
                cipher_proto = cipher_tuple[1] if cipher_tuple else tls_version
                cipher_bits = cipher_tuple[2] if cipher_tuple and len(cipher_tuple) > 2 else 0
                alpn = ssock.selected_alpn_protocol()
                compression = ssock.compression()

                peer_cert = ssock.getpeercert() or {}

                # Parse Subject & Issuer
                subject_dict = extract_rdn_dict(peer_cert.get("subject"))
                issuer_dict = extract_rdn_dict(peer_cert.get("issuer"))

                # Parse Validity Dates
                not_before_str = peer_cert.get("notBefore")
                not_after_str = peer_cert.get("notAfter")
                not_before_dt = parse_cert_date(not_before_str)
                not_after_dt = parse_cert_date(not_after_str)

                days_remaining: Optional[int] = None
                is_expired = False
                expiring_soon = False

                if not_after_dt:
                    diff = not_after_dt - now
                    days_remaining = int(diff.total_seconds() // 86400)
                    is_expired = days_remaining <= 0
                    expiring_soon = 0 < days_remaining <= 30

                # Extract SANs
                sans: List[str] = []
                for entry in peer_cert.get("subjectAltName", ()):
                    if len(entry) >= 2:
                        sans.append(str(entry[1]))

                serial_number = str(peer_cert.get("serialNumber", ""))
                version = int(peer_cert.get("version", 3))
                ocsp_list = list(peer_cert.get("OCSP", ()))
                ca_issuers = list(peer_cert.get("caIssuers", ()))

                # Calculate Security Grade
                grade, score, findings = calculate_tls_grade(
                    tls_version=tls_version,
                    cipher_name=cipher_name,
                    cipher_bits=cipher_bits,
                    days_remaining=days_remaining,
                    is_expired=is_expired,
                    is_trusted=True,
                )

                summary = (
                    f"{tls_version} / {cipher_name} ({cipher_bits} bits) - "
                    f"Grade {grade.value} ({score}/100) - "
                    f"Cert expires in {days_remaining if days_remaining is not None else 'N/A'} days"
                )

                return {
                    "hostname": hostname,
                    "port": resolved_port,
                    "connected": True,
                    "tls_version": tls_version,
                    "cipher": {
                        "name": cipher_name,
                        "protocol_version": cipher_proto,
                        "bits": cipher_bits,
                    },
                    "certificate": {
                        "subject": subject_dict,
                        "issuer": issuer_dict,
                        "valid_from": not_before_dt.isoformat() if not_before_dt else None,
                        "valid_until": not_after_dt.isoformat() if not_after_dt else None,
                        "valid_from_formatted": not_before_str,
                        "valid_until_formatted": not_after_str,
                        "days_remaining": days_remaining,
                        "is_expired": is_expired,
                        "expiring_soon": expiring_soon,
                        "subject_alt_names": sans,
                        "serial_number": serial_number,
                        "version": version,
                        "ocsp": ocsp_list,
                        "ca_issuers": ca_issuers,
                    },
                    "alpn_protocol": alpn,
                    "compression": compression,
                    "grade": grade.value,
                    "score": score,
                    "passed": score >= 85,
                    "findings": findings,
                    "summary": summary,
                    "mode": "live",
                }

    except (socket.timeout, TimeoutError) as e:
        grade, score, findings = calculate_tls_grade(
            tls_version="UNKNOWN",
            cipher_name="",
            cipher_bits=0,
            days_remaining=None,
            is_expired=False,
            is_trusted=False,
            error_msg=f"Connection timed out after {timeout}s: {e}",
        )
        return {
            "hostname": hostname,
            "port": resolved_port,
            "connected": False,
            "error": f"Connection timed out after {timeout}s: {e}",
            "tls_version": "UNKNOWN",
            "cipher": {"name": "NONE", "protocol_version": "NONE", "bits": 0},
            "certificate": None,
            "grade": grade.value,
            "score": score,
            "passed": False,
            "findings": findings,
            "summary": f"Failed to connect to {hostname}:{resolved_port} (Timeout)",
            "mode": "live",
        }
    except ssl.SSLCertVerificationError as e:
        grade, score, findings = calculate_tls_grade(
            tls_version="UNKNOWN",
            cipher_name="",
            cipher_bits=0,
            days_remaining=None,
            is_expired="expired" in str(e).lower(),
            is_trusted=False,
            error_msg=f"SSL Certificate Verification Failed: {e}",
        )
        return {
            "hostname": hostname,
            "port": resolved_port,
            "connected": False,
            "error": f"SSL Certificate Verification Failed: {e}",
            "tls_version": "UNKNOWN",
            "cipher": {"name": "NONE", "protocol_version": "NONE", "bits": 0},
            "certificate": None,
            "grade": grade.value,
            "score": score,
            "passed": False,
            "findings": findings,
            "summary": f"SSL Certificate Verification Failed for {hostname}: {e.strerror if hasattr(e, 'strerror') else e}",
            "mode": "live",
        }
    except (socket.error, ssl.SSLError, Exception) as e:
        grade, score, findings = calculate_tls_grade(
            tls_version="UNKNOWN",
            cipher_name="",
            cipher_bits=0,
            days_remaining=None,
            is_expired=False,
            is_trusted=False,
            error_msg=f"TLS/Socket Connection Failed: {e}",
        )
        return {
            "hostname": hostname,
            "port": resolved_port,
            "connected": False,
            "error": f"TLS Connection Failed: {e}",
            "tls_version": "UNKNOWN",
            "cipher": {"name": "NONE", "protocol_version": "NONE", "bits": 0},
            "certificate": None,
            "grade": grade.value,
            "score": score,
            "passed": False,
            "findings": findings,
            "summary": f"Connection to {hostname}:{resolved_port} failed: {e}",
            "mode": "live",
        }


def format_tls_markdown_report(result: Dict[str, Any]) -> str:
    """
    Generates a GitHub-flavored Markdown inspection report for SSL/TLS state.
    """
    hostname = result.get("hostname", "Unknown")
    port = result.get("port", 443)
    grade = result.get("grade", "F")
    score = result.get("score", 0)
    tls_ver = result.get("tls_version", "N/A")
    cipher = result.get("cipher", {})
    cert = result.get("certificate") or {}
    findings = result.get("findings", [])

    lines = [
        f"# 🔒 TLS & SSL Certificate Audit: `{hostname}:{port}`",
        "",
        f"> **Security Grade:** `[{grade}]` (Score: **{score}/100**)  ",
        f"> **Protocol Version:** `{tls_ver}`  ",
        f"> **Cipher Suite:** `{cipher.get('name', 'N/A')}` ({cipher.get('bits', 0)} bits)  ",
        "",
        "---",
        "",
        "## 📜 Certificate Details",
        "",
    ]

    if cert:
        subj = cert.get("subject", {})
        iss = cert.get("issuer", {})
        lines.extend([
            "| Property | Value |",
            "| :--- | :--- |",
            f"| **Common Name (CN)** | `{subj.get('commonName', 'N/A')}` |",
            f"| **Organization** | `{subj.get('organizationName', 'N/A')}` |",
            f"| **Issuer** | `{iss.get('organizationName', iss.get('commonName', 'N/A'))}` |",
            f"| **Valid From** | `{cert.get('valid_from_formatted', 'N/A')}` |",
            f"| **Valid Until** | `{cert.get('valid_until_formatted', 'N/A')}` |",
            f"| **Days Remaining** | **{cert.get('days_remaining', 'N/A')} days** |",
            f"| **Subject Alternative Names** | `{', '.join(cert.get('subject_alt_names', [])[:5])}` |",
            f"| **Serial Number** | `{cert.get('serial_number', 'N/A')}` |",
            "",
        ])
    else:
        lines.append(f"⚠️ *No certificate retrieved (Error: {result.get('error', 'Connection failed')})*\n")

    lines.extend([
        "## 🔍 Findings & Warnings",
        "",
    ])

    if not findings:
        lines.append("✅ **No TLS vulnerabilities or certificate issues detected!**\n")
    else:
        lines.extend([
            "| ID | Severity | Title | Description |",
            "| :--- | :---: | :--- | :--- |",
        ])
        for f in findings:
            sev = f.get("severity", "INFO")
            lines.append(f"| `{f.get('id')}` | **{sev}** | {f.get('title')} | {f.get('description')} |")
        lines.append("")

    return "\n".join(lines)
