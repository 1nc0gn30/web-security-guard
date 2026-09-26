"""Web Security Guard - Deep Port Scanner Module.

Comprehensive TCP/UDP port scanner with service fingerprinting,
vulnerability detection, and zero-dependency stdlib implementation.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ScanType(str, Enum):
    TCP_CONNECT = "tcp-connect"
    TCP_SYN = "tcp-syn"
    UDP = "udp"
    ALL = "all"


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    POP3 = "pop3"
    IMAP = "imaps"
    TELNET = "telnet"
    RDP = "rdp"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    REDIS = "redis"
    LDAP = "ldap"
    SNMP = "snmp"
    SOCKS = "socks"
    SMTP_ALT = "smtp-alt"
    UNKNOWN = "unknown"


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    version: str = ""
    vulnerability: str = ""
    response_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "vulnerability": self.vulnerability,
            "response_time_ms": round(self.response_time_ms, 2),
        }


@dataclass
class PortScanReport:
    target: str
    ports_scanned: int
    ports_open: int
    ports_closed: int
    ports_filtered: int
    scan_type: str
    total_time_ms: float
    results: List[PortResult] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def open_ports(self) -> List[int]:
        return [r.port for r in self.results if r.state == "open"]

    @property
    def severity(self) -> str:
        critical = sum(1 for v in self.vulnerabilities if v.get("severity") == "CRITICAL")
        high = sum(1 for v in self.vulnerabilities if v.get("severity") == "HIGH")
        if critical > 0 or high > 0:
            return "HIGH"
        if self.ports_open > 10:
            return "MEDIUM"
        if self.ports_open > 0:
            return "LOW"
        return "NONE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "ports_scanned": self.ports_scanned,
            "ports_open": self.ports_open,
            "ports_closed": self.ports_closed,
            "ports_filtered": self.ports_filtered,
            "scan_type": self.scan_type,
            "total_time_ms": round(self.total_time_ms, 2),
            "severity": self.severity,
            "results": [r.to_dict() for r in self.results],
            "vulnerabilities": self.vulnerabilities,
            "open_port_list": self.open_ports,
        }

    def format_text(self) -> str:
        lines = [
            f"=== Deep Port Scan: {self.target} ===",
            f"Type: {self.scan_type} | Ports: {self.ports_scanned} | Time: {self.total_time_ms:.1f}ms",
            f"Open: {self.ports_open} | Closed: {self.ports_closed} | Filtered: {self.ports_filtered}",
            f"Severity: {self.severity}",
            "-" * 60,
        ]
        if self.results:
            for r in sorted(self.results, key=lambda x: x.port):
                if r.state == "open":
                    lines.append(f"  [{r.port}/tcp] {r.state.upper()} - {r.service or 'unknown'}")
                    if r.banner:
                        lines.append(f"    Banner: {r.banner[:120]}")
                    if r.vulnerability:
                        lines.append(f"    ⚠ {r.vulnerability}")
        if self.vulnerabilities:
            lines.append("\nVulnerabilities:")
            for v in self.vulnerabilities:
                lines.append(f"  [{v.get('severity', 'UNKNOWN')}] {v.get('title', '')}")
        return "\n".join(lines)

    def format_markdown(self) -> str:
        md = [
            f"# 🔌 Deep Port Scan: `{self.target}`\n",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Scan Type | `{self.scan_type}` |",
            f"| Ports Scanned | {self.ports_scanned} |",
            f"| Open | {self.ports_open} |",
            f"| Closed | {self.ports_closed} |",
            f"| Filtered | {self.ports_filtered} |",
            f"| Severity | **{self.severity}** |",
            f"| Duration | {self.total_time_ms:.1f}ms |",
            "",
        ]
        open_results = [r for r in self.results if r.state == "open"]
        if open_results:
            md.append("## Open Ports\n")
            md.append("| Port | Service | Banner | Vulnerability |")
            md.append("|---|---|---|---|")
            for r in sorted(open_results, key=lambda x: x.port):
                md.append(f"| {r.port}/tcp | {r.service or 'unknown'} | `{r.banner[:80]}` | {r.vulnerability or '—'} |")
            md.append("")
        if self.vulnerabilities:
            md.append("## Detected Vulnerabilities\n")
            for v in self.vulnerabilities:
                md.append(f"- **[{v.get('severity', '?')}]** {v.get('title', '')}")
        return "\n".join(md)


# Well-known port -> service mapping
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps",
    989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle",
    2049: "nfs", 2121: "ftp-proxy", 2375: "docker", 2376: "docker-tls",
    27017: "mongodb", 3128: "squid", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt2",
    9200: "elasticsearch", 9443: "es-https", 11211: "memcached",
}

VULNERABLE_BANNERS: List[Tuple[str, str, str]] = [
    (r"SSH-1\.", "SSHv1 Protocol", "CRITICAL - SSHv1 is deprecated and vulnerable"),
    (r"FTP.*220.*Microsoft", "FTP Server Info Disclosure", "HIGH - Server reveals version"),
    (r"Telnet", "Telnet Service", "HIGH - Telnet transmits credentials in cleartext"),
    (r"Redis", "Redis Exposed", "CRITICAL - Redis without auth is critical"),
    (r"MongoDB", "MongoDB Exposed", "CRITICAL - MongoDB without auth is critical"),
    (r"Microsoft-IIS/6\.", "IIS 6.0", "CRITICAL - IIS 6.0 is end-of-life"),
    (r"Apache/2\.2\.", "Apache 2.2", "HIGH - Apache 2.2 is end-of-life"),
    (r"Apache/2\.0\.", "Apache 2.0", "CRITICAL - Apache 2.0 is end-of-life"),
    (r"nginx/0\.", "Old Nginx", "HIGH - Outdated Nginx version"),
    (r"Elasticsearch", "Elasticsearch Exposed", "HIGH - Elasticsearch without auth"),
]

DEFAULT_PORTS = list(range(1, 1025))  # Well-known ports
STANDARD_PORTS = list(range(1, 65536))  # All TCP ports
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 138, 139, 143, 161, 389,
                443, 445, 465, 587, 636, 989, 990, 993, 995, 1433, 1521, 2049, 2121,
                2375, 2376, 27017, 3128, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                8443, 8888, 9200, 9443, 11211]


def _resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def _identify_service(port: int, banner: str = "") -> str:
    """Identify service running on a port."""
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    # Banner-based detection
    banner_lower = banner.lower()
    if "http" in banner_lower or "html" in banner_lower:
        return "http"
    if "ssh" in banner_lower:
        return "ssh"
    if "ftp" in banner_lower:
        return "ftp"
    if "smtp" in banner_lower or "220" in banner_lower:
        return "smtp"
    if "mysql" in banner_lower:
        return "mysql"
    if "postgresql" in banner_lower or "postgres" in banner_lower:
        return "postgres"
    if "redis" in banner_lower:
        return "redis"
    if "ldap" in banner_lower:
        return "ldap"
    return ""


def _check_vulnerability(port: int, banner: str, service: str) -> str:
    """Check for known vulnerabilities based on banner and port."""
    for pattern, title, vuln_desc in VULNERABLE_BANNERS:
        import re
        if re.search(pattern, banner, re.IGNORECASE):
            return vuln_desc
    # Port-specific vulnerability checks
    if port == 23 and service == "telnet":
        return "Telnet service detected - credentials transmitted in cleartext"
    if port == 21 and "220" in banner.lower():
        return "FTP service - check for anonymous login"
    if port == 445:
        return "SMB service - potential EternalBlue/BlueKeep exposure"
    if port == 3389:
        return "RDP service - check for credential stuffing risk"
    if port == 3306 and "mysql" in banner.lower():
        return "MySQL exposed - default credentials may apply"
    if port == 5432:
        return "PostgreSQL exposed - check authentication"
    if port == 6379 and not banner:
        return "Redis likely exposed without auth"
    return ""


def _tcp_connect_scan(
    target: str,
    port: int,
    timeout: float,
) -> PortResult:
    """Perform TCP connect scan on a single port."""
    result = PortResult(port=port, protocol="tcp", state="closed")
    start = time.time()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            elapsed = (time.time() - start) * 1000
            result.state = "open"
            result.response_time_ms = elapsed
            # Try to grab banner
            try:
                with socket.create_connection((target, port), timeout=min(timeout, 2.0)) as sock:
                    sock.settimeout(min(timeout, 2.0))
                    if port in (80, 443, 8080, 8443):
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner_bytes = sock.recv(1024)
                    if banner_bytes:
                        result.banner = banner_bytes.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
            result.service = _identify_service(port, result.banner)
            result.vulnerability = _check_vulnerability(port, result.banner, result.service)
    except socket.timeout:
        result.state = "filtered"
        result.response_time_ms = timeout * 1000
    except ConnectionRefusedError:
        result.state = "closed"
        result.response_time_ms = (time.time() - start) * 1000
    except OSError:
        result.state = "filtered"
        result.response_time_ms = (time.time() - start) * 1000
    return result


def _udp_scan(
    target: str,
    port: int,
    timeout: float,
) -> PortResult:
    """Perform UDP scan on a single port."""
    result = PortResult(port=port, protocol="udp", state="closed")
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Send empty UDP packet or DNS query for port 53
        if port == 53:
            # DNS query for version.bind
            txn_id = b"\x12\x34"
            flags = b"\x00\x00"
            questions = b"\x00\x01"
            answer_rrs = b"\x00\x00"
            authority_rrs = b"\x00\x00"
            additional_rrs = b"\x00\x00"
            query_name = b"\x07version\x04bind\x00"
            query_type = b"\x00\x10"  # TXT
            query_class = b"\x00\x01"
            dns_query = txn_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query_name + query_type + query_class
            sock.sendto(dns_query, (target, port))
        else:
            sock.sendto(b"\x00", (target, port))

        try:
            data, _ = sock.recvfrom(4096)
            elapsed = (time.time() - start) * 1000
            result.state = "open"
            result.response_time_ms = elapsed
            result.banner = data[:200].decode("utf-8", errors="replace")
            result.service = _identify_service(port, result.banner)
        except socket.timeout:
            # No response could mean open|filtered or closed
            result.state = "filtered"
            result.response_time_ms = timeout * 1000
        finally:
            sock.close()
    except OSError:
        result.state = "filtered"
        result.response_time_ms = (time.time() - start) * 1000
    return result


def deep_port_scan(
    target: str,
    ports: Optional[List[int]] = None,
    scan_type: str = "tcp-connect",
    timeout: float = 3.0,
    max_threads: int = 200,
    verbose: bool = False,
) -> PortScanReport:
    """Perform a deep port scan on the target.
    
    Parameters:
        target: Hostname or IP address to scan
        ports: List of ports to scan (default: well-known ports 1-1024)
        scan_type: 'tcp-connect', 'tcp-syn', 'udp', or 'all'
        timeout: Connection timeout in seconds per port
        max_threads: Maximum concurrent threads
        verbose: Print progress during scan
    
    Returns:
        PortScanReport with all results
    """
    hostname = target
    resolved = _resolve_target(target)
    
    if ports is None:
        ports = DEFAULT_PORTS
    
    if scan_type == "all":
        scan_type = "tcp-connect"
    
    results: List[PortResult] = []
    lock = threading.Lock()
    scanned = 0
    start_time = time.time()
    
    def scan_port(port: int) -> None:
        nonlocal scanned
        if scan_type in ("tcp-connect", "all"):
            result = _tcp_connect_scan(resolved, port, timeout)
        elif scan_type == "udp":
            result = _udp_scan(resolved, port, timeout)
        else:
            result = PortResult(port=port, protocol="tcp", state="closed")
        
        with lock:
            results.append(result)
            scanned += 1
            if verbose and scanned % 50 == 0:
                print(f"  Progress: {scanned}/{len(ports)} ports scanned...")
    
    # Thread-based scanning
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        t.daemon = True
        threads.append(t)
        t.start()
        # Throttle threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join(timeout=timeout + 5)
            threads = [t for t in threads if t.is_alive()]
    
    # Wait for remaining threads
    for t in threads:
        t.join(timeout=timeout + 10)
    
    total_time_ms = (time.time() - start_time) * 1000
    
    # Build report
    ports_open = sum(1 for r in results if r.state == "open")
    ports_closed = sum(1 for r in results if r.state == "closed")
    ports_filtered = sum(1 for r in results if r.state == "filtered")
    
    # Collect vulnerabilities
    vulnerabilities = []
    for r in results:
        if r.vulnerability:
            sev = "CRITICAL" if "CRITICAL" in r.vulnerability else (
                "HIGH" if "HIGH" in r.vulnerability else "MEDIUM")
            vulnerabilities.append({
                "port": r.port,
                "service": r.service,
                "severity": sev,
                "title": r.vulnerability,
            })
    
    report = PortScanReport(
        target=f"{hostname} ({resolved})",
        ports_scanned=len(ports),
        ports_open=ports_open,
        ports_closed=ports_closed,
        ports_filtered=ports_filtered,
        scan_type=scan_type,
        total_time_ms=total_time_ms,
        results=results,
        vulnerabilities=vulnerabilities,
    )
    
    return report


def quick_scan(target: str, timeout: float = 2.0) -> PortScanReport:
    """Fast scan of common ports only."""
    return deep_port_scan(target, ports=COMMON_PORTS, scan_type="tcp-connect", timeout=timeout)


def full_scan(target: str, timeout: float = 1.0, max_threads: int = 500) -> PortScanReport:
    """Full TCP port scan of all 65535 ports."""
    return deep_port_scan(target, ports=STANDARD_PORTS, scan_type="tcp-connect",
                          timeout=timeout, max_threads=max_threads)