"""Web Security Guard - Zero-Dependency Web Security Auditing, CSP Generator, SRI Hasher & MCP Server."""

from web_security_guard.auditor import (
    SecurityAuditor,
    AuditResult,
    Finding,
    Severity,
    Category,
    Grade,
    AuditMetrics,
)
from web_security_guard.remediator import SecurityRemediator
from web_security_guard.ci_gate import run_security_check

from web_security_guard.mcp_server import (
    MCP_TOOLS_DEFINITIONS,
    SERVER_NAME,
    SERVER_VERSION,
    MCPServer,
    audit_security,
    calculate_contrast,
    generate_csp_policy,
    generate_mcp_client_config,
    generate_remediation_configs,
    generate_sri_hash,
    inject_sri_into_html,
    run_mcp_server,
)
from web_security_guard.cors_policy import (
    CORSVulnerabilityFinding,
    CORSAuditReport,
    audit_cors_configuration,
    generate_secure_cors_headers,
    generate_permissions_policy,
)

__version__ = SERVER_VERSION
__author__ = "Zoth Security Architecture Team"
__license__ = "MIT"
__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "SERVER_NAME",
    "SERVER_VERSION",
    "MCP_TOOLS_DEFINITIONS",
    "MCPServer",
    "run_mcp_server",
    "generate_mcp_client_config",
    "audit_security",
    "calculate_contrast",
    "generate_csp_policy",
    "generate_sri_hash",
    "inject_sri_into_html",
    "generate_remediation_configs",
    "SecurityAuditor",
    "AuditResult",
    "Finding",
    "Severity",
    "Category",
    "Grade",
    "AuditMetrics",
    "SecurityRemediator",
    "run_security_check",
    "main",
    "CORSVulnerabilityFinding",
    "CORSAuditReport",
    "audit_cors_configuration",
    "generate_secure_cors_headers",
    "generate_permissions_policy",
]


def main(*args, **kwargs):
    """Lazy wrapper for web_security_guard.cli.main."""
    from web_security_guard.cli import main as _main
    return _main(*args, **kwargs)


