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
from web_security_guard.isolation_guard import (
    COOPMode,
    COEPMode,
    CORPMode,
    IsolationRisk,
    CrossOriginIsolationReport,
    audit_cross_origin_isolation,
    generate_isolation_headers,
    generate_coi_serviceworker,
    generate_server_isolation_configs,
)
from web_security_guard.secret_scanner import (
    SecretLeakFinding,
    SecretAuditReport,
    scan_secrets,
    shannon_entropy,
    mask_secret,
)
from web_security_guard.supply_chain_auditor import (
    SupplyChainRisk,
    SupplyChainReport,
    audit_supply_chain,
    classify_domain,
)
from web_security_guard.port_scanner import (
    PortResult,
    PortScanReport,
    deep_port_scan,
    quick_scan,
    full_scan,
)
from web_security_guard.target_info import (
    TargetInfoReport,
    gather_target_info,
)
from web_security_guard.collaboration import (
    Annotation,
    CollaborationWorkspace,
    SharedReport,
    TeamMember,
)
from web_security_guard.scheduler import (
    StrikeFrequency,
    StrikeResult,
    StrikeScheduler,
    StrikeTarget,
    ScheduledStrike,
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
    "COOPMode",
    "COEPMode",
    "CORPMode",
    "IsolationRisk",
    "CrossOriginIsolationReport",
    "audit_cross_origin_isolation",
    "generate_isolation_headers",
    "generate_coi_serviceworker",
    "generate_server_isolation_configs",
    "SecretLeakFinding",
    "SecretAuditReport",
    "scan_secrets",
    "shannon_entropy",
    "mask_secret",
    "SupplyChainRisk",
    "SupplyChainReport",
    "audit_supply_chain",
    "classify_domain",
    "PortResult",
    "PortScanReport",
    "deep_port_scan",
    "quick_scan",
    "full_scan",
    "TargetInfoReport",
    "gather_target_info",
    "Annotation",
    "CollaborationWorkspace",
    "SharedReport",
    "TeamMember",
    "StrikeFrequency",
    "StrikeResult",
    "StrikeScheduler",
    "StrikeTarget",
    "ScheduledStrike",
]


def main(*args, **kwargs):
    """Lazy wrapper for web_security_guard.cli.main."""
    from web_security_guard.cli import main as _main
    return _main(*args, **kwargs)


