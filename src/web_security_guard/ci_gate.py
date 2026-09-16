"""
Web Security Guard - CI/CD Security Gate Module
Enforces automated zero-trust security thresholds in continuous integration
pipelines, generating ASCII tables, JSON metrics, and GitHub Actions annotations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
import argparse
import json
import os
import sys

from .auditor import SecurityAuditor, AuditResult, Finding, Severity, Grade
from .remediator import SecurityRemediator


def run_security_check(
    target_url_or_path: str,
    min_score: int = 85,
    fail_on_critical: bool = True,
    output_format: str = "text",
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Executes an automated security audit and checks against CI policy thresholds.

    Args:
        target_url_or_path: URL (e.g. https://example.com) or local config/HTML file path.
        min_score: Minimum allowable score (0-100) to pass CI (default: 85).
        fail_on_critical: If True, any CRITICAL finding fails CI regardless of score.
        output_format: "text", "json", "github", or "markdown".

    Returns:
        Tuple[bool, Dict[str, Any], str]: (passed, audit_dict, formatted_output)
    """
    auditor = SecurityAuditor()

    # Determine URL vs File audit
    if target_url_or_path.startswith(("http://", "https://")):
        audit_result = auditor.audit_url(target_url_or_path)
    else:
        path = Path(target_url_or_path)
        if path.is_dir():
            # Look for standard headers or config files inside directory
            possible_files = ["_headers", "vercel.json", "nginx.conf", "Caddyfile", "index.html", "public/index.html"]
            target_file = None
            for pf in possible_files:
                candidate = path / pf
                if candidate.exists():
                    target_file = candidate
                    break
            if target_file:
                audit_result = auditor.audit_file(target_file)
            else:
                audit_result = auditor.audit_file(path)
        else:
            audit_result = auditor.audit_file(path)

    # Evaluate Gate Pass/Fail Conditions
    has_critical = any(f.severity == Severity.CRITICAL for f in audit_result.findings)
    score_passed = audit_result.score >= min_score
    critical_passed = not (fail_on_critical and has_critical)
    passed = score_passed and critical_passed

    result_dict = audit_result.to_dict()
    result_dict["ci_gate"] = {
        "passed": passed,
        "min_score": min_score,
        "fail_on_critical": fail_on_critical,
        "score_passed": score_passed,
        "critical_passed": critical_passed,
        "has_critical": has_critical,
    }

    # Format Output
    fmt = output_format.lower().strip()
    if fmt == "json":
        formatted_output = json.dumps(result_dict, indent=2)
    elif fmt == "github":
        formatted_output = _format_github_actions_output(audit_result, passed, min_score, fail_on_critical)
    elif fmt == "markdown":
        formatted_output = _format_markdown_output(audit_result, passed, min_score)
    else:  # "text"
        formatted_output = _format_ascii_text_output(audit_result, passed, min_score, fail_on_critical)

    # Append to GITHUB_STEP_SUMMARY if available
    step_summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_file and Path(step_summary_file).parent.exists():
        try:
            with open(step_summary_file, "a", encoding="utf-8") as f:
                f.write(_format_markdown_output(audit_result, passed, min_score) + "\n")
        except Exception:
            pass

    return passed, result_dict, formatted_output


# -----------------------------------------------------------------------------
# Output Formatters
# -----------------------------------------------------------------------------

def _format_ascii_text_output(
    res: AuditResult,
    passed: bool,
    min_score: int,
    fail_on_critical: bool,
) -> str:
    crit = res.metrics.critical_count
    high = res.metrics.high_count
    med = res.metrics.medium_count
    low = res.metrics.low_count
    info = res.metrics.info_count

    status_str = "PASSED" if passed else "FAILED"
    status_icon = "[PASS]" if passed else "[FAIL]"

    lines = [
        "=" * 78,
        "                  WEB SECURITY GUARD - CI/CD GATEWAY",
        "=" * 78,
        f" Target:       {res.target}",
        f" Target Type:  {res.target_type}",
        f" Score:        {res.score} / 100   (Grade: {res.grade.value})",
        f" Gate Status:  {status_icon} {status_str} (Required: >={min_score}, No Critical: {fail_on_critical})",
        f" Breakdown:    {crit} Critical | {high} High | {med} Medium | {low} Low | {info} Info",
        "-" * 78,
    ]

    if not res.findings:
        lines.append("  [+] No vulnerabilities or misconfigurations detected! (100% Secure)")
    else:
        lines.append(f" {'ID':<30} | {'SEVERITY':<10} | {'DEDUCT':<6} | {'TITLE'}")
        lines.append("-" * 78)
        for f in res.findings:
            title_trunc = f.title[:30] + ("..." if len(f.title) > 30 else "")
            lines.append(f" {f.id:<30} | {f.severity.value:<10} | -{f.deduction:<5} | {title_trunc}")

    lines.append("=" * 78)
    if not passed:
        lines.append(" [!] Action Required: Run with --remediate-dir to auto-generate fixed configurations.")
    return "\n".join(lines)


def _format_github_actions_output(
    res: AuditResult,
    passed: bool,
    min_score: int,
    fail_on_critical: bool,
) -> str:
    lines = []
    target_file = res.target if res.target_type == "file" else "index.html"

    # Emit workflow commands for each finding
    for f in res.findings:
        msg = f"{f.title}: {f.description} (Remediation: {f.remediation_hint})"
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            lines.append(f"::error file={target_file},title={f.id}::{msg}")
        elif f.severity == Severity.MEDIUM:
            lines.append(f"::warning file={target_file},title={f.id}::{msg}")
        else:
            lines.append(f"::notice file={target_file},title={f.id}::{msg}")

    # Emit summary notice
    status_str = "PASSED" if passed else "FAILED"
    lines.append(
        f"::notice title=Security Gate {status_str}::Score: {res.score}/100 ({res.grade.value}) - "
        f"{res.metrics.critical_count} Critical, {res.metrics.high_count} High, {res.metrics.medium_count} Medium"
    )

    # Append markdown summary
    lines.append("")
    lines.append(_format_markdown_output(res, passed, min_score))
    return "\n".join(lines)


def _format_markdown_output(res: AuditResult, passed: bool, min_score: int) -> str:
    status_badge = "✅ **PASSED**" if passed else "❌ **FAILED**"
    lines = [
        "## 🛡️ Web Security Guard CI Gate Summary",
        "",
        f"- **Target:** `{res.target}`",
        f"- **Security Score:** **{res.score}/100** (Grade: `{res.grade.value}`)",
        f"- **CI Threshold:** Minimum **{min_score}** | Status: {status_badge}",
        f"- **Vulnerabilities:** 🔴 {res.metrics.critical_count} Critical | 🟠 {res.metrics.high_count} High | 🟡 {res.metrics.medium_count} Medium | 🔵 {res.metrics.low_count + res.metrics.info_count} Low/Info",
        "",
    ]

    if res.findings:
        lines.extend([
            "| Severity | Finding ID | Title | Deduction | Remediation Hint |",
            "| :---: | :--- | :--- | :---: | :--- |",
        ])
        for f in res.findings:
            sev_icon = "🔴" if f.severity == Severity.CRITICAL else ("🟠" if f.severity == Severity.HIGH else ("🟡" if f.severity == Severity.MEDIUM else "🔵"))
            lines.append(
                f"| {sev_icon} **{f.severity.value}** | `{f.id}` | {f.title} | `-{f.deduction}` | {f.remediation_hint} |"
            )
    else:
        lines.append("🎉 **No security issues found. Configuration satisfies 100/100 A+ standard.**")

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------

def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="web-security-guard",
        description="Zero-Trust Web Security Auditor & CI Gate",
    )
    parser.add_argument("target", help="URL or configuration file path to audit")
    parser.add_argument("--min-score", type=int, default=85, help="Minimum score to pass CI (default: 85)")
    parser.add_argument("--fail-on-critical", action="store_true", default=True, help="Fail if any critical vulnerabilities found")
    parser.add_argument("--no-fail-on-critical", action="store_false", dest="fail_on_critical", help="Do not fail solely on critical findings")
    parser.add_argument("--format", choices=["text", "json", "github", "markdown"], default="text", help="Output format")
    parser.add_argument("--output", "-o", type=str, help="Save report output to file")
    parser.add_argument("--remediate-dir", type=str, help="Auto-write full remediation configuration bundle to directory")

    parsed = parser.parse_args(args)

    passed, result_dict, output_str = run_security_check(
        target_url_or_path=parsed.target,
        min_score=parsed.min_score,
        fail_on_critical=parsed.fail_on_critical,
        output_format=parsed.format,
    )

    print(output_str)

    if parsed.output:
        out_path = Path(parsed.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")

    if parsed.remediate_dir:
        # Generate remediation files
        auditor = SecurityAuditor()
        if parsed.target.startswith(("http://", "https://")):
            audit_res = auditor.audit_url(parsed.target)
        else:
            audit_res = auditor.audit_file(parsed.target)
        remediator = SecurityRemediator(audit_result=audit_res)
        created = remediator.write_remediation_bundle(parsed.remediate_dir)
        print(f"\n[+] Successfully wrote {len(created)} remediation files to: {parsed.remediate_dir}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
