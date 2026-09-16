"""
Web Security Guard - Security Diff Analyzer Module
Analyzes differences between two security postures (baseline vs candidate / PR vs main),
tracking resolved vulnerabilities, introduced regressions, and score/grade deltas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Dict, List, Optional, Any, Union, Set, Tuple


def _extract_audit_data(audit: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
    """Extracts normalized audit data dictionary from AuditResult or dict."""
    if hasattr(audit, "to_dict") and callable(audit.to_dict):
        return audit.to_dict()
    if isinstance(audit, dict):
        return audit
    raise ValueError(f"Unsupported audit format: {type(audit)}")


def _normalize_findings(findings_raw: List[Any]) -> List[Dict[str, Any]]:
    """Converts a list of Finding objects or dicts into uniform dict representations."""
    normalized: List[Dict[str, Any]] = []
    for f in findings_raw:
        if hasattr(f, "to_dict") and callable(f.to_dict):
            normalized.append(f.to_dict())
        elif isinstance(f, dict):
            normalized.append(dict(f))
    return normalized


class SecurityDiffAnalyzer:
    """
    Compares two security audit runs (e.g. baseline vs candidate / pre-patch vs post-patch)
    and produces quantitative deltas, vulnerability diff lists, markdown tables, and ASCII reports.
    """

    def __init__(
        self,
        baseline_audit: Union[Dict[str, Any], Any],
        candidate_audit: Union[Dict[str, Any], Any],
    ):
        self.baseline = _extract_audit_data(baseline_audit)
        self.candidate = _extract_audit_data(candidate_audit)

        self.baseline_score: int = int(self.baseline.get("score", 0))
        self.candidate_score: int = int(self.candidate.get("score", 0))
        self.score_delta: int = self.candidate_score - self.baseline_score

        self.baseline_grade: str = str(self.baseline.get("grade", "F"))
        self.candidate_grade: str = str(self.candidate.get("grade", "F"))

        self.baseline_findings = _normalize_findings(self.baseline.get("findings", []))
        self.candidate_findings = _normalize_findings(self.candidate.get("findings", []))

    def analyze(self) -> Dict[str, Any]:
        """Performs full comparison analysis and returns structured diff results."""
        # Index findings by id
        base_map: Dict[str, Dict[str, Any]] = {}
        for f in self.baseline_findings:
            fid = f.get("id") or f.get("title", "")
            base_map[fid] = f

        cand_map: Dict[str, Dict[str, Any]] = {}
        for f in self.candidate_findings:
            fid = f.get("id") or f.get("title", "")
            cand_map[fid] = f

        resolved_ids = set(base_map.keys()) - set(cand_map.keys())
        new_ids = set(cand_map.keys()) - set(base_map.keys())
        unchanged_ids = set(base_map.keys()) & set(cand_map.keys())

        resolved_findings = [base_map[fid] for fid in sorted(resolved_ids)]
        new_findings = [cand_map[fid] for fid in sorted(new_ids)]
        unchanged_findings = [cand_map[fid] for fid in sorted(unchanged_ids)]

        # Calculate metrics deltas
        def count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": len(findings)}
            for f in findings:
                sev = str(f.get("severity", "INFO")).upper()
                if sev in counts:
                    counts[sev] += 1
            return counts

        base_counts = count_severities(self.baseline_findings)
        cand_counts = count_severities(self.candidate_findings)

        metrics_delta = {
            "critical": cand_counts["CRITICAL"] - base_counts["CRITICAL"],
            "high": cand_counts["HIGH"] - base_counts["HIGH"],
            "medium": cand_counts["MEDIUM"] - base_counts["MEDIUM"],
            "low": cand_counts["LOW"] - base_counts["LOW"],
            "info": cand_counts["INFO"] - base_counts["INFO"],
            "total": cand_counts["TOTAL"] - base_counts["TOTAL"],
        }

        # Grade change representation
        if self.baseline_grade == self.candidate_grade:
            grade_change = f"UNCHANGED ({self.candidate_grade})"
        else:
            grade_change = f"{self.baseline_grade} -> {self.candidate_grade}"

        improved = self.score_delta > 0 or len(resolved_findings) > 0
        regressed = self.score_delta < 0 or len(new_findings) > 0 or metrics_delta["critical"] > 0 or metrics_delta["high"] > 0

        markdown_table = self._generate_markdown_table(
            metrics_delta, resolved_findings, new_findings, unchanged_findings
        )
        ascii_report = self._generate_ascii_report(
            metrics_delta, resolved_findings, new_findings, unchanged_findings
        )

        delta_sign = f"+{self.score_delta}" if self.score_delta > 0 else str(self.score_delta)
        summary = (
            f"Security Posture Diff: Score {self.baseline_score} -> {self.candidate_score} ({delta_sign} pts), "
            f"Grade {grade_change}. "
            f"Resolved: {len(resolved_findings)}, New: {len(new_findings)}, Unchanged: {len(unchanged_findings)}."
        )

        return {
            "baseline_score": self.baseline_score,
            "candidate_score": self.candidate_score,
            "score_delta": self.score_delta,
            "score_delta_formatted": delta_sign,
            "baseline_grade": self.baseline_grade,
            "candidate_grade": self.candidate_grade,
            "grade_change": grade_change,
            "improved": improved,
            "regressed": regressed,
            "resolved_findings": resolved_findings,
            "new_findings": new_findings,
            "unchanged_findings": unchanged_findings,
            "resolved_count": len(resolved_findings),
            "new_count": len(new_findings),
            "unchanged_count": len(unchanged_findings),
            "metrics_delta": metrics_delta,
            "baseline_metrics": base_counts,
            "candidate_metrics": cand_counts,
            "markdown_table": markdown_table,
            "diff_table_md": markdown_table,
            "ascii_report": ascii_report,
            "terminal_report": ascii_report,
            "summary": summary,
        }

    def _generate_markdown_table(
        self,
        metrics_delta: Dict[str, int],
        resolved: List[Dict[str, Any]],
        new_f: List[Dict[str, Any]],
        unchanged: List[Dict[str, Any]],
    ) -> str:
        """Generates clean GitHub-Flavored Markdown comparison tables."""
        delta_str = f"+{self.score_delta}" if self.score_delta > 0 else str(self.score_delta)
        delta_badge = "🟢 " if self.score_delta > 0 else ("🔴 " if self.score_delta < 0 else "⚪ ")

        lines = [
            "## 🛡️ Web Security Guard - Posture Diff Analysis",
            "",
            "### 📊 Score & Grade Comparison",
            "",
            "| Metric | Baseline | Candidate | Delta | Status |",
            "| :--- | :---: | :---: | :---: | :--- |",
            f"| **Security Score** | `{self.baseline_score}/100` | `{self.candidate_score}/100` | **{delta_badge}{delta_str} pts** | {'✅ Improved' if self.score_delta > 0 else ('❌ Regressed' if self.score_delta < 0 else '➖ Unchanged')} |",
            f"| **Security Grade** | `[{self.baseline_grade}]` | `[{self.candidate_grade}]` | **{self.baseline_grade} → {self.candidate_grade}** | {'✅ Grade Up' if self.candidate_score > self.baseline_score else ('❌ Grade Down' if self.candidate_score < self.baseline_score else '➖ Same')} |",
            f"| **Critical Issues** | `{self.baseline.get('metrics', {}).get('critical_count', 0)}` | `{self.candidate.get('metrics', {}).get('critical_count', 0)}` | `{metrics_delta['critical']:+d}` | {'✅ Clean' if metrics_delta['critical'] <= 0 else '🚨 New Critical'} |",
            f"| **High Issues** | `{self.baseline.get('metrics', {}).get('high_count', 0)}` | `{self.candidate.get('metrics', {}).get('high_count', 0)}` | `{metrics_delta['high']:+d}` | {'✅ Reduced' if metrics_delta['high'] < 0 else ('⚠️ Increased' if metrics_delta['high'] > 0 else '➖ Same')} |",
            f"| **Total Findings** | `{len(self.baseline_findings)}` | `{len(self.candidate_findings)}` | `{metrics_delta['total']:+d}` | {len(resolved)} fixed, {len(new_f)} new |",
            "",
            "### 🔍 Findings Diff Matrix",
            "",
        ]

        if not resolved and not new_f and not unchanged:
            lines.append("🎉 *Zero findings in both baseline and candidate postures.*\n")
            return "\n".join(lines)

        lines.extend([
            "| Status | ID | Severity | Title | Deduction |",
            "| :---: | :--- | :---: | :--- | :---: |",
        ])

        for f in resolved:
            lines.append(
                f"| ✅ **RESOLVED** | `{f.get('id', 'N/A')}` | `{f.get('severity', 'INFO')}` | {f.get('title', 'N/A')} | `+{f.get('deduction', 0)} pts` |"
            )

        for f in new_f:
            lines.append(
                f"| 🚨 **NEW** | `{f.get('id', 'N/A')}` | `{f.get('severity', 'INFO')}` | {f.get('title', 'N/A')} | `-{f.get('deduction', 0)} pts` |"
            )

        for f in unchanged:
            lines.append(
                f"| ⏳ **UNCHANGED** | `{f.get('id', 'N/A')}` | `{f.get('severity', 'INFO')}` | {f.get('title', 'N/A')} | `-{f.get('deduction', 0)} pts` |"
            )

        lines.append("")
        return "\n".join(lines)

    def _generate_ascii_report(
        self,
        metrics_delta: Dict[str, int],
        resolved: List[Dict[str, Any]],
        new_f: List[Dict[str, Any]],
        unchanged: List[Dict[str, Any]],
    ) -> str:
        """Generates terminal ASCII formatted diff report."""
        delta_str = f"+{self.score_delta}" if self.score_delta > 0 else str(self.score_delta)
        
        lines = [
            "================================================================================",
            "                     WEB SECURITY GUARD - POSTURE DIFF REPORT                   ",
            "================================================================================",
            f" Baseline Score: {self.baseline_score:>3}/100 [{self.baseline_grade:>2}]  -->  Candidate Score: {self.candidate_score:>3}/100 [{self.candidate_grade:>2}] (Delta: {delta_str} pts)",
            "--------------------------------------------------------------------------------",
            f" [VULNERABILITY SUMMARY]  Resolved: {len(resolved):<3} | New: {len(new_f):<3} | Unchanged: {len(unchanged):<3}",
            f" [CRITICAL ISSUES]        Baseline: {self.baseline.get('metrics', {}).get('critical_count', 0):<3} | Candidate: {self.candidate.get('metrics', {}).get('critical_count', 0):<3} | Delta: {metrics_delta['critical']:+d}",
            f" [HIGH ISSUES]            Baseline: {self.baseline.get('metrics', {}).get('high_count', 0):<3} | Candidate: {self.candidate.get('metrics', {}).get('high_count', 0):<3} | Delta: {metrics_delta['high']:+d}",
            "--------------------------------------------------------------------------------",
        ]

        if resolved:
            lines.append(" [*] RESOLVED VULNERABILITIES (FIXED):")
            for f in resolved:
                lines.append(f"   [+] [{f.get('severity', 'INFO'):<8}] {f.get('id', 'N/A')}: {f.get('title', '')}")
            lines.append("--------------------------------------------------------------------------------")

        if new_f:
            lines.append(" [!] NEW REGRESSIONS / VULNERABILITIES (ACTION REQUIRED):")
            for f in new_f:
                lines.append(f"   [-] [{f.get('severity', 'INFO'):<8}] {f.get('id', 'N/A')}: {f.get('title', '')}")
            lines.append("--------------------------------------------------------------------------------")

        if unchanged:
            lines.append(" [=] REMAINING UNRESOLVED FINDINGS:")
            for f in unchanged:
                lines.append(f"   [ ] [{f.get('severity', 'INFO'):<8}] {f.get('id', 'N/A')}: {f.get('title', '')}")
            lines.append("--------------------------------------------------------------------------------")

        lines.append("================================================================================")
        return "\n".join(lines)


def compare_security_postures(
    baseline_audit: Union[Dict[str, Any], Any],
    candidate_audit: Union[Dict[str, Any], Any],
) -> Dict[str, Any]:
    """
    Main entrypoint function to compare baseline vs candidate security posture.
    
    Parameters:
      - baseline_audit: Baseline AuditResult or dictionary
      - candidate_audit: Candidate AuditResult or dictionary
      
    Returns:
      Dict with score deltas, grade transitions, resolved/new/unchanged findings,
      markdown diff table, and terminal ASCII report.
    """
    analyzer = SecurityDiffAnalyzer(baseline_audit, candidate_audit)
    return analyzer.analyze()
