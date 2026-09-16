"""
Unit tests for Security Diff Analyzer Module (web_security_guard.diff_analyzer).
"""

import pytest
from web_security_guard.auditor import (
    AuditResult,
    Finding,
    Severity,
    Category,
    Grade,
    AuditMetrics,
)
from web_security_guard.diff_analyzer import (
    SecurityDiffAnalyzer,
    compare_security_postures,
)


class TestDiffAnalyzerDictInputs:
    def test_improvement_comparison(self):
        baseline = {
            "score": 45,
            "grade": "F",
            "findings": [
                {
                    "id": "CSP_MISSING",
                    "severity": "CRITICAL",
                    "title": "Missing Content-Security-Policy",
                    "deduction": 30,
                },
                {
                    "id": "HSTS_MISSING",
                    "severity": "HIGH",
                    "title": "Missing Strict-Transport-Security",
                    "deduction": 25,
                },
                {
                    "id": "XFO_MISSING",
                    "severity": "MEDIUM",
                    "title": "Missing X-Frame-Options",
                    "deduction": 10,
                },
            ],
            "metrics": {"critical_count": 1, "high_count": 1, "medium_count": 1, "total_findings": 3},
        }

        candidate = {
            "score": 90,
            "grade": "A",
            "findings": [
                {
                    "id": "XFO_MISSING",
                    "severity": "MEDIUM",
                    "title": "Missing X-Frame-Options",
                    "deduction": 10,
                }
            ],
            "metrics": {"critical_count": 0, "high_count": 0, "medium_count": 1, "total_findings": 1},
        }

        diff = compare_security_postures(baseline, candidate)

        assert diff["baseline_score"] == 45
        assert diff["candidate_score"] == 90
        assert diff["score_delta"] == 45
        assert diff["score_delta_formatted"] == "+45"
        assert diff["baseline_grade"] == "F"
        assert diff["candidate_grade"] == "A"
        assert diff["grade_change"] == "F -> A"
        assert diff["improved"] is True
        assert diff["regressed"] is False

        # Resolved: CSP_MISSING, HSTS_MISSING
        resolved_ids = [f["id"] for f in diff["resolved_findings"]]
        assert "CSP_MISSING" in resolved_ids
        assert "HSTS_MISSING" in resolved_ids
        assert diff["resolved_count"] == 2

        # New: None
        assert diff["new_count"] == 0
        assert len(diff["new_findings"]) == 0

        # Unchanged: XFO_MISSING
        unchanged_ids = [f["id"] for f in diff["unchanged_findings"]]
        assert "XFO_MISSING" in unchanged_ids
        assert diff["unchanged_count"] == 1

        # Metrics delta
        assert diff["metrics_delta"]["critical"] == -1
        assert diff["metrics_delta"]["high"] == -1
        assert diff["metrics_delta"]["medium"] == 0
        assert diff["metrics_delta"]["total"] == -2

        # Markdown and ASCII reports exist
        assert "## 🛡️ Web Security Guard - Posture Diff Analysis" in diff["markdown_table"]
        assert "RESOLVED" in diff["markdown_table"]
        assert "WEB SECURITY GUARD - POSTURE DIFF REPORT" in diff["ascii_report"]

    def test_regression_comparison(self):
        baseline = {
            "score": 100,
            "grade": "A+",
            "findings": [],
            "metrics": {"critical_count": 0, "high_count": 0, "total_findings": 0},
        }

        candidate = {
            "score": 60,
            "grade": "C",
            "findings": [
                {
                    "id": "CORS_WILDCARD_CREDENTIALS",
                    "severity": "CRITICAL",
                    "title": "CORS Wildcard with Credentials",
                    "deduction": 40,
                }
            ],
            "metrics": {"critical_count": 1, "high_count": 0, "total_findings": 1},
        }

        diff = compare_security_postures(baseline, candidate)

        assert diff["score_delta"] == -40
        assert diff["score_delta_formatted"] == "-40"
        assert diff["improved"] is False
        assert diff["regressed"] is True
        assert diff["grade_change"] == "A+ -> C"
        assert diff["resolved_count"] == 0
        assert diff["new_count"] == 1
        assert diff["new_findings"][0]["id"] == "CORS_WILDCARD_CREDENTIALS"
        assert diff["metrics_delta"]["critical"] == 1

    def test_unchanged_posture(self):
        state = {
            "score": 85,
            "grade": "A",
            "findings": [
                {
                    "id": "REFERRER_POLICY_UNSAFE",
                    "severity": "LOW",
                    "title": "Unsafe Referrer Policy",
                    "deduction": 15,
                }
            ],
            "metrics": {"low_count": 1, "total_findings": 1},
        }

        diff = compare_security_postures(state, state)

        assert diff["score_delta"] == 0
        assert diff["grade_change"] == "UNCHANGED (A)"
        assert diff["resolved_count"] == 0
        assert diff["new_count"] == 0
        assert diff["unchanged_count"] == 1
        assert diff["metrics_delta"]["total"] == 0


class TestDiffAnalyzerAuditResultObjects:
    def test_with_audit_result_instances(self):
        f1 = Finding(
            id="CSP_MISSING",
            category=Category.CSP,
            severity=Severity.CRITICAL,
            title="Missing CSP",
            description="Content Security Policy header is missing",
            remediation_hint="Add Content-Security-Policy header",
            deduction=30,
        )
        f2 = Finding(
            id="HSTS_MISSING",
            category=Category.HSTS,
            severity=Severity.HIGH,
            title="Missing HSTS",
            description="Strict-Transport-Security header is missing",
            remediation_hint="Add Strict-Transport-Security header",
            deduction=25,
        )

        res_baseline = AuditResult(
            target="https://baseline.test",
            target_type="url",
            timestamp=1700000000.0,
            score=45,
            grade=Grade.F,
            passed_ci_default=False,
            findings=[f1, f2],
            metrics=AuditMetrics(total_findings=2, critical_count=1, high_count=1),
        )

        res_candidate = AuditResult(
            target="https://candidate.test",
            target_type="url",
            timestamp=1700001000.0,
            score=100,
            grade=Grade.A_PLUS,
            passed_ci_default=True,
            findings=[],
            metrics=AuditMetrics(total_findings=0),
        )

        diff = compare_security_postures(res_baseline, res_candidate)

        assert diff["baseline_score"] == 45
        assert diff["candidate_score"] == 100
        assert diff["score_delta"] == 55
        assert diff["baseline_grade"] == "F"
        assert diff["candidate_grade"] == "A+"
        assert diff["grade_change"] == "F -> A+"
        assert diff["improved"] is True
        assert diff["resolved_count"] == 2
        assert len(diff["new_findings"]) == 0
