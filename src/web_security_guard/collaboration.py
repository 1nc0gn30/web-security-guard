"""Web Security Guard - Collaboration & Sharing Module.

Team collaboration features: shared reports, annotations,
team workspaces, and report export/import.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TeamMember:
    """Team member with role."""
    id: str
    name: str
    email: str = ""
    role: str = "viewer"  # admin, editor, viewer
    joined_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "joined_at": self.joined_at,
        }


@dataclass
class Annotation:
    """Finding annotation / comment."""
    id: str
    finding_id: str
    author: str
    text: str
    created_at: str = ""
    resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "author": self.author,
            "text": self.text,
            "created_at": self.created_at,
            "resolved": self.resolved,
        }


@dataclass
class SharedReport:
    """Shared audit report with team annotations."""
    report_id: str
    target: str
    author: str
    created_at: str
    report_data: Dict[str, Any] = field(default_factory=dict)
    annotations: List[Annotation] = field(default_factory=list)
    team_members: List[TeamMember] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    status: str = "draft"  # draft, review, approved, archived

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target": self.target,
            "author": self.author,
            "created_at": self.created_at,
            "report_data": self.report_data,
            "annotations": [a.to_dict() for a in self.annotations],
            "team_members": [m.to_dict() for m in self.team_members],
            "tags": self.tags,
            "status": self.status,
        }

    def format_text(self) -> str:
        lines = [
            f"=== Shared Report: {self.target} ===",
            f"Report ID: {self.report_id}",
            f"Author: {self.author}",
            f"Created: {self.created_at}",
            f"Status: {self.status}",
            f"Team Members: {len(self.team_members)}",
            f"Annotations: {len(self.annotations)}",
            f"Tags: {', '.join(self.tags) if self.tags else 'None'}",
            "-" * 60,
        ]
        if self.annotations:
            lines.append("Annotations:")
            for a in self.annotations:
                status = "✓ RESOLVED" if a.resolved else "⏳ OPEN"
                lines.append(f"  [{status}] [{a.author}] {a.text}")
        if self.team_members:
            lines.append("\nTeam:")
            for m in self.team_members:
                lines.append(f"  • {m.name} ({m.role})")
        return "\n".join(lines)

    def format_markdown(self) -> str:
        md = [
            f"# 📋 Shared Report: `{self.target}`\n",
            f"| Property | Value |",
            f"|---|---|",
            f"| Report ID | `{self.report_id}` |",
            f"| Author | {self.author} |",
            f"| Created | {self.created_at} |",
            f"| Status | **{self.status}** |",
            f"| Team Members | {len(self.team_members)} |",
            f"| Annotations | {len(self.annotations)} |",
            f"| Tags | {', '.join(self.tags) if self.tags else 'None'} |",
            "",
        ]
        if self.team_members:
            md.append("## Team\n")
            md.append("| Name | Role | Joined |")
            md.append("|---|---|---|")
            for m in self.team_members:
                md.append(f"| {m.name} | {m.role} | {m.joined_at} |")
            md.append("")
        
        if self.annotations:
            md.append("## Annotations\n")
            md.append("| # | Author | Status | Text |")
            md.append("|---|---|---|---|")
            for i, a in enumerate(self.annotations, 1):
                status = "✅" if a.resolved else "⏳"
                md.append(f"| {i} | {a.author} | {status} | {a.text[:80]} |")
            md.append("")
        
        return "\n".join(md)


class CollaborationWorkspace:
    """Manages shared reports and team collaboration."""
    
    def __init__(self, workspace_dir: str = ""):
        self.workspace_dir = workspace_dir or os.path.join(
            os.path.expanduser("~"), ".web-security-guard", "collaboration"
        )
        self.reports: Dict[str, SharedReport] = {}
        self._load_workspace()
    
    def _workspace_path(self) -> str:
        os.makedirs(self.workspace_dir, exist_ok=True)
        return os.path.join(self.workspace_dir, "workspace.json")
    
    def _load_workspace(self) -> None:
        """Load workspace from disk."""
        path = self._workspace_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for rid, rdata in data.get("reports", {}).items():
                members = [
                    TeamMember(**m) for m in rdata.get("team_members", [])
                ]
                annotations = [
                    Annotation(**a) for a in rdata.get("annotations", [])
                ]
                self.reports[rid] = SharedReport(
                    report_id=rid,
                    target=rdata.get("target", ""),
                    author=rdata.get("author", ""),
                    created_at=rdata.get("created_at", ""),
                    report_data=rdata.get("report_data", {}),
                    annotations=annotations,
                    team_members=members,
                    tags=rdata.get("tags", []),
                    status=rdata.get("status", "draft"),
                )
        except (json.JSONDecodeError, OSError):
            pass
    
    def _save_workspace(self) -> None:
        """Save workspace to disk."""
        os.makedirs(self.workspace_dir, exist_ok=True)
        data = {
            "reports": {
                rid: report.to_dict() for rid, report in self.reports.items()
            }
        }
        path = self._workspace_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    
    def create_report(
        self,
        target: str,
        author: str = "anonymous",
        report_data: Optional[Dict[str, Any]] = None,
    ) -> SharedReport:
        """Create a new shared report."""
        report = SharedReport(
            report_id=str(uuid.uuid4())[:8],
            target=target,
            author=author,
            created_at=datetime.now(timezone.utc).isoformat(),
            report_data=report_data or {},
        )
        self.reports[report.report_id] = report
        self._save_workspace()
        return report
    
    def get_report(self, report_id: str) -> Optional[SharedReport]:
        """Get a report by ID."""
        return self.reports.get(report_id)
    
    def list_reports(self) -> List[SharedReport]:
        """List all shared reports."""
        return list(self.reports.values())
    
    def add_annotation(
        self,
        report_id: str,
        finding_id: str,
        author: str,
        text: str,
    ) -> Optional[Annotation]:
        """Add an annotation to a report."""
        report = self.reports.get(report_id)
        if not report:
            return None
        annotation = Annotation(
            id=str(uuid.uuid4())[:8],
            finding_id=finding_id,
            author=author,
            text=text,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        report.annotations.append(annotation)
        self._save_workspace()
        return annotation
    
    def resolve_annotation(self, report_id: str, annotation_id: str) -> bool:
        """Mark an annotation as resolved."""
        report = self.reports.get(report_id)
        if not report:
            return False
        for a in report.annotations:
            if a.id == annotation_id:
                a.resolved = True
                self._save_workspace()
                return True
        return False
    
    def add_team_member(
        self,
        report_id: str,
        name: str,
        email: str = "",
        role: str = "viewer",
    ) -> Optional[TeamMember]:
        """Add a team member to a report."""
        report = self.reports.get(report_id)
        if not report:
            return None
        member = TeamMember(
            id=str(uuid.uuid4())[:8],
            name=name,
            email=email,
            role=role,
            joined_at=datetime.now(timezone.utc).isoformat(),
        )
        report.team_members.append(member)
        self._save_workspace()
        return member
    
    def update_status(self, report_id: str, status: str) -> bool:
        """Update report status."""
        report = self.reports.get(report_id)
        if not report:
            return False
        report.status = status
        self._save_workspace()
        return True
    
    def add_tag(self, report_id: str, tag: str) -> bool:
        """Add a tag to a report."""
        report = self.reports.get(report_id)
        if not report:
            return False
        if tag not in report.tags:
            report.tags.append(tag)
        self._save_workspace()
        return True
    
    def export_report(self, report_id: str, output_path: str) -> bool:
        """Export a report to a JSON file."""
        report = self.reports.get(report_id)
        if not report:
            return False
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        return True
    
    def import_report(self, input_path: str) -> Optional[SharedReport]:
        """Import a report from a JSON file."""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            report = SharedReport(
                report_id=data.get("report_id", str(uuid.uuid4())[:8]),
                target=data.get("target", ""),
                author=data.get("author", ""),
                created_at=data.get("created_at", ""),
                report_data=data.get("report_data", {}),
                tags=data.get("tags", []),
                status=data.get("status", "draft"),
            )
            for a_data in data.get("annotations", []):
                report.annotations.append(Annotation(**a_data))
            for m_data in data.get("team_members", []):
                report.team_members.append(TeamMember(**m_data))
            self.reports[report.report_id] = report
            self._save_workspace()
            return report
        except (json.JSONDecodeError, OSError, KeyError):
            return None
    
    def delete_report(self, report_id: str) -> bool:
        """Delete a report."""
        if report_id in self.reports:
            del self.reports[report_id]
            self._save_workspace()
            return True
        return False
    
    def search_reports(self, query: str) -> List[SharedReport]:
        """Search reports by target, tag, or annotation text."""
        query_lower = query.lower()
        results = []
        for report in self.reports.values():
            if query_lower in report.target.lower():
                results.append(report)
                continue
            if query_lower in " ".join(report.tags).lower():
                results.append(report)
                continue
            for a in report.annotations:
                if query_lower in a.text.lower():
                    results.append(report)
                    break
        return results