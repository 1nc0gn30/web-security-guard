"""Web Security Guard - Scheduled Strikes / Recurring Scan Scheduler.

Schedule security audits, port scans, and target reconnaissance
to run at intervals with result history and alerting.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum


class StrikeFrequency(str, Enum):
    ONCE = "once"
    EVERY_HOUR = "hourly"
    EVERY_6_HOURS = "6h"
    EVERY_12_HOURS = "12h"
    DAILY = "daily"
    WEEKLY = "weekly"


@dataclass
class StrikeTarget:
    """Target for a scheduled strike."""
    url: str
    scan_type: str = "audit"  # audit, port-scan, target-info, all
    ports: Optional[List[int]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "scan_type": self.scan_type,
            "ports": self.ports or [],
        }


@dataclass
class StrikeResult:
    """Result from a single strike execution."""
    strike_id: str
    timestamp: str
    target: str
    scan_type: str
    success: bool
    output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strike_id": self.strike_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "scan_type": self.scan_type,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class ScheduledStrike:
    """A scheduled security strike (recurring scan task)."""
    strike_id: str
    name: str
    target: StrikeTarget
    frequency: StrikeFrequency
    interval_seconds: int
    enabled: bool = True
    created_at: str = ""
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    results: List[StrikeResult] = field(default_factory=list)
    max_results: int = 50  # Keep last N results
    alert_on_critical: bool = True
    _thread: Optional[threading.Thread] = field(default=None, repr=False)
    _stop_event: Optional[threading.Event] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strike_id": self.strike_id,
            "name": self.name,
            "target": self.target.to_dict(),
            "frequency": self.frequency.value,
            "interval_seconds": self.interval_seconds,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "results_count": len(self.results),
            "max_results": self.max_results,
            "alert_on_critical": self.alert_on_critical,
        }


class StrikeScheduler:
    """Manages scheduled security strikes."""
    
    def __init__(self, data_dir: str = ""):
        self.data_dir = data_dir or os.path.join(
            os.path.expanduser("~"), ".web-security-guard", "strikes"
        )
        os.makedirs(self.data_dir, exist_ok=True)
        self.strikes: Dict[str, ScheduledStrike] = {}
        self._lock = threading.Lock()
        self._load()
    
    def _data_path(self) -> str:
        return os.path.join(self.data_dir, "strikes.json")
    
    def _load(self) -> None:
        """Load strikes from disk."""
        path = self._data_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for sid, sdata in data.get("strikes", {}).items():
                target = StrikeTarget(
                    url=sdata.get("target", {}).get("url", ""),
                    scan_type=sdata.get("target", {}).get("scan_type", "audit"),
                    ports=sdata.get("target", {}).get("ports"),
                )
                strike = ScheduledStrike(
                    strike_id=sid,
                    name=sdata.get("name", ""),
                    target=target,
                    frequency=StrikeFrequency(sdata.get("frequency", "daily")),
                    interval_seconds=sdata.get("interval_seconds", 86400),
                    enabled=sdata.get("enabled", True),
                    created_at=sdata.get("created_at", ""),
                    last_run=sdata.get("last_run"),
                    next_run=sdata.get("next_run"),
                    max_results=sdata.get("max_results", 50),
                    alert_on_critical=sdata.get("alert_on_critical", True),
                )
                self.strikes[sid] = strike
        except (json.JSONDecodeError, OSError):
            pass
    
    def _save(self) -> None:
        """Save strikes to disk."""
        data = {
            "strikes": {
                sid: strike.to_dict() for sid, strike in self.strikes.items()
            }
        }
        path = self._data_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    
    def schedule_strike(
        self,
        name: str,
        target_url: str,
        frequency: StrikeFrequency = StrikeFrequency.DAILY,
        scan_type: str = "audit",
        ports: Optional[List[int]] = None,
        alert_on_critical: bool = True,
        max_results: int = 50,
    ) -> ScheduledStrike:
        """Schedule a new recurring strike."""
        interval_map: Dict[StrikeFrequency, int] = {
            StrikeFrequency.ONCE: 0,
            StrikeFrequency.EVERY_HOUR: 3600,
            StrikeFrequency.EVERY_6_HOURS: 21600,
            StrikeFrequency.EVERY_12_HOURS: 43200,
            StrikeFrequency.DAILY: 86400,
            StrikeFrequency.WEEKLY: 604800,
        }
        interval = interval_map.get(frequency, 86400)
        
        strike = ScheduledStrike(
            strike_id=str(uuid.uuid4())[:8],
            name=name,
            target=StrikeTarget(url=target_url, scan_type=scan_type, ports=ports),
            frequency=frequency,
            interval_seconds=interval,
            enabled=True,
            created_at=datetime.now(timezone.utc).isoformat(),
            next_run=datetime.now(timezone.utc).isoformat(),
            alert_on_critical=alert_on_critical,
            max_results=max_results,
        )
        
        with self._lock:
            self.strikes[strike.strike_id] = strike
            self._save()
        
        return strike
    
    def cancel_strike(self, strike_id: str) -> bool:
        """Cancel a scheduled strike."""
        with self._lock:
            strike = self.strikes.get(strike_id)
            if not strike:
                return False
            strike.enabled = False
            if strike._stop_event:
                strike._stop_event.set()
            self._save()
        return True
    
    def delete_strike(self, strike_id: str) -> bool:
        """Permanently delete a strike."""
        with self._lock:
            if strike_id in self.strikes:
                strike = self.strikes[strike_id]
                strike.enabled = False
                if strike._stop_event:
                    strike._stop_event.set()
                del self.strikes[strike_id]
                self._save()
                return True
        return False
    
    def get_strike(self, strike_id: str) -> Optional[ScheduledStrike]:
        """Get a strike by ID."""
        return self.strikes.get(strike_id)
    
    def list_strikes(self, enabled_only: bool = False) -> List[ScheduledStrike]:
        """List all strikes."""
        with self._lock:
            if enabled_only:
                return [s for s in self.strikes.values() if s.enabled]
            return list(self.strikes.values())
    
    def run_strike_now(self, strike_id: str) -> Optional[StrikeResult]:
        """Execute a strike immediately."""
        strike = self.strikes.get(strike_id)
        if not strike:
            return None
        
        result = self._execute_strike(strike)
        with self._lock:
            strike.last_run = datetime.now(timezone.utc).isoformat()
            strike.next_run = (
                datetime.now(timezone.utc) + timedelta(seconds=strike.interval_seconds)
            ).isoformat()
            strike.results.append(result)
            # Trim old results
            if len(strike.results) > strike.max_results:
                strike.results = strike.results[-strike.max_results:]
            self._save()
        return result
    
    def _execute_strike(self, strike: ScheduledStrike) -> StrikeResult:
        """Execute a strike and return results."""
        start = time.time()
        try:
            output: Dict[str, Any] = {}
            target_url = strike.target.url
            
            if strike.target.scan_type in ("audit", "all"):
                try:
                    from web_security_guard.mcp_server import audit_security
                    output["audit"] = audit_security(target=target_url)
                except Exception as e:
                    output["audit_error"] = str(e)
            
            if strike.target.scan_type in ("port-scan", "all"):
                try:
                    from web_security_guard.port_scanner import deep_port_scan
                    ports = strike.target.ports
                    output["port_scan"] = deep_port_scan(
                        target_url,
                        ports=ports,
                        timeout=1.0,
                        max_threads=100,
                    ).to_dict()
                except Exception as e:
                    output["port_scan_error"] = str(e)
            
            if strike.target.scan_type in ("target-info", "all"):
                try:
                    from web_security_guard.target_info import gather_target_info
                    output["target_info"] = gather_target_info(
                        target=target_url,
                        fetch_http=True,
                        dns_lookup=True,
                        fetch_html=True,
                    ).to_dict()
                except Exception as e:
                    output["target_info_error"] = str(e)
            
            duration = (time.time() - start) * 1000
            return StrikeResult(
                strike_id=strike.strike_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                target=target_url,
                scan_type=strike.target.scan_type,
                success=True,
                output=output,
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.time() - start) * 1000
            return StrikeResult(
                strike_id=strike.strike_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                target=strike.target.url,
                scan_type=strike.target.scan_type,
                success=False,
                error=str(e),
                duration_ms=duration,
            )
    
    def start_recurring(self, strike_id: str) -> bool:
        """Start a recurring strike in background thread."""
        strike = self.strikes.get(strike_id)
        if not strike or not strike.enabled:
            return False
        
        strike._stop_event = threading.Event()
        
        def _run_loop():
            while not strike._stop_event.is_set():
                result = self._execute_strike(strike)
                with self._lock:
                    strike.last_run = datetime.now(timezone.utc).isoformat()
                    strike.next_run = (
                        datetime.now(timezone.utc) + timedelta(seconds=strike.interval_seconds)
                    ).isoformat()
                    strike.results.append(result)
                    if len(strike.results) > strike.max_results:
                        strike.results = strike.results[-strike.max_results:]
                    self._save()
                
                # Wait for interval or stop
                if strike._stop_event and strike._stop_event.wait(timeout=strike.interval_seconds):
                    break
        
        strike._thread = threading.Thread(target=_run_loop, daemon=True)
        strike._thread.start()
        return True
    
    def stop_recurring(self, strike_id: str) -> bool:
        """Stop a recurring strike."""
        strike = self.strikes.get(strike_id)
        if not strike or not strike._thread:
            return False
        if strike._stop_event:
            strike._stop_event.set()
        strike._thread.join(timeout=5.0)
        strike._thread = None
        strike._stop_event = None
        return True
    
    def get_results(self, strike_id: str, limit: int = 10) -> List[StrikeResult]:
        """Get recent results for a strike."""
        strike = self.strikes.get(strike_id)
        if not strike:
            return []
        return strike.results[-limit:]
    
    def export_strikes(self, output_path: str) -> bool:
        """Export all strikes to a JSON file."""
        data = {
            "strikes": {
                sid: strike.to_dict() for sid, strike in self.strikes.items()
            }
        }
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except OSError:
            return False
    
    def import_strikes(self, input_path: str) -> int:
        """Import strikes from a JSON file. Returns count imported."""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            count = 0
            for sid, sdata in data.get("strikes", {}).items():
                target = StrikeTarget(
                    url=sdata.get("target", {}).get("url", ""),
                    scan_type=sdata.get("target", {}).get("scan_type", "audit"),
                    ports=sdata.get("target", {}).get("ports"),
                )
                strike = ScheduledStrike(
                    strike_id=sid,
                    name=sdata.get("name", ""),
                    target=target,
                    frequency=StrikeFrequency(sdata.get("frequency", "daily")),
                    interval_seconds=sdata.get("interval_seconds", 86400),
                    enabled=sdata.get("enabled", True),
                    created_at=sdata.get("created_at", ""),
                    max_results=sdata.get("max_results", 50),
                    alert_on_critical=sdata.get("alert_on_critical", True),
                )
                self.strikes[sid] = strike
                count += 1
            self._save()
            return count
        except (json.JSONDecodeError, OSError):
            return 0
    
    def format_strike_text(self, strike: ScheduledStrike) -> str:
        """Format a strike for terminal display."""
        lines = [
            f"=== Strike: {strike.name} ===",
            f"ID: {strike.strike_id}",
            f"Target: {strike.target.url}",
            f"Scan Type: {strike.target.scan_type}",
            f"Frequency: {strike.frequency.value}",
            f"Enabled: {'Yes' if strike.enabled else 'No'}",
            f"Last Run: {strike.last_run or 'Never'}",
            f"Next Run: {strike.next_run or 'N/A'}",
            f"Results: {len(strike.results)}",
            "-" * 60,
        ]
        for r in strike.results[-5:]:
            status = green_check = "✓" if r.success else "✗"
            lines.append(f"  [{status}] {r.timestamp} - {r.duration_ms:.0f}ms")
            if r.error:
                lines.append(f"    Error: {r.error}")
        return "\n".join(lines)