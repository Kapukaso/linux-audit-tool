"""
Data models and enumeration types for the Linux Security Hardening Toolkit.
Author: Kartik Soni
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class Severity(str, Enum):
    """Severity ratings for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def penalty_points(self) -> int:
        """Deduction penalty used in the deterministic scoring engine."""
        penalties = {
            "CRITICAL": 15,
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 2,
            "INFO": 0
        }
        return penalties.get(self.value, 0)


class Status(str, Enum):
    """Status evaluation of an individual security check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class RiskLevel(str, Enum):
    """Overall system risk classification based on final score."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        if score < 50.0:
            return cls.CRITICAL
        elif score < 70.0:
            return cls.HIGH
        elif score < 85.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class AuditFinding:
    """Individual security check result."""
    check_id: str
    category: str
    title: str
    severity: Severity
    status: Status
    description: str
    evidence: str
    recommendation: str
    remediable: bool = False
    remediation_details: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


@dataclass
class CategoryScore:
    """Calculated compliance score for a single security category."""
    category_id: str
    category_name: str
    weight: float
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0
    score: float = 100.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SystemMeta:
    """Host environment metadata collected during audit."""
    hostname: str = "unknown"
    os_name: str = "Linux"
    os_version: str = "unknown"
    kernel_version: str = "unknown"
    architecture: str = "unknown"
    cpu_info: str = "unknown"
    memory_total_mb: float = 0.0
    memory_free_mb: float = 0.0
    disk_usage: Dict[str, Any] = field(default_factory=dict)
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Complete security audit report container."""
    tool_name: str = "secureaudit"
    tool_version: str = "1.0.0"
    author: str = "Kartik Soni"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    system_meta: SystemMeta = field(default_factory=SystemMeta)
    overall_score: float = 100.0
    risk_level: RiskLevel = RiskLevel.LOW
    findings: List[AuditFinding] = field(default_factory=list)
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)
    summary: Dict[str, int] = field(default_factory=lambda: {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "author": self.author,
            "timestamp": self.timestamp,
            "system_meta": self.system_meta.to_dict(),
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
            "category_scores": {k: v.to_dict() for k, v in self.category_scores.items()},
            "summary": self.summary
        }


@dataclass
class HardeningAction:
    """Action record performed or planned during hardening."""
    action_id: str
    check_id: str
    title: str
    target_path: Optional[str] = None
    backup_path: Optional[str] = None
    status: str = "PLANNED"  # PLANNED, APPLIED, FAILED, ROLLED_BACK
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
