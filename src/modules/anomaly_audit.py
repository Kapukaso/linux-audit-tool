"""
Anomaly Detection / Threat Intelligence Module.
Author: AI Assistant

Checks:
- THREAT-001: Detect anomalous login patterns in auth logs
- THREAT-002: Track unusual or dormant accounts
"""

import re
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import safe_read_file

logger = AuditLogger.get_logger()

class AnomalyAuditModule:
    """Audits system for anomalies and threat intelligence."""

    def __init__(self, checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes all threat anomaly audit checks."""
        findings = [
            self.audit_anomalous_logins(),
            self.audit_dormant_accounts(),
        ]
        return findings

    def audit_anomalous_logins(self) -> AuditFinding:
        """THREAT-001: Detect anomalous login patterns in auth logs."""
        check_id = "THREAT-001"
        log_files = ["/var/log/auth.log", "/var/log/secure"]
        log_content = ""
        for f in log_files:
            content = safe_read_file(f)
            if content:
                log_content += content
        
        if not log_content:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Detect anomalous login patterns in auth logs",
                severity=Severity.HIGH,
                status=Status.SKIP,
                description="No auth logs found to analyze.",
                evidence="Checked /var/log/auth.log and /var/log/secure",
                recommendation="Ensure auth logs are present."
            )

        failed_logins = len(re.findall(r"Failed password", log_content, re.IGNORECASE))
        if failed_logins > 50:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Detect anomalous login patterns in auth logs",
                severity=Severity.HIGH,
                status=Status.WARN,
                description=f"High number of failed logins detected ({failed_logins}).",
                evidence=f"{failed_logins} failed logins found",
                recommendation="Review auth logs for brute force attacks.",
                remediable=False
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Detect anomalous login patterns in auth logs",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="Login patterns appear normal.",
                evidence=f"{failed_logins} failed logins found",
                recommendation="None.",
                remediable=False
            )

    def audit_dormant_accounts(self) -> AuditFinding:
        """THREAT-002: Track unusual or dormant accounts."""
        check_id = "THREAT-002"
        shadow_content = safe_read_file("/etc/shadow")

        if not shadow_content:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Track unusual or dormant accounts",
                severity=Severity.HIGH,
                status=Status.SKIP,
                description="Unable to read /etc/shadow.",
                evidence="Could not access shadow file",
                recommendation="Run tool with root privileges."
            )

        dormant_accounts = []
        for line in shadow_content.splitlines():
            parts = line.split(":")
            if len(parts) > 7:
                user = parts[0]
                inactive = parts[6]
                if inactive and inactive.isdigit():
                    if int(inactive) > 30:
                        dormant_accounts.append(user)

        if dormant_accounts:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Track unusual or dormant accounts",
                severity=Severity.HIGH,
                status=Status.WARN,
                description=f"Dormant accounts detected: {', '.join(dormant_accounts)}.",
                evidence=f"Found {len(dormant_accounts)} dormant accounts.",
                recommendation="Review and disable unused accounts.",
                remediable=False
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="threat_intel",
                title="Track unusual or dormant accounts",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="No dormant accounts detected.",
                evidence="All active accounts seem in use.",
                recommendation="None.",
                remediable=False
            )
