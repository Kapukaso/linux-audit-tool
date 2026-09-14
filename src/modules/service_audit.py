"""
Services & Daemons Audit Module.
Author: Kartik Soni

Checks:
- SRV-001: Obsolete legacy services masked or not running
"""

from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import is_service_active

logger = AuditLogger.get_logger()


class ServiceAuditModule:
    """Audits running daemons and identifies unnecessary/legacy system services."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes service security audit checks."""
        return [
            self.audit_obsolete_services()
        ]

    def audit_obsolete_services(self) -> AuditFinding:
        """SRV-001: Ensure obsolete services are masked or not installed."""
        check_id = "SRV-001"
        disallowed_services = ["telnet", "telnetd", "rsh", "rsh-server", "rlogin", "nis", "tftp", "xinetd", "vsftpd"]
        active_obsolete: List[str] = []

        for srv in disallowed_services:
            if is_service_active(srv):
                active_obsolete.append(srv)

        if not active_obsolete:
            return AuditFinding(
                check_id=check_id,
                category="service_security",
                title="Ensure obsolete services are masked or not installed",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description="No prohibited legacy daemons (telnet, rsh, xinetd) are active.",
                evidence="0 obsolete services running.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="service_security",
                title="Ensure obsolete services are masked or not installed",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="Insecure legacy services are currently active on the host!",
                evidence=f"Active obsolete daemons: {', '.join(active_obsolete)}",
                recommendation="Stop and mask obsolete services using 'systemctl stop <srv>; systemctl mask <srv>'.",
                remediable=True,
                remediation_details=f"Stop and mask obsolete daemons: {', '.join(active_obsolete)}"
            )
