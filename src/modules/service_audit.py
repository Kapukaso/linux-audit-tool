"""
Services & Daemons Audit Module.
Author: Kartik Soni

Checks:
- SRV-001: Obsolete legacy services masked or not running
"""

from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import is_service_active, is_service_enabled, command_exists

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
        
        # Default baseline values
        disallowed_services = ["telnet", "telnetd", "rsh", "rsh-server", "rlogin", "nis", "tftp", "xinetd", "vsftpd"]
        severity = Severity.MEDIUM
        title = "Ensure obsolete services are masked or not installed"
        
        # Incorporate baseline configuration (ARCH-02, LOW-12)
        for check in self.checks:
            if check.get("id") == check_id:
                disallowed_services = check.get("disallowed_services", disallowed_services)
                if "severity" in check:
                    try:
                        severity = Severity[check["severity"].upper()]
                    except (KeyError, AttributeError):
                        pass
                title = check.get("title", title)
                break
                
        # ARCH-01: Check for command availability instead of silent PASS
        if not command_exists("systemctl"):
            return AuditFinding(
                check_id=check_id,
                category="service_security",
                title=title,
                severity=severity,
                status=Status.SKIP,
                description="The systemctl command is not available.",
                evidence="Command 'systemctl' not found.",
                recommendation="Install systemd or verify service management manually.",
                remediable=False
            )

        active_obsolete: List[str] = []
        enabled_obsolete: List[str] = []

        # HIGH-14: Check both active and enabled states
        for srv in disallowed_services:
            if is_service_active(srv):
                active_obsolete.append(srv)
            elif is_service_enabled(srv):
                enabled_obsolete.append(srv)

        if not active_obsolete and not enabled_obsolete:
            return AuditFinding(
                check_id=check_id,
                category="service_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description="No prohibited legacy daemons are active or enabled.",
                evidence="0 obsolete services running or enabled.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            issues = []
            if active_obsolete:
                issues.append(f"Active: {', '.join(active_obsolete)}")
            if enabled_obsolete:
                issues.append(f"Enabled (inactive): {', '.join(enabled_obsolete)}")
                
            evidence_str = "; ".join(issues)
            all_obsolete = active_obsolete + enabled_obsolete
            
            return AuditFinding(
                check_id=check_id,
                category="service_security",
                title=title,
                severity=severity,
                status=Status.FAIL,
                description="Insecure legacy services are currently active or enabled on the host!",
                evidence=f"Obsolete daemons found - {evidence_str}",
                recommendation="Stop and mask obsolete services using 'systemctl stop <srv>; systemctl mask <srv>'.",
                remediable=True,
                remediation_details=f"Stop and mask obsolete daemons: {', '.join(all_obsolete)}"
            )
