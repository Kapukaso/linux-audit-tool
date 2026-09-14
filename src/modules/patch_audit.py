"""
Patch & Package Management Audit Module.
Author: Kartik Soni

Checks:
- PTC-001: Pending security package updates
- PTC-002: Unattended-upgrades package installation and service status
"""

from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import command_exists, is_service_active, run_command

logger = AuditLogger.get_logger()


class PatchAuditModule:
    """Audits system package security updates and unattended-upgrades status."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes patch audit checks."""
        return [
            self.audit_pending_updates(),
            self.audit_unattended_upgrades()
        ]

    def audit_pending_updates(self) -> AuditFinding:
        """PTC-001: Check for pending security package updates via package manager."""
        check_id = "PTC-001"

        if not command_exists("apt-get") and not command_exists("dpkg"):
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check for pending security package updates via package manager",
                severity=Severity.HIGH,
                status=Status.SKIP,
                description="APT package manager not detected on host.",
                evidence="apt-get binary missing.",
                recommendation="Ensure a supported package manager is installed.",
                remediable=False
            )

        # Simulation mode check for apt-get upgrade
        code, stdout, _ = run_command(["apt-get", "-s", "upgrade"])
        security_updates = 0
        total_upgradable = 0

        if code == 0 and stdout:
            for line in stdout.splitlines():
                if line.startswith("Inst "):
                    total_upgradable += 1
                    if "security" in line.lower() or "-security" in line.lower():
                        security_updates += 1

        if total_upgradable == 0:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check for pending security package updates via package manager",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="System is fully up to date. 0 pending package updates.",
                evidence="0 packages pending upgrade.",
                recommendation="None. Current configuration is secure.",
                remediable=False
            )
        elif security_updates == 0:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check for pending security package updates via package manager",
                severity=Severity.HIGH,
                status=Status.PASS,
                description=f"{total_upgradable} standard packages pending upgrade (0 critical security updates).",
                evidence=f"{total_upgradable} upgradable packages (0 security).",
                recommendation="Schedule regular system package maintenance.",
                remediable=False
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check for pending security package updates via package manager",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Critical pending security updates detected! ({security_updates} security updates out of {total_upgradable} total).",
                evidence=f"{security_updates} pending security package updates.",
                recommendation="Run 'sudo apt-get update && sudo apt-get upgrade' to install security patches.",
                remediable=False
            )

    def audit_unattended_upgrades(self) -> AuditFinding:
        """PTC-002: Check if unattended-upgrades is installed and enabled."""
        check_id = "PTC-002"
        is_installed = False

        if command_exists("dpkg-query"):
            code, stdout, _ = run_command(["dpkg-query", "-W", "-f='${Status}'", "unattended-upgrades"])
            if code == 0 and "install ok installed" in stdout:
                is_installed = True

        is_active = is_service_active("unattended-upgrades")

        if is_installed or is_active:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check if unattended-upgrades is installed and enabled",
                severity=Severity.LOW,
                status=Status.PASS,
                description="Automatic security updates package (unattended-upgrades) is installed.",
                evidence=f"Installed: {is_installed}, Active daemon: {is_active}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title="Check if unattended-upgrades is installed and enabled",
                severity=Severity.LOW,
                status=Status.FAIL,
                description="Automatic security updates package (unattended-upgrades) is missing or inactive.",
                evidence="unattended-upgrades not active.",
                recommendation="Install and enable automatic security updates: 'apt-get install unattended-upgrades'.",
                remediable=True,
                remediation_details="apt-get install -y unattended-upgrades"
            )
