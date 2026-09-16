"""
Patch & Package Management Audit Module.
Author: Kartik Soni

Checks:
- PTC-001: Pending security package updates
- PTC-002: Unattended-upgrades package installation and service status
"""

import os
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import command_exists, is_service_active, run_command

logger = AuditLogger.get_logger()


class PatchAuditModule:
    """Audits system package security updates and unattended-upgrades status."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def _get_check_config(self, check_id: str, default_title: str, default_severity: Severity, default_description: str) -> Dict[str, Any]:
        for check in self.checks:
            if check.get("id") == check_id:
                return check
        return {
            "title": default_title,
            "severity": default_severity.name,
            "description": default_description,
            "remediable": False
        }

    def audit_all(self) -> List[AuditFinding]:
        """Executes patch audit checks."""
        return [
            self.audit_pending_updates(),
            self.audit_unattended_upgrades()
        ]

    def audit_pending_updates(self) -> AuditFinding:
        """PTC-001: Check for pending security package updates via package manager."""
        check_id = "PTC-001"
        cfg = self._get_check_config(
            check_id, 
            "Check for pending security package updates via package manager", 
            Severity.HIGH, 
            "System should have no pending security updates."
        )
        try:
            sev = Severity[cfg.get("severity", "HIGH").upper()]
        except KeyError:
            sev = Severity.HIGH

        if not command_exists("apt-get"):
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title=cfg.get("title", ""),
                severity=sev,
                status=Status.SKIP,
                description="APT package manager not detected on host.",
                evidence="apt-get binary missing.",
                recommendation="Ensure a supported package manager is installed.",
                remediable=False
            )

        # Simulation mode check for apt-get upgrade
        code, stdout, stderr = run_command(["apt-get", "-s", "upgrade"])
        
        if code != 0:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title=cfg.get("title", ""),
                severity=sev,
                status=Status.ERROR,
                description=f"Failed to check pending updates: apt-get exited with code {code}",
                evidence=stderr or stdout or f"Exit code {code}",
                recommendation="Investigate apt-get errors manually.",
                remediable=False
            )

        security_updates = 0
        total_upgradable = 0

        if stdout:
            for line in stdout.splitlines():
                if line.startswith("Inst "):
                    total_upgradable += 1
                    if "security" in line.lower() or "-security" in line.lower():
                        security_updates += 1

        if total_upgradable == 0:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title=cfg.get("title", ""),
                severity=sev,
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
                title=cfg.get("title", ""),
                severity=sev,
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
                title=cfg.get("title", ""),
                severity=sev,
                status=Status.FAIL,
                description=f"Critical pending security updates detected! ({security_updates} security updates out of {total_upgradable} total).",
                evidence=f"{security_updates} pending security package updates.",
                recommendation="Run 'sudo apt-get update && sudo apt-get upgrade' to install security patches.",
                remediable=False
            )

    def audit_unattended_upgrades(self) -> AuditFinding:
        """PTC-002: Check if unattended-upgrades is installed and enabled."""
        check_id = "PTC-002"
        cfg = self._get_check_config(
            check_id, 
            "Check if unattended-upgrades is installed and enabled", 
            Severity.LOW, 
            "Automatic security updates package (unattended-upgrades) should be installed and enabled."
        )
        try:
            sev = Severity[cfg.get("severity", "LOW").upper()]
        except KeyError:
            sev = Severity.LOW

        is_installed = False

        if command_exists("dpkg-query"):
            code, stdout, _ = run_command(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
            if code == 0 and "install ok installed" in stdout:
                is_installed = True

        is_active = is_service_active("unattended-upgrades")
        
        config_enabled = False
        config_path = "/etc/apt/apt.conf.d/20auto-upgrades"
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    if 'Unattended-Upgrade "1"' in f.read():
                        config_enabled = True
            except Exception:
                pass

        if is_installed and config_enabled:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title=cfg.get("title", ""),
                severity=sev,
                status=Status.PASS,
                description="Automatic security updates package (unattended-upgrades) is installed and enabled.",
                evidence=f"Installed: {is_installed}, Config enabled: {config_enabled}",
                recommendation="None. Current configuration is secure.",
                remediable=cfg.get("remediable", True)
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="patch_security",
                title=cfg.get("title", ""),
                severity=sev,
                status=Status.FAIL,
                description="Automatic security updates package (unattended-upgrades) is missing or inactive/disabled.",
                evidence=f"Installed: {is_installed}, Config enabled: {config_enabled}",
                recommendation="Install and enable automatic security updates: 'apt-get install unattended-upgrades'.",
                remediable=cfg.get("remediable", True),
                remediation_details="apt-get install -y unattended-upgrades"
            )
