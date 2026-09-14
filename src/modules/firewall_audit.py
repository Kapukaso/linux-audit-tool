"""
Firewall Audit Module.
Author: Kartik Soni

Checks:
- FW-001: Ensure UFW is active and running
- FW-002: Ensure default incoming firewall policy is deny
- FW-003: Ensure SSH port is explicitly allowed
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import command_exists, run_command

logger = AuditLogger.get_logger()


class FirewallAuditModule:
    """Audits UFW (Uncomplicated Firewall), iptables, and nftables firewall configurations."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes firewall security audit checks."""
        return [
            self.audit_ufw_active(),
            self.audit_default_incoming_policy(),
            self.audit_ssh_port_allowed()
        ]

    def _get_ufw_status(self) -> Tuple[bool, str, List[str]]:
        """
        Queries UFW status.
        Returns (is_active, default_incoming_policy, active_rules).
        """
        if not command_exists("ufw"):
            return False, "unknown", []

        code, stdout, _ = run_command(["ufw", "status", "verbose"])
        if code != 0 or "Status: active" not in stdout:
            return False, "unknown", []

        # Parse default incoming policy
        default_policy = "unknown"
        policy_match = re.search(r'Default:\s+([^\s,]+)\s+\(incoming\)', stdout, re.IGNORECASE)
        if policy_match:
            default_policy = policy_match.group(1).lower()

        # Collect rule lines
        rules = [line.strip() for line in stdout.splitlines() if "ALLOW" in line or "DENY" in line]
        return True, default_policy, rules

    def audit_ufw_active(self) -> AuditFinding:
        """FW-001: Ensure host firewall (UFW) is active and running."""
        check_id = "FW-001"
        is_active, _, _ = self._get_ufw_status()

        if is_active:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure host firewall (UFW) is active and running",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="Host firewall (UFW) is active and filtering network traffic.",
                evidence="UFW status: active",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )

        # Check fallback iptables or nftables
        code_ip, out_ip, _ = run_command(["iptables", "-L", "-n"])
        if code_ip == 0 and ("CHAIN" in out_ip.upper() and len(out_ip.splitlines()) > 6):
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure host firewall (UFW) is active and running",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="UFW is inactive, but custom iptables rules are active.",
                evidence="Active iptables rules detected.",
                recommendation="Consider standardizing on UFW for manageable baseline enforcement.",
                remediable=True
            )

        return AuditFinding(
            check_id=check_id,
            category="firewall_security",
            title="Ensure host firewall (UFW) is active and running",
            severity=Severity.HIGH,
            status=Status.FAIL,
            description="Host firewall (UFW) is disabled or not installed!",
            evidence="UFW status: inactive",
            recommendation="Enable UFW host firewall using 'ufw enable'. Ensure SSH port is allowed first!",
            remediable=True,
            remediation_details="Enable UFW firewall after allowing SSH access"
        )

    def audit_default_incoming_policy(self) -> AuditFinding:
        """FW-002: Ensure default incoming firewall policy is deny or reject."""
        check_id = "FW-002"
        is_active, default_incoming, _ = self._get_ufw_status()

        if not is_active:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure default incoming firewall policy is deny or reject",
                severity=Severity.HIGH,
                status=Status.SKIP,
                description="UFW firewall is inactive; default policy check skipped.",
                evidence="UFW inactive.",
                recommendation="Enable UFW firewall first.",
                remediable=True
            )

        if default_incoming in ["deny", "reject"]:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure default incoming firewall policy is deny or reject",
                severity=Severity.HIGH,
                status=Status.PASS,
                description=f"Default incoming UFW policy is set to '{default_incoming}'.",
                evidence=f"Default incoming policy: {default_incoming}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure default incoming firewall policy is deny or reject",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=f"Insecure default incoming firewall policy: '{default_incoming}'!",
                evidence=f"Default incoming policy: {default_incoming}",
                recommendation="Set default incoming policy to deny using 'ufw default deny incoming'.",
                remediable=True,
                remediation_details="ufw default deny incoming"
            )

    def audit_ssh_port_allowed(self) -> AuditFinding:
        """FW-003: Ensure SSH port is explicitly allowed before enabling firewall."""
        check_id = "FW-003"
        is_active, _, rules = self._get_ufw_status()

        ssh_allowed = False
        for rule in rules:
            if "22" in rule or "SSH" in rule.upper():
                if "ALLOW" in rule.upper():
                    ssh_allowed = True
                    break

        if ssh_allowed or not is_active:
            evidence_msg = "SSH port (22) is allowed in UFW rules" if is_active else "UFW inactive (pre-flight lockout check)"
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure SSH port is explicitly allowed before enabling firewall",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                description="Anti-lockout check verified: SSH port access is permitted.",
                evidence=evidence_msg,
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title="Ensure SSH port is explicitly allowed before enabling firewall",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                description="UFW is active but no explicit SSH allow rule was detected!",
                evidence="No rule matching 'ALLOW 22/tcp' found in active UFW status.",
                recommendation="Immediately run 'ufw allow 22/tcp' to prevent administrator lockout.",
                remediable=True,
                remediation_details="ufw allow 22/tcp"
            )
