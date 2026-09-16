import re
import os
from typing import Any, Dict, List, Optional, Tuple

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import command_exists, run_command

logger = AuditLogger.get_logger()


class FirewallAuditModule:
    """Audits UFW (Uncomplicated Firewall), iptables, and nftables firewall configurations."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def _get_check_config(self, check_id: str) -> Dict[str, Any]:
        for check in self.checks:
            if check.get("id") == check_id:
                return check
        return {}

    def _get_ssh_port(self) -> str:
        port = "22"
        try:
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.lower().startswith("port "):
                            parts = line.split()
                            if len(parts) >= 2:
                                port = parts[1]
                                break
        except Exception:
            pass
        return port

    def audit_all(self) -> List[AuditFinding]:
        """Executes firewall security audit checks."""
        return [
            self.audit_ufw_active(),
            self.audit_default_incoming_policy(),
            self.audit_ssh_port_allowed()
        ]

    def _get_ufw_status(self) -> Tuple[bool, str, List[str], bool]:
        """
        Queries UFW status.
        Returns (is_active, default_incoming_policy, active_rules, permission_denied).
        """
        if not command_exists("ufw"):
            return False, "unknown", [], False

        code, stdout, stderr = run_command(["ufw", "status", "verbose"])

        if code != 0 and ("permission denied" in stderr.lower() or "root" in stderr.lower() or "must be root" in stderr.lower()):
            return False, "unknown", [], True

        if code != 0 or "Status: active" not in stdout:
            return False, "unknown", [], False

        # Parse default incoming policy
        default_policy = "unknown"
        policy_match = re.search(r'Default:\s+([^\s,]+)\s+\(incoming\)', stdout, re.IGNORECASE)
        if policy_match:
            default_policy = policy_match.group(1).lower()

        # Collect rule lines
        rules = [line.strip() for line in stdout.splitlines() if "ALLOW" in line or "DENY" in line]
        return True, default_policy, rules, False

    def audit_ufw_active(self) -> AuditFinding:
        """FW-001: Ensure host firewall (UFW) is active and running."""
        check_id = "FW-001"
        config = self._get_check_config(check_id)
        title = config.get("title", "Ensure host firewall (UFW) is active and running")
        severity_str = config.get("severity", "HIGH").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.HIGH

        is_active, _, _, perm_denied = self._get_ufw_status()

        if perm_denied:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description="Unable to check UFW status due to missing privileges.",
                evidence="Permission denied when running 'ufw status verbose'.",
                recommendation="Run the audit tool as root to verify firewall status.",
                remediable=False
            )

        if is_active:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description="Host firewall (UFW) is active and filtering network traffic.",
                evidence="UFW status: active",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )

        # Check fallback iptables or nftables
        code_ip, out_ip, err_ip = run_command(["iptables", "-L", "-n"])
        if code_ip != 0 and ("permission denied" in err_ip.lower() or "root" in err_ip.lower()):
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description="Unable to check iptables status due to missing privileges.",
                evidence="Permission denied when running 'iptables -L -n'.",
                recommendation="Run the audit tool as root to verify firewall status.",
                remediable=False
            )

        if code_ip == 0 and ("CHAIN" in out_ip.upper() and len(out_ip.splitlines()) > 6):
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description="UFW is inactive, but custom iptables rules are active.",
                evidence="Active iptables rules detected.",
                recommendation="Consider standardizing on UFW for manageable baseline enforcement.",
                remediable=True
            )

        return AuditFinding(
            check_id=check_id,
            category="firewall_security",
            title=title,
            severity=severity,
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
        config = self._get_check_config(check_id)
        title = config.get("title", "Ensure default incoming firewall policy is deny or reject")
        severity_str = config.get("severity", "HIGH").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.HIGH

        is_active, default_incoming, _, perm_denied = self._get_ufw_status()
        
        if perm_denied:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description="Unable to check UFW policy due to missing privileges.",
                evidence="Permission denied.",
                recommendation="Run as root.",
                remediable=False
            )

        if not is_active:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
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
                title=title,
                severity=severity,
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
                title=title,
                severity=severity,
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
        config = self._get_check_config(check_id)
        title = config.get("title", "Ensure SSH port is explicitly allowed before enabling firewall")
        severity_str = config.get("severity", "CRITICAL").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.CRITICAL

        is_active, _, rules, perm_denied = self._get_ufw_status()
        
        if perm_denied:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description="Unable to check UFW rules due to missing privileges.",
                evidence="Permission denied.",
                recommendation="Run as root.",
                remediable=False
            )

        if not is_active:
             return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.SKIP,
                description="UFW is inactive, skipping SSH port rule check.",
                evidence="UFW is not active.",
                recommendation="Ensure UFW is configured before enabling.",
                remediable=True
            )

        ssh_port = self._get_ssh_port()
        ssh_allowed = False
        regex_pattern = rf'\b({ssh_port}/tcp|openssh|ssh)\b'
        
        for rule in rules:
            if re.search(regex_pattern, rule, re.IGNORECASE):
                if "ALLOW" in rule.upper():
                    ssh_allowed = True
                    break

        if ssh_allowed:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description=f"Anti-lockout check verified: SSH port access is permitted on port {ssh_port}.",
                evidence=f"SSH port ({ssh_port}) is allowed in UFW rules",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="firewall_security",
                title=title,
                severity=severity,
                status=Status.FAIL,
                description=f"UFW is active but no explicit SSH allow rule was detected for port {ssh_port}!",
                evidence=f"No rule matching 'ALLOW {ssh_port}/tcp' found in active UFW status.",
                recommendation=f"Immediately run 'ufw allow {ssh_port}/tcp' to prevent administrator lockout.",
                remediable=True,
                remediation_details=f"ufw allow {ssh_port}/tcp"
            )
