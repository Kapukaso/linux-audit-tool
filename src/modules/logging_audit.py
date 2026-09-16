"""
Logging & Authentication Audit Module.
Author: Kartik Soni

Checks:
- LOG-001: System logging daemon (rsyslog / systemd-journald) active
- LOG-002: Auditd (Linux Audit Daemon) installed and active
- LOG-003: Failed login attempts threshold monitoring in auth logs
"""

import re
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import is_service_active, run_command, safe_read_file

logger = AuditLogger.get_logger()


import os
from pathlib import Path

class LoggingAuditModule:
    """Audits system logging daemons, auditd, and authentication failure patterns."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def _get_check_config(self, check_id: str) -> Dict[str, Any]:
        """Retrieve baseline configuration for a specific check."""
        for check in self.checks:
            if check.get("id") == check_id:
                return check
        return {}

    def audit_all(self) -> List[AuditFinding]:
        """Executes logging audit checks."""
        return [
            self.audit_logging_daemon(),
            self.audit_auditd_service(),
            self.audit_failed_logins()
        ]

    def audit_logging_daemon(self) -> AuditFinding:
        """LOG-001: Verify system logging daemon (rsyslog or systemd-journald) is active."""
        check_id = "LOG-001"
        config = self._get_check_config(check_id)
        title = config.get("title", "Verify system logging daemon (rsyslog or systemd-journald) is active")
        severity_str = config.get("severity", "HIGH").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.HIGH
        services = config.get("services", ["rsyslog", "systemd-journald"])

        rsyslog_active = is_service_active(services[0] if len(services) > 0 else "rsyslog")
        journald_active = is_service_active(services[1] if len(services) > 1 else "systemd-journald") or is_service_active("systemd-journald.service")

        if rsyslog_active or journald_active:
            evidence = f"{services[0] if len(services) > 0 else 'rsyslog'}: {'active' if rsyslog_active else 'inactive'}, {services[1] if len(services) > 1 else 'systemd-journald'}: {'active' if journald_active else 'inactive'}"
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description="System event logging daemon is active.",
                evidence=evidence,
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.FAIL,
                description="No active system logging daemon detected! Events are not being recorded.",
                evidence=f"Neither {services[0] if len(services) > 0 else 'rsyslog'} nor {services[1] if len(services) > 1 else 'systemd-journald'} is active.",
                recommendation="Enable logging daemon using 'systemctl enable --now rsyslog'.",
                remediable=True,
                remediation_details="systemctl enable --now rsyslog"
            )

    def audit_auditd_service(self) -> AuditFinding:
        """LOG-002: Verify auditd (Linux Audit Daemon) is installed and active."""
        check_id = "LOG-002"
        config = self._get_check_config(check_id)
        title = config.get("title", "Verify auditd (Linux Audit Daemon) is installed and active")
        severity_str = config.get("severity", "MEDIUM").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.MEDIUM
        service_name = config.get("service_name", "auditd")

        auditd_active = is_service_active(service_name)

        if auditd_active:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description="Linux Audit Daemon (auditd) is active and collecting kernel audit logs.",
                evidence=f"{service_name} service: active",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.FAIL,
                description="Linux Audit Daemon (auditd) is inactive or not installed.",
                evidence=f"{service_name} service: inactive",
                recommendation="Install and start auditd: 'apt-get install auditd && systemctl enable --now auditd'.",
                remediable=True,
                remediation_details="apt-get install -y auditd && systemctl enable --now auditd"
            )

    def audit_failed_logins(self) -> AuditFinding:
        """LOG-003: Check for excessive failed login attempts in recent auth logs."""
        check_id = "LOG-003"
        config = self._get_check_config(check_id)
        title = config.get("title", "Check for excessive failed login attempts in recent auth logs")
        severity_str = config.get("severity", "MEDIUM").upper()
        severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.MEDIUM
        threshold = config.get("failure_threshold", 25)

        failed_count = 0
        read_success = False
        evidence_list = []

        # 1. Try reading /var/log/auth.log (Debian/Ubuntu)
        auth_log_path = Path("/var/log/auth.log")
        if auth_log_path.exists():
            if os.access(auth_log_path, os.R_OK):
                auth_log = safe_read_file(auth_log_path)
                if auth_log:
                    lines = auth_log.splitlines()[-200:]
                    recent_log = "\n".join(lines)
                    failed_count += len(re.findall(r'Failed password|authentication failure|FAILED LOGIN', recent_log, re.IGNORECASE))
                    read_success = True
                    evidence_list.append("Read /var/log/auth.log")
            else:
                evidence_list.append("/var/log/auth.log: Permission denied")
        else:
            evidence_list.append("/var/log/auth.log: Not found")

        # 2. Try journalctl for SSH/PAM auth failures
        code, stdout, stderr = run_command(["journalctl", "-u", "ssh", "-n", "200", "--no-pager"])
        if code == 0:
            failed_count += len(re.findall(r'Failed password|authentication failure', stdout, re.IGNORECASE))
            read_success = True
            evidence_list.append("Read journalctl")
        else:
            evidence_list.append(f"journalctl error: {stderr.strip() or 'Permission denied or no entries'}")

        if not read_success:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description="Unable to read authentication logs due to insufficient permissions or missing logs.",
                evidence="; ".join(evidence_list),
                recommendation="Run the audit with root privileges to analyze authentication logs.",
                remediable=False
            )

        if failed_count < threshold:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.PASS,
                description=f"Authentication log analysis detected {failed_count} failed login events (below threshold of {threshold}).",
                evidence=f"Failed login events: {failed_count}",
                recommendation="None. Current configuration is secure.",
                remediable=False
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title=title,
                severity=severity,
                status=Status.WARN,
                description=f"High frequency of failed authentication attempts ({failed_count} events) detected!",
                evidence=f"Failed login events: {failed_count} (threshold: {threshold})",
                recommendation="Inspect /var/log/auth.log for brute-force activity and deploy Fail2ban.",
                remediable=False
            )
