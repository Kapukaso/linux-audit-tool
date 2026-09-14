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
from src.core.utils import command_exists, is_service_active, run_command, safe_read_file

logger = AuditLogger.get_logger()


class LoggingAuditModule:
    """Audits system logging daemons, auditd, and authentication failure patterns."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

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
        rsyslog_active = is_service_active("rsyslog")
        journald_active = is_service_active("systemd-journald") or is_service_active("systemd-journald.service")

        if rsyslog_active or journald_active:
            evidence = f"rsyslog: {'active' if rsyslog_active else 'inactive'}, systemd-journald: {'active' if journald_active else 'inactive'}"
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title="Verify system logging daemon (rsyslog or systemd-journald) is active",
                severity=Severity.HIGH,
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
                title="Verify system logging daemon (rsyslog or systemd-journald) is active",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="No active system logging daemon detected! Events are not being recorded.",
                evidence="Neither rsyslog nor systemd-journald is active.",
                recommendation="Enable logging daemon using 'systemctl enable --now rsyslog'.",
                remediable=True,
                remediation_details="systemctl enable --now rsyslog"
            )

    def audit_auditd_service(self) -> AuditFinding:
        """LOG-002: Verify auditd (Linux Audit Daemon) is installed and active."""
        check_id = "LOG-002"
        auditd_active = is_service_active("auditd")

        if auditd_active:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title="Verify auditd (Linux Audit Daemon) is installed and active",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description="Linux Audit Daemon (auditd) is active and collecting kernel audit logs.",
                evidence="auditd service: active",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title="Verify auditd (Linux Audit Daemon) is installed and active",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="Linux Audit Daemon (auditd) is inactive or not installed.",
                evidence="auditd service: inactive",
                recommendation="Install and start auditd: 'apt-get install auditd && systemctl enable --now auditd'.",
                remediable=True,
                remediation_details="apt-get install -y auditd && systemctl enable --now auditd"
            )

    def audit_failed_logins(self) -> AuditFinding:
        """LOG-003: Check for excessive failed login attempts in recent auth logs."""
        check_id = "LOG-003"
        failed_count = 0
        threshold = 25

        # 1. Try reading /var/log/auth.log (Debian/Ubuntu)
        auth_log = safe_read_file("/var/log/auth.log")
        if auth_log:
            failed_count += len(re.findall(r'Failed password|authentication failure|FAILED LOGIN', auth_log, re.IGNORECASE))
        else:
            # 2. Try journalctl for SSH/PAM auth failures
            code, stdout, _ = run_command(["journalctl", "-u", "ssh", "-n", "200", "--no-pager"])
            if code == 0 and stdout:
                failed_count += len(re.findall(r'Failed password|authentication failure', stdout, re.IGNORECASE))

        if failed_count < threshold:
            return AuditFinding(
                check_id=check_id,
                category="logging_security",
                title="Check for excessive failed login attempts in recent auth logs",
                severity=Severity.MEDIUM,
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
                title="Check for excessive failed login attempts in recent auth logs",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                description=f"High frequency of failed authentication attempts ({failed_count} events) detected!",
                evidence=f"Failed login events: {failed_count} (threshold: {threshold})",
                recommendation="Inspect /var/log/auth.log for brute-force activity and deploy Fail2ban.",
                remediable=False
            )
