"""
Service & Daemon Remediation Handler.
Author: Kartik Soni

Stops and masks obsolete daemons (telnet, rsh, xinetd) and activates security services (rsyslog, auditd).
"""

from typing import Any, Dict

from src.core.logger import AuditLogger
from src.core.utils import is_service_active, run_command
from src.hardening.backup import BackupManager

logger = AuditLogger.get_logger()


class ServiceFixer:
    """Remediates active obsolete daemons and enables security logging daemons."""

    def __init__(self, backup_mgr: BackupManager):
        self.backup_mgr = backup_mgr

    def disable_obsolete_services(self, dry_run: bool = False) -> Dict[str, Any]:
        """Stops and masks legacy services (telnet, rsh, xinetd, vsftpd)."""
        disallowed = ["telnet", "telnetd", "rsh", "rsh-server", "rlogin", "nis", "tftp", "xinetd", "vsftpd"]
        actioned = []

        for srv in disallowed:
            if is_service_active(srv):
                if dry_run:
                    logger.info(f"[DRY-RUN] Proposed: systemctl stop {srv}; systemctl mask {srv}")
                    actioned.append(srv)
                    continue

                run_command(["systemctl", "stop", srv])
                run_command(["systemctl", "mask", srv])
                actioned.append(srv)
                logger.info(f"Stopped and masked obsolete service '{srv}'")

        status = "PLANNED" if dry_run else ("APPLIED" if actioned else "SKIPPED")
        return {"status": status, "details": f"Obsolete services processed: {', '.join(actioned) if actioned else 'none'}"}

    def enable_security_services(self, dry_run: bool = False) -> Dict[str, Any]:
        """Enables rsyslog, auditd, and unattended-upgrades daemons."""
        security_daemons = ["rsyslog", "auditd", "unattended-upgrades"]
        actioned = []

        for srv in security_daemons:
            if not is_service_active(srv):
                if dry_run:
                    logger.info(f"[DRY-RUN] Proposed: systemctl enable --now {srv}")
                    actioned.append(srv)
                    continue

                code, _, _ = run_command(["systemctl", "enable", "--now", srv])
                if code == 0:
                    actioned.append(srv)
                    logger.info(f"Enabled security service '{srv}'")

        status = "PLANNED" if dry_run else ("APPLIED" if actioned else "SKIPPED")
        return {"status": status, "details": f"Security daemons enabled: {', '.join(actioned) if actioned else 'none'}"}
