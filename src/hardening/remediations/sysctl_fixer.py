"""
Sysctl Kernel Network Hardening Remediation Handler.
Author: Kartik Soni

Writes hardened kernel security parameters to /etc/sysctl.d/99-secureaudit.conf and applies them.
"""

from pathlib import Path
from typing import Any, Dict

from src.core.logger import AuditLogger
from src.core.utils import run_command, safe_write_file
from src.hardening.backup import BackupManager

logger = AuditLogger.get_logger()


class SysctlFixer:
    """Applies kernel network hardening parameters via sysctl."""

    def __init__(self, backup_mgr: BackupManager):
        self.backup_mgr = backup_mgr
        self.config_path = Path("/etc/sysctl.d/99-secureaudit.conf")

    def apply_hardening(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Writes kernel security configuration:
        net.ipv4.ip_forward = 0
        net.ipv4.conf.all.send_redirects = 0
        net.ipv4.conf.all.accept_redirects = 0
        net.ipv4.conf.all.log_martians = 1
        """
        sysctl_content = (
            "# Linux Security Hardening Toolkit - sysctl parameters\n"
            "net.ipv4.ip_forward = 0\n"
            "net.ipv4.conf.all.send_redirects = 0\n"
            "net.ipv4.conf.default.send_redirects = 0\n"
            "net.ipv4.conf.all.accept_redirects = 0\n"
            "net.ipv4.conf.default.accept_redirects = 0\n"
            "net.ipv4.conf.all.accept_source_route = 0\n"
            "net.ipv4.conf.all.log_martians = 1\n"
        )

        if dry_run:
            logger.info("[DRY-RUN] Writing sysctl network parameters to /etc/sysctl.d/99-secureaudit.conf:")
            for line in sysctl_content.splitlines():
                if not line.startswith("#"):
                    logger.info(f"  [DRY-RUN] Proposed: {line}")
            return {"status": "PLANNED", "details": "Dry-run simulation completed for sysctl configuration."}

        self.backup_mgr.backup_file(self.config_path)

        if not safe_write_file(self.config_path, sysctl_content, mode=0o644):
            return {"status": "FAILED", "details": "Failed to write sysctl configuration."}

        code, stdout, stderr = run_command(["sysctl", "-p", str(self.config_path)])
        if code == 0:
            logger.info("Successfully applied sysctl kernel network parameters.")
            return {"status": "APPLIED", "details": "Applied /etc/sysctl.d/99-secureaudit.conf parameters."}
        else:
            return {"status": "FAILED", "details": f"sysctl command failed: {stderr}"}
