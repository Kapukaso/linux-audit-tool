"""
Firewall Hardening Remediation Handler.
Author: Kartik Soni

Safely configures UFW firewall while preventing administrator remote SSH lockout.
"""

from typing import Any, Dict

from src.core.logger import AuditLogger
from src.core.utils import command_exists, run_command
from src.hardening.backup import BackupManager

logger = AuditLogger.get_logger()


class FirewallFixer:
    """Remediates host firewall configurations safely."""

    def __init__(self, backup_mgr: BackupManager):
        self.backup_mgr = backup_mgr

    def apply_hardening(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Safely enables UFW:
        1. ufw allow 22/tcp (Anti-lockout rule FIRST)
        2. ufw default deny incoming
        3. ufw --force enable
        """
        if not command_exists("ufw"):
            return {"status": "SKIPPED", "details": "UFW utility not installed on system."}

        if dry_run:
            logger.info("[DRY-RUN] Hardening Host Firewall (UFW):")
            logger.info("  [DRY-RUN] Step 1: ufw allow 22/tcp (Anti-lockout check)")
            logger.info("  [DRY-RUN] Step 2: ufw default deny incoming")
            logger.info("  [DRY-RUN] Step 3: ufw --force enable")
            return {"status": "PLANNED", "details": "Dry-run simulation completed for UFW firewall activation."}

        # 1. ANTI-LOCKOUT RULE FIRST
        code1, _, err1 = run_command(["ufw", "allow", "22/tcp"])
        if code1 != 0:
            logger.error(f"Failed to add SSH anti-lockout rule: {err1}. Aborting firewall activation!")
            return {"status": "FAILED", "details": f"Anti-lockout SSH rule failed: {err1}"}

        logger.info("Added explicit SSH port 22/tcp allow rule in UFW.")

        # 2. Set default deny incoming
        run_command(["ufw", "default", "deny", "incoming"])

        # 3. Enable UFW
        code3, out3, err3 = run_command(["ufw", "--force", "enable"])
        if code3 == 0:
            logger.info("Successfully activated UFW firewall with default incoming deny policy.")
            return {"status": "APPLIED", "details": "Enabled UFW firewall with SSH allowed and default incoming deny."}
        else:
            return {"status": "FAILED", "details": f"Failed to enable UFW: {err3}"}
