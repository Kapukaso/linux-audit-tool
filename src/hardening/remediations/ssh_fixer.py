"""
SSH Hardening Remediation Handler.
Author: Kartik Soni

Safely updates SSH directives with syntax verification (sshd -t) and transactional rollback.
"""

import shutil
from pathlib import Path
from typing import Any, Dict

from src.core.logger import AuditLogger
from src.core.utils import command_exists, run_command, safe_read_file, safe_write_file
from src.hardening.backup import BackupManager

logger = AuditLogger.get_logger()


class SshFixer:
    """Applies hardened directives to SSH configuration safely."""

    def __init__(self, backup_mgr: BackupManager, config_path: str = "/etc/ssh/sshd_config"):
        self.backup_mgr = backup_mgr
        self.config_path = Path(config_path)

    def apply_hardening(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Applies hardened SSH settings:
        PermitRootLogin no
        PermitEmptyPasswords no
        MaxAuthTries 4
        X11Forwarding no
        Protocol 2
        """
        target_file = self.config_path
        desired_settings = {
            "PermitRootLogin": "no",
            "PermitEmptyPasswords": "no",
            "MaxAuthTries": "4",
            "X11Forwarding": "no",
            "Protocol": "2"
        }

        # Detect OpenSSH version to omit Protocol 2 on >= 7.4
        ssh_version_str = ""
        if command_exists("ssh"):
            _, out, err = run_command(["ssh", "-V"])
            ssh_version_str = err if err else out
        if "OpenSSH_" in ssh_version_str:
            try:
                ver_part = ssh_version_str.split("OpenSSH_")[1].split()[0]
                # ver_part e.g. "8.9p1" or "7.2p2"
                major_minor = ver_part.split("p")[0].split(".")
                major = int(major_minor[0])
                minor = int(major_minor[1])
                if major > 7 or (major == 7 and minor >= 4):
                    del desired_settings["Protocol"]
            except Exception:
                pass

        if dry_run:
            logger.info("[DRY-RUN] Hardening SSH Configuration:")
            for k, v in desired_settings.items():
                logger.info(f"  [DRY-RUN] Proposed: {k} -> {v}")
            return {"status": "PLANNED", "details": "Dry-run simulation completed for SSH directives."}

        # 1. Backup original configuration
        backup_path = self.backup_mgr.backup_file(target_file)

        # 2. Read existing content
        content = safe_read_file(target_file) or ""
        lines = content.splitlines()
        updated_keys = set()
        new_lines = []
        
        match_idx = -1

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.lower().startswith("match "):
                if match_idx == -1:
                    match_idx = len(new_lines)
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            parts = stripped.split(maxsplit=1)
            key = parts[0].strip()
            key_lower = key.lower()

            matched_key = None
            for d_key in desired_settings:
                if d_key.lower() == key_lower:
                    matched_key = d_key
                    break

            if matched_key:
                new_lines.append(f"{matched_key} {desired_settings[matched_key]}")
                updated_keys.add(matched_key)
            else:
                new_lines.append(line)

        # Append missing directives before the first Match block
        missing_lines = []
        for d_key, d_val in desired_settings.items():
            if d_key not in updated_keys:
                missing_lines.append(f"{d_key} {d_val}")

        if missing_lines:
            if match_idx != -1:
                new_lines = new_lines[:match_idx] + missing_lines + new_lines[match_idx:]
            else:
                new_lines.extend(missing_lines)

        new_content = "\n".join(new_lines) + "\n"

        # 3. Write modified content
        if not safe_write_file(target_file, new_content, mode=0o600):
            return {"status": "FAILED", "details": "Failed to write modified sshd_config."}

        # 4. Syntax Validation (sshd -t)
        if command_exists("sshd"):
            code, stdout, stderr = run_command(["sshd", "-t"])
            if code != 0:
                logger.error(f"SSH syntax validation (sshd -t) failed: {stderr}. Rolling back sshd_config...")
                if backup_path and backup_path.exists():
                    shutil.copy2(backup_path, target_file)
                return {"status": "FAILED", "details": f"Syntax error during sshd -t check: {stderr}"}

            # 5. Reload SSH service safely
            run_command(["systemctl", "reload", "ssh"])
            run_command(["systemctl", "reload", "sshd"])

        logger.info("Successfully hardened SSH configuration directives.")
        return {"status": "APPLIED", "details": "Updated SSH directives and verified syntax."}
