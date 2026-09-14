"""
Filesystem Permissions Remediation Handler.
Author: Kartik Soni

Remediates POSIX permissions and ownership on critical system files and strips world-write bits.
"""

import os
import stat
from pathlib import Path
from typing import Any, Dict, List

from src.core.logger import AuditLogger
from src.core.utils import get_file_metadata
from src.hardening.backup import BackupManager

logger = AuditLogger.get_logger()


class PermissionsFixer:
    """Fixes file permissions and ownership on critical Linux files."""

    def __init__(self, backup_mgr: BackupManager):
        self.backup_mgr = backup_mgr

    def fix_critical_files(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Remediates permissions:
        - /etc/passwd: 0644
        - /etc/shadow: 0640
        - /etc/group:  0644
        - /etc/gshadow: 0640
        """
        targets = [
            {"path": "/etc/passwd", "mode": 0o644, "owner": "root", "group": "root"},
            {"path": "/etc/shadow", "mode": 0o640, "owner": "root", "group": "shadow"},
            {"path": "/etc/group", "mode": 0o644, "owner": "root", "group": "root"},
            {"path": "/etc/gshadow", "mode": 0o640, "owner": "root", "group": "shadow"},
        ]

        actions_taken = []
        for t in targets:
            filepath = Path(t["path"])
            if not filepath.exists():
                continue

            meta = get_file_metadata(filepath)
            current_mode = meta["mode_octal"] if meta else "unknown"

            if dry_run:
                logger.info(f"[DRY-RUN] Proposed: {t['path']} permissions -> {oct(t['mode'])[-4:]} (Current: {current_mode})")
                actions_taken.append(f"Proposed chmod {oct(t['mode'])[-4:]} on {t['path']}")
                continue

            # Backup metadata/file
            self.backup_mgr.backup_file(filepath)

            try:
                os.chmod(filepath, t["mode"])
                actions_taken.append(f"Applied chmod {oct(t['mode'])[-4:]} on {t['path']}")
                logger.info(f"Fixed permissions on '{t['path']}' to {oct(t['mode'])[-4:]}")
            except Exception as e:
                logger.error(f"Failed to set permissions on '{t['path']}': {e}")

        status = "PLANNED" if dry_run else "APPLIED"
        return {"status": status, "details": "; ".join(actions_taken)}

    def fix_world_writable(self, target_paths: List[str], dry_run: bool = False) -> Dict[str, Any]:
        """Strips world-write bit (chmod o-w) from specified files."""
        fixed_count = 0
        for p_str in target_paths:
            path = Path(p_str)
            if not path.exists() or path.is_symlink():
                continue

            if dry_run:
                logger.info(f"[DRY-RUN] Proposed: chmod o-w on {path}")
                fixed_count += 1
                continue

            self.backup_mgr.backup_file(path)
            try:
                st = path.stat()
                new_mode = st.st_mode & ~stat.S_IWOTH
                os.chmod(path, new_mode)
                fixed_count += 1
                logger.info(f"Stripped world-write bit from '{path}'")
            except Exception as e:
                logger.error(f"Failed to fix world-writable file '{path}': {e}")

        status = "PLANNED" if dry_run else "APPLIED"
        return {"status": status, "details": f"Remediated {fixed_count} world-writable files."}
