"""
Backup & Rollback Snapshot Engine.
Author: Kartik Soni

Features:
- Transactional snapshot backup before system configuration edits
- Preservation of POSIX modes, owner, and group metadata
- Manifest generation (manifest.json)
- Full automated rollback capability (--rollback)
"""

from datetime import datetime, timezone
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.core.logger import AuditLogger
from src.core.utils import get_file_metadata, safe_write_file

logger = AuditLogger.get_logger()


class BackupManager:
    """Manages transactional backup snapshots and system restoration."""

    def __init__(self, base_backup_dir: Optional[Union[str, Path]] = None):
        if base_backup_dir:
            self.base_dir = Path(base_backup_dir)
        else:
            # Prefer /var/backups/secureaudit/ if root, else local backups/
            var_backup = Path("/var/backups/secureaudit")
            if os.name != "nt" and os.access("/var/backups", os.W_OK):
                self.base_dir = var_backup
            else:
                self.base_dir = Path("backups")

        self.current_snapshot_dir: Optional[Path] = None
        self.manifest_data: Dict[str, Any] = {}

    def create_snapshot_session(self) -> Path:
        """Initializes a new timestamped backup directory."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_dir = self.base_dir / f"backup_{ts}"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.current_snapshot_dir = snapshot_dir

        self.manifest_data = {
            "backup_id": f"backup_{ts}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_dir": str(snapshot_dir.resolve()),
            "files": []
        }
        logger.info(f"Initialized backup snapshot session: '{snapshot_dir.resolve()}'")
        return snapshot_dir

    def backup_file(self, target_filepath: Union[str, Path]) -> Optional[Path]:
        """
        Backs up a file into the current snapshot directory before modification.
        Preserves metadata in manifest.json.
        """
        target = Path(target_filepath).resolve()
        if not target.exists():
            logger.debug(f"File '{target}' does not exist yet; recording non-existence for rollback.")
            if self.current_snapshot_dir:
                self.manifest_data["files"].append({
                    "target_path": str(target),
                    "backup_path": None,
                    "existed": False
                })
            return None

        if not self.current_snapshot_dir:
            self.create_snapshot_session()

        meta = get_file_metadata(target)
        backup_filename = target.name + ".orig"
        backup_path = self.current_snapshot_dir / backup_filename

        # Handle duplicate filenames in same snapshot
        counter = 1
        while backup_path.exists():
            backup_path = self.current_snapshot_dir / f"{target.name}.orig.{counter}"
            counter += 1

        try:
            shutil.copy2(target, backup_path)
            self.manifest_data["files"].append({
                "target_path": str(target),
                "backup_path": str(backup_path.resolve()),
                "existed": True,
                "mode_octal": meta["mode_octal"] if meta else "0644",
                "owner": meta["owner"] if meta else "root",
                "group": meta["group"] if meta else "root"
            })
            self._save_manifest()
            logger.debug(f"Backed up '{target}' to '{backup_path}'")
            return backup_path
        except Exception as e:
            logger.error(f"Failed to backup file '{target}': {e}")
            return None

    def _save_manifest(self) -> None:
        """Saves current manifest.json inside snapshot directory."""
        if self.current_snapshot_dir:
            manifest_file = self.current_snapshot_dir / "manifest.json"
            content = json.dumps(self.manifest_data, indent=2)
            safe_write_file(manifest_file, content, mode=0o600)

    def list_backups(self) -> List[Dict[str, Any]]:
        """Lists all existing backup snapshots across backup directories."""
        results = []
        if not self.base_dir.exists():
            return results

        for p in sorted(self.base_dir.glob("backup_*"), reverse=True):
            if p.is_dir():
                manifest = p / "manifest.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8"))
                        results.append(data)
                    except Exception:
                        results.append({"backup_id": p.name, "created_at": "unknown", "snapshot_dir": str(p)})
                else:
                    results.append({"backup_id": p.name, "created_at": "unknown", "snapshot_dir": str(p)})
        return results

    def rollback(self, backup_identifier: str) -> bool:
        """
        Restores all files recorded in a specified backup snapshot.

        Args:
            backup_identifier: Backup ID (e.g. 'backup_20260914_185000') or manifest file path.
        """
        logger.info(f"Initiating system rollback from backup identifier: '{backup_identifier}'...")

        # Resolve manifest file safely to prevent path traversal
        manifest_path = None
        target_path = Path(backup_identifier)
        if target_path.is_file() and target_path.name == "manifest.json":
            candidate = target_path.resolve()
        elif target_path.is_dir():
            candidate = (target_path / "manifest.json").resolve()
        else:
            candidate = (self.base_dir / backup_identifier / "manifest.json").resolve()

        base_resolved = self.base_dir.resolve()
        try:
            if candidate.exists() and candidate.is_relative_to(base_resolved):
                manifest_path = candidate
            else:
                logger.error(f"Manifest path '{candidate}' is outside allowed backup directory '{base_resolved}'")
                return False
        except ValueError:
            logger.error(f"Path traversal detected in backup identifier '{backup_identifier}'")
            return False

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            files = data.get("files", [])
            restored_count = 0

            for entry in files:
                target_file = Path(entry["target_path"])
                existed = entry.get("existed", True)

                if not existed:
                    # File was newly created during hardening; remove it
                    if target_file.exists():
                        target_file.unlink(missing_ok=True)
                        logger.info(f"Rollback removed newly added file: '{target_file}'")
                        restored_count += 1
                else:
                    backup_file = Path(entry["backup_path"])
                    if backup_file.exists():
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(backup_file, target_file)
                        mode_str = entry.get("mode_octal", "0644")
                        try:
                            os.chmod(target_file, int(mode_str, 8))
                        except Exception:
                            pass
                        logger.info(f"Restored file '{target_file}' from '{backup_file}' (Perms: {mode_str})")
                        restored_count += 1
                    else:
                        logger.warning(f"Backup file '{backup_file}' missing during rollback!")

            logger.info(f"Rollback completed successfully! {restored_count} files restored.")
            return True
        except Exception as e:
            logger.error(f"Rollback execution failed for '{backup_identifier}': {e}")
            return False
