"""
Unit tests for Hardening Subsystem, BackupManager, and Rollback Engine.
Author: Kartik Soni
"""

from pathlib import Path
import pytest

from src.hardening.backup import BackupManager
from src.hardening.manager import HardeningManager
from src.hardening.remediations.firewall_fixer import FirewallFixer
from src.hardening.remediations.permissions_fixer import PermissionsFixer
from src.hardening.remediations.service_fixer import ServiceFixer
from src.hardening.remediations.ssh_fixer import SshFixer
from src.hardening.remediations.sysctl_fixer import SysctlFixer


def test_backup_manager_snapshot_and_rollback(tmp_path):
    """Verifies file backup creation, manifest recording, and rollback restoration."""
    backup_base = tmp_path / "backups"
    target_dir = tmp_path / "etc_test"
    target_dir.mkdir()
    original_file = target_dir / "test_config.conf"
    original_file.write_text("Original Value = 1\n", encoding="utf-8")

    mgr = BackupManager(base_backup_dir=backup_base)
    snapshot_dir = mgr.create_snapshot_session()

    # Backup file
    backup_file = mgr.backup_file(original_file)
    assert backup_file is not None
    assert backup_file.exists()

    # Modify file
    original_file.write_text("Modified Insecure Value = 2\n", encoding="utf-8")

    # Rollback
    success = mgr.rollback(data_id := mgr.manifest_data["backup_id"])
    assert success is True
    assert original_file.read_text(encoding="utf-8") == "Original Value = 1\n"


def test_ssh_fixer_dry_run(tmp_path):
    """Verifies SSH fixer dry-run simulation."""
    backup_mgr = BackupManager(base_backup_dir=tmp_path / "backups")
    sshd_conf = tmp_path / "sshd_config"
    sshd_conf.write_text("PermitRootLogin yes\n", encoding="utf-8")

    fixer = SshFixer(backup_mgr, config_path=str(sshd_conf))
    res = fixer.apply_hardening(dry_run=True)

    assert res["status"] == "PLANNED"
    # Original file must remain untouched in dry-run
    assert "PermitRootLogin yes" in sshd_conf.read_text(encoding="utf-8")


def test_permissions_fixer_dry_run(tmp_path):
    """Verifies permissions fixer dry-run mode."""
    backup_mgr = BackupManager(base_backup_dir=tmp_path / "backups")
    fixer = PermissionsFixer(backup_mgr)

    res = fixer.fix_critical_files(dry_run=True)
    assert res["status"] == "PLANNED"


def test_firewall_fixer_dry_run(tmp_path):
    """Verifies firewall fixer dry-run mode."""
    backup_mgr = BackupManager(base_backup_dir=tmp_path / "backups")
    fixer = FirewallFixer(backup_mgr)

    res = fixer.apply_hardening(dry_run=True)
    assert res["status"] in ["PLANNED", "SKIPPED"]


def test_sysctl_fixer_dry_run(tmp_path):
    """Verifies sysctl fixer dry-run mode."""
    backup_mgr = BackupManager(base_backup_dir=tmp_path / "backups")
    fixer = SysctlFixer(backup_mgr)

    res = fixer.apply_hardening(dry_run=True)
    assert res["status"] == "PLANNED"


def test_service_fixer_dry_run(tmp_path):
    """Verifies service fixer dry-run mode."""
    backup_mgr = BackupManager(base_backup_dir=tmp_path / "backups")
    fixer = ServiceFixer(backup_mgr)

    res1 = fixer.disable_obsolete_services(dry_run=True)
    res2 = fixer.enable_security_services(dry_run=True)

    assert res1["status"] in ["PLANNED", "SKIPPED"]
    assert res2["status"] in ["PLANNED", "SKIPPED"]


def test_hardening_manager_dry_run(baseline_manager):
    """Verifies full HardeningManager dry-run orchestration pipeline."""
    manager = HardeningManager(baseline_manager)
    actions, pre_rep, post_rep = manager.execute_hardening(dry_run=True)

    assert pre_rep is not None
    assert post_rep is None  # Post-audit is None in dry-run mode
    assert len(actions) > 0
    for act in actions:
        assert act.status == "PLANNED"
