"""
Hardening Subsystem Orchestrator.
Author: Kartik Soni

Coordinates pre-checks, backup snapshotting, dry-run simulation, interactive confirmation,
atomic remediation handlers, post-remediation audit evaluation, and rollback manifests.
"""

from typing import List, Optional, Tuple

from src.core.baseline import BaselineManager
from src.core.engine import AuditEngine
from src.core.logger import AuditLogger
from src.core.models import AuditReport, HardeningAction, Status
from src.core.scoring import ScoringEngine
from src.core.utils import is_root
from src.hardening.backup import BackupManager
from src.hardening.remediations.firewall_fixer import FirewallFixer
from src.hardening.remediations.permissions_fixer import PermissionsFixer
from src.hardening.remediations.service_fixer import ServiceFixer
from src.hardening.remediations.ssh_fixer import SshFixer
from src.hardening.remediations.sysctl_fixer import SysctlFixer

logger = AuditLogger.get_logger()


class HardeningManager:
    """Orchestrates security hardening remediation pipeline."""

    def __init__(self, baseline_manager: Optional[BaselineManager] = None):
        self.baseline_mgr = baseline_manager or BaselineManager()
        self.backup_mgr = BackupManager()
        self.audit_engine = AuditEngine(self.baseline_mgr)
        self.scoring_engine = ScoringEngine(self.baseline_mgr)

    def execute_hardening(
        self,
        dry_run: bool = False,
        auto_confirm: bool = False
    ) -> Tuple[List[HardeningAction], Optional[AuditReport], Optional[AuditReport]]:
        """
        Executes the hardening workflow.

        Returns:
            Tuple of (actions_list, pre_audit_report, post_audit_report)
        """
        logger.info(f"Initiating Hardening Subsystem (Dry-Run: {dry_run}, Auto-Confirm: {auto_confirm})...")

        # 1. Run Pre-Hardening Audit
        pre_report = self.scoring_engine.evaluate_report(self.audit_engine.run_audit("all"))
        remediable_findings = [f for f in pre_report.findings if f.remediable and f.status != Status.PASS]

        logger.info(f"Pre-Hardening Score: {pre_report.overall_score}/100 ({len(remediable_findings)} remediable issues found).")

        actions: List[HardeningAction] = []

        if not remediable_findings:
            logger.info("No remediable security misconfigurations detected! System is already hardened.")
            return actions, pre_report, pre_report

        # 2. Display Proposed Remediations
        print("\n" + "=" * 75)
        print(f"PROPOSED REMEDIATION ACTIONS ({'DRY-RUN SIMULATION' if dry_run else 'ACTIVE REMEDIATION'})")
        print("=" * 75)
        for idx, f in enumerate(remediable_findings, 1):
            details = f.remediation_details or f.recommendation
            print(f"  {idx}. [{f.check_id}] {f.title}")
            print(f"     Proposed Action: {details}")
            print("-" * 75)

        # 3. Require Root & Confirmation if NOT dry_run
        if not dry_run:
            if not is_root():
                logger.error("Active hardening requires root privileges. Please run with 'sudo secureaudit harden'.")
                raise PermissionError("Root privileges (UID 0) required for active hardening execution.")

            if not auto_confirm:
                answer = input(f"\nDo you want to apply these {len(remediable_findings)} security remediations? (y/N): ")
                if answer.strip().lower() not in ["y", "yes"]:
                    logger.info("Hardening operation cancelled by user.")
                    return actions, pre_report, None

            # Initialize Transactional Backup Session
            snapshot_dir = self.backup_mgr.create_snapshot_session()
            print(f"\n[*] Transactional Backup Snapshot created: '{snapshot_dir.resolve()}'")
        else:
            logger.info("Dry-run mode active. Simulating hardening remediations without modifying configuration.")

        # 4. Invoke Remediation Handlers (passing dynamic dry_run parameter)
        ssh_fixer = SshFixer(self.backup_mgr)
        perm_fixer = PermissionsFixer(self.backup_mgr)
        fw_fixer = FirewallFixer(self.backup_mgr)
        sysctl_fixer = SysctlFixer(self.backup_mgr)
        srv_fixer = ServiceFixer(self.backup_mgr)

        def run_remedy(prefix, func, action_id, target, title, *args, **kwargs):
            if any(f.check_id.startswith(prefix) for f in remediable_findings):
                try:
                    res = func(*args, dry_run=dry_run, **kwargs)
                    actions.append(HardeningAction(action_id, target, title, status=res.get("status", "FAILED"), details=res.get("details", "")))
                except Exception as e:
                    logger.error(f"Failed to execute remediation {action_id}: {e}")
                    actions.append(HardeningAction(action_id, target, title, status="FAILED", details=f"Exception: {str(e)}"))

        run_remedy("SSH-", ssh_fixer.apply_hardening, "ACT-SSH", "SSH-ALL", "SSH Server Hardening")
        run_remedy("FS-001", perm_fixer.fix_critical_files, "ACT-FS-PERM", "FS-001..004", "File Permissions Fixer")
        run_remedy("FS-002", perm_fixer.fix_critical_files, "ACT-FS-PERM", "FS-001..004", "File Permissions Fixer")
        run_remedy("FS-003", perm_fixer.fix_critical_files, "ACT-FS-PERM", "FS-001..004", "File Permissions Fixer")
        run_remedy("FS-004", perm_fixer.fix_critical_files, "ACT-FS-PERM", "FS-001..004", "File Permissions Fixer")

        ww_findings = [f for f in remediable_findings if f.check_id == "FS-005"]
        if ww_findings:
            ww_files = []
            for f in ww_findings:
                if "): " in f.evidence:
                    paths = f.evidence.split("): ")[1].split(", ")
                    ww_files.extend(paths)
            if ww_files:
                try:
                    res_ww = perm_fixer.fix_world_writable(ww_files, dry_run=dry_run)
                    actions.append(HardeningAction("ACT-FS-WW", "FS-005", "World-Writable Bit Removal", status=res_ww.get("status", "FAILED"), details=res_ww.get("details", "")))
                except Exception as e:
                    logger.error(f"Failed to execute ACT-FS-WW: {e}")
                    actions.append(HardeningAction("ACT-FS-WW", "FS-005", "World-Writable Bit Removal", status="FAILED", details=f"Exception: {str(e)}"))

        run_remedy("FW-", fw_fixer.apply_hardening, "ACT-FW", "FW-001..003", "Host Firewall Hardening")
        run_remedy("NET-003", sysctl_fixer.apply_hardening, "ACT-SYSCTL", "NET-003", "Sysctl Kernel Hardening")
        run_remedy("SRV-001", srv_fixer.disable_obsolete_services, "ACT-SRV-OBS", "SRV-001", "Disable Obsolete Daemons")
        run_remedy("LOG-", srv_fixer.enable_security_services, "ACT-SRV-SEC", "LOG-001..002", "Enable Security Daemons")

        # 5. Run Post-Hardening Verification Audit
        if not dry_run:
            post_report = self.scoring_engine.evaluate_report(self.audit_engine.run_audit("all"))

            print("\n" + "=" * 75)
            print("HARDENING EXECUTION SUMMARY")
            print("=" * 75)
            print(f"  PRE-HARDENING SCORE:   {pre_report.overall_score} / 100 ({pre_report.risk_level.value} Risk)")
            print(f"  POST-HARDENING SCORE:  {post_report.overall_score} / 100 ({post_report.risk_level.value} Risk)")
            print(f"  BACKUP SNAPSHOT ID:    {self.backup_mgr.manifest_data.get('backup_id', 'unknown')}")
            print("=" * 75 + "\n")
        else:
            post_report = None
            print("\n[+] Dry-run simulation complete. No system files were modified.\n")

        return actions, pre_report, post_report

    def execute_rollback(self, backup_identifier: str) -> bool:
        """Executes automated rollback from a specified backup snapshot."""
        return self.backup_mgr.rollback(backup_identifier)
