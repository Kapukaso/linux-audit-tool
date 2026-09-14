"""
Audit Engine Orchestrator.
Author: Kartik Soni

Coordinates execution across all inspection modules, aggregates findings, and prepares
unscored AuditReport objects.
"""

from typing import Dict, List, Optional

from src.core.baseline import BaselineManager
from src.core.logger import AuditLogger
from src.core.models import AuditFinding, AuditReport, Severity, Status
from src.modules.filesystem_audit import FilesystemAuditModule
from src.modules.firewall_audit import FirewallAuditModule
from src.modules.logging_audit import LoggingAuditModule
from src.modules.network_audit import NetworkAuditModule
from src.modules.patch_audit import PatchAuditModule
from src.modules.service_audit import ServiceAuditModule
from src.modules.ssh_audit import SshAuditModule
from src.modules.system_info import SystemInfoCollector
from src.modules.user_audit import UserAuditModule

logger = AuditLogger.get_logger()


class AuditEngine:
    """Orchestrates security baseline evaluation across all inspection modules."""

    def __init__(self, baseline_manager: Optional[BaselineManager] = None):
        self.baseline_mgr = baseline_manager or BaselineManager()
        self.system_collector = SystemInfoCollector()

    def run_audit(self, category_filter: str = "all") -> AuditReport:
        """
        Executes audit checks across categories and returns a populated AuditReport.

        Args:
            category_filter: 'all' or specific category identifier (e.g., 'ssh_security')
        """
        logger.info(f"Starting security audit execution (Filter: {category_filter})...")
        report = AuditReport()

        # 1. Collect System Metadata
        report.system_meta = self.system_collector.collect()

        # 2. Dispatch Audit Modules
        findings: List[AuditFinding] = []
        target_cat = category_filter.lower()

        # User Security
        if target_cat in ["all", "user_security"]:
            user_mod = UserAuditModule(self.baseline_mgr.get_checks_by_category("user_security"))
            findings.extend(user_mod.audit_all())

        # SSH Security
        if target_cat in ["all", "ssh_security"]:
            ssh_mod = SshAuditModule(self.baseline_mgr.get_checks_by_category("ssh_security"))
            findings.extend(ssh_mod.audit_all())

        # Filesystem Security
        if target_cat in ["all", "filesystem_security"]:
            fs_mod = FilesystemAuditModule(self.baseline_mgr.get_checks_by_category("filesystem_security"))
            findings.extend(fs_mod.audit_all())

        # Firewall Security
        if target_cat in ["all", "firewall_security"]:
            fw_mod = FirewallAuditModule(self.baseline_mgr.get_checks_by_category("firewall_security"))
            findings.extend(fw_mod.audit_all())

        # Network Security
        if target_cat in ["all", "network_security"]:
            net_mod = NetworkAuditModule(self.baseline_mgr.get_checks_by_category("network_security"))
            findings.extend(net_mod.audit_all())

        # Service Security
        if target_cat in ["all", "service_security"]:
            srv_mod = ServiceAuditModule(self.baseline_mgr.get_checks_by_category("service_security"))
            findings.extend(srv_mod.audit_all())

        # Patch Management
        if target_cat in ["all", "patch_security"]:
            patch_mod = PatchAuditModule(self.baseline_mgr.get_checks_by_category("patch_security"))
            findings.extend(patch_mod.audit_all())

        # Logging Security
        if target_cat in ["all", "logging_security"]:
            log_mod = LoggingAuditModule(self.baseline_mgr.get_checks_by_category("logging_security"))
            findings.extend(log_mod.audit_all())

        report.findings = findings
        self._calculate_summary(report)

        logger.info(f"Audit completed: {len(findings)} checks evaluated ({report.summary['passed']} passed, {report.summary['failed']} failed, {report.summary['warnings']} warnings).")
        return report

    def _calculate_summary(self, report: AuditReport) -> None:
        """Aggregates status and severity metrics into report.summary."""
        summary = {
            "total": len(report.findings),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in report.findings:
            if finding.status == Status.PASS:
                summary["passed"] += 1
            elif finding.status == Status.FAIL:
                summary["failed"] += 1
            elif finding.status == Status.WARN:
                summary["warnings"] += 1

            if finding.severity == Severity.CRITICAL:
                summary["critical"] += 1
            elif finding.severity == Severity.HIGH:
                summary["high"] += 1
            elif finding.severity == Severity.MEDIUM:
                summary["medium"] += 1
            elif finding.severity == Severity.LOW:
                summary["low"] += 1
            elif finding.severity == Severity.INFO:
                summary["info"] += 1

        report.summary = summary
