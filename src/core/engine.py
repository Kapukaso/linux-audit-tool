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

        if target_cat != "all":
            valid_cats = {k.lower() for k in self.baseline_mgr.get_categories().keys()}
            if target_cat not in valid_cats:
                logger.error(f"Invalid category filter: '{category_filter}'. Valid categories: {', '.join(valid_cats)}")
                report.findings = findings
                self._calculate_summary(report)
                return report

        module_mapping = {
            "user_security": UserAuditModule,
            "ssh_security": SshAuditModule,
            "filesystem_security": FilesystemAuditModule,
            "firewall_security": FirewallAuditModule,
            "network_security": NetworkAuditModule,
            "service_security": ServiceAuditModule,
            "patch_security": PatchAuditModule,
            "logging_security": LoggingAuditModule,
        }

        for cat, mod_cls in module_mapping.items():
            if target_cat in ["all", cat]:
                self._run_module_safe(mod_cls, cat, findings)

        report.findings = findings
        self._calculate_summary(report)

        logger.info(f"Audit completed: {len(findings)} checks evaluated ({report.summary['passed']} passed, {report.summary['failed']} failed, {report.summary['warnings']} warnings).")
        return report

    def _run_module_safe(self, module_cls, category_name: str, findings: List[AuditFinding]) -> None:
        try:
            checks = self.baseline_mgr.get_checks_by_category(category_name)
            mod = module_cls(checks)
            findings.extend(mod.audit_all())
        except Exception as exc:
            logger.error(f"Audit module {module_cls.__name__} crashed: {exc}")
            findings.append(AuditFinding(
                check_id="SYS-ERR",
                category=category_name,
                title=f"{module_cls.__name__} Execution Failure",
                severity=Severity.CRITICAL,
                status=Status.ERROR,
                description=f"Unhandled exception during module execution: {exc}",
                evidence=str(exc),
                recommendation="Review audit logs and report bug."
            ))

    def _calculate_summary(self, report: AuditReport) -> None:
        """Aggregates status and severity metrics into report.summary."""
        summary = {
            "total": len(report.findings),
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "skipped": 0,
            "errors": 0,
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
            elif finding.status == Status.SKIP:
                summary["skipped"] += 1
            elif finding.status == Status.ERROR:
                summary["errors"] += 1

            if finding.status in (Status.FAIL, Status.WARN, Status.ERROR):
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
