"""
Console & Text Report Generator Module.
Author: Kartik Soni

Formats audit reports for high-contrast terminal display and plain text report files (report.txt).
"""

from pathlib import Path
from typing import Union

from src.core.logger import AuditLogger
from src.core.models import AuditReport, Status
from src.core.utils import safe_write_file

logger = AuditLogger.get_logger()


class ConsoleReporter:
    """Formats audit reports for console display and text file export."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate_text_content(self) -> str:
        """Constructs plain text summary report string."""
        rep = self.report
        meta = rep.system_meta
        s = rep.summary
        lines = []

        lines.append("=" * 80)
        lines.append("LINUX SECURITY HARDENING & AUTOMATED AUDIT REPORT")
        lines.append("Author: Kartik Soni | SmartED Cybersecurity Minor Project")
        lines.append(f"Timestamp: {rep.timestamp}")
        lines.append("=" * 80)

        lines.append("\n[SYSTEM METADATA]")
        lines.append(f"  Hostname:     {meta.hostname}")
        lines.append(f"  OS Release:   {meta.os_name} {meta.os_version}")
        lines.append(f"  Kernel:       {meta.kernel_version} ({meta.architecture})")
        lines.append(f"  CPU Info:     {meta.cpu_info}")
        lines.append(f"  Memory:       {meta.memory_total_mb} MB ({meta.memory_free_mb} MB free)")

        lines.append("\n[SECURITY POSTURE SCORECARD]")
        lines.append(f"  OVERALL SECURITY SCORE:  {rep.overall_score} / 100")
        lines.append(f"  OVERALL RISK LEVEL:      {rep.risk_level.value}")
        lines.append(f"  CHECKS EVALUATED:        {s['total']} Total | {s['passed']} Passed | {s['failed']} Failed | {s['warnings']} Warnings")
        lines.append(f"  SEVERITY BREAKDOWN:      {s['critical']} Critical | {s['high']} High | {s['medium']} Medium | {s['low']} Low")

        lines.append("\n[CATEGORY COMPLIANCE BREAKDOWN]")
        for cat_id, cat_score in rep.category_scores.items():
            lines.append(f"  - {cat_score.category_name:<38} Score: {cat_score.score:>5.1f}%  ({cat_score.passed_checks}/{cat_score.total_checks} passed)")

        lines.append("\n" + "=" * 80)
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 80)
        for f in rep.findings:
            status_tag = f"[{f.status.value}]"
            lines.append(f"{status_tag:<8} ({f.severity.value:<8}) {f.check_id}: {f.title}")
            lines.append(f"         Evidence: {f.evidence}")
            if f.status != Status.PASS:
                lines.append(f"         Fix:      {f.recommendation}")
            lines.append("-" * 80)

        return "\n".join(lines)

    def print_to_console(self) -> None:
        """Prints formatted text report to terminal."""
        print(self.generate_text_content())

    def export_to_file(self, output_path: Union[str, Path] = "reports/report.txt") -> bool:
        """Writes plain text report to disk."""
        target_path = Path(output_path)
        content = self.generate_text_content()
        success = safe_write_file(target_path, content, mode=0o644)
        if success:
            logger.info(f"Successfully generated plain text audit report: '{target_path.resolve()}'")
        else:
            logger.error(f"Failed to export plain text report to '{output_path}'")
        return success
