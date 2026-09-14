"""
JSON Report Generator Module.
Author: Kartik Soni

Exports audit findings, system metadata, category scores, and overall metrics to structured JSON.
"""

import json
from pathlib import Path
from typing import Optional, Union

from src.core.logger import AuditLogger
from src.core.models import AuditReport
from src.core.utils import safe_write_file

logger = AuditLogger.get_logger()


class JsonReporter:
    """Generates machine-readable JSON security audit reports."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate_json_string(self, indent: int = 2) -> str:
        """Returns the audit report as a formatted JSON string."""
        data = self.report.to_dict()
        return json.dumps(data, indent=indent, ensure_ascii=False)

    def export_to_file(self, output_path: Union[str, Path] = "reports/report.json") -> bool:
        """Writes the JSON report to the specified file path."""
        target_path = Path(output_path)
        content = self.generate_json_string()
        success = safe_write_file(target_path, content, mode=0o644)
        if success:
            logger.info(f"Successfully generated JSON audit report: '{target_path.resolve()}'")
        else:
            logger.error(f"Failed to export JSON report to '{output_path}'")
        return success
