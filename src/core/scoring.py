"""
Deterministic Security Scoring Engine.
Author: Kartik Soni

Calculates:
- Overall deterministic security score out of 100
- Category-level weighted compliance scores
- Severity penalty deductions
- Overall RiskLevel classification (CRITICAL, HIGH, MEDIUM, LOW)
"""

from typing import Dict, List, Optional

from src.core.baseline import BaselineManager
from src.core.logger import AuditLogger
from src.core.models import (
    AuditFinding,
    AuditReport,
    CategoryScore,
    RiskLevel,
    Severity,
    Status
)

logger = AuditLogger.get_logger()


class ScoringEngine:
    """Computes mathematical security scores, category breakdowns, and risk levels."""

    def __init__(self, baseline_manager: Optional[BaselineManager] = None):
        self.baseline_mgr = baseline_manager or BaselineManager()

    def evaluate_report(self, report: AuditReport) -> AuditReport:
        """
        Evaluates an AuditReport by calculating category scores, total score, and risk level.

        Args:
            report: AuditReport containing findings and summary

        Returns:
            Evaluated AuditReport with overall_score, risk_level, and category_scores populated.
        """
        categories = self.baseline_mgr.get_categories()
        category_scores: Dict[str, CategoryScore] = {}

        total_penalty = 0.0

        # Group findings by category
        findings_by_cat: Dict[str, List[AuditFinding]] = {}
        for f in report.findings:
            findings_by_cat.setdefault(f.category, []).append(f)

        # 1. Process Category Scores
        for cat_id, cat_meta in categories.items():
            cat_name = cat_meta.get("name", cat_id)
            cat_weight = float(cat_meta.get("weight", 10.0))
            cat_findings = findings_by_cat.get(cat_id, [])

            total_cat_checks = len(cat_findings)
            passed = sum(1 for f in cat_findings if f.status == Status.PASS)
            failed = sum(1 for f in cat_findings if f.status == Status.FAIL)
            warnings = sum(1 for f in cat_findings if f.status == Status.WARN)

            # Calculate category penalty
            cat_penalty = 0.0
            for f in cat_findings:
                if f.status == Status.FAIL:
                    cat_penalty += f.severity.penalty_points
                elif f.status == Status.WARN:
                    cat_penalty += (f.severity.penalty_points * 0.5)

            total_penalty += cat_penalty
            cat_score_val = max(0.0, 100.0 - (cat_penalty * 2.5 if total_cat_checks > 0 else 0.0))

            category_scores[cat_id] = CategoryScore(
                category_id=cat_id,
                category_name=cat_name,
                weight=cat_weight,
                total_checks=total_cat_checks,
                passed_checks=passed,
                failed_checks=failed,
                warning_checks=warnings,
                score=round(cat_score_val, 1)
            )

        # 2. Overall Score Calculation
        overall_score = max(0.0, round(100.0 - total_penalty, 1))

        report.overall_score = overall_score
        report.risk_level = RiskLevel.from_score(overall_score)
        report.category_scores = category_scores

        logger.info(f"Evaluated Security Posture: Score = {overall_score}/100 | Risk = {report.risk_level.value}")
        return report
