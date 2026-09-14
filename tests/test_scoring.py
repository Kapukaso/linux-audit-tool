"""
Unit tests for the ScoringEngine and mathematical score evaluations.
Author: Kartik Soni
"""

import pytest
from src.core.models import AuditFinding, AuditReport, RiskLevel, Severity, Status
from src.core.scoring import ScoringEngine


def test_scoring_engine_perfect_score(baseline_manager):
    """Verifies that a report with all PASS findings receives a 100.0 score and LOW risk."""
    scoring = ScoringEngine(baseline_manager)
    report = AuditReport()

    # Synthetic all-pass findings
    report.findings = [
        AuditFinding(
            check_id="SSH-001",
            category="ssh_security",
            title="Disable SSH Root Login",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="Root login disabled.",
            evidence="PermitRootLogin no",
            recommendation="None."
        ),
        AuditFinding(
            check_id="FS-001",
            category="filesystem_security",
            title="Permissions on /etc/passwd",
            severity=Severity.HIGH,
            status=Status.PASS,
            description="Permissions 0644.",
            evidence="0644",
            recommendation="None."
        )
    ]

    evaluated = scoring.evaluate_report(report)
    assert evaluated.overall_score == 100.0
    assert evaluated.risk_level == RiskLevel.LOW
    assert "ssh_security" in evaluated.category_scores


def test_scoring_engine_penalty_deduction(baseline_manager):
    """Verifies penalty deductions for CRITICAL and HIGH findings."""
    scoring = ScoringEngine(baseline_manager)
    report = AuditReport()

    report.findings = [
        AuditFinding(
            check_id="USR-001",
            category="user_security",
            title="UID 0 Exclusivity",
            severity=Severity.CRITICAL,  # -15 penalty
            status=Status.FAIL,
            description="Extra UID 0 user.",
            evidence="user2 has UID 0",
            recommendation="Fix UID."
        ),
        AuditFinding(
            check_id="SSH-001",
            category="ssh_security",
            title="Disable SSH Root Login",
            severity=Severity.HIGH,  # -10 penalty
            status=Status.FAIL,
            description="Root login enabled.",
            evidence="PermitRootLogin yes",
            recommendation="Disable."
        )
    ]

    evaluated = scoring.evaluate_report(report)
    # Expected penalty: 15 + 10 = 25 -> Score = 75.0
    assert evaluated.overall_score == 75.0
    assert evaluated.risk_level == RiskLevel.MEDIUM
    assert evaluated.category_scores["user_security"].failed_checks == 1
