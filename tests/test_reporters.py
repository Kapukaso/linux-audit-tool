"""
Unit tests for JSON, HTML, and Console reporters.
Author: Kartik Soni
"""

import json
from pathlib import Path
import pytest

from src.core.models import AuditFinding, AuditReport, Severity, Status
from src.core.scoring import ScoringEngine
from src.reporters.html_reporter import HtmlReporter
from src.reporters.json_reporter import JsonReporter
from src.reporters.console_reporter import ConsoleReporter


@pytest.fixture
def evaluated_sample_report(baseline_manager):
    """Provides a fully evaluated sample report for testing reporters."""
    report = AuditReport()
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
            check_id="FW-001",
            category="firewall_security",
            title="Ensure UFW is active",
            severity=Severity.HIGH,
            status=Status.FAIL,
            description="UFW inactive.",
            evidence="UFW status: inactive",
            recommendation="Enable UFW."
        )
    ]
    scoring = ScoringEngine(baseline_manager)
    return scoring.evaluate_report(report)


def test_json_reporter_export(evaluated_sample_report, tmp_path):
    """Verifies JSON report file generation and deserialization."""
    out_file = tmp_path / "report.json"
    reporter = JsonReporter(evaluated_sample_report)

    success = reporter.export_to_file(out_file)
    assert success is True
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["tool_name"] == "secureaudit"
    assert "overall_score" in data
    assert len(data["findings"]) == 2


def test_html_reporter_export(evaluated_sample_report, tmp_path):
    """Verifies single-file HTML executive report generation."""
    out_file = tmp_path / "report.html"
    reporter = HtmlReporter(evaluated_sample_report)

    success = reporter.export_to_file(out_file)
    assert success is True
    assert out_file.exists()

    html_content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "Kartik Soni" in html_content
    assert "SSH-001" in html_content
    assert "FW-001" in html_content


def test_console_reporter_export(evaluated_sample_report, tmp_path):
    """Verifies plain text report file export and console formatting."""
    out_file = tmp_path / "report.txt"
    reporter = ConsoleReporter(evaluated_sample_report)

    success = reporter.export_to_file(out_file)
    assert success is True
    assert out_file.exists()

    text_content = out_file.read_text(encoding="utf-8")
    assert "LINUX SECURITY HARDENING & AUTOMATED AUDIT REPORT" in text_content
    assert "OVERALL SECURITY SCORE" in text_content
