"""
Unit tests for data models, sensitive logging redaction, and system utilities.
Author: Kartik Soni
"""

import os
from pathlib import Path
import pytest

from src.core.models import (
    AuditFinding,
    AuditReport,
    CategoryScore,
    RiskLevel,
    Severity,
    Status,
    SystemMeta
)
from src.core.logger import SensitiveDataFilter
from src.core.utils import (
    run_command,
    safe_read_file,
    safe_write_file
)


def test_severity_penalty_points():
    """Validates the severity deduction points for deterministic scoring."""
    assert Severity.CRITICAL.penalty_points == 15
    assert Severity.HIGH.penalty_points == 10
    assert Severity.MEDIUM.penalty_points == 5
    assert Severity.LOW.penalty_points == 2
    assert Severity.INFO.penalty_points == 0


def test_risk_level_calculation():
    """Validates risk category thresholds."""
    assert RiskLevel.from_score(95.0) == RiskLevel.LOW
    assert RiskLevel.from_score(85.0) == RiskLevel.LOW
    assert RiskLevel.from_score(80.0) == RiskLevel.MEDIUM
    assert RiskLevel.from_score(65.0) == RiskLevel.HIGH
    assert RiskLevel.from_score(45.0) == RiskLevel.CRITICAL


def test_audit_finding_serialization():
    """Verifies that an AuditFinding serializes into a clean dictionary."""
    finding = AuditFinding(
        check_id="SSH-001",
        category="ssh_security",
        title="Disable SSH Root Login",
        severity=Severity.HIGH,
        status=Status.FAIL,
        description="Root login enabled in sshd_config",
        evidence="PermitRootLogin yes",
        recommendation="Set PermitRootLogin no in /etc/ssh/sshd_config",
        remediable=True
    )
    data = finding.to_dict()
    assert data["check_id"] == "SSH-001"
    assert data["severity"] == "HIGH"
    assert data["status"] == "FAIL"
    assert data["remediable"] is True


def test_audit_report_structure():
    """Verifies full AuditReport dictionary generation."""
    report = AuditReport(
        overall_score=78.5,
        risk_level=RiskLevel.MEDIUM
    )
    data = report.to_dict()
    assert data["tool_name"] == "secureaudit"
    assert data["overall_score"] == 78.5
    assert data["risk_level"] == "MEDIUM"
    assert "summary" in data


def test_sensitive_data_redaction():
    """Ensures passwords and private keys are scrubbed by the log filter."""
    msg1 = "User login attempt with password=SecretP@ssword123 failed"
    sanitized1 = SensitiveDataFilter.sanitize(msg1)
    assert "SecretP@ssword123" not in sanitized1
    assert "[REDACTED]" in sanitized1

    msg2 = "Token: api_key=ak_live_abcdef123456789"
    sanitized2 = SensitiveDataFilter.sanitize(msg2)
    assert "ak_live_abcdef123456789" not in sanitized2

    msg3 = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    sanitized3 = SensitiveDataFilter.sanitize(msg3)
    assert "MIIEowIBAAKCAQEA0" not in sanitized3
    assert "[REDACTED PRIVATE KEY]" in sanitized3

    # SHA-512 crypt hash redaction
    sha_hash = "$6$abc12345$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    msg4 = f"User root hash is {sha_hash} in shadow file"
    sanitized4 = SensitiveDataFilter.sanitize(msg4)
    assert sha_hash not in sanitized4
    assert "[REDACTED HASH]" in sanitized4


def test_safe_subprocess_execution():
    """Tests run_command using python executable as a safe test command."""
    code, stdout, stderr = run_command([os.sys.executable, "-c", "print('Antigravity Secure Test')"])
    assert code == 0
    assert "Antigravity Secure Test" in stdout


def test_safe_file_io(tmp_path):
    """Verifies safe_write_file atomic writing and safe_read_file reading."""
    test_file = tmp_path / "test_config.conf"
    content = "PermitRootLogin no\nPasswordAuthentication no\n"

    success = safe_write_file(test_file, content, mode=0o600)
    assert success is True
    assert test_file.exists()

    read_back = safe_read_file(test_file)
    assert read_back == content
