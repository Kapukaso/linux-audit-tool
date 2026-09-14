"""
Integration & End-to-End CLI Tests for secureaudit.
Author: Kartik Soni

Tests full subcommand CLI execution, argument parsing routing, report file generation,
and system-info collection via the main entrypoint.
"""

import argparse
import json
from pathlib import Path
import pytest

from src.main import create_parser, main


def test_cli_parser_structure():
    """Verifies that create_parser builds all required commands and global flags."""
    parser = create_parser()
    
    # Test version command
    args_version = parser.parse_args(["version"])
    assert args_version.command == "version"

    # Test audit command options
    args_audit = parser.parse_args(["audit", "--category", "ssh_security", "--format", "json"])
    assert args_audit.command == "audit"
    assert args_audit.category == "ssh_security"
    assert args_audit.format == "json"

    # Test harden command options
    args_harden = parser.parse_args(["harden", "--dry-run", "--yes"])
    assert args_harden.command == "harden"
    assert args_harden.dry_run is True
    assert args_harden.yes is True


def test_cli_main_version(capsys):
    """Verifies end-to-end version subcommand execution."""
    test_args = ["secureaudit", "version"]
    import sys
    sys.argv = test_args

    ret = main()
    assert ret == 0

    captured = capsys.readouterr()
    assert "secureaudit" in captured.out
    assert "1.0.0" in captured.out


def test_cli_main_system_info(capsys):
    """Verifies end-to-end system-info subcommand execution."""
    test_args = ["secureaudit", "system-info"]
    import sys
    sys.argv = test_args

    ret = main()
    assert ret == 0

    captured = capsys.readouterr()
    assert "SYSTEM INFORMATION SUMMARY" in captured.out
    assert "Hostname:" in captured.out


def test_cli_main_audit_and_report_generation(tmp_path, capsys):
    """Verifies end-to-end audit execution and multi-format file generation."""
    out_dir = tmp_path / "reports_test"
    test_args = ["secureaudit", "-o", str(out_dir), "audit", "--format", "all"]
    import sys
    sys.argv = test_args

    ret = main()
    assert ret == 0

    # Verify generated files
    json_path = out_dir / "report.json"
    html_path = out_dir / "report.html"
    txt_path = out_dir / "report.txt"

    assert json_path.exists()
    assert html_path.exists()
    assert txt_path.exists()

    # Validate JSON content structure
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "overall_score" in data
    assert "findings" in data
    assert len(data["findings"]) == 29

    # Validate HTML content
    html_str = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_str
    assert "Linux Security Audit & Baseline Report" in html_str


def test_cli_main_harden_dry_run(capsys):
    """Verifies end-to-end harden subcommand execution in dry-run mode."""
    test_args = ["secureaudit", "harden", "--dry-run"]
    import sys
    sys.argv = test_args

    ret = main()
    assert ret == 0

    captured = capsys.readouterr()
    assert "Executing Hardening Pipeline (Dry-Run: True)" in captured.out
    assert "Dry-run simulation completed" in captured.out
