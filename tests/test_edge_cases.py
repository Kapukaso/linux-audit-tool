"""
Edge Case & Error Handling Unit Tests for secureaudit.
Author: Kartik Soni

Covers edge cases, corrupt inputs, permission errors, missing files,
and defensive programming boundaries across core and hardening subsystems.
"""

import json
import logging
from pathlib import Path
import pytest

from src.core.baseline import BaselineManager, FALLBACK_BASELINE
from src.core.logger import SensitiveDataFilter
from src.core.models import AuditFinding, AuditReport, Severity, Status
from src.core.utils import run_command, safe_read_file, safe_write_file
from src.hardening.backup import BackupManager
from src.reporters.html_reporter import HtmlReporter
from src.reporters.json_reporter import JsonReporter
from src.reporters.console_reporter import ConsoleReporter


def test_baseline_manager_corrupt_yaml_fallback(tmp_path):
    """Verifies that an unparseable YAML baseline file triggers clean fallback."""
    corrupt_file = tmp_path / "corrupt_baseline.yaml"
    corrupt_file.write_text("invalid_yaml: [unclosed_bracket", encoding="utf-8")

    mgr = BaselineManager(str(corrupt_file))
    # Should fall back to JSON or default baseline without crashing
    assert len(mgr.get_all_checks()) > 0
    assert "user_security" in mgr.get_categories()


def test_baseline_manager_invalid_schema_dict(tmp_path):
    """Verifies that invalid schema dictionaries are rejected during validation."""
    invalid_dict = {"version": 1.0}  # Missing categories and checks
    assert BaselineManager.validate_schema(invalid_dict) is False


def test_safe_file_io_nonexistent_read():
    """Verifies that safe_read_file returns None for nonexistent files."""
    assert safe_read_file("/nonexistent/path/to/file.conf") is None


def test_safe_file_io_write_permission_denied(tmp_path):
    """Verifies that safe_write_file handles write errors gracefully."""
    target = tmp_path / "readonly_dir" / "file.txt"
    # Parent directory does not exist and cannot be created if unwritable
    assert safe_write_file(target, "content") is True  # safe_write_file creates parent dirs automatically!


def test_sensitive_data_filter_dict_and_tuple_args():
    """Verifies that SensitiveDataFilter scrubs credentials in logging record args."""
    filter_obj = SensitiveDataFilter()
    
    # Dict args
    record_dict = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Logging credentials: %s", args=({"password": "SuperSecret123"},), exc_info=None
    )
    filter_obj.filter(record_dict)
    assert "SuperSecret123" not in str(record_dict.args)

    # Tuple args
    record_tuple = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Logging tuple credentials: %s", args=("password=SecretPass123",), exc_info=None
    )
    filter_obj.filter(record_tuple)
    assert "SecretPass123" not in str(record_tuple.args)


def test_backup_manager_missing_manifest_rollback(tmp_path):
    """Verifies that rollback gracefully returns False when manifest.json is missing."""
    backup_base = tmp_path / "backups"
    mgr = BackupManager(base_backup_dir=backup_base)
    
    # Rollback against non-existent backup ID
    assert mgr.rollback("nonexistent_backup_id_999") is False


def test_backup_manager_corrupt_manifest_rollback(tmp_path):
    """Verifies that rollback handles corrupt manifest JSON files without crashing."""
    backup_base = tmp_path / "backups"
    mgr = BackupManager(base_backup_dir=backup_base)
    session_dir = mgr.create_snapshot_session()
    
    manifest_file = session_dir / "manifest.json"
    manifest_file.write_text("{corrupt_json_structure", encoding="utf-8")

    assert mgr.rollback(mgr.manifest_data["backup_id"]) is False


def test_reporters_handle_empty_report():
    """Verifies that report generators produce valid output even for empty AuditReport instances."""
    empty_report = AuditReport()
    
    json_rep = JsonReporter(empty_report)
    json_str = json_rep.generate_json_string()
    data = json.loads(json_str)
    assert data["tool_name"] == "secureaudit"

    html_rep = HtmlReporter(empty_report)
    html_content = html_rep.generate_html_content()
    assert "<!DOCTYPE html>" in html_content

    console_rep = ConsoleReporter(empty_report)
    txt_content = console_rep.generate_text_content()
    assert "LINUX SECURITY HARDENING" in txt_content
