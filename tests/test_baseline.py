"""
Unit tests for BaselineManager and baseline validation.
Author: Kartik Soni
"""

import pytest
from src.core.baseline import BaselineManager, FALLBACK_BASELINE


def test_baseline_manager_loads_valid_file(baseline_manager):
    """Verifies that the project security baseline is loaded correctly."""
    categories = baseline_manager.get_categories()
    checks = baseline_manager.get_all_checks()

    assert len(categories) > 0, "Baseline should have defined categories"
    assert len(checks) > 0, "Baseline should have defined checks"

    # Verify essential categories exist
    assert "user_security" in categories
    assert "ssh_security" in categories
    assert "filesystem_security" in categories
    assert "firewall_security" in categories


def test_baseline_query_by_id(baseline_manager):
    """Verifies that individual checks can be queried by ID."""
    chk = baseline_manager.get_check_by_id("SSH-001")
    assert chk is not None
    assert chk["category"] == "ssh_security"
    assert chk["severity"] == "HIGH"


def test_baseline_query_by_category(baseline_manager):
    """Verifies checks can be filtered by category."""
    ssh_checks = baseline_manager.get_checks_by_category("ssh_security")
    assert len(ssh_checks) >= 5
    for c in ssh_checks:
        assert c["category"] == "ssh_security"


def test_baseline_schema_validation(sample_valid_baseline_dict):
    """Tests the schema validator with valid and invalid dictionaries."""
    assert BaselineManager.validate_schema(sample_valid_baseline_dict) is True

    # Missing categories
    invalid_dict = sample_valid_baseline_dict.copy()
    del invalid_dict["categories"]
    assert BaselineManager.validate_schema(invalid_dict) is False

    # Invalid severity
    invalid_check = {
        "version": "1.0",
        "categories": {"c": {"name": "c", "weight": 10}},
        "checks": [{"id": "1", "category": "c", "title": "t", "severity": "SUPER_CRITICAL"}]
    }
    assert BaselineManager.validate_schema(invalid_check) is False


def test_baseline_fallback_on_missing_file(tmp_path):
    """Verifies fallback baseline is loaded when file does not exist."""
    non_existent = tmp_path / "does_not_exist.yaml"
    mgr = BaselineManager(str(non_existent))
    assert mgr.baseline_data["version"] == FALLBACK_BASELINE["version"]
    assert len(mgr.get_all_checks()) == len(FALLBACK_BASELINE["checks"])
