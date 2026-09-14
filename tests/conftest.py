"""
Pytest configuration and shared fixtures for the secureaudit test suite.
Author: Kartik Soni
"""

import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.baseline import BaselineManager


@pytest.fixture
def baseline_manager():
    """Provides an instantiated BaselineManager using the project baseline."""
    baseline_path = PROJECT_ROOT / "config" / "security_baseline.yaml"
    return BaselineManager(str(baseline_path))


@pytest.fixture
def sample_valid_baseline_dict():
    """Returns a valid dictionary baseline structure."""
    return {
        "version": "1.0-test",
        "benchmark_name": "Test Benchmark",
        "categories": {
            "test_cat": {"name": "Test Category", "weight": 100}
        },
        "checks": [
            {
                "id": "TST-001",
                "category": "test_cat",
                "title": "Test Check Definition",
                "severity": "HIGH",
                "expected": "test_val"
            }
        ]
    }
