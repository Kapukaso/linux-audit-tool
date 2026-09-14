"""
Security baseline loader and schema validator.
Author: Kartik Soni

Features:
- Robust YAML parsing using safe_load
- Schema validation for check definitions
- Extensible baseline querying and fallback defaults
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger

logger = AuditLogger.get_logger()

# Fallback minimal baseline in case external file is inaccessible
FALLBACK_BASELINE: Dict[str, Any] = {
    "version": "1.0-fallback",
    "benchmark_name": "Built-in Emergency Baseline",
    "categories": {
        "user_security": {"name": "User & Privilege Management", "weight": 25},
        "ssh_security": {"name": "SSH Server Hardening", "weight": 25},
        "filesystem_security": {"name": "Filesystem & Permissions", "weight": 25},
        "firewall_security": {"name": "Host Firewall", "weight": 25}
    },
    "checks": [
        {
            "id": "USR-001",
            "category": "user_security",
            "title": "Verify UID 0 is assigned exclusively to root",
            "severity": "CRITICAL",
            "expected": ["root"],
            "remediable": False
        },
        {
            "id": "SSH-001",
            "category": "ssh_security",
            "title": "Disable SSH Root Login",
            "severity": "HIGH",
            "parameter": "PermitRootLogin",
            "expected": "no",
            "remediable": True
        },
        {
            "id": "FS-001",
            "category": "filesystem_security",
            "title": "Permissions on /etc/passwd",
            "severity": "HIGH",
            "path": "/etc/passwd",
            "expected_perms": "0644",
            "remediable": True
        },
        {
            "id": "FW-001",
            "category": "firewall_security",
            "title": "Host firewall (UFW) active",
            "severity": "HIGH",
            "expected": "active",
            "remediable": True
        }
    ]
}


class BaselineManager:
    """Loads, validates, and queries security baseline configurations."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path("config/security_baseline.yaml")
        self.baseline_data: Dict[str, Any] = {}
        self.load_baseline()

    def load_baseline(self) -> None:
        """Loads configuration from YAML or JSON file with validation."""
        if not self.config_path.exists():
            logger.warning(f"Baseline file '{self.config_path}' not found. Falling back to built-in baseline.")
            self.baseline_data = FALLBACK_BASELINE
            return

        try:
            content = self.config_path.read_text(encoding="utf-8")
            if self.config_path.suffix in [".yaml", ".yml"]:
                try:
                    import yaml
                    data = yaml.safe_load(content)
                except ImportError:
                    logger.warning("PyYAML not installed. Attempting JSON load or fallback.")
                    data = json.loads(content)
            else:
                data = json.loads(content)

            if self.validate_schema(data):
                self.baseline_data = data
                logger.debug(f"Successfully loaded security baseline from '{self.config_path}'.")
            else:
                logger.error(f"Baseline '{self.config_path}' failed schema validation. Using fallback.")
                self.baseline_data = FALLBACK_BASELINE
        except Exception as exc:
            logger.error(f"Error reading baseline '{self.config_path}': {exc}. Using fallback.")
            self.baseline_data = FALLBACK_BASELINE

    @staticmethod
    def validate_schema(data: Any) -> bool:
        """Verifies that baseline structure conforms to specifications."""
        if not isinstance(data, dict):
            return False

        if "categories" not in data or "checks" not in data:
            return False

        if not isinstance(data["categories"], dict) or not isinstance(data["checks"], list):
            return False

        # Validate each check entry
        required_fields = {"id", "category", "title", "severity"}
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        for check in data["checks"]:
            if not isinstance(check, dict):
                return False
            if not required_fields.issubset(check.keys()):
                return False
            if check["severity"].upper() not in valid_severities:
                return False

        return True

    def get_categories(self) -> Dict[str, Any]:
        """Returns the dictionary of configured categories."""
        return self.baseline_data.get("categories", {})

    def get_all_checks(self) -> List[Dict[str, Any]]:
        """Returns all checks configured in the baseline."""
        return self.baseline_data.get("checks", [])

    def get_checks_by_category(self, category_key: str) -> List[Dict[str, Any]]:
        """Filters checks by specific category identifier."""
        return [
            chk for chk in self.get_all_checks()
            if chk.get("category", "").lower() == category_key.lower()
        ]

    def get_check_by_id(self, check_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single check definition by its unique ID."""
        for chk in self.get_all_checks():
            if chk.get("id", "").upper() == check_id.upper():
                return chk
        return None
