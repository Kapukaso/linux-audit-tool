# Phase 2: Core Framework Implementation

**Project Title:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Author:** Kartik Soni  
**Context:** SmartED Cybersecurity Internship Minor Project  

---

## 1. Overview of Core Framework

Phase 2 constructed the foundation for **`secureaudit`**, decoupling business logic from underlying operating system execution, logging, configuration loading, and command-line routing.

```text
src/
├── main.py                    # Argument parsing and subcommand CLI router
├── core/
│   ├── models.py              # Domain dataclasses & enumerations
│   ├── logger.py              # Credential-scrubbing logger
│   ├── utils.py               # Safe process execution & POSIX helpers
│   └── baseline.py            # Baseline YAML/JSON parser & validator
secureaudit.py                 # Top-level executable entrypoint launcher
```

---

## 2. Component Design & Detailed Implementation

### 2.1 Domain Data Models (`src/core/models.py`)
Provides standardized dataclasses and enums:
* **`Severity` Enum:** `CRITICAL` (-15 penalty), `HIGH` (-10), `MEDIUM` (-5), `LOW` (-2), `INFO` (0).
* **`Status` Enum:** `PASS`, `FAIL`, `WARN`, `SKIP`, `ERROR`.
* **`RiskLevel` Enum:** Evaluates overall score thresholds: `CRITICAL` (<50), `HIGH` (50–69.9), `MEDIUM` (70–84.9), `LOW` (>=85).
* **`AuditFinding` Dataclass:** Represents individual check results:
  * `check_id`: Unique check identifier (e.g., `SSH-001`, `FS-002`).
  * `category`: Inspection group (e.g., `ssh_security`, `user_security`).
  * `title`: Concise check description.
  * `severity`: Severity enumeration instance.
  * `status`: Status evaluation instance.
  * `evidence`: Actual system configuration discovered.
  * `recommendation`: Guidance to resolve misconfiguration.
  * `remediable`: Boolean flag indicating if automated fix is available.
  * `remediation_details`: Exact command string used in hardening mode.
* **`SystemMeta` Dataclass:** Host environment metadata container.
* **`AuditReport` Dataclass:** Container aggregating system metadata, findings, category scores, and summary counts.
* **`HardeningAction` Dataclass:** Log record for applied or planned remediations.

### 2.2 Security-Conscious Logging (`src/core/logger.py`)
Features a custom filter, `SensitiveDataFilter`, which scrubs passwords, hashes, API tokens, and RSA/PEM private keys from both console streams and file logs (`logs/secureaudit.log`):

```python
SENSITIVE_PATTERNS = [
    re.compile(r'(password\s*[:=]\s*)([^\s,]+)', re.IGNORECASE),
    re.compile(r'(secret\s*[:=]\s*)([^\s,]+)', re.IGNORECASE),
    re.compile(r'(api[_-]?key\s*[:=]\s*)([^\s,]+)', re.IGNORECASE),
    re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'),
    re.compile(r'(\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86})'),  # SHA-512 crypt
]
```

### 2.3 Defensive Utilities (`src/core/utils.py`)
* **`run_command(cmd_list, timeout=20)`:** Executes system commands strictly via argument arrays with `shell=False`, preventing shell injection vulnerabilities.
* **`safe_read_file(filepath, max_bytes=5MB)`:** Caps file reading to 5 MB to prevent memory exhaustion DoS attacks.
* **`safe_write_file(filepath, content, mode=0o600)`:** Writes to a `.tmp.<hex>` file with restrictive permissions before performing an atomic rename.
* **`get_file_metadata(filepath)`:** Extracts POSIX octal mode permissions, UID/GID, owner/group names, and world-writable/SUID/SGID bit flags.

### 2.4 Baseline Manager (`src/core/baseline.py`)
Loads `config/security_baseline.yaml` using PyYAML's `yaml.safe_load`. If PyYAML is missing, it falls back to `config/security_baseline.json`, and retains an in-memory `FALLBACK_BASELINE` if both are inaccessible. Includes `validate_schema()` to verify all check structures.

### 2.5 CLI Entry Point (`src/main.py` & `secureaudit.py`)
Implements argument parsing with subcommands:
* `system-info`: Displays hardware and OS details.
* `audit`: Runs baseline security checks (`--category` supported).
* `harden`: Prepares remediation (`--dry-run` supported).
* `score`: Computes security score.
* `report`: Exports reports.
* `version`: Displays version and author info.

---

## 3. Test Suite Verification

Phase 2 established 12 foundation unit tests in `tests/test_baseline.py` and `tests/test_parsers.py`:

```bash
python -m pytest tests/ -v
```

### Tests Summary:
1. `test_baseline_manager_loads_valid_file`: Validates baseline loading.
2. `test_baseline_query_by_id`: Queries individual checks.
3. `test_baseline_query_by_category`: Filters checks by category.
4. `test_baseline_schema_validation`: Tests schema validation on valid/invalid inputs.
5. `test_baseline_fallback_on_missing_file`: Verifies fallback baseline on missing files.
6. `test_severity_penalty_points`: Validates penalty deductions.
7. `test_risk_level_calculation`: Validates risk thresholds.
8. `test_audit_finding_serialization`: Tests dictionary conversion.
9. `test_audit_report_structure`: Tests report aggregation.
10. `test_sensitive_data_redaction`: Verifies scrubbing of passwords and private keys.
11. `test_safe_subprocess_execution`: Tests array subprocess execution.
12. `test_safe_file_io`: Tests atomic write and safe read.
