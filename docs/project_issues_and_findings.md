# SecureAudit — Project Issues & Findings Report

**Author:** Kartik Soni  
**Date:** September 14, 2026  
**Scope:** Full codebase analysis of the `secureaudit` Linux Security Hardening Toolkit  
**Method:** Automated multi-agent deep code review across all source, test, config, and documentation files

---

## Executive Summary

A comprehensive code review of the `secureaudit` project identified **28 issues** across the entire codebase, categorized by severity:

| Severity     | Count | Description                                           |
|:-------------|:-----:|:------------------------------------------------------|
| 🔴 Critical  |   2   | Security vulnerabilities that could be exploited       |
| 🟠 High      |   5   | Bugs or flaws that cause incorrect/dangerous behavior  |
| 🟡 Medium    |   8   | Logic flaws, design inconsistencies, missing coverage  |
| 🟢 Low       |  13   | Code quality, unused imports, documentation issues     |

---

## Table of Contents

1. [Critical Issues](#1-critical-issues)
2. [High-Severity Issues](#2-high-severity-issues)
3. [Medium-Severity Issues](#3-medium-severity-issues)
4. [Low-Severity Issues](#4-low-severity-issues)
5. [Summary & Recommendations](#5-summary--recommendations)

---

## 1. Critical Issues

### CRIT-01: Sensitive Data Redaction Failure in Logger

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/core/logger.py`                                            |
| **Lines**      | 25–26, 46                                                       |
| **Category**   | Security — Information Disclosure                                |

**Description:**  
The `SensitiveDataFilter.sanitize()` method is designed to scrub password hashes (SHA-512 and yescrypt) from log output. However, the regex patterns on lines 25–26 wrap the **entire hash** in a single capturing group:

```python
re.compile(r'(\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86})')   # SHA-512
re.compile(r'(\$y\$[a-zA-Z0-9./]{8,}\$[a-zA-Z0-9./]{40,})')     # yescrypt
```

The sanitize method then applies:
```python
text = pattern.sub(r'\1[REDACTED]', text)
```

Since `\1` captures the entire hash, the substitution produces `<full_hash>[REDACTED]` — the sensitive hash is preserved in its entirety, completely defeating the redaction mechanism.

**Impact:** Password hashes written to log files are NOT redacted, potentially exposing them to unauthorized readers.

**Recommended Fix:**  
Remove the capturing group from hash patterns and replace the entire match:
```python
re.compile(r'\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}'),
re.compile(r'\$y\$[a-zA-Z0-9./]{8,}\$[a-zA-Z0-9./]{40,}'),
```
Then update the sanitize method to handle these differently (replace the full match with `[REDACTED HASH]`), or restructure the logic to separate "prefix-preserving" patterns (like `password=xxx`) from "full-match" patterns (like hashes and private keys).

---

### CRIT-02: Path Traversal in Backup Rollback Mechanism

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/backup.py`                                       |
| **Lines**      | 141–150                                                         |
| **Category**   | Security — Path Traversal / Arbitrary File Overwrite             |

**Description:**  
The `rollback()` method accepts a `backup_identifier` string and uses it directly to construct file paths without any validation:

```python
candidate = self.base_dir / backup_identifier / "manifest.json"
if candidate.exists():
    manifest_path = candidate
```

An attacker (or a malicious input) could provide a path traversal payload such as `../../tmp/malicious` to point the rollback engine at an externally crafted `manifest.json`. Since the rollback engine restores files based on paths defined in the manifest, this enables **arbitrary file overwrite as root** — the tool runs with root privileges during hardening operations.

**Impact:** A crafted `backup_identifier` could overwrite critical system files (e.g., `/etc/passwd`, `/etc/sudoers`) with attacker-controlled content.

**Recommended Fix:**  
Validate that the resolved path strictly falls under `self.base_dir`:
```python
candidate = (self.base_dir / backup_identifier).resolve()
if not candidate.is_relative_to(self.base_dir.resolve()):
    logger.error("Invalid backup identifier: path traversal detected.")
    return False
```

---

## 2. High-Severity Issues

### HIGH-01: Cross-Site Scripting (XSS) in HTML Reporter

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/reporters/html_reporter.py`                                |
| **Lines**      | 58, 104, 106–108, 284–286                                      |
| **Category**   | Security — XSS                                                   |

**Description:**  
The HTML report generator directly interpolates unescaped Python string values into HTML output using f-strings. Fields such as `category_name`, `check_id`, `title`, `evidence`, `recommendation`, and system metadata are embedded without any HTML entity encoding.

If any audit finding contains malicious content (e.g., a file path or service name with embedded `<script>` tags), the generated HTML report becomes an XSS vector when opened in a browser.

**Impact:** Anyone viewing the HTML report could execute arbitrary JavaScript in their browser context.

**Recommended Fix:**  
Import the `html` standard library module and wrap all interpolated values in `html.escape()`:
```python
import html
# Before: f"<td>{f.evidence}</td>"
# After:  f"<td>{html.escape(str(f.evidence))}</td>"
```

---

### HIGH-02: SSH Config Parsing Uses Last-Match Instead of First-Match

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/ssh_audit.py`                                      |
| **Line**       | 62                                                              |
| **Category**   | Security — Logic Flaw                                            |

**Description:**  
The `sshd_config` file format uses a **first-match-wins** semantic — the first occurrence of a directive takes precedence. However, the SSH audit module iterates through the file and unconditionally overwrites existing keys:

```python
self.settings[key.lower()] = val
```

This means the **last** value encountered is stored, not the first. If an `sshd_config` contains:
```
PermitRootLogin no
PermitRootLogin yes
```
The audit would report `yes` (correct by last-match), but `sshd` actually uses `no` (first-match). Conversely, the reverse ordering would cause a **false positive** — the audit reports "safe" when the system is actually vulnerable.

**Impact:** Can produce both false positives (reporting security where none exists) and false negatives (missing actual vulnerabilities), undermining audit reliability.

**Recommended Fix:**  
Only store the first encountered value:
```python
if key.lower() not in self.settings:
    self.settings[key.lower()] = val
```

---

### HIGH-03: Missing `Any` Import Causes NameError in `utils.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/core/utils.py`                                             |
| **Lines**      | 18 (import), 125 (usage)                                        |
| **Category**   | Bug — Missing Import / Type Error                                |

**Description:**  
The function `get_file_metadata()` has a return type annotation of `-> Optional[Dict[str, Any]]`, but `Any` is never imported from the `typing` module. Depending on Python version and whether annotations are evaluated eagerly, this can cause a `NameError` at runtime.

**Recommended Fix:**  
Add `Any` to the typing import:
```python
from typing import Dict, List, Optional, Tuple, Union, Any
```

---

### HIGH-04: Missing `Any` Import Causes NameError in `ssh_fixer.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/remediations/ssh_fixer.py`                       |
| **Lines**      | 10 (import), 26 (usage)                                         |
| **Category**   | Bug — Missing Import / Type Error                                |

**Description:**  
The `apply_hardening()` method has a return type annotation of `-> Dict[str, Any]`, but `Any` is not imported. This will cause a `NameError` when the module is loaded.

**Recommended Fix:**  
Update the import statement:
```python
from typing import Dict, Optional, Any
```

---

### HIGH-05: Test Assertions Use `>=` Instead of Exact Count

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `tests/test_audit_modules.py`                                   |
| **Line**       | 141                                                             |
| **Category**   | Missing Test / False Positive                                    |

**Description:**  
The assertion `assert len(report.findings) >= 28` allows the test to pass even if an entire check is accidentally deleted or fails to run (baseline has exactly 29 checks). Similarly, `tests/test_baseline.py` line 36 uses `>= 5` for SSH checks when there are exactly 6.

**Impact:** Regressions that silently drop checks will go undetected.

**Recommended Fix:**  
Use exact assertions:
```python
assert len(report.findings) == 29   # test_audit_modules.py
assert len(ssh_checks) == 6         # test_baseline.py
```

---

## 3. Medium-Severity Issues

### MED-01: `SshAuditModule` Instantiated Without Baseline Checks

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/core/engine.py`                                            |
| **Line**       | 58                                                              |
| **Category**   | Logic Flaw — Inconsistency                                       |

**Description:**  
All audit modules receive their baseline checks via `self.baseline_mgr.get_checks_by_category(...)`, except `SshAuditModule` which is instantiated with no arguments:

```python
ssh_mod = SshAuditModule()       # ← No baseline checks passed
# vs.
user_mod = UserAuditModule(self.baseline_mgr.get_checks_by_category("user_security"))
```

If `SshAuditModule.__init__` expects a checks parameter, this will raise a `TypeError`. If it has a default, it will run without the configurable baseline, making its behavior inconsistent with every other module.

**Recommended Fix:**  
```python
ssh_mod = SshAuditModule(self.baseline_mgr.get_checks_by_category("ssh_security"))
```

---

### MED-02: Scoring Formula Inconsistency Between Category and Overall Score

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/core/scoring.py`                                           |
| **Lines**      | 73–74, 88                                                       |
| **Category**   | Logic Flaw — Mathematical Inconsistency                          |

**Description:**  
Category scores are calculated with a `×2.5` penalty multiplier:
```python
cat_score_val = max(0.0, 100.0 - (cat_penalty * 2.5 ...))
```
But the overall score simply sums raw, unmultiplied penalties:
```python
total_penalty += cat_penalty        # raw penalty
overall_score = max(0.0, round(100.0 - total_penalty, 1))
```

This creates a disconnect where individual categories can appear severely penalized (e.g., 30%) while the overall score remains high (e.g., 85%), confusing users and misrepresenting the actual security posture.

**Recommended Fix:**  
Apply a consistent formula. Either remove the `×2.5` multiplier from category scores, or apply it uniformly to the overall calculation as well.

---

### MED-03: `run_command()` Silently Swallows `CalledProcessError`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/core/utils.py`                                             |
| **Lines**      | 42–76                                                           |
| **Category**   | Logic Flaw                                                       |

**Description:**  
The `run_command()` function accepts a `check=True` parameter (passed to `subprocess.run()`), which is intended to raise `CalledProcessError` on non-zero exit codes. However, the `except CalledProcessError` block on line 75 catches this exception and returns a normal tuple, completely defeating the purpose of `check=True`.

**Recommended Fix:**  
Re-raise the exception when `check=True`, or don't catch `CalledProcessError` when `check` is set:
```python
except subprocess.CalledProcessError as cpe:
    if check:
        raise
    return cpe.returncode, cpe.stdout.strip() if cpe.stdout else "", cpe.stderr.strip() if cpe.stderr else ""
```

---

### MED-04: Hardening Manager `dry_run` Logic Makes Fixer Dry-Run Code Unreachable

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/manager.py`                                      |
| **Lines**      | 72–82, 107–128                                                  |
| **Category**   | Logic Flaw — Unreachable Code                                    |

**Description:**  
The `execute_hardening()` method intercepts `dry_run=True` and returns early (line 82) before calling any fixers. Additionally, all fixer calls hardcode `dry_run=False` (e.g., `ssh_fixer.apply_hardening(dry_run=False)`). This means:
1. The extensive dry-run simulation logic in each fixer module is **completely unreachable**.
2. The `dry_run` parameter on fixer methods is never exercised.

**Recommended Fix:**  
Remove the early-return block and pass the `dry_run` parameter dynamically:
```python
ssh_fixer.apply_hardening(dry_run=dry_run)
```

---

### MED-05: `--format` CLI Argument Is Completely Ignored

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/main.py`                                                   |
| **Lines**      | 52–57, 195–205                                                  |
| **Category**   | Logic Flaw — Dead Feature                                        |

**Description:**  
The `audit` and `report` commands accept a `--format` argument with choices `["all", "html", "json", "txt"]`. However, the report generation code unconditionally generates all three formats regardless of the user's selection:
```python
json_rep.export_to_file(json_path)
html_rep.export_to_file(html_path)
console_rep.export_to_file(txt_path)
```

**Recommended Fix:**  
Check `args.format` before generating reports:
```python
fmt = getattr(args, "format", "all")
if fmt in ("all", "json"):
    json_rep.export_to_file(json_path)
if fmt in ("all", "html"):
    html_rep.export_to_file(html_path)
if fmt in ("all", "txt"):
    console_rep.export_to_file(txt_path)
```

---

### MED-06: Missing `expected_group` in `FS-002` Baseline Check

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `config/security_baseline.yaml` (L154–162), `config/security_baseline.json` (L168–177) |
| **Category**   | Config Error                                                     |

**Description:**  
The `FS-002` check validates `/etc/shadow` permissions and states it must be restricted to "root or shadow group" in the description, but the `expected_group` field is missing entirely. Only `expected_owner: "root"` is defined.

**Recommended Fix:**  
Add `expected_group: "shadow"` to both YAML and JSON configuration files.

---

### MED-07: No Negative Test Cases for Audit Modules

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `tests/test_audit_modules.py`                                   |
| **Lines**      | 48–134                                                          |
| **Category**   | Missing Test Coverage                                            |

**Description:**  
All audit module unit tests only verify "happy path" scenarios — that checks produce a certain number of findings or report a "PASS". There are **no failure/negative test cases** to verify that insecure configurations correctly trigger "FAIL" status. This means the audit logic has never been tested for its primary purpose: detecting vulnerabilities.

**Recommended Fix:**  
Add tests with mock insecure configurations (e.g., `PermitRootLogin yes` in SSH config) to verify that violations are correctly detected with FAIL status.

---

### MED-08: Network Interface Parsing Appends to Potentially Corrupt List

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/system_info.py`                                    |
| **Lines**      | 139–142                                                         |
| **Category**   | Logic Flaw                                                       |

**Description:**  
In `_get_network_interfaces()`, if JSON parsing fails midway, the `interfaces` list might contain partial/corrupt data. The fallback plaintext parser then appends to this same list rather than resetting it.

**Recommended Fix:**  
Reset `interfaces = []` inside the exception handler before starting the plaintext fallback parsing.

---

## 4. Low-Severity Issues

### LOW-01: Unused Import — `is_root` in `main.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/main.py`, Line 15                                          |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `is_root` is imported but never used. The `harden` command does not check for root before executing.  
**Recommended Fix:** Either remove the import, or add a root check before hardening execution.

---

### LOW-02: Unused Import — `sys` in `system_info.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/system_info.py`, Line 12                           |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `sys` is imported but never used.  
**Recommended Fix:** Remove `import sys`.

---

### LOW-03: Unused Import — `re` in `user_audit.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/user_audit.py`, Line 13                            |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `re` module is imported but never used.  
**Recommended Fix:** Remove `import re`.

---

### LOW-04: Unused Import — `glob` in `ssh_audit.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/ssh_audit.py`, Line 14                             |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `glob` module is imported but never used (code uses `Path.glob()` instead).  
**Recommended Fix:** Remove `import glob`.

---

### LOW-05: Unused Import — `re` in `patch_audit.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/patch_audit.py`, Line 10                           |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `re` module is imported but never used.  
**Recommended Fix:** Remove `import re`.

---

### LOW-06: Unused Import — `command_exists` in `logging_audit.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/modules/logging_audit.py`, Line 16                         |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `command_exists` is imported from `src.core.utils` but never called.  
**Recommended Fix:** Remove `command_exists` from the import statement.

---

### LOW-07: Unused Import — `Optional` in `html_reporter.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/reporters/html_reporter.py`, Line 10                       |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `Optional` imported but not used.  
**Recommended Fix:** Remove from import.

---

### LOW-08: Unused Import — `Optional` in `json_reporter.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/reporters/json_reporter.py`, Line 10                       |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `Optional` imported but not used.  
**Recommended Fix:** Remove from import.

---

### LOW-09: Unused Import — `Optional` in `permissions_fixer.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/remediations/permissions_fixer.py`, Line 11      |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `Optional` imported but not used.  
**Recommended Fix:** Remove from import.

---

### LOW-10: Unused Import — `List` in `service_fixer.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/remediations/service_fixer.py`, Line 8           |
| **Category**   | Code Quality — Unused Import                                     |

**Description:** `List` imported but not used.  
**Recommended Fix:** Remove from import.

---

### LOW-11: Inline Import — `shutil` Inside Function in `ssh_fixer.py`

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `src/hardening/remediations/ssh_fixer.py`, Line 97              |
| **Category**   | Code Quality                                                     |

**Description:** `import shutil` is placed inside the `apply_hardening()` function body instead of at the top of the file.  
**Recommended Fix:** Move to top-level imports.

---

### LOW-12: Stale Artifact in README

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `README.md`, Line 120                                           |
| **Category**   | Documentation                                                    |

**Description:** The README ends with an accidental string artifact `"# linux-audit-tool"` trailing after the testing instructions.  
**Recommended Fix:** Remove line 120.

---

### LOW-13: Unnecessary `.gitignore` Entry

| Field          | Detail                                                          |
|:---------------|:----------------------------------------------------------------|
| **File**       | `.gitignore`, Line 52                                           |
| **Category**   | Config Quality                                                   |

**Description:** `/var/backups/secureaudit/` is an absolute OS filesystem path that should not appear in a project-level `.gitignore` — git only tracks paths relative to the repository root.  
**Recommended Fix:** Remove the entry.

---

## 5. Summary & Recommendations

### Issue Distribution by Component

```
Core Modules (engine, scoring, utils, logger, main)   ████████████  10 issues
Audit Modules (ssh, user, fs, net, etc.)               ████████      6 issues
Reporters & Hardening (html, backup, fixers)           ██████████    7 issues
Config, Tests & Docs                                   ██████████    5 issues
```

### Priority Remediation Order

1. **Immediate (Critical):** Fix logger hash redaction failure (CRIT-01) and backup path traversal vulnerability (CRIT-02). These are exploitable security bugs.

2. **Urgent (High):** Address HTML reporter XSS (HIGH-01), SSH config parsing semantics (HIGH-02), and missing `Any` imports that cause NameError (HIGH-03, HIGH-04).

3. **Soon (Medium):** Fix scoring formula inconsistency (MED-02), engine SSH module initialization (MED-01), `run_command()` check logic (MED-03), and add negative test cases (MED-07).

4. **Cleanup (Low):** Remove 10 unused imports, fix README artifact, clean up `.gitignore`.

### Architectural Observations

- **No root privilege check before hardening:** The `harden` command modifies system configurations as root but doesn't verify root access upfront. It imports `is_root` but never calls it, relying on `PermissionError` exceptions at individual file operations — poor UX.

- **Dry-run path is disconnected:** The manager's early-return for dry-run mode means fixer-level dry-run code is dead code. The entire dry-run simulation architecture needs rewiring.

- **Test suite lacks adversarial scenarios:** All 34 tests pass because they only test happy paths. No tests verify that the tool correctly detects insecure configurations — the tool's primary purpose.

---

> **Document generated by automated multi-agent code review.**  
> **Total files analyzed:** 33 (source, test, config, documentation)  
> **Total issues found:** 28
