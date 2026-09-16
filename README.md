# Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)

**Author:** Kartik Soni  
**Academic Project:** SmartED Cybersecurity Internship Minor Project  
**Target Environments:** Ubuntu 22.04/24.04 LTS, Debian 12, Kali Linux  

---

## 1. Project Overview

`secureaudit` is a non-destructive, modular Python 3 command-line security auditing and hardening toolkit. It benchmarks Linux host configurations against an extensible YAML security baseline, identifies weaknesses, calculates deterministic security scores (0–100), outputs multi-format reports (HTML, JSON, TXT), and provides safe remediation with pre-checks, dry-run simulation, automated file backups, and rollback capabilities.

---

## 2. Core Architecture

```text
secureaudit/
├── config/
│   ├── security_baseline.yaml     # Main audit criteria & thresholds
│   └── security_baseline.json     # Zero-dependency JSON baseline mirror
├── src/
│   ├── main.py                    # Primary CLI router and argument parsing
│   ├── core/
│   │   ├── models.py              # Normalized AuditFinding, CategoryScore, AuditReport
│   │   ├── logger.py              # Security-conscious logger with credential redaction
│   │   ├── utils.py               # Safe subprocess execution & POSIX permission helpers
│   │   └── baseline.py            # YAML/JSON baseline loader & schema validator
│   ├── modules/                   # Audit inspection modules (Phase 3)
│   ├── hardening/                 # Remediation, backup & rollback (Phase 5)
│   └── reporters/                 # Multi-format report generators (Phase 4)
├── tests/                         # Automated pytest test harness
└── logs/                          # Application audit trail logs
```

---

## 3. Installation & Quick Start

### Prerequisites
* Python 3.10 or higher
* Linux environment (Ubuntu/Debian recommended) or test workstation

### Setup
```bash
# Clone or navigate to the project directory
cd linux-security-toolkit

# Install the package and dependencies
pip install .
```

### Basic Usage
```bash
# Display tool information
python secureaudit.py version

# View CLI options
python secureaudit.py --help

# Inspect loaded baseline checks (verbose)
python secureaudit.py --verbose audit
```

---

## 4. Security Guarantees & Safeguards
* **Zero Command Injection:** All system interaction uses strictly parameterized subprocess lists (`shell=False`).
* **Sensitive Log Sanitization:** Automatic regex filters redact passwords, tokens, and private keys from console and log streams.
* **Non-Destructive by Default:** Audit mode operates in strict read-only mode without altering system states.
* **Safe Hardening Mode:** Modifications enforce pre-flight safety checks, dry-run simulation, and timestamped file backups.

---

## 5. Inspection Modules (Phase 3)

`secureaudit` includes 8 specialized inspection modules coordinated by the [`AuditEngine`](file:///C:/Users/dell/Projects/Linux%20Audit%20Tool/src/core/engine.py):

1. **System Information (`system_info.py`):** Collects hostname, OS version, kernel release, architecture, CPU model, memory, disk, and network interfaces.
2. **User & Privilege Audit (`user_audit.py`):** Audits UID 0 accounts, passwordless accounts in `/etc/shadow`, root account status, system account login shells, and `/etc/login.defs` password expiration policies.
3. **SSH Security Audit (`ssh_audit.py`):** Evaluates `sshd_config` and drop-in `.conf` files for `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `MaxAuthTries`, `X11Forwarding`, and `Protocol`.
4. **Filesystem Security Audit (`filesystem_audit.py`):** Checks POSIX mode and ownership on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, scans target paths for world-writable files, and audits SUID/SGID binaries.
5. **Firewall Security Audit (`firewall_audit.py`):** Evaluates UFW status, default incoming/outgoing policies, iptables fallbacks, and verifies anti-lockout SSH rules.
6. **Network Security Audit (`network_audit.py`):** Checks for unencrypted legacy ports (FTP, Telnet, TFTP, r-services), promiscuous interface flags, and sysctl parameters (`ip_forward`, `accept_redirects`, `log_martians`).
7. **Service & Daemon Audit (`service_audit.py`):** Detects active obsolete daemons (`telnetd`, `rshd`, `xinetd`, `vsftpd`).
8. **Patch & Update Audit (`patch_audit.py`):** Queries pending APT security updates and `unattended-upgrades` status.
9. **Logging & Accounting Audit (`logging_audit.py`):** Verifies `rsyslog`, `systemd-journald`, `auditd` services, and tracks recent PAM/SSH failed authentication attempt spikes.

---

## 6. Scoring & Reporting (Phase 4)

`secureaudit` features a deterministic scoring engine and multi-format report generators:

* **Scoring Engine (`src/core/scoring.py`):** Calculates an overall score out of 100 based on severity penalties (`CRITICAL` -15, `HIGH` -10, `MEDIUM` -5, `LOW` -2) and computes category compliance scores.
* **HTML Dashboard (`src/reporters/html_reporter.py`):** Generates a self-contained executive HTML report (`reports/report.html`) with a visual scorecard badge, risk pills, category progress bars, and structured findings.
* **Technical JSON (`src/reporters/json_reporter.py`):** Exports machine-readable audit metadata to `reports/report.json`.
* **Console Text (`src/reporters/console_reporter.py`):** Formats high-contrast terminal summaries and `reports/report.txt`.

---

## 7. Hardening Subsystem (Phase 5)

`secureaudit` provides a non-destructive audit mode and a safe, interactive hardening subsystem:

* **Dry-Run Simulation (`--dry-run`):** Previews all proposed remediations with exact command details without modifying system files.
* **Transactional Backups:** Preserves original files into timestamped snapshot directories (`/var/backups/secureaudit/backup_<timestamp>/`) with metadata manifests (`manifest.json`).
* **SSH Syntax Verification:** Validates configuration syntax via `sshd -t` before reloading SSH services. Automatically rolls back on syntax failure.
* **Anti-Lockout Protection:** Explicitly adds SSH allow rules (`ufw allow 22/tcp`) prior to activating firewall policies.
* **Automated Rollback Engine (`--rollback <ID>`):** Restores original file content, permissions, and ownership from snapshot manifests.

---

## 8. Lab Test Scripts & Benchmark Harness (Phase 6)

`secureaudit` includes automated lab scripts and a comparative benchmark harness:

* **Vulnerable Lab Setup (`scripts/setup_vulnerable_lab.sh`):** Intentionally injects misconfigurations across all 7 categories into a target Linux VM for testing.
* **Lab Cleanup (`scripts/cleanup_lab.sh`):** Removes test drop-ins and restores standard POSIX permissions and system configurations.
* **Automated Benchmark Harness (`scripts/run_benchmarks.py`):** Runs pre-hardening audit, executes dry-run hardening, runs post-hardening audit, and displays a side-by-side comparative metrics table.

---

## 9. Testing
Run the automated test suite with:
```bash
pytest tests/ -v
```
All 49 unit and integration tests pass with 100% compliance.

---

## 10. Documentation Roadmap

Comprehensive documentation for all 8 project phases is available in the `docs/` folder:

1. [`phase1_architecture_and_specifications.md`](docs/phase1_architecture_and_specifications.md): Project Blueprint, STRIDE Threat Model, 29 Checks Specification.
2. [`phase2_core_framework_implementation.md`](docs/phase2_core_framework_implementation.md): Core Framework Foundation (Models, Logger, Utils, Baseline Manager).
3. [`phase3_audit_engine_and_inspection_modules.md`](docs/phase3_audit_engine_and_inspection_modules.md): Audit Engine Orchestration & 8 Inspection Modules.
4. [`phase4_scoring_engine_and_reporters.md`](docs/phase4_scoring_engine_and_reporters.md): Deterministic Scoring Engine & HTML/JSON/Console Reporters.
5. [`phase5_hardening_subsystem_and_rollback.md`](docs/phase5_hardening_subsystem_and_rollback.md): Hardening Manager, Remediation Fixers & Rollback Engine.
6. [`phase6_lab_test_scripts_and_metrics.md`](docs/phase6_lab_test_scripts_and_metrics.md): Lab Setup/Cleanup Scripts & Before/After Metrics Analysis.
7. [`phase7_comprehensive_pytest_suite_expansion.md`](docs/phase7_comprehensive_pytest_suite_expansion.md): 49 Automated Pytest Suite & Edge Case Verification.
8. [`phase8_internship_report_and_presentation.md`](docs/phase8_internship_report_and_presentation.md): Internship Academic Report, Screenshot Execution Plan & Slide Deck Blueprint.
9. [`project_issues_and_findings.md`](docs/project_issues_and_findings.md): Comprehensive 85-Issue Code Audit & Remediation Findings Report (All 85 issues have been resolved).
