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

# Install required dependencies
pip install -r requirements.txt
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

## 5. Testing
Run the automated test suite with:
```bash
pytest tests/ -v
```
All 12 foundation tests pass with 100% compliance.
