# secureaudit - Evaluator Quick Start Guide

This guide is designed for project evaluators and reviewers to quickly set up, test, and evaluate the **Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)**.

## 1. Environment Setup

For the best evaluation experience, we recommend running this on a clean **Ubuntu, Debian, or Kali Linux** virtual machine.

```bash
# 1. Clone or extract the project directory
cd linux-audit-tool

# 2. Install dependencies (Requires Python 3.8+)
pip install -r requirements.txt
```

---

## 2. Running a Basic Audit

You can execute the tool directly using the Python wrapper script provided in the root directory.

```bash
# View the tool's help menu and version
python3 secureaudit.py --help
python3 secureaudit.py version

# Collect basic system hardware and OS information
python3 secureaudit.py system-info

# Run a full read-only security audit
python3 secureaudit.py audit

# View the security scorecard and risk level
python3 secureaudit.py score
```

---

## 3. Evaluating the Vulnerable Lab & Hardening (Interactive Test)

To fully demonstrate the tool's capabilities, we have included scripts to intentionally inject vulnerabilities into the VM, which the toolkit will then detect and automatically fix.

### Step A: Inject Vulnerabilities
*Warning: Only do this in a test VM, never on a host machine.*
```bash
sudo ./scripts/setup_vulnerable_lab.sh
```
*This will relax file permissions, misconfigure SSH, disable the firewall, and create vulnerable sysctl network parameters.*

### Step B: See the Damage (Pre-Hardening Audit)
Run the audit again to see how the score dropped and which checks failed:
```bash
python3 secureaudit.py score
```

### Step C: Execute Automated Hardening
Run the hardening subsystem to automatically remediate the vulnerabilities. This requires `sudo`.
```bash
# Preview what the tool intends to fix (Safe Dry-Run)
python3 secureaudit.py harden --dry-run

# Apply the actual fixes (will prompt for confirmation)
sudo python3 secureaudit.py harden
```

### Step D: Verification
Run the score command one last time to verify the system has been secured and the score has returned to 100/100:
```bash
python3 secureaudit.py score
```

### Step E: Cleanup
Restore the lab back to its original state (re-locks root, restarts security daemons, removes vulnerable configs):
```bash
sudo ./scripts/cleanup_lab.sh
```

---

## 4. Viewing the Generated Reports

Every time you run the `audit` command, the tool generates comprehensive reports in the `reports/` directory.

You can explicitly generate all formats at once:
```bash
python3 secureaudit.py report --format all
```

**Available Reports:**
- **HTML Dashboard:** `reports/report.html` (Open in any web browser for a visual scorecard and findings table)
- **JSON Metadata:** `reports/report.json`
- **Console Text:** `reports/report.txt`
