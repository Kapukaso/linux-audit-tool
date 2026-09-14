# Audit Methodology & Scoring Methodology

**Project Title:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Author:** Kartik Soni  
**Context:** SmartED Cybersecurity Internship Minor Project  

---

## 1. Threat Model & Risk Assessment

`secureaudit` applies the **STRIDE threat classification framework** tailored for Linux server security:

1. **Spoofing Identity:** Unrestricted SSH root login or passwordless accounts allow unauthorized remote access.
2. **Tampering with Data:** Insecure permissions on system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) allow unauthorized modification.
3. **Repudiation:** Disabled or unmonitored logging daemons (`rsyslog`, `auditd`) allow attackers to conceal lateral movement.
4. **Information Disclosure:** Unencrypted legacy services (FTP, Telnet, TFTP) transmit credentials in cleartext.
5. **Denial of Service:** Inactive host firewalls (UFW) and unpatched kernel vulnerabilities leave systems susceptible to network attacks.
6. **Elevation of Privilege:** Misconfigured SUID/SGID binaries and non-root UID 0 accounts enable local privilege escalation (LPE).

---

## 2. Security Baseline Design

The security baseline ([`config/security_baseline.yaml`](file:///C:/Users/dell/Projects/Linux%20Audit%20Tool/config/security_baseline.yaml)) establishes benchmarking standards aligned with **CIS Ubuntu Linux Benchmarks** and **DISA STIG** principles.

Each check is defined with:
* `id`: Unique identifier (e.g. `SSH-001`).
* `category`: Logical grouping.
* `title`: Concise summary.
* `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
* `expected`: Target secure configuration value.
* `remediable`: Flag indicating whether automated hardening supports remediation.

---

## 3. Deterministic Scoring Algorithm

The scoring engine calculates a deterministic score out of 100 using category weights and severity deductions:

$$\text{Overall Score} = \max\left(0, 100 - \sum \text{Deduction}(\text{Finding Severity})\right)$$

### Penalty Deduction Scale:
* **`CRITICAL` Finding:** -15 points penalty.
* **`HIGH` Finding:** -10 points penalty.
* **`MEDIUM` Finding:** -5 points penalty.
* **`LOW` Finding:** -2 points penalty.
* **`INFO` Finding:** 0 points penalty.

### Overall Risk Classification:
* **Score 85.0 – 100.0:** `LOW` Risk (Hardened, production-ready posture).
* **Score 70.0 – 84.9:** `MEDIUM` Risk (Moderate vulnerabilities present).
* **Score 50.0 – 69.9:** `HIGH` Risk (Significant security misconfigurations).
* **Score 0.0 – 49.9:** `CRITICAL` Risk (High vulnerability to exploitation).

---

## 4. Audit Inspection Methodology

1. **Non-Destructive Standard:** Audit commands query `/proc`, `/sys`, `/etc`, and system utility outputs without making state modifications.
2. **Defensive Subprocess Execution:** All system calls utilize `subprocess.run` with parameterized string lists (`shell=False`).
3. **Privilege Awareness:** Non-root execution gracefully flags permission-restricted checks without unhandled exceptions.

---

## 5. Testing & Verification Methodology

1. **Automated Pytest Harness:** Unit tests mock system calls and configuration parsers to verify edge cases.
2. **Lab VM Testing:** Tested across clean systems, intentionally misconfigured lab environments, and post-hardening remediated environments to verify measurable score improvements.
