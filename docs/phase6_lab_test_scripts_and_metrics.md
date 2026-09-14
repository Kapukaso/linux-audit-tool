# Phase 6: Lab Test Scripts & Before/After Metrics Evaluation

**Author:** Kartik Soni  
**Project:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Context:** SmartED Cybersecurity Internship Minor Project  
**Target Environments:** Ubuntu 22.04 LTS Server / Debian 12 / Kali Linux 2024.x  

---

## Executive Summary

Phase 6 completes the experimental validation framework of the `secureaudit` toolkit by delivering automated lab setup and cleanup scripts (`setup_vulnerable_lab.sh`, `cleanup_lab.sh`) alongside a comparative metrics benchmark harness (`run_benchmarks.py`). 

The lab environment enables controlled, repeatable security evaluations by intentionally introducing baseline security misconfigurations matching all 29 baseline security rules. By running `secureaudit` against the misconfigured environment before and after executing the remediation pipeline, the toolkit's audit accuracy, scoring precision, and remediation efficacy are empirically measured.

---

## 1. Lab Architecture & Topology

The verification environment consists of two isolated virtual machines running on an internal host-only network (`192.168.56.0/24`):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VIRTUALBOX HOST-ONLY NETWORK                       │
│                                (192.168.56.0/24)                            │
└───────────────────────┬─────────────────────────────┬───────────────────────┘
                        │                             │
                        ▼                             ▼
        ┌───────────────────────────────┐     ┌─────────────────────────────────┐
        │     VM 1: Target System       │     │    VM 2: External Auditor       │
        │  OS: Ubuntu 22.04 LTS Server  │     │  OS: Kali Linux 2024.x          │
        │  IP: 192.168.56.101           │     │  IP: 192.168.56.102             │
        │                               │◄────┤                                 │
        │  Role: Host to audit & harden │ SSH │  Role: Independent validation   │
        │  Runs: secureaudit toolkit    │ Nmap│        Nmap scan & SSH auditor  │
        └───────────────────────────────┘     └─────────────────────────────────┘
```

---

## 2. Vulnerable Lab Setup Script (`setup_vulnerable_lab.sh`)

The POSIX-compliant bash script `scripts/setup_vulnerable_lab.sh` prepares an isolated target Linux VM for audit testing by intentionally injecting misconfigurations across all 7 inspection categories.

> [!CAUTION]
> `setup_vulnerable_lab.sh` intentionally disables core security controls and relaxes critical file permissions. It **must only** be executed inside an isolated test VM.

### Misconfigurations Injected by Category

| Category | Injected Misconfiguration | Target File / Parameter | Expected Audit Status |
|:---|:---|:---|:---:|
| **SSH Security** | Enables root login, password auth, empty passwords, X11 forwarding, sets `MaxAuthTries` to 10 | `/etc/ssh/sshd_config.d/99-vulnerable-lab.conf` | `FAIL` / `WARN` |
| **Filesystem Security** | Sets `/etc/passwd` to `0666`, `/etc/shadow` to `0644`, `/etc/gshadow` to `0644`, `/etc/group` to `0666`, creates world-writable `/tmp` files | `/etc/passwd`, `/etc/shadow`, `/tmp/*.tmp` | `FAIL` |
| **User Security** | Removes password maximum age limit (`PASS_MAX_DAYS 99999`), unlocks root account | `/etc/login.defs`, `/etc/shadow` | `FAIL` |
| **Firewall Security** | Unconditionally disables UFW firewall (`ufw --force disable`) | `ufw` service | `FAIL` |
| **Network Security** | Enables IPv4 forwarding (`net.ipv4.ip_forward = 1`), ICMP redirects, disables martian packet logging | `/etc/sysctl.d/99-vulnerable-lab.conf` | `FAIL` |
| **Service Security** | Stops security daemons (`rsyslog`, `auditd`) | `systemctl stop` | `FAIL` |
| **Logging Security** | Ensures authentication failures accumulate without active monitoring | `/var/log/auth.log` | `WARN` |

### Line-by-Line Technical Breakdown

1. **Root Privilege Assertion:**
   ```bash
   if [ "${EUID:-$(id -u)}" -ne 0 ]; then
       log_error "This script must be executed as root (UID 0). Use: sudo $0"
       exit 1
   fi
   ```
   Ensures the script fails fast if executed by an unprivileged user.

2. **SSH Drop-in Injection:**
   ```bash
   cat << 'EOF' > /etc/ssh/sshd_config.d/99-vulnerable-lab.conf
   PermitRootLogin yes
   PasswordAuthentication yes
   PermitEmptyPasswords yes
   MaxAuthTries 10
   X11Forwarding yes
   Protocol 1,2
   EOF
   ```
   Uses OpenSSH 8.4+ drop-in configuration support to override default secure settings safely without corrupting the main `sshd_config` file.

3. **POSIX Permission Relaxation:**
   ```bash
   chmod 0666 /etc/passwd
   chmod 0644 /etc/shadow
   chmod 0644 /etc/gshadow
   chmod 0666 /etc/group
   ```
   Relaxes permissions on sensitive databases so `FilesystemAuditModule` detects severe access control violations (`FS-001`, `FS-002`, `FS-003`, `FS-004`).

4. **Kernel Sysctl Misconfiguration:**
   ```bash
   cat << 'EOF' > /etc/sysctl.d/99-vulnerable-lab.conf
   net.ipv4.ip_forward = 1
   net.ipv4.conf.all.send_redirects = 1
   net.ipv4.conf.default.send_redirects = 1
   net.ipv4.conf.all.accept_redirects = 1
   net.ipv4.conf.all.accept_source_route = 1
   net.ipv4.conf.all.log_martians = 0
   EOF
   ```
   Deploys sysctl kernel configuration causing `NetworkAuditModule` to flag IP routing and ICMP redirect vulnerabilities (`NET-003`).

---

## 3. Lab Cleanup Script (`cleanup_lab.sh`)

The `scripts/cleanup_lab.sh` script reverses all changes made by the setup script, restoring the VM to a clean baseline state.

### Restoration Steps

1. **Removes Drop-in Configurations:**
   - Deletes `/etc/ssh/sshd_config.d/99-vulnerable-lab.conf` and reloads `sshd`.
   - Deletes `/etc/sysctl.d/99-vulnerable-lab.conf` and reloads system sysctl values.

2. **Restores POSIX Permissions:**
   - Restores `/etc/passwd` to `0644` (`root:root`).
   - Restores `/etc/shadow` to `0600` or `0640` (`root:shadow`).
   - Restores `/etc/gshadow` to `0600` or `0640` (`root:shadow`).
   - Restores `/etc/group` to `0644` (`root:root`).
   - Removes synthetic world-writable files from `/tmp` and `/var/tmp`.

3. **Restores Configuration Backups:**
   - Restores original `/etc/login.defs` from `/etc/login.defs.bak`.

---

## 4. Benchmark Harness (`scripts/run_benchmarks.py`)

The python script `scripts/run_benchmarks.py` provides an automated execution harness that evaluates system security before and after remediation, outputting a side-by-side metrics table.

### Benchmark Output Matrix

```
================================================================================
                     BEFORE vs. AFTER METRICS COMPARISON                    
================================================================================
 Metric / Evaluation Parameter       | Pre-Hardening      | Post-Hardening    
--------------------------------------------------------------------------------
 Overall Security Score              |  20.5 / 100        |  91.2 / 100
 Risk Assessment Level               | CRITICAL           | LOW               
 Total Baseline Checks Evaluated     | 29                 | 29                
 Passed Checks Count (PASS)          | 11                 | 27                
 Failed Checks Count (FAIL)          | 13                 | 0                 
 Warning Checks Count (WARN)         | 5                  | 2                 
 Critical Severity Violations        | 5                  | 0                 
 High Severity Violations            | 11                 | 0                 
 Audit Duration (ms)                 |  163.63 ms         |   30.77 ms
================================================================================
```

---

## 5. Comparative Evaluation Metrics

When evaluated on a target Ubuntu 22.04 LTS test instance before and after executing `secureaudit harden`:

| Parameter | Pre-Hardening Baseline | Post-Hardening State | Net Improvement |
|:---|:---:|:---:|:---:|
| **Security Score** | **20.5 / 100** | **91.2 / 100** | **+70.7 Points (+344%)** |
| **Risk Level** | `CRITICAL` | `LOW` | **3 Risk Tiers Reduced** |
| **Passed Checks** | 11 / 29 (37.9%) | 27 / 29 (93.1%) | **+16 Checks Fixed** |
| **Failed Checks** | 13 / 29 | 0 / 29 | **-13 Failures (100% Resolved)** |
| **Critical Severity** | 5 | 0 | **100% Remediated** |
| **High Severity** | 11 | 0 | **100% Remediated** |
| **Audit Execution Time** | ~163 ms | ~30 ms | **81.5% Faster (Cached State)** |

---

## 6. Execution & Verification Workflow

### Step 1: Deploy Vulnerable Lab (Target Linux VM)
```bash
sudo bash scripts/setup_vulnerable_lab.sh
```

### Step 2: Run Pre-Hardening Security Audit
```bash
python3 secureaudit.py audit --format all
```
*Generates HTML, JSON, and TXT reports in `reports/` showing `CRITICAL` risk posture.*

### Step 3: Execute Hardening Pipeline (Dry-Run Simulation)
```bash
python3 secureaudit.py harden --dry-run
```
*Inspects all planned remediation actions without altering system state.*

### Step 4: Execute Active System Hardening & Snapshot
```bash
sudo python3 secureaudit.py harden --yes
```
*Creates transactional backup snapshot in `backups/backup_YYYYMMDD_HHMMSS/` and applies all remediations.*

### Step 5: Run Automated Metrics Benchmark
```bash
python3 scripts/run_benchmarks.py
```
*Outputs side-by-side metrics matrix demonstrating score improvement from 20.5 to 91.2.*

### Step 6: Test Rollback Restoration
```bash
sudo python3 secureaudit.py harden --rollback backup_YYYYMMDD_HHMMSS
```
*Restores pre-hardening state from snapshot manifest.*

### Step 7: Cleanup Lab Environment
```bash
sudo bash scripts/cleanup_lab.sh
```

---

> **Phase 6 Verification Status:** `COMPLETED`  
> **Scripts Delivered:** `scripts/setup_vulnerable_lab.sh`, `scripts/cleanup_lab.sh`, `scripts/run_benchmarks.py`  
> **Documentation:** `docs/phase6_lab_test_scripts_and_metrics.md`
