# Phase 3: Audit Engine & Inspection Modules

**Project Title:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Author:** Kartik Soni  
**Context:** SmartED Cybersecurity Internship Minor Project  

---

## 1. Overview of Inspection Modules

Phase 3 implemented the core security audit inspection engine and 8 specialized modules covering all 29 security baseline checks:

```text
src/
├── core/
│   └── engine.py                  # Audit Engine orchestrator
└── modules/
    ├── system_info.py             # OS, hardware, memory, disk, network collector
    ├── user_audit.py              # UID 0, empty passwords, root lock, login shells
    ├── ssh_audit.py               # sshd_config & drop-in config inspector
    ├── filesystem_audit.py        # /etc perms, world-writable files, SUID binaries
    ├── firewall_audit.py          # UFW status, default policies, SSH rules
    ├── network_audit.py           # Legacy listening ports, promiscuous mode, sysctls
    ├── service_audit.py           # Active obsolete daemons inspector
    ├── patch_audit.py             # Pending security updates & unattended-upgrades
    └── logging_audit.py           # rsyslog, journald, auditd, auth failure logs
```

---

## 2. Detailed Inspection Modules Breakdown

### 2.1 System Information Collector (`src/modules/system_info.py`)
* **`collect()`:** Gathers host metadata into a `SystemMeta` object.
* **OS & Kernel:** Parses `/etc/os-release` for `PRETTY_NAME` or `NAME`/`VERSION` and `platform.release()`.
* **Hardware:** Parses `/proc/cpuinfo` for CPU model and core counts; parses `/proc/meminfo` for `MemTotal` and `MemAvailable` in MB.
* **Disk & Network:** Runs `df -h /` and `ip -j addr` to discover active network interfaces and IP addresses.

### 2.2 User & Privilege Audit Module (`src/modules/user_audit.py`)
* **`USR-001` (UID 0 Exclusivity):** Parses `/etc/passwd` to ensure UID 0 is assigned exclusively to `root`.
* **`USR-002` (Empty Passwords):** Inspects `/etc/shadow` for empty password hash fields (`::`).
* **`USR-003` (Root Password Lock):** Checks whether root's password hash in `/etc/shadow` is locked (`!` or `*`).
* **`USR-004` (System Login Shells):** Identifies system accounts (UID < 1000) configured with interactive shells (`/bin/bash`, `/bin/sh`).
* **`USR-005` (Password Policy):** Checks `PASS_MAX_DAYS` in `/etc/login.defs` (threshold <= 90 days).

### 2.3 SSH Security Audit Module (`src/modules/ssh_audit.py`)
Parses both `/etc/ssh/sshd_config` and drop-in configuration files in `/etc/ssh/sshd_config.d/*.conf`:
* **`SSH-001` (PermitRootLogin):** Verifies setting is `no` or `prohibit-password`.
* **`SSH-002` (PasswordAuthentication):** Checks if password authentication is disabled (`no`).
* **`SSH-003` (PermitEmptyPasswords):** Verifies setting is `no`.
* **`SSH-004` (MaxAuthTries):** Verifies maximum authentication tries <= 4.
* **`SSH-005` (X11Forwarding):** Verifies X11 GUI forwarding is `no`.
* **`SSH-006` (Protocol Version):** Verifies SSH protocol version is strictly `2`.

### 2.4 Filesystem Security Audit Module (`src/modules/filesystem_audit.py`)
* **`FS-001` (`/etc/passwd`):** Verifies mode `0644` owned by `root`.
* **`FS-002` (`/etc/shadow`):** Verifies mode `0640`, `0600`, or `0000` owned by `root`.
* **`FS-003` (`/etc/group`):** Verifies mode `0644` owned by `root`.
* **`FS-004` (`/etc/gshadow`):** Verifies mode `0640` or `0600` owned by `root`.
* **`FS-005` (World-Writable Files):** Scans targeted paths (`/etc`, `/tmp`, `/var/tmp`, `/opt`, `/srv`) for files with world-write permissions (`0o002`).
* **`FS-006` (SUID/SGID Binaries):** Audits system directories for executables with SUID (`0o4000`) or SGID (`0o2000`) bits set.

### 2.5 Firewall Audit Module (`src/modules/firewall_audit.py`)
* **`FW-001` (UFW Active Status):** Runs `ufw status verbose` to verify firewall active status (falls back to `iptables -L -n`).
* **`FW-002` (Default Incoming Policy):** Checks if default ingress policy is `deny` or `reject`.
* **`FW-003` (SSH Anti-Lockout Rule):** Verifies an explicit rule permitting SSH (port 22) exists before enabling UFW.

### 2.6 Network Security Audit Module (`src/modules/network_audit.py`)
* **`NET-001` (Legacy Ports):** Runs `ss -tulpn` or `netstat -tulpn` to detect cleartext legacy listening ports (21 FTP, 23 Telnet, 69 TFTP, 512-514 r-services).
* **`NET-002` (Promiscuous Interfaces):** Runs `ip link` to detect interfaces operating with the `PROMISC` flag.
* **`NET-003` (Sysctl Hardening):** Evaluates kernel parameters: `net.ipv4.ip_forward` (0), `net.ipv4.conf.all.send_redirects` (0), `net.ipv4.conf.all.accept_redirects` (0), `net.ipv4.conf.all.log_martians` (1).

### 2.7 Service Audit Module (`src/modules/service_audit.py`)
* **`SRV-001` (Obsolete Daemons):** Checks `systemctl is-active` for obsolete services (`telnet`, `rsh`, `rlogin`, `nis`, `tftp`, `xinetd`, `vsftpd`).

### 2.8 Patch Audit Module (`src/modules/patch_audit.py`)
* **`PTC-001` (Pending Security Updates):** Runs `apt-get -s upgrade` in simulation mode to detect pending security package upgrades.
* **`PTC-002` (Unattended-Upgrades):** Verifies installation and daemon status of `unattended-upgrades`.

### 2.9 Logging Audit Module (`src/modules/logging_audit.py`)
* **`LOG-001` (Logging Daemon):** Verifies `rsyslog` or `systemd-journald` active status.
* **`LOG-002` (Auditd Service):** Checks `auditd` kernel audit service status.
* **`LOG-003` (Failed Login Monitoring):** Parses `/var/log/auth.log` or `journalctl -u ssh` for failed authentication attempt spikes (> 25 threshold).

### 2.10 Audit Engine Orchestrator (`src/core/engine.py`)
Coordinates the audit lifecycle:
1. Calls `SystemInfoCollector` to record host state.
2. Dispatches specified category modules or all 8 modules.
3. Consolidates results into `AuditReport.findings`.
4. Calculates summary stats (`passed`, `failed`, `warnings`, `critical`, `high`, `medium`, `low`).

---

## 3. Test Suite & Verification Results

Phase 3 added module integration tests in `tests/test_audit_modules.py`. The complete test suite now contains 22 passing unit tests:

```text
tests/test_audit_modules.py::test_system_info_collector PASSED           [  4%]
tests/test_audit_modules.py::test_user_audit_module PASSED               [  9%]
tests/test_audit_modules.py::test_ssh_audit_module PASSED                [ 13%]
tests/test_audit_modules.py::test_filesystem_audit_module PASSED         [ 18%]
tests/test_audit_modules.py::test_firewall_audit_module PASSED           [ 22%]
tests/test_audit_modules.py::test_network_audit_module PASSED            [ 27%]
tests/test_audit_modules.py::test_service_audit_module PASSED            [ 31%]
tests/test_audit_modules.py::test_patch_audit_module PASSED              [ 36%]
tests/test_audit_modules.py::test_logging_audit_module PASSED            [ 40%]
tests/test_audit_modules.py::test_audit_engine_full_run PASSED           [ 45%]
tests/test_baseline.py::test_baseline_manager_loads_valid_file PASSED    [ 50%]
tests/test_baseline.py::test_baseline_query_by_id PASSED                 [ 54%]
tests/test_baseline.py::test_baseline_query_by_category PASSED           [ 59%]
tests/test_baseline.py::test_baseline_schema_validation PASSED           [ 63%]
tests/test_baseline.py::test_baseline_fallback_on_missing_file PASSED    [ 68%]
tests/test_parsers.py::test_severity_penalty_points PASSED               [ 72%]
tests/test_parsers.py::test_risk_level_calculation PASSED                [ 77%]
tests/test_parsers.py::test_audit_finding_serialization PASSED           [ 81%]
tests/test_parsers.py::test_audit_report_structure PASSED                [ 86%]
tests/test_parsers.py::test_sensitive_data_redaction PASSED              [ 90%]
tests/test_parsers.py::test_safe_subprocess_execution PASSED             [ 95%]
tests/test_parsers.py::test_safe_file_io PASSED                          [100%]

============================= 22 passed in 0.36s ==============================
```
