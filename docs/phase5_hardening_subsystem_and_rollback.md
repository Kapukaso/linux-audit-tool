# Phase 5: Hardening Subsystem, Transactional Backups, & Rollback Engine

**Project Title:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Author:** Kartik Soni  
**Context:** SmartED Cybersecurity Internship Minor Project  

---

## 1. Overview of Phase 5 Components

Phase 5 implemented the interactive remediation engine, transactional file snapshotting, dry-run simulation mode, configuration syntax verification (`sshd -t`), and automated system rollback:

```text
src/hardening/
├── __init__.py
├── manager.py                 # Hardening orchestrator (interactive, dry-run, rollback)
├── backup.py                  # Snapshot engine & manifest generator (manifest.json)
└── remediations/
    ├── __init__.py
    ├── ssh_fixer.py           # SSH configuration fixer with syntax verification
    ├── permissions_fixer.py   # Critical file permission & world-writable fixer
    ├── firewall_fixer.py      # UFW host firewall fixer with anti-lockout SSH pre-rule
    ├── sysctl_fixer.py        # Kernel network parameter sysctl fixer
    └── service_fixer.py       # Obsolete service mask & logging service activator
```

---

## 2. Component Design & Implementation Details

### 2.1 Backup Snapshot Engine (`src/hardening/backup.py`)
* **`create_snapshot_session()`:** Initializes a timestamped backup directory (e.g. `/var/backups/secureaudit/backup_20260914_185000/` or `backups/backup_20260914_185000/`).
* **`backup_file(target_file)`:** Copies original target files into the snapshot directory, preserving POSIX permissions, owner, and group metadata in `manifest.json`.
* **`rollback(backup_identifier)`:** Restores all original files from `manifest.json`, restores original permissions/ownership, and removes files newly created during remediation.

### 2.2 SSH Hardening Fixer (`src/hardening/remediations/ssh_fixer.py`)
* Applies hardened directives (`PermitRootLogin no`, `PermitEmptyPasswords no`, `MaxAuthTries 4`, `X11Forwarding no`, `Protocol 2`).
* Executes `sshd -t` configuration syntax validation **before** reloading SSH daemons. If syntax errors occur, it automatically restores the backup file and aborts.

### 2.3 Filesystem Permissions Fixer (`src/hardening/remediations/permissions_fixer.py`)
* Restores restrictive permissions: `/etc/passwd` (`0644 root:root`), `/etc/shadow` (`0640 root:shadow`), `/etc/group` (`0644 root:root`), `/etc/gshadow` (`0640 root:shadow`).
* Strips world-write permission bits (`chmod o-w`) from unconfined files.

### 2.4 Host Firewall Fixer (`src/hardening/remediations/firewall_fixer.py`)
* Enforces **Anti-Lockout Pre-Check**: Adds explicit SSH allow rule (`ufw allow 22/tcp`) **before** setting default incoming policy (`ufw default deny incoming`) and activating UFW (`ufw --force enable`).

### 2.5 Sysctl Kernel Hardening Fixer (`src/hardening/remediations/sysctl_fixer.py`)
* Writes kernel security parameters to `/etc/sysctl.d/99-secureaudit.conf` (`net.ipv4.ip_forward = 0`, `send_redirects = 0`, `accept_redirects = 0`, `log_martians = 1`) and executes `sysctl -p`.

### 2.6 Service Fixer (`src/hardening/remediations/service_fixer.py`)
* Stops and masks legacy daemons (`telnet`, `rsh`, `xinetd`, `vsftpd`) via `systemctl stop/mask`.
* Enables essential security daemons (`rsyslog`, `auditd`, `unattended-upgrades`).

### 2.7 Hardening Orchestration (`src/hardening/manager.py`)
1. Pre-Hardening Audit: Runs `AuditEngine` to establish initial score.
2. Displays proposed remediations with descriptions.
3. Dry-Run Check: In `--dry-run` mode, previews changes without altering files.
4. Interactive Confirmation: Requests user confirmation unless `-y` / `--yes` is set.
5. Snapshot Creation: Creates timestamped backup session.
6. Execution & Verification: Invokes handlers and runs Post-Hardening Audit to verify score improvement.

---

## 3. Commands & Execution

```bash
# 1. Preview proposed security remediations without altering files (Dry-Run)
python secureaudit.py harden --dry-run

# 2. Run active hardening interactively (requires sudo / root privileges)
sudo python secureaudit.py harden

# 3. Run active hardening non-interactively
sudo python secureaudit.py harden -y

# 4. Roll back system modifications from a specific backup snapshot
sudo python secureaudit.py harden --rollback backup_20260914_185000

# 5. Run full test suite (34 unit tests passing)
python -m pytest tests/ -v
```

---

## 4. Test Suite Verification

Phase 5 added 7 new unit tests in `tests/test_hardening.py`. All 34 unit tests pass:

```text
tests/test_hardening.py::test_backup_manager_snapshot_and_rollback PASSED [ 47%]
tests/test_hardening.py::test_ssh_fixer_dry_run PASSED                   [ 50%]
tests/test_hardening.py::test_permissions_fixer_dry_run PASSED           [ 52%]
tests/test_hardening.py::test_firewall_fixer_dry_run PASSED              [ 55%]
tests/test_hardening.py::test_sysctl_fixer_dry_run PASSED                [ 58%]
tests/test_hardening.py::test_service_fixer_dry_run PASSED               [ 61%]
tests/test_hardening.py::test_hardening_manager_dry_run PASSED           [ 64%]

============================= 34 passed in 0.65s ==============================
```
