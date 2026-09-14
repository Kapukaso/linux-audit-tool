# Organizational Linux Security Policy

**Author / Maintainer:** Kartik Soni  
**Context:** SmartED Security Compliance Baseline  
**Effective Date:** 2026-09-14  

---

## 1. Access Control Policy

1. **Principle of Least Privilege:** Users must be granted only the minimum necessary privileges required to perform their authorized roles.
2. **Superuser Access:** Direct root logins over SSH or interactive terminals are strictly prohibited. Administrative elevation must occur via `sudo` with individual user credentials.
3. **UID 0 Enforcement:** UID 0 must be assigned exclusively to the `root` account. No auxiliary user accounts may possess UID 0.
4. **Service Accounts:** All system service accounts (UID < 1000) must be configured with non-interactive shells (`/usr/sbin/nologin` or `/bin/false`).

---

## 2. Password & Authentication Policy

1. **Password Expiration:** Maximum password age (`PASS_MAX_DAYS`) in `/etc/login.defs` must not exceed 90 days.
2. **SSH Authentication:** Public-key authentication (Ed25519 or RSA 4096-bit) is required. Plaintext password authentication over SSH must be disabled.
3. **Empty Passwords:** Accounts with empty passwords (`PermitEmptyPasswords no`) are strictly forbidden.
4. **Authentication Retries:** Remote SSH authentication attempts must be capped at 4 or fewer (`MaxAuthTries 4`).

---

## 3. Patch & Vulnerability Management Policy

1. **Security Updates:** Systems must apply critical security package updates within 7 days of public release.
2. **Automated Security Updates:** The `unattended-upgrades` package must be installed and active on all production Debian/Ubuntu hosts to automatically apply security patches.
3. **Kernel Maintenance:** Systems running outdated Linux kernels with known unpatched local privilege escalations must be scheduled for maintenance reboots.

---

## 4. Network & Host Firewall Policy

1. **Default Firewall Policy:** Host firewalls (UFW) must be active on all systems with default incoming policy set to `DENY` or `REJECT`.
2. **Unencrypted Protocols:** Legacy cleartext protocols (Telnet, FTP, TFTP, Rsh) are prohibited. All remote shell and file transfer operations must use encrypted protocols (SSH, SFTP, HTTPS).
3. **Anti-Lockout Rule:** Firewall rules allowing administrative SSH traffic must be verified prior to enabling firewall daemons.

---

## 5. Logging & Audit Policy

1. **Logging Daemons:** A system logging daemon (`rsyslog` or `systemd-journald`) must run continuously.
2. **Kernel Auditing:** The Linux Audit Daemon (`auditd`) must be installed and active to track system calls, file access events, and privilege changes.
3. **Authentication Monitoring:** Failed login attempts in `/var/log/auth.log` must be monitored to detect brute-force attacks.

---

## 6. Incident Response & Security Audits

1. **Routine Auditing:** Automated security audits using `secureaudit` must be performed weekly.
2. **Audit Verification:** Audit reports must be generated in machine-readable JSON and executive HTML formats for compliance recordkeeping.
3. **Remediation Workflow:** Any `CRITICAL` or `HIGH` severity findings discovered during audit must be remediated within 24 hours.
