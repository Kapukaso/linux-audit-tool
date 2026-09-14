"""
User and Privilege Security Audit Module.
Author: Kartik Soni

Checks:
- USR-001: Exclusivity of UID 0 to root
- USR-002: Accounts with empty passwords in /etc/shadow
- USR-003: Root account status and password lock
- USR-004: Interactive login shells on service/non-system accounts
- USR-005: Password expiration maximum days policy in /etc/login.defs
"""

from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import safe_read_file

logger = AuditLogger.get_logger()


class UserAuditModule:
    """Audits local users, superuser privileges, password security, and login shells."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes all user and privilege security checks."""
        findings: List[AuditFinding] = []
        findings.append(self.audit_uid_zero())
        findings.append(self.audit_empty_passwords())
        findings.append(self.audit_root_status())
        findings.append(self.audit_login_shells())
        findings.append(self.audit_password_policy())
        return [f for f in findings if f is not None]

    def audit_uid_zero(self) -> AuditFinding:
        """USR-001: Verifies UID 0 is assigned exclusively to root."""
        check_id = "USR-001"
        passwd_content = safe_read_file("/etc/passwd")

        if not passwd_content:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify UID 0 is assigned exclusively to the root account",
                severity=Severity.CRITICAL,
                status=Status.SKIP,
                description="Unable to read /etc/passwd",
                evidence="File /etc/passwd was unreadable or missing.",
                recommendation="Ensure /etc/passwd exists with 0644 permissions.",
                remediable=False
            )

        uid_zero_users: List[str] = []
        for line in passwd_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid_zero_users.append(parts[0])

        if uid_zero_users == ["root"]:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify UID 0 is assigned exclusively to the root account",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                description="UID 0 is assigned exclusively to root.",
                evidence=f"UID 0 accounts: {', '.join(uid_zero_users)}",
                recommendation="None. Current configuration is secure.",
                remediable=False
            )
        else:
            unauthorized = [u for u in uid_zero_users if u != "root"]
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify UID 0 is assigned exclusively to the root account",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                description="Unauthorized non-root accounts have UID 0 superuser privileges!",
                evidence=f"Non-root UID 0 accounts found: {', '.join(unauthorized)}",
                recommendation="Immediately change UID of non-root accounts or lock/delete them.",
                remediable=False
            )

    def audit_empty_passwords(self) -> AuditFinding:
        """USR-002: Verifies no user accounts have empty password fields in /etc/shadow."""
        check_id = "USR-002"
        shadow_content = safe_read_file("/etc/shadow")

        if not shadow_content:
            # Unprivileged user running audit cannot read /etc/shadow
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify no accounts have empty password fields",
                severity=Severity.CRITICAL,
                status=Status.WARN,
                description="Permission denied reading /etc/shadow. Run audit with root privileges to inspect password hashes.",
                evidence="Permission denied accessing /etc/shadow.",
                recommendation="Re-run audit with sudo to perform deep shadow verification.",
                remediable=True
            )

        empty_pass_accounts: List[str] = []
        for line in shadow_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                password_field = parts[1]
                if password_field == "" or password_field == "::":
                    empty_pass_accounts.append(username)

        if not empty_pass_accounts:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify no accounts have empty password fields",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                description="No local accounts have empty password hashes.",
                evidence="0 accounts with empty passwords found in /etc/shadow.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify no accounts have empty password fields",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                description="Accounts with empty passwords allow unauthenticated login!",
                evidence=f"Empty password accounts: {', '.join(empty_pass_accounts)}",
                recommendation="Lock accounts using 'passwd -l <user>' or set a strong password.",
                remediable=True,
                remediation_details=f"Lock passwordless accounts: {', '.join(empty_pass_accounts)}"
            )

    def audit_root_status(self) -> AuditFinding:
        """USR-003: Verifies root account password status."""
        check_id = "USR-003"
        shadow_content = safe_read_file("/etc/shadow")

        if shadow_content:
            for line in shadow_content.splitlines():
                if line.startswith("root:"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        hash_val = parts[1]
                        is_locked = hash_val.startswith("!") or hash_val.startswith("*") or hash_val == "!"
                        evidence = "Root password is locked (!/*)" if is_locked else "Root account has active password hash"
                        return AuditFinding(
                            check_id=check_id,
                            category="user_security",
                            title="Verify root account status and lock status",
                            severity=Severity.MEDIUM,
                            status=Status.PASS if is_locked else Status.WARN,
                            description="Direct root login should use locked password with sudo elevation.",
                            evidence=evidence,
                            recommendation="Enforce sudo for administrative tasks and lock direct root password.",
                            remediable=False
                        )

        return AuditFinding(
            check_id=check_id,
            category="user_security",
            title="Verify root account status and lock status",
            severity=Severity.MEDIUM,
            status=Status.WARN,
            description="Root status could not be verified directly from /etc/shadow.",
            evidence="Read access to /etc/shadow unavailable.",
            recommendation="Run secureaudit with sudo privileges.",
            remediable=False
        )

    def audit_login_shells(self) -> AuditFinding:
        """USR-004: Inspects login shells for system accounts."""
        check_id = "USR-004"
        passwd_content = safe_read_file("/etc/passwd")

        if not passwd_content:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Check for non-system accounts with interactive login shells",
                severity=Severity.MEDIUM,
                status=Status.SKIP,
                description="Unable to read /etc/passwd",
                evidence="File /etc/passwd unreadable.",
                recommendation="Inspect /etc/passwd permissions.",
                remediable=True
            )

        interactive_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh"}
        system_users_with_interactive_shell: List[str] = []

        for line in passwd_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                try:
                    uid = int(parts[2])
                except ValueError:
                    continue
                shell = parts[6]

                # System accounts typically have UID < 1000 (excluding root)
                if 0 < uid < 1000 and username not in ["root", "sync"]:
                    if shell in interactive_shells:
                        system_users_with_interactive_shell.append(f"{username} ({shell})")

        if not system_users_with_interactive_shell:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Check for non-system accounts with interactive login shells",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description="System service accounts correctly use non-interactive shells.",
                evidence="All system accounts (UID < 1000) have non-interactive shells.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Check for non-system accounts with interactive login shells",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="System service accounts have interactive login shells enabled!",
                evidence=f"System accounts with interactive shells: {', '.join(system_users_with_interactive_shell)}",
                recommendation="Set shell to /usr/sbin/nologin or /bin/false via usermod -s /usr/sbin/nologin <user>.",
                remediable=True,
                remediation_details="Update system user login shells to /usr/sbin/nologin"
            )

    def audit_password_policy(self) -> AuditFinding:
        """USR-005: Verifies PASS_MAX_DAYS in /etc/login.defs."""
        check_id = "USR-005"
        login_defs = safe_read_file("/etc/login.defs")

        if not login_defs:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify password expiration policy in /etc/login.defs",
                severity=Severity.LOW,
                status=Status.SKIP,
                description="Unable to read /etc/login.defs",
                evidence="/etc/login.defs missing or unreadable.",
                recommendation="Ensure /etc/login.defs exists.",
                remediable=True
            )

        max_days = None
        for line in login_defs.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "PASS_MAX_DAYS":
                try:
                    max_days = int(parts[1])
                    break
                except ValueError:
                    pass

        if max_days is not None and max_days <= 90:
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify password expiration policy in /etc/login.defs",
                severity=Severity.LOW,
                status=Status.PASS,
                description=f"PASS_MAX_DAYS is set to {max_days} days (<= 90 days).",
                evidence=f"PASS_MAX_DAYS = {max_days}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            evidence_str = f"PASS_MAX_DAYS = {max_days}" if max_days is not None else "PASS_MAX_DAYS not found"
            return AuditFinding(
                check_id=check_id,
                category="user_security",
                title="Verify password expiration policy in /etc/login.defs",
                severity=Severity.LOW,
                status=Status.FAIL,
                description="Password maximum age exceeds recommended threshold (90 days).",
                evidence=evidence_str,
                recommendation="Set PASS_MAX_DAYS 90 in /etc/login.defs.",
                remediable=True,
                remediation_details="Update PASS_MAX_DAYS 90 in /etc/login.defs"
            )
