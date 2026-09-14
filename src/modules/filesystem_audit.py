"""
Filesystem Security Audit Module.
Author: Kartik Soni

Checks:
- FS-001: Permissions & ownership of /etc/passwd
- FS-002: Permissions & ownership of /etc/shadow
- FS-003: Permissions & ownership of /etc/group
- FS-004: Permissions & ownership of /etc/gshadow
- FS-005: World-writable files in targeted scan paths
- FS-006: SUID/SGID binaries audit in system binaries paths
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import get_file_metadata

logger = AuditLogger.get_logger()


class FilesystemAuditModule:
    """Audits system file permissions, world-writable files, and SUID/SGID binaries."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes all filesystem security checks."""
        return [
            self.audit_passwd_permissions(),
            self.audit_shadow_permissions(),
            self.audit_group_permissions(),
            self.audit_gshadow_permissions(),
            self.audit_world_writable_files(),
            self.audit_suid_sgid_binaries()
        ]

    def audit_passwd_permissions(self) -> AuditFinding:
        """FS-001: Verify permissions and ownership of /etc/passwd."""
        check_id = "FS-001"
        meta = get_file_metadata("/etc/passwd")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="File /etc/passwd does not exist or is inaccessible!",
                evidence="File /etc/passwd not found.",
                recommendation="Recreate or restore /etc/passwd.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode == "0644" and owner == "root":
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="Permissions on /etc/passwd are correctly set to 0644 root:root.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta['group']}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Insecure permissions or ownership on /etc/passwd!",
                evidence=f"Permissions: {mode} (expected 0644), Owner: {owner} (expected root)",
                recommendation="Run 'chmod 0644 /etc/passwd' and 'chown root:root /etc/passwd'.",
                remediable=True,
                remediation_details="chmod 0644 /etc/passwd; chown root:root /etc/passwd"
            )

    def audit_shadow_permissions(self) -> AuditFinding:
        """FS-002: Verify permissions and ownership of /etc/shadow."""
        check_id = "FS-002"
        meta = get_file_metadata("/etc/shadow")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=Severity.CRITICAL,
                status=Status.WARN,
                description="Permission denied or file /etc/shadow inaccessible.",
                evidence="File /etc/shadow could not be inspected without root permissions.",
                recommendation="Run audit with root privileges to inspect /etc/shadow.",
                remediable=True
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]
        allowed_modes = {"0640", "0600", "0000"}

        if mode in allowed_modes and owner == "root":
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                description=f"Permissions on /etc/shadow ({mode}) are secure.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta['group']}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                description="Insecure permissions on /etc/shadow! Password hashes may be exposed.",
                evidence=f"Permissions: {mode} (expected 0640/0600), Owner: {owner}",
                recommendation="Run 'chmod 0640 /etc/shadow' and 'chown root:shadow /etc/shadow'.",
                remediable=True,
                remediation_details="chmod 0640 /etc/shadow; chown root:shadow /etc/shadow"
            )

    def audit_group_permissions(self) -> AuditFinding:
        """FS-003: Verify permissions and ownership of /etc/group."""
        check_id = "FS-003"
        meta = get_file_metadata("/etc/group")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="File /etc/group does not exist or is inaccessible.",
                evidence="File /etc/group missing.",
                recommendation="Restore /etc/group.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode == "0644" and owner == "root":
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description="Permissions on /etc/group are correctly set to 0644.",
                evidence=f"Permissions: {mode}, Owner: {owner}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="Insecure permissions or ownership on /etc/group.",
                evidence=f"Permissions: {mode} (expected 0644), Owner: {owner}",
                recommendation="Run 'chmod 0644 /etc/group' and 'chown root:root /etc/group'.",
                remediable=True,
                remediation_details="chmod 0644 /etc/group; chown root:root /etc/group"
            )

    def audit_gshadow_permissions(self) -> AuditFinding:
        """FS-004: Verify permissions and ownership of /etc/gshadow."""
        check_id = "FS-004"
        meta = get_file_metadata("/etc/gshadow")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=Severity.HIGH,
                status=Status.WARN,
                description="File /etc/gshadow inaccessible or missing.",
                evidence="File /etc/gshadow unreadable without root.",
                recommendation="Run secureaudit with root privileges.",
                remediable=True
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]
        allowed_modes = {"0640", "0600", "0000"}

        if mode in allowed_modes and owner == "root":
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=Severity.HIGH,
                status=Status.PASS,
                description=f"Permissions on /etc/gshadow ({mode}) are secure.",
                evidence=f"Permissions: {mode}, Owner: {owner}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Insecure permissions on /etc/gshadow.",
                evidence=f"Permissions: {mode} (expected 0640/0600), Owner: {owner}",
                recommendation="Run 'chmod 0640 /etc/gshadow' and 'chown root:shadow /etc/gshadow'.",
                remediable=True,
                remediation_details="chmod 0640 /etc/gshadow; chown root:shadow /etc/gshadow"
            )

    def audit_world_writable_files(self) -> AuditFinding:
        """FS-005: Check for unconfined world-writable files in target scan paths."""
        check_id = "FS-005"
        target_dirs = ["/etc", "/var/tmp", "/tmp", "/opt", "/srv"]
        world_writable_files: List[str] = []
        max_results = 20

        for target in target_dirs:
            path = Path(target)
            if not path.exists() or not path.is_dir():
                continue

            try:
                for root, _, files in os.walk(path):
                    for filename in files:
                        filepath = Path(root) / filename
                        # Skip symlinks
                        if filepath.is_symlink():
                            continue
                        try:
                            st = filepath.stat()
                            # Check world-writable bit (other write)
                            if st.st_mode & 0o002:
                                world_writable_files.append(str(filepath))
                                if len(world_writable_files) >= max_results:
                                    break
                        except (PermissionError, OSError):
                            continue
                    if len(world_writable_files) >= max_results:
                        break
            except (PermissionError, OSError):
                continue

        if not world_writable_files:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Check for unconfined world-writable files in common paths",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description="No unconfined world-writable files discovered in target scan directories.",
                evidence="0 world-writable files found across /etc, /tmp, /var/tmp, /opt, /srv.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Check for unconfined world-writable files in common paths",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description="World-writable files discovered! Local unprivileged users can alter these files.",
                evidence=f"World-writable files ({len(world_writable_files)} found): {', '.join(world_writable_files[:5])}",
                recommendation="Remove world-write bit using 'chmod o-w <file>'.",
                remediable=True,
                remediation_details="Remove world-write permissions on listed files"
            )

    def audit_suid_sgid_binaries(self) -> AuditFinding:
        """FS-006: Audit SUID/SGID binaries in standard system directories."""
        check_id = "FS-006"
        target_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"]
        suid_binaries: List[str] = []
        max_results = 25

        for target in target_dirs:
            path = Path(target)
            if not path.exists() or not path.is_dir():
                continue

            try:
                for entry in path.iterdir():
                    if entry.is_file() and not entry.is_symlink():
                        try:
                            st = entry.stat()
                            if st.st_mode & (0o4000 | 0o2000):  # SUID or SGID
                                suid_binaries.append(str(entry))
                                if len(suid_binaries) >= max_results:
                                    break
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        # Standard expected SUID binaries on Linux (sudo, passwd, su, etc.)
        return AuditFinding(
            check_id=check_id,
            category="filesystem_security",
            title="Audit unauthorized SUID/SGID binaries in standard directories",
            severity=Severity.MEDIUM,
            status=Status.PASS if len(suid_binaries) < 20 else Status.WARN,
            description=f"Discovered {len(suid_binaries)} SUID/SGID binaries in system paths.",
            evidence=f"SUID/SGID executables found: {', '.join(suid_binaries[:5])}...",
            recommendation="Audit listed SUID/SGID binaries and remove unnecessary SUID bits (chmod u-s <file>).",
            remediable=False
        )
