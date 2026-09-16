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

    def _get_check_config(self, check_id: str) -> Optional[Dict[str, Any]]:
        for check in self.checks:
            if check.get("id") == check_id:
                return check
        return None

    def _get_severity(self, config: Optional[Dict[str, Any]], default: Severity) -> Severity:
        if not config:
            return default
        sev_str = config.get("severity", default.value)
        try:
            return Severity(sev_str.upper())
        except ValueError:
            return default

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
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.HIGH)

        expected_owner = config.get("expected_owner", "root") if config else "root"
        expected_group = config.get("expected_group", "root") if config else "root"
        
        meta = get_file_metadata("/etc/passwd")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=severity,
                status=Status.WARN,
                description="File /etc/passwd does not exist or is inaccessible!",
                evidence="File /etc/passwd not found or permission denied.",
                recommendation="Run secureaudit with sufficient privileges or restore /etc/passwd.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode in ["0644", "0444"] and owner == expected_owner and meta.get("group") == expected_group:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=severity,
                status=Status.PASS,
                description=f"Permissions on /etc/passwd are correctly set to {mode} {expected_owner}:{expected_group}.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/passwd",
                severity=severity,
                status=Status.FAIL,
                description="Insecure permissions or ownership on /etc/passwd!",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation=f"Run 'chmod 0644 /etc/passwd' and 'chown {expected_owner}:{expected_group} /etc/passwd'.",
                remediable=True,
                remediation_details=f"chmod 0644 /etc/passwd; chown {expected_owner}:{expected_group} /etc/passwd"
            )

    def audit_shadow_permissions(self) -> AuditFinding:
        """FS-002: Verify permissions and ownership of /etc/shadow."""
        check_id = "FS-002"
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.CRITICAL)

        allowed_modes = config.get("allowed_perms", ["0640", "0600", "0000"]) if config else ["0640", "0600", "0000"]
        expected_owner = config.get("expected_owner", "root") if config else "root"
        expected_group = config.get("expected_group", "shadow") if config else "shadow"

        meta = get_file_metadata("/etc/shadow")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=severity,
                status=Status.WARN,
                description="Permission denied or file /etc/shadow inaccessible.",
                evidence="File /etc/shadow could not be inspected without root permissions.",
                recommendation="Run audit with root privileges to inspect /etc/shadow.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode in allowed_modes and owner == expected_owner and meta.get("group") in [expected_group, "root"]:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=severity,
                status=Status.PASS,
                description=f"Permissions on /etc/shadow ({mode}) are secure.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/shadow",
                severity=severity,
                status=Status.FAIL,
                description="Insecure permissions on /etc/shadow! Password hashes may be exposed.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation=f"Run 'chmod 0640 /etc/shadow' and 'chown {expected_owner}:{expected_group} /etc/shadow'.",
                remediable=True,
                remediation_details=f"chmod 0640 /etc/shadow; chown {expected_owner}:{expected_group} /etc/shadow"
            )

    def audit_group_permissions(self) -> AuditFinding:
        """FS-003: Verify permissions and ownership of /etc/group."""
        check_id = "FS-003"
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.MEDIUM)

        expected_owner = config.get("expected_owner", "root") if config else "root"
        expected_group = config.get("expected_group", "root") if config else "root"

        meta = get_file_metadata("/etc/group")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=severity,
                status=Status.WARN,
                description="File /etc/group does not exist or is inaccessible.",
                evidence="File /etc/group missing or permission denied.",
                recommendation="Run secureaudit with sufficient privileges or restore /etc/group.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode in ["0644", "0444"] and owner == expected_owner and meta.get("group") == expected_group:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=severity,
                status=Status.PASS,
                description="Permissions on /etc/group are correctly set.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/group",
                severity=severity,
                status=Status.FAIL,
                description="Insecure permissions or ownership on /etc/group.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation=f"Run 'chmod 0644 /etc/group' and 'chown {expected_owner}:{expected_group} /etc/group'.",
                remediable=True,
                remediation_details=f"chmod 0644 /etc/group; chown {expected_owner}:{expected_group} /etc/group"
            )

    def audit_gshadow_permissions(self) -> AuditFinding:
        """FS-004: Verify permissions and ownership of /etc/gshadow."""
        check_id = "FS-004"
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.HIGH)

        allowed_modes = config.get("allowed_perms", ["0640", "0600", "0000"]) if config else ["0640", "0600", "0000"]
        expected_owner = config.get("expected_owner", "root") if config else "root"
        expected_group = config.get("expected_group", "shadow") if config else "shadow"

        meta = get_file_metadata("/etc/gshadow")

        if not meta:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=severity,
                status=Status.WARN,
                description="File /etc/gshadow inaccessible or missing.",
                evidence="File /etc/gshadow unreadable without root.",
                recommendation="Run secureaudit with root privileges.",
                remediable=False
            )

        mode = meta["mode_octal"]
        owner = meta["owner"]

        if mode in allowed_modes and owner == expected_owner and meta.get("group") in [expected_group, "root"]:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=severity,
                status=Status.PASS,
                description=f"Permissions on /etc/gshadow ({mode}) are secure.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Verify permissions and ownership of /etc/gshadow",
                severity=severity,
                status=Status.FAIL,
                description="Insecure permissions on /etc/gshadow.",
                evidence=f"Permissions: {mode}, Owner: {owner}:{meta.get('group')}",
                recommendation=f"Run 'chmod 0640 /etc/gshadow' and 'chown {expected_owner}:{expected_group} /etc/gshadow'.",
                remediable=True,
                remediation_details=f"chmod 0640 /etc/gshadow; chown {expected_owner}:{expected_group} /etc/gshadow"
            )

    def audit_world_writable_files(self) -> AuditFinding:
        """FS-005: Check for unconfined world-writable files in target scan paths."""
        check_id = "FS-005"
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.MEDIUM)

        target_dirs = config.get("scan_paths", ["/etc", "/var/tmp", "/tmp", "/opt", "/srv"]) if config else ["/etc", "/var/tmp", "/tmp", "/opt", "/srv"]
        world_writable_files: List[str] = []
        max_results = 20
        max_depth = 3

        for target in target_dirs:
            path = Path(target)
            if not path.exists() or not path.is_dir():
                continue

            try:
                base_depth = len(path.resolve().parts)
                for root, dirs, files in os.walk(path):
                    current_depth = len(Path(root).resolve().parts) - base_depth
                    if current_depth >= max_depth:
                        dirs.clear() # Stop descending

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
            
            if len(world_writable_files) >= max_results:
                break

        if not world_writable_files:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Check for unconfined world-writable files in common paths",
                severity=severity,
                status=Status.PASS,
                description="No unconfined world-writable files discovered in target scan directories.",
                evidence=f"0 world-writable files found across {', '.join(target_dirs)}.",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="filesystem_security",
                title="Check for unconfined world-writable files in common paths",
                severity=severity,
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
        config = self._get_check_config(check_id)
        severity = self._get_severity(config, Severity.MEDIUM)

        target_dirs = config.get("scan_paths", ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"]) if config else ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp"]
        suid_binaries: List[str] = []
        seen_inodes = set()
        max_results = 25

        for target in target_dirs:
            path = Path(target).resolve()
            if not path.exists() or not path.is_dir():
                continue

            try:
                for entry in path.iterdir():
                    if entry.is_file() and not entry.is_symlink():
                        try:
                            st = entry.stat()
                            inode = (st.st_dev, st.st_ino)
                            if inode in seen_inodes:
                                continue
                            if st.st_mode & (0o4000 | 0o2000):  # SUID or SGID
                                suid_binaries.append(str(entry))
                                seen_inodes.add(inode)
                                if len(suid_binaries) >= max_results:
                                    break
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue
            
            if len(suid_binaries) >= max_results:
                break

        return AuditFinding(
            check_id=check_id,
            category="filesystem_security",
            title="Audit unauthorized SUID/SGID binaries in standard directories",
            severity=severity,
            status=Status.PASS if len(suid_binaries) < 20 else Status.WARN,
            description=f"Discovered {len(suid_binaries)} SUID/SGID binaries in system paths.",
            evidence=f"SUID/SGID executables found: {', '.join(suid_binaries[:5])}...",
            recommendation="Audit listed SUID/SGID binaries and remove unnecessary SUID bits (chmod u-s <file>).",
            remediable=False
        )
