"""
SSH Security Audit Module.
Author: Kartik Soni

Checks:
- SSH-001: PermitRootLogin set to no
- SSH-002: PasswordAuthentication restricted (no)
- SSH-003: PermitEmptyPasswords set to no
- SSH-004: MaxAuthTries set to <= 4
- SSH-005: X11Forwarding disabled (no)
- SSH-006: Protocol version set to 2
"""

import re
import glob
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import safe_read_file

logger = AuditLogger.get_logger()


class SshAuditModule:
    """Audits SSH server configuration (sshd_config and drop-in include files)."""

    def __init__(self, checks: Optional[List[Dict[str, Any]]] = None, config_path: str = "/etc/ssh/sshd_config"):
        self.checks = checks or []
        self.config_path = config_path
        self.settings: Dict[str, str] = {}
        self.in_match_block = False
        self._parse_config()

    def _parse_config(self) -> None:
        """Parses main sshd_config file and any Included drop-in files."""
        self.settings = {}
        self.in_match_block = False

        main_content = safe_read_file(self.config_path)
        if main_content:
            self._parse_content(main_content, Path(self.config_path).parent)

    def _parse_content(self, content: str, base_dir: Path) -> None:
        """Parses directive key-value pairs ignoring comments."""
        for line in content.splitlines():
            line = line.strip()
            
            # Strip inline comments
            if "#" in line:
                line = line.split("#", 1)[0].strip()
                
            if not line:
                continue
                
            # Split by whitespace or '='
            parts = re.split(r'[\s=]+', line, maxsplit=1)
            if not parts:
                continue
                
            key = parts[0].strip()
            val = parts[1].strip() if len(parts) > 1 else ""
            
            # Remove surrounding quotes
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
                
            if key.lower() == "match":
                self.in_match_block = True
                continue
                
            if key.lower() == "include":
                include_path = val
                if not include_path.startswith("/"):
                    include_path = str(base_dir / include_path)
                for conf_file in sorted(glob.glob(include_path)):
                    c = safe_read_file(conf_file)
                    if c:
                        prev_match = self.in_match_block
                        self.in_match_block = False
                        self._parse_content(c, base_dir)
                        self.in_match_block = prev_match
                continue

            if self.in_match_block:
                continue

            # Store case-insensitive key (first match wins in OpenSSH sshd_config)
            if key.lower() not in self.settings:
                self.settings[key.lower()] = val

    def get_directive(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a parsed sshd setting by name (case-insensitive)."""
        return self.settings.get(key.lower(), default)

    def _get_openssh_version(self) -> float:
        try:
            result = subprocess.run(["ssh", "-V"], stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            output = result.stderr if result.stderr else result.stdout
            m = re.search(r"OpenSSH_([0-9]+\.[0-9]+)", output)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return 0.0

    def audit_all(self) -> List[AuditFinding]:
        """Executes all SSH audit checks."""
        config_p = Path(self.config_path)
        if not config_p.exists():
            skip_msg = "SSH server configuration not found; assuming SSH is not installed."
            return [
                AuditFinding(check_id="SSH-001", category="ssh_security", title="Ensure SSH Root Login is disabled", severity=Severity.HIGH, status=Status.SKIP, description=skip_msg, evidence=f"Missing {self.config_path}"),
                AuditFinding(check_id="SSH-002", category="ssh_security", title="Ensure SSH Password Authentication is restricted", severity=Severity.HIGH, status=Status.SKIP, description=skip_msg, evidence=""),
                AuditFinding(check_id="SSH-003", category="ssh_security", title="Ensure SSH PermitEmptyPasswords is set to no", severity=Severity.CRITICAL, status=Status.SKIP, description=skip_msg, evidence=""),
                AuditFinding(check_id="SSH-004", category="ssh_security", title="Ensure SSH MaxAuthTries is set to 4 or fewer", severity=Severity.MEDIUM, status=Status.SKIP, description=skip_msg, evidence=""),
                AuditFinding(check_id="SSH-005", category="ssh_security", title="Ensure SSH X11Forwarding is disabled", severity=Severity.LOW, status=Status.SKIP, description=skip_msg, evidence=""),
                AuditFinding(check_id="SSH-006", category="ssh_security", title="Ensure SSH Protocol version is strictly 2", severity=Severity.HIGH, status=Status.SKIP, description=skip_msg, evidence="")
            ]
            
        findings = [
            self.audit_permit_root_login(),
            self.audit_password_authentication(),
            self.audit_permit_empty_passwords(),
            self.audit_max_auth_tries(),
            self.audit_x11_forwarding(),
        ]
        
        # LOW-18: Obsolete Protocol 2 Recommendation in SSH Audit
        # Check OpenSSH version. If >= 7.4, Protocol 2 is implicitly enforced and recommending it causes syntax errors.
        if self._get_openssh_version() < 7.4:
            findings.append(self.audit_protocol_version())
        else:
            findings.append(
                AuditFinding(
                    check_id="SSH-006", 
                    category="ssh_security", 
                    title="Ensure SSH Protocol version is strictly 2", 
                    severity=Severity.HIGH, 
                    status=Status.SKIP, 
                    description="OpenSSH version >= 7.4 detected. Protocol 2 is implicitly enforced and the directive is obsolete.", 
                    evidence="OpenSSH >= 7.4"
                )
            )
            
        return findings

    def audit_permit_root_login(self) -> AuditFinding:
        """SSH-001: Ensure SSH Root Login is disabled."""
        check_id = "SSH-001"
        val = self.get_directive("PermitRootLogin", default="prohibit-password")

        if val and val.lower() in ["no", "prohibit-password", "without-password"]:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Root Login is disabled",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="Direct root SSH login is restricted or prohibited.",
                evidence=f"PermitRootLogin = '{val}'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Root Login is disabled",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Direct root SSH login is enabled ('yes'), exposing superuser to remote attacks.",
                evidence=f"PermitRootLogin = '{val}'",
                recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
                remediable=True,
                remediation_details="Set PermitRootLogin no in /etc/ssh/sshd_config"
            )

    def audit_password_authentication(self) -> AuditFinding:
        """SSH-002: Ensure Password Authentication is restricted."""
        check_id = "SSH-002"
        val = self.get_directive("PasswordAuthentication", default="yes")

        if val and val.lower() == "no":
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Password Authentication is restricted",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="SSH Password Authentication is disabled in favor of public key authentication.",
                evidence="PasswordAuthentication = 'no'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Password Authentication is restricted",
                severity=Severity.HIGH,
                status=Status.WARN,
                description="Password authentication is enabled over SSH, increasing risk of brute-force attacks.",
                evidence=f"PasswordAuthentication = '{val}'",
                recommendation="Set 'PasswordAuthentication no' after deploying SSH key pairs.",
                remediable=True,
                remediation_details="Set PasswordAuthentication no in /etc/ssh/sshd_config"
            )

    def audit_permit_empty_passwords(self) -> AuditFinding:
        """SSH-003: Ensure PermitEmptyPasswords is set to no."""
        check_id = "SSH-003"
        val = self.get_directive("PermitEmptyPasswords", default="no")

        if val and val.lower() == "no":
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH PermitEmptyPasswords is set to no",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                description="Empty passwords over SSH are explicitly disallowed.",
                evidence="PermitEmptyPasswords = 'no'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH PermitEmptyPasswords is set to no",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                description="SSH allows accounts with empty passwords to log in!",
                evidence=f"PermitEmptyPasswords = '{val}'",
                recommendation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                remediable=True,
                remediation_details="Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
            )

    def audit_max_auth_tries(self) -> AuditFinding:
        """SSH-004: Ensure MaxAuthTries is set to 4 or fewer."""
        check_id = "SSH-004"
        val_str = self.get_directive("MaxAuthTries", default="6")

        try:
            val = int(val_str)
        except ValueError:
            val = 6

        if 0 < val <= 4:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH MaxAuthTries is set to 4 or fewer",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                description=f"MaxAuthTries is set to {val} (<= 4).",
                evidence=f"MaxAuthTries = '{val}'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH MaxAuthTries is set to 4 or fewer",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                description=f"MaxAuthTries ({val}) is invalid or exceeds maximum threshold of 4.",
                evidence=f"MaxAuthTries = '{val}'",
                recommendation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.",
                remediable=True,
                remediation_details="Set MaxAuthTries 4 in /etc/ssh/sshd_config"
            )

    def audit_x11_forwarding(self) -> AuditFinding:
        """SSH-005: Ensure X11Forwarding is disabled."""
        check_id = "SSH-005"
        val = self.get_directive("X11Forwarding", default="no")

        if val and val.lower() == "no":
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH X11Forwarding is disabled",
                severity=Severity.LOW,
                status=Status.PASS,
                description="X11Forwarding is disabled.",
                evidence="X11Forwarding = 'no'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH X11Forwarding is disabled",
                severity=Severity.LOW,
                status=Status.FAIL,
                description="X11Forwarding is enabled, presenting GUI hijacking risk.",
                evidence=f"X11Forwarding = '{val}'",
                recommendation="Set 'X11Forwarding no' in /etc/ssh/sshd_config.",
                remediable=True,
                remediation_details="Set X11Forwarding no in /etc/ssh/sshd_config"
            )

    def audit_protocol_version(self) -> AuditFinding:
        """SSH-006: Ensure SSH Protocol version is 2."""
        check_id = "SSH-006"
        val = self.get_directive("Protocol", default="2")

        if val == "2":
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Protocol version is strictly 2",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="SSH Protocol version 2 is enforced.",
                evidence="Protocol = '2'",
                recommendation="None. Current configuration is secure.",
                remediable=True
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="ssh_security",
                title="Ensure SSH Protocol version is strictly 2",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description="Legacy SSH protocol version 1 detected!",
                evidence=f"Protocol = '{val}'",
                recommendation="Set 'Protocol 2' in /etc/ssh/sshd_config.",
                remediable=True,
                remediation_details="Set Protocol 2 in /etc/ssh/sshd_config"
            )
