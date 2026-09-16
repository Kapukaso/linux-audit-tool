"""
Network & Port Security Audit Module.
Author: Kartik Soni

Checks:
- NET-001: Unencrypted legacy service ports listening on external interfaces
- NET-002: Network interfaces operating in promiscuous mode
- NET-003: Kernel sysctl network security configuration
"""

import re
from typing import Any, Dict, List, Optional

from src.core.logger import AuditLogger
from src.core.models import AuditFinding, Severity, Status
from src.core.utils import run_command, safe_read_file

logger = AuditLogger.get_logger()


class NetworkAuditModule:
    """Audits network security, open ports, promiscuous interfaces, and sysctl hardening."""

    def __init__(self, baseline_checks: Optional[List[Dict[str, Any]]] = None):
        self.checks = baseline_checks or []

    def audit_all(self) -> List[AuditFinding]:
        """Executes all network security audit checks."""
        return [
            self.audit_legacy_ports(),
            self.audit_promiscuous_interfaces(),
            self.audit_sysctl_hardening()
        ]

    def audit_legacy_ports(self) -> AuditFinding:
        """NET-001: Check for unencrypted legacy service ports listening on interfaces."""
        check_id = "NET-001"
        check_def = next((c for c in self.checks if c.get("id") == check_id), {})
        
        default_ports = {21: "FTP", 23: "Telnet", 69: "TFTP", 512: "rexec", 513: "rlogin", 514: "rsh"}
        prohibited_ports = {}
        if "prohibited_ports" in check_def:
            for p in check_def["prohibited_ports"]:
                prohibited_ports[p] = default_ports.get(p, f"Service-{p}")
        else:
            prohibited_ports = default_ports

        exposed_legacy: List[str] = []

        # Run ss -tulpn or netstat -tulpn
        code, stdout, stderr = run_command(["ss", "-tulpn"])
        if code != 0:
            code, stdout, stderr = run_command(["netstat", "-tulpn"])

        if code != 0:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Check for unencrypted legacy service ports listening on all interfaces"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.SKIP,
                description="Unable to inspect listening ports. Both 'ss' and 'netstat' commands failed.",
                evidence=stderr or "Commands failed or are not installed.",
                recommendation="Install 'iproute2' or 'net-tools' package to allow port auditing.",
                remediable=False
            )

        if code == 0 and stdout:
            for line in stdout.splitlines():
                if "LISTEN" in line or "udp" in line.lower():
                    for port, service_name in prohibited_ports.items():
                        # Match pattern like :21 or :23 in local address column
                        if re.search(r':{}\b'.format(port), line):
                            exposed_legacy.append(f"{service_name} (Port {port})")

        if not exposed_legacy:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Check for unencrypted legacy service ports listening on all interfaces"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.PASS,
                description="No cleartext legacy service ports (telnet, ftp, rsh) are listening.",
                evidence="0 prohibited legacy ports listening on TCP/UDP interfaces.",
                recommendation="None. Current configuration is secure.",
                remediable=check_def.get("remediable", False)
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Check for unencrypted legacy service ports listening on all interfaces"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.FAIL,
                description="Unencrypted legacy network ports are active and listening!",
                evidence=f"Exposed legacy services: {', '.join(set(exposed_legacy))}",
                recommendation="Disable and mask legacy services; migrate to SSH/SFTP/TLS.",
                remediable=check_def.get("remediable", False)
            )

    def audit_promiscuous_interfaces(self) -> AuditFinding:
        """NET-002: Verify no network interfaces are operating in promiscuous mode."""
        check_id = "NET-002"
        check_def = next((c for c in self.checks if c.get("id") == check_id), {})
        promisc_ifaces: List[str] = []

        code, stdout, stderr = run_command(["ip", "link"])
        if code != 0:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Verify no network interfaces are operating in promiscuous mode"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.SKIP,
                description="Unable to inspect network interfaces. 'ip link' command failed.",
                evidence=stderr or "Command failed or is not installed.",
                recommendation="Ensure 'iproute2' is installed and executable.",
                remediable=False
            )

        if code == 0 and stdout:
            for line in stdout.splitlines():
                if "PROMISC" in line:
                    match = re.match(r'^\d+:\s+([^:]+):', line)
                    if match:
                        promisc_ifaces.append(match.group(1))

        if not promisc_ifaces:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Verify no network interfaces are operating in promiscuous mode"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.PASS,
                description="No network interfaces are operating in promiscuous packet-sniffing mode.",
                evidence="0 promiscuous interfaces detected.",
                recommendation="None. Current configuration is secure.",
                remediable=check_def.get("remediable", False)
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Verify no network interfaces are operating in promiscuous mode"),
                severity=Severity[check_def.get("severity", "HIGH").upper()] if "severity" in check_def else Severity.HIGH,
                status=Status.FAIL,
                description="Network interfaces running in PROMISCUOUS mode detected!",
                evidence=f"Promiscuous interfaces: {', '.join(promisc_ifaces)}",
                recommendation="Investigate unauthorized sniffing or packet capture tools (tcpdump, Wireshark).",
                remediable=check_def.get("remediable", False)
            )

    def audit_sysctl_hardening(self) -> AuditFinding:
        """NET-003: Verify kernel sysctl network hardening parameters."""
        check_id = "NET-003"
        check_def = next((c for c in self.checks if c.get("id") == check_id), {})
        
        default_sysctls = {
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.log_martians": "1"
        }
        expected_sysctls = check_def.get("sysctl_settings", default_sysctls)
        failed_params: List[str] = []

        for param, expected_val in expected_sysctls.items():
            code, stdout, _ = run_command(["sysctl", "-n", param])
            actual_val = stdout.strip() if code == 0 else ""

            if not actual_val:
                # Try reading directly from /proc/sys/
                proc_path = "/proc/sys/" + param.replace(".", "/")
                val_from_proc = safe_read_file(proc_path)
                if val_from_proc:
                    actual_val = val_from_proc.strip()

            if str(actual_val) != str(expected_val):
                failed_params.append(f"{param} = {actual_val or 'unknown'} (expected {expected_val})")

        if not failed_params:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Verify kernel sysctl network hardening settings"),
                severity=Severity[check_def.get("severity", "MEDIUM").upper()] if "severity" in check_def else Severity.MEDIUM,
                status=Status.PASS,
                description="Kernel sysctl network hardening parameters match recommended baseline.",
                evidence="All tested sysctl parameters match expected values.",
                recommendation="None. Current configuration is secure.",
                remediable=check_def.get("remediable", True)
            )
        else:
            return AuditFinding(
                check_id=check_id,
                category="network_security",
                title=check_def.get("title", "Verify kernel sysctl network hardening settings"),
                severity=Severity[check_def.get("severity", "MEDIUM").upper()] if "severity" in check_def else Severity.MEDIUM,
                status=Status.FAIL,
                description="Insecure kernel sysctl network parameters detected.",
                evidence=f"Misconfigured sysctl settings: {', '.join(failed_params)}",
                recommendation="Apply recommended network settings in /etc/sysctl.d/99-security.conf.",
                remediable=check_def.get("remediable", True),
                remediation_details="Apply recommended settings to /etc/sysctl.d/99-security.conf"
            )
