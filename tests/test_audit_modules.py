"""
Unit tests for Audit Engine and all 8 inspection modules.
Author: Kartik Soni
"""

from pathlib import Path
import pytest

from src.core.engine import AuditEngine
from src.core.models import Status, Severity
from src.modules.filesystem_audit import FilesystemAuditModule
from src.modules.firewall_audit import FirewallAuditModule
from src.modules.logging_audit import LoggingAuditModule
from src.modules.network_audit import NetworkAuditModule
from src.modules.patch_audit import PatchAuditModule
from src.modules.service_audit import ServiceAuditModule
from src.modules.ssh_audit import SshAuditModule
from src.modules.system_info import SystemInfoCollector
from src.modules.user_audit import UserAuditModule


def test_system_info_collector():
    """Verifies that SystemInfoCollector gathers host hardware, OS, and network metadata."""
    collector = SystemInfoCollector()
    meta = collector.collect()

    assert meta.hostname != ""
    assert meta.os_name != ""
    assert meta.architecture != ""
    assert isinstance(meta.disk_usage, dict)
    assert isinstance(meta.network_interfaces, list)


def test_user_audit_module():
    """Verifies user audit check routines."""
    user_mod = UserAuditModule()
    findings = user_mod.audit_all()

    assert len(findings) == 5
    ids = [f.check_id for f in findings]
    assert "USR-001" in ids
    assert "USR-002" in ids
    assert "USR-003" in ids
    assert "USR-004" in ids
    assert "USR-005" in ids


def test_ssh_audit_module(tmp_path):
    """Verifies SSH audit module parsing with a synthetic sshd_config file."""
    sshd_conf = tmp_path / "sshd_config"
    sshd_conf.write_text(
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "MaxAuthTries 4\n"
        "X11Forwarding no\n"
        "Protocol 2\n",
        encoding="utf-8"
    )

    ssh_mod = SshAuditModule(config_path=str(sshd_conf))
    findings = ssh_mod.audit_all()

    assert len(findings) == 6
    for f in findings:
        assert f.status == Status.PASS, f"Check {f.check_id} failed unexpectedly: {f.evidence}"


def test_filesystem_audit_module():
    """Verifies filesystem permission audit handlers."""
    fs_mod = FilesystemAuditModule()
    findings = fs_mod.audit_all()

    assert len(findings) == 6
    ids = [f.check_id for f in findings]
    assert "FS-001" in ids
    assert "FS-002" in ids


def test_firewall_audit_module():
    """Verifies firewall audit checks."""
    fw_mod = FirewallAuditModule()
    findings = fw_mod.audit_all()

    assert len(findings) == 3
    ids = [f.check_id for f in findings]
    assert "FW-001" in ids
    assert "FW-002" in ids
    assert "FW-003" in ids


def test_network_audit_module():
    """Verifies network security and sysctl parameter audits."""
    net_mod = NetworkAuditModule()
    findings = net_mod.audit_all()

    assert len(findings) == 3
    ids = [f.check_id for f in findings]
    assert "NET-001" in ids
    assert "NET-002" in ids
    assert "NET-003" in ids


def test_service_audit_module():
    """Verifies service audit checks for obsolete daemons."""
    srv_mod = ServiceAuditModule()
    findings = srv_mod.audit_all()

    assert len(findings) == 1
    assert findings[0].check_id == "SRV-001"


def test_patch_audit_module():
    """Verifies package update and unattended-upgrades checks."""
    patch_mod = PatchAuditModule()
    findings = patch_mod.audit_all()

    assert len(findings) == 2
    ids = [f.check_id for f in findings]
    assert "PTC-001" in ids
    assert "PTC-002" in ids


def test_logging_audit_module():
    """Verifies logging daemon and authentication log audits."""
    log_mod = LoggingAuditModule()
    findings = log_mod.audit_all()

    assert len(findings) == 3
    ids = [f.check_id for f in findings]
    assert "LOG-001" in ids
    assert "LOG-002" in ids
    assert "LOG-003" in ids


def test_audit_engine_full_run(baseline_manager):
    """Verifies AuditEngine orchestration across all categories."""
    engine = AuditEngine(baseline_manager)
    report = engine.run_audit("all")

    assert len(report.findings) >= 28
    assert report.summary["total"] == len(report.findings)
    assert report.system_meta.hostname != ""
