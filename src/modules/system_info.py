"""
System Information Collector Module.
Author: Kartik Soni

Collects hardware, OS, kernel, memory, disk, and network metadata without exposing
sensitive environment credentials.
"""

import os
import platform
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.logger import AuditLogger
from src.core.models import SystemMeta
from src.core.utils import run_command, safe_read_file

logger = AuditLogger.get_logger()


class SystemInfoCollector:
    """Collects host machine hardware, system software, and network configuration."""

    def collect(self) -> SystemMeta:
        """Executes metadata collection and returns a populated SystemMeta dataclass."""
        meta = SystemMeta()
        meta.hostname = platform.node() or "unknown"
        meta.os_name = platform.system() or "Linux"
        meta.kernel_version = platform.release() or "unknown"
        meta.architecture = platform.machine() or "unknown"

        meta.os_version = self._get_os_version()
        meta.cpu_info = self._get_cpu_info()
        meta.memory_total_mb, meta.memory_free_mb = self._get_memory_info()
        meta.disk_usage = self._get_disk_usage()
        meta.network_interfaces = self._get_network_interfaces()

        logger.debug(f"Collected SystemMeta for host: {meta.hostname} ({meta.os_name} {meta.os_version})")
        return meta

    def _get_os_version(self) -> str:
        """Parses /etc/os-release or platform info for OS version string."""
        os_release = safe_read_file("/etc/os-release")
        if os_release:
            pretty_name = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
            if pretty_name:
                return pretty_name.group(1)
            name = re.search(r'NAME="([^"]+)"', os_release)
            version = re.search(r'VERSION="([^"]+)"', os_release)
            if name and version:
                return f"{name.group(1)} {version.group(1)}"

        # Fallback to platform module
        return f"{platform.system()} {platform.version()}"

    def _get_cpu_info(self) -> str:
        """Parses /proc/cpuinfo or platform processor info."""
        cpuinfo = safe_read_file("/proc/cpuinfo")
        if cpuinfo:
            model_match = re.search(r'model name\s*:\s*(.+)', cpuinfo)
            cores = len(re.findall(r'^processor\s*:', cpuinfo, re.MULTILINE))
            if model_match:
                return f"{model_match.group(1).strip()} ({cores} cores)"

        processor = platform.processor()
        return processor if processor else f"{os.cpu_count() or 1} vCPUs"

    def _get_memory_info(self) -> Tuple[float, float]:
        """Parses /proc/meminfo to extract total and available RAM in MB."""
        meminfo = safe_read_file("/proc/meminfo")
        total_mb, free_mb = 0.0, 0.0

        if meminfo:
            total_match = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
            avail_match = re.search(r'MemAvailable:\s+(\d+)\s+kB', meminfo)
            if total_match:
                total_mb = round(int(total_match.group(1)) / 1024, 1)
            if avail_match:
                free_mb = round(int(avail_match.group(1)) / 1024, 1)
            return total_mb, free_mb

        # Fallback for Windows/non-Linux development
        return 2048.0, 1024.0

    def _get_disk_usage(self) -> Dict[str, Any]:
        """Runs df command or uses shutil to inspect root filesystem disk usage."""
        code, stdout, _ = run_command(["df", "-h", "/"])
        if code == 0 and stdout:
            lines = stdout.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    return {
                        "mount": "/",
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "avail": parts[3],
                        "use_percent": parts[4]
                    }

        try:
            import shutil
            total, used, free = shutil.disk_usage("/")
            return {
                "mount": "/",
                "size": f"{round(total / (1024**3), 1)}G",
                "used": f"{round(used / (1024**3), 1)}G",
                "avail": f"{round(free / (1024**3), 1)}G",
                "use_percent": f"{round((used / total) * 100)}%"
            }
        except Exception:
            return {"mount": "/", "size": "unknown", "use_percent": "0%"}

    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Parses IP address configuration via 'ip addr' command."""
        interfaces: List[Dict[str, Any]] = []
        code, stdout, _ = run_command(["ip", "-j", "addr"])

        if code == 0 and stdout:
            try:
                import json
                data = json.loads(stdout)
                for iface in data:
                    ifname = iface.get("ifname", "unknown")
                    ip_addresses = []
                    for addr_info in iface.get("addr_info", []):
                        if addr_info.get("family") in ["inet", "inet6"]:
                            ip_addresses.append(f"{addr_info.get('local')}/{addr_info.get('prefixlen')}")

                    interfaces.append({
                        "interface": ifname,
                        "state": iface.get("operstate", "UNKNOWN"),
                        "ips": ip_addresses,
                        "mac": iface.get("address", "")
                    })
                return interfaces
            except Exception as e:
                logger.debug(f"JSON parsing for 'ip addr' failed: {e}")
                interfaces = []

        # Plaintext fallback for 'ip addr'
        code, stdout, _ = run_command(["ip", "addr"])
        if code == 0 and stdout:
            current_iface = None
            for line in stdout.splitlines():
                if_match = re.match(r'^\d+:\s+([^:]+):', line)
                if if_match:
                    current_iface = if_match.group(1)
                    interfaces.append({"interface": current_iface, "ips": []})
                elif current_iface and "inet " in line:
                    ip_match = re.search(r'inet\s+([^\s]+)', line)
                    if ip_match and interfaces:
                        interfaces[-1]["ips"].append(ip_match.group(1))

        return interfaces
