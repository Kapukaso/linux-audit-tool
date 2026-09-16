"""
Security-conscious system utilities, safe subprocess execution, and privilege helpers.
Author: Kartik Soni

Security Principles:
- Never invoke shell=True on untrusted inputs
- Strict argument array invocation for all subprocesses
- Safe path handling with canonicalization
- Robust exception handling and graceful fallbacks
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.core.logger import AuditLogger

logger = AuditLogger.get_logger()


def is_root() -> bool:
    """Checks if the current process is running with effective UID 0 (root)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    # Fallback for Windows test environments
    return False





def run_command(
    cmd: List[str],
    timeout: int = 20,
    check: bool = False
) -> Tuple[int, str, str]:
    """
    Executes a command safely using an argument array (shell=False).

    Args:
        cmd: List of command arguments (e.g., ['systemctl', 'is-active', 'ufw'])
        timeout: Maximum seconds to wait before terminating
        check: If True, raises subprocess.CalledProcessError on non-zero exit

    Returns:
        Tuple of (returncode, stdout_str, stderr_str)
    """
    if not cmd or not isinstance(cmd, list):
        raise ValueError("Command must be a non-empty list of string arguments.")

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False,
            check=check
        )
        return process.returncode, process.stdout.strip(), process.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command '{cmd[0]}' not found in PATH."
    except subprocess.TimeoutExpired:
        logger.warning(f"Command '{' '.join(cmd)}' timed out after {timeout}s.")
        return 124, "", f"Command execution timed out after {timeout} seconds."
    except subprocess.CalledProcessError:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error executing '{' '.join(cmd)}': {exc}")
        return 1, "", str(exc)


def safe_read_file(filepath: Union[str, Path], max_bytes: int = 5_000_000) -> Optional[str]:
    """
    Reads a file securely with size caps to avoid memory exhaustion (DoS).
    """
    path = Path(filepath)
    try:
        if not path.is_file():
            return None

        size = path.stat().st_size
        if size > max_bytes:
            logger.warning(f"File {filepath} exceeds size limit ({size} > {max_bytes} bytes).")
            return None

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (PermissionError, OSError) as e:
        logger.debug(f"Could not read {filepath}: {e}")
        return None


def safe_write_file(filepath: Union[str, Path], content: str, mode: int = 0o600) -> bool:
    """
    Writes content to a file atomically via a temporary file with secure permissions.
    """
    target = Path(filepath)
    temp_file = None

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_file = target.parent / f".{target.name}.tmp.{os.urandom(4).hex()}"
        
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(temp_file, flags, mode)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(content)
        
        temp_file.replace(target)
        return True
    except (OSError, IOError) as e:
        logger.error(f"Failed to atomically write to {filepath}: {e}")
        if temp_file and temp_file.exists():
            temp_file.unlink(missing_ok=True)
        return False


def get_file_metadata(filepath: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """
    Extracts POSIX permissions, owner, group, and octal mode of a file.
    """
    path = Path(filepath)

    try:
        if not path.exists():
            return None

        st = path.stat()
        mode_octal = f"{stat.S_IMODE(st.st_mode):04o}"
        
        owner = str(st.st_uid)
        group = str(st.st_gid)
        
        # Resolve username and group if pwd/grp modules are available (Linux/POSIX)
        try:
            import pwd
            owner = pwd.getpwuid(st.st_uid).pw_name
        except (ImportError, KeyError):
            pass

        try:
            import grp
            group = grp.getgrgid(st.st_gid).gr_name
        except (ImportError, KeyError):
            pass

        return {
            "path": str(path),
            "exists": True,
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "mode_octal": mode_octal,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": owner,
            "group": group,
            "is_world_writable": bool(st.st_mode & stat.S_IWOTH),
            "is_suid": bool(st.st_mode & stat.S_ISUID),
            "is_sgid": bool(st.st_mode & stat.S_ISGID)
        }
    except OSError as e:
        logger.debug(f"Failed to inspect metadata for {filepath}: {e}")
        return None


def is_service_active(service_name: str) -> bool:
    """Checks whether a systemd service is currently running."""
    code, out, _ = run_command(["systemctl", "is-active", service_name])
    return code == 0 and out.strip() == "active"


def is_service_enabled(service_name: str) -> bool:
    """Checks whether a systemd service is enabled at boot."""
    code, out, _ = run_command(["systemctl", "is-enabled", service_name])
    return code == 0 and out.strip() == "enabled"


def command_exists(cmd_name: str) -> bool:
    """Verifies whether an executable exists in the system PATH."""
    return shutil.which(cmd_name) is not None
