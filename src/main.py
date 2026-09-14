"""
Main CLI entrypoint for the Linux Security Hardening Toolkit (secureaudit).
Author: Kartik Soni
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from src import __author__, __version__
from src.core.baseline import BaselineManager
from src.core.logger import AuditLogger
from src.core.models import RiskLevel
from src.core.utils import is_root


def create_parser() -> argparse.ArgumentParser:
    """Configures the command-line interface argument parser."""
    parser = argparse.ArgumentParser(
        prog="secureaudit",
        description="Linux Security Hardening and Automated Security Audit Toolkit",
        epilog="Academic Project for SmartED Cybersecurity Internship - Developed by Kartik Soni"
    )

    # Global options
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress informational console output")
    parser.add_argument("-c", "--config", default="config/security_baseline.yaml", help="Path to security baseline YAML file")
    parser.add_argument("-o", "--output", help="Custom output directory or file path for reports")

    subparsers = parser.add_subparsers(dest="command", help="Operational commands")

    # Command: version
    subparsers.add_parser("version", help="Display tool version and author information")

    # Command: system-info
    subparsers.add_parser("system-info", help="Collect and display host operating system, hardware, and network details")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Perform comprehensive security audit against baseline")
    audit_parser.add_argument(
        "--category",
        choices=[
            "all", "system_info", "user_security", "network_security",
            "service_security", "filesystem_security", "ssh_security",
            "firewall_security", "patch_security", "logging_security"
        ],
        default="all",
        help="Target a specific audit category"
    )
    audit_parser.add_argument(
        "--format",
        choices=["all", "html", "json", "txt"],
        default="all",
        help="Output report formats to generate"
    )

    # Command: harden
    harden_parser = subparsers.add_parser("harden", help="Execute automated security hardening remediation")
    harden_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate proposed remediations without modifying system files"
    )
    harden_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Automatically confirm all hardening actions (non-interactive)"
    )
    harden_parser.add_argument(
        "--rollback",
        metavar="BACKUP_ID",
        help="Roll back system modifications from a specified backup timestamp or directory"
    )

    # Command: score
    subparsers.add_parser("score", help="Compute and display system security score and risk level")

    # Command: report
    report_parser = subparsers.add_parser("report", help="Generate or view security reports from recent audit")
    report_parser.add_argument(
        "--format",
        choices=["html", "json", "txt"],
        default="html",
        help="Report format to export"
    )

    return parser


def handle_version() -> int:
    """Handles 'version' command."""
    print("=" * 60)
    print(f"Linux Security Hardening & Automated Audit Toolkit (secureaudit)")
    print(f"Version: {__version__}")
    print(f"Author:  {__author__}")
    print(f"Project: SmartED Minor Project")
    print("=" * 60)
    return 0


def handle_baseline_summary(baseline_mgr: BaselineManager) -> None:
    """Helper to display baseline check statistics."""
    categories = baseline_mgr.get_categories()
    checks = baseline_mgr.get_all_checks()
    print(f"\nLoaded Baseline: {baseline_mgr.baseline_data.get('benchmark_name', 'Default')}")
    print(f"Active Categories: {len(categories)}")
    print(f"Total Defined Checks: {len(checks)}")
    for cat_id, meta in categories.items():
        cat_checks = baseline_mgr.get_checks_by_category(cat_id)
        print(f"  - {meta.get('name', cat_id)} (Weight: {meta.get('weight', 0)}%): {len(cat_checks)} checks")
    print()


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI execution routing."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Initialize logger
    logger = AuditLogger.setup_logger(
        name="secureaudit",
        log_file="logs/secureaudit.log",
        verbose=args.verbose,
        quiet=args.quiet
    )

    if args.command == "version":
        return handle_version()

    # Load security baseline
    baseline_mgr = BaselineManager(args.config)

    if args.verbose:
        handle_baseline_summary(baseline_mgr)

    if args.command == "system-info":
        # Placeholder call to system info module (implemented in Phase 3)
        print("\n[*] Initializing System Information Collector...")
        print(f"    Effective Root Privilege: {'Yes' if is_root() else 'No'}")
        print("    [System Information Collector will execute here]\n")
        return 0

    elif args.command == "audit":
        target_cat = getattr(args, "category", "all")
        print(f"\n[*] Starting Security Audit (Category: {target_cat})...")
        print(f"    Using baseline: {baseline_mgr.config_path}")
        print("    [Audit Engine Orchestration will execute here]\n")
        return 0

    elif args.command == "harden":
        is_dry = getattr(args, "dry_run", False)
        rollback_id = getattr(args, "rollback", None)

        if rollback_id:
            print(f"\n[*] Initializing Rollback Pipeline for snapshot: {rollback_id}...")
            return 0

        print(f"\n[*] Initializing Hardening Engine (Dry-Run: {is_dry})...")
        if not is_root() and not is_dry:
            logger.error("Hardening requires root privileges. Please run with 'sudo secureaudit harden'.")
            return 1
        print("    [Hardening Engine Orchestration will execute here]\n")
        return 0

    elif args.command == "score":
        print("\n[*] Calculating Security Posture Score...")
        print("    [Deterministic Scoring Engine will execute here]\n")
        return 0

    elif args.command == "report":
        rpt_fmt = getattr(args, "format", "html")
        print(f"\n[*] Exporting Security Report (Format: {rpt_fmt})...")
        print("    [Report Generation Subsystem will execute here]\n")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
