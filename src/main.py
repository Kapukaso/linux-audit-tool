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

    try:
        if args.command == "system-info":
            from src.modules.system_info import SystemInfoCollector
            collector = SystemInfoCollector()
            meta = collector.collect()
            print("\n" + "=" * 60)
            print("SYSTEM INFORMATION SUMMARY")
            print("=" * 60)
            print(f"  Hostname:       {meta.hostname}")
            print(f"  OS Name:        {meta.os_name}")
            print(f"  OS Version:     {meta.os_version}")
            print(f"  Kernel:         {meta.kernel_version}")
            print(f"  Architecture:   {meta.architecture}")
            print(f"  CPU Info:       {meta.cpu_info}")
            print(f"  Total Memory:   {meta.memory_total_mb} MB")
            print(f"  Free Memory:    {meta.memory_free_mb} MB")
            if meta.disk_usage:
                print(f"  Root Disk:      {meta.disk_usage.get('used', 'N/A')} / {meta.disk_usage.get('size', 'N/A')} ({meta.disk_usage.get('use_percent', 'N/A')} used)")
            print(f"  Interfaces:     {len(meta.network_interfaces)} detected")
            print("=" * 60 + "\n")
            return 0

        elif args.command in ["audit", "score", "report"]:
            from src.core.engine import AuditEngine
            from src.core.scoring import ScoringEngine
            from src.reporters.html_reporter import HtmlReporter
            from src.reporters.json_reporter import JsonReporter
            from src.reporters.console_reporter import ConsoleReporter

            target_cat = getattr(args, "category", "all")
            print(f"\n[*] Running Audit & Scoring Engine (Category: {target_cat})...")

            engine = AuditEngine(baseline_mgr)
            raw_report = engine.run_audit(target_cat)
            scoring = ScoringEngine(baseline_mgr)
            report = scoring.evaluate_report(raw_report)

            if args.command == "score":
                print("\n" + "=" * 70)
                print("SECURITY POSTURE SCORECARD")
                print("=" * 70)
                print(f"  OVERALL SECURITY SCORE:  {report.overall_score} / 100")
                print(f"  OVERALL RISK LEVEL:      {report.risk_level.value}")
                print(f"  EVALUATED CHECKS:        {report.summary['total']} Total ({report.summary['passed']} passed, {report.summary['failed']} failed, {report.summary['warnings']} warnings)")
                print("\n[CATEGORY BREAKDOWN]")
                for cat_id, cs in report.category_scores.items():
                    print(f"  - {cs.category_name:<36} Score: {cs.score:>5.1f}% ({cs.passed_checks}/{cs.total_checks} passed)")
                print("=" * 70 + "\n")
                return 0

            # Generate reports based on --format
            out_path = Path(args.output) if args.output else Path("reports")
            is_file = bool(out_path.suffix)
            out_dir = out_path.parent if is_file else out_path
            out_dir.mkdir(parents=True, exist_ok=True)
            rpt_fmt = getattr(args, "format", "all")

            generated_paths = []
            if rpt_fmt in ["all", "html"]:
                html_rep = HtmlReporter(report)
                html_path = out_path if is_file and out_path.suffix == ".html" else out_dir / "report.html"
                if html_rep.export_to_file(html_path):
                    generated_paths.append(("HTML Report", html_path))

            if rpt_fmt in ["all", "json"]:
                json_rep = JsonReporter(report)
                json_path = out_path if is_file and out_path.suffix == ".json" else out_dir / "report.json"
                if json_rep.export_to_file(json_path):
                    generated_paths.append(("JSON Report", json_path))

            if rpt_fmt in ["all", "txt"]:
                console_rep = ConsoleReporter(report)
                txt_path = out_path if is_file and out_path.suffix == ".txt" else out_dir / "report.txt"
                if console_rep.export_to_file(txt_path):
                    generated_paths.append(("TXT Report", txt_path))

            print(f"\n[*] Reports successfully generated in '{out_dir.resolve()}':")
            for label, path in generated_paths:
                print(f"    - {label:<12}: {path.resolve()}")
            print()
            return 0
    except Exception as exc:
        logger.error(f"Command execution failed: {exc}")
        print(f"\n[-] Error: Command execution failed: {exc}")
        return 1

    elif args.command == "harden":
        from src.hardening.manager import HardeningManager
        is_dry = getattr(args, "dry_run", False)
        auto_confirm = getattr(args, "yes", False)
        rollback_id = getattr(args, "rollback", None)

        if not is_dry and not is_root():
            logger.error("Active hardening requires root privileges. Please run with sudo.")
            print("\n[-] Error: Active hardening requires root privileges. Please run with sudo.")
            return 1

        hardener = HardeningManager(baseline_mgr)

        if rollback_id:
            print(f"\n[*] Executing System Rollback for snapshot: '{rollback_id}'...")
            success = hardener.execute_rollback(rollback_id)
            if success:
                print("[+] System rollback completed successfully!")
                return 0
            else:
                print("[-] System rollback failed. Inspect log file logs/secureaudit.log.")
                return 1

        print(f"\n[*] Executing Hardening Pipeline (Dry-Run: {is_dry})...")
        try:
            actions, pre_rep, post_rep = hardener.execute_hardening(dry_run=is_dry, auto_confirm=auto_confirm)
            if is_dry:
                print(f"\n[+] Dry-run simulation completed. {len(actions)} actions planned.")
            elif post_rep:
                print(f"\n[+] Security Hardening Complete! Security Score improved from {pre_rep.overall_score} to {post_rep.overall_score}.")
            return 0
        except PermissionError as pe:
            logger.error(str(pe))
            return 1
        except Exception as exc:
            logger.error(f"Hardening execution failed: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
