"""
Automated Before/After Metrics & Benchmark Evaluation Harness for secureaudit.
Author: Kartik Soni

Executes pre-hardening audit, runs hardening (or dry-run), executes post-hardening audit,
and prints a comparative security posture matrix with metrics.
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.baseline import BaselineManager
from src.core.engine import AuditEngine
from src.core.scoring import ScoringEngine
from src.hardening.manager import HardeningManager


def main():
    print("=" * 80)
    print("  SECUREAUDIT — AUTOMATED BEFORE/AFTER METRICS BENCHMARK EVALUATOR")
    print("  Author: Kartik Soni | SmartED Internship Minor Project")
    print("=" * 80 + "\n")

    baseline_mgr = BaselineManager("config/security_baseline.yaml")
    engine = AuditEngine(baseline_mgr)
    scoring = ScoringEngine(baseline_mgr)
    hardener = HardeningManager(baseline_mgr)

    # 1. Pre-Hardening Audit Benchmark
    print("[*] Running PRE-HARDENING Security Audit...")
    start_pre = time.perf_counter()
    pre_report = scoring.evaluate_report(engine.run_audit("all"))
    dur_pre = (time.perf_counter() - start_pre) * 1000  # ms

    # 2. Hardening Execution
    print("\n[*] Executing HARDENING Pipeline (Active Remediation)...")
    start_harden = time.perf_counter()
    actions, pre_rep, post_rep = hardener.execute_hardening(dry_run=False, auto_confirm=True)
    dur_harden = (time.perf_counter() - start_harden) * 1000  # ms

    # 3. Post-Hardening Simulated Audit
    print("\n[*] Processing POST-HARDENING Verification Metrics...")
    start_post = time.perf_counter()
    post_report = post_rep if post_rep else scoring.evaluate_report(engine.run_audit("all"))
    dur_post = (time.perf_counter() - start_post) * 1000  # ms

    # 4. Print Comparative Metrics Table
    print("\n" + "=" * 80)
    print("                     BEFORE vs. AFTER METRICS COMPARISON                    ")
    print("=" * 80)
    print(f" {'Metric / Evaluation Parameter':<35} | {'Pre-Hardening':<18} | {'Post-Hardening':<18}")
    print("-" * 80)
    print(f" {'Overall Security Score':<35} | {pre_report.overall_score:>5.1f} / 100        | {post_report.overall_score:>5.1f} / 100")
    print(f" {'Risk Assessment Level':<35} | {pre_report.risk_level.value:<18} | {post_report.risk_level.value:<18}")
    print(f" {'Total Baseline Checks Evaluated':<35} | {pre_report.summary['total']:<18} | {post_report.summary['total']:<18}")
    print(f" {'Passed Checks Count (PASS)':<35} | {pre_report.summary['passed']:<18} | {post_report.summary['passed']:<18}")
    print(f" {'Failed Checks Count (FAIL)':<35} | {pre_report.summary['failed']:<18} | {post_report.summary['failed']:<18}")
    print(f" {'Warning Checks Count (WARN)':<35} | {pre_report.summary['warnings']:<18} | {post_report.summary['warnings']:<18}")
    print(f" {'Critical Severity Violations':<35} | {pre_report.summary['critical']:<18} | {post_report.summary['critical']:<18}")
    print(f" {'High Severity Violations':<35} | {pre_report.summary['high']:<18} | {post_report.summary['high']:<18}")
    print(f" {'Audit Duration (ms)':<35} | {dur_pre:>7.2f} ms         | {dur_post:>7.2f} ms")
    print("=" * 80)

    print("\n[+] Benchmark evaluation complete. All findings recorded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
