"""
HTML Executive Report Generator Module.
Author: Kartik Soni

Generates a single-file, self-contained HTML dashboard with responsive CSS visual scorecard,
category progress bars, severity badges, and structured security findings.
"""

import html
from pathlib import Path
from typing import Union

from src.core.logger import AuditLogger
from src.core.models import AuditReport, RiskLevel, Severity, Status
from src.core.utils import safe_write_file

logger = AuditLogger.get_logger()


class HtmlReporter:
    """Generates executive HTML security audit reports."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate_html_content(self) -> str:
        """Constructs complete HTML document string with inline CSS."""
        rep = self.report
        meta = rep.system_meta
        s = rep.summary
        score = rep.overall_score
        risk = html.escape(str(rep.risk_level.value))

        # Score card color
        if score >= 85.0:
            score_color = "#10b981"  # Emerald Green
            risk_badge_bg = "#d1fae5"
            risk_badge_fg = "#065f46"
        elif score >= 70.0:
            score_color = "#f59e0b"  # Amber Yellow
            risk_badge_bg = "#fef3c7"
            risk_badge_fg = "#92400e"
        elif score >= 50.0:
            score_color = "#f97316"  # Orange
            risk_badge_bg = "#ffedd5"
            risk_badge_fg = "#9a3412"
        else:
            score_color = "#ef4444"  # Red
            risk_badge_bg = "#fee2e2"
            risk_badge_fg = "#991b1b"

        # Category Progress Rows
        cat_rows_html = ""
        for cat_id, cat_score in rep.category_scores.items():
            c_score = cat_score.score
            c_bar_color = "#10b981" if c_score >= 85 else ("#f59e0b" if c_score >= 70 else "#ef4444")
            cat_name_safe = html.escape(str(cat_score.category_name))
            cat_rows_html += f"""
            <tr>
                <td style="font-weight: 600;">{cat_name_safe}</td>
                <td><span class="pill">{cat_score.weight}%</span></td>
                <td>{cat_score.passed_checks} / {cat_score.total_checks}</td>
                <td><span style="color: #ef4444; font-weight: 600;">{cat_score.failed_checks}</span></td>
                <td style="width: 35%;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" style="width: {c_score}%; background-color: {c_bar_color};"></div>
                        </div>
                        <span style="font-weight: 700; font-size: 0.9rem; min-width: 45px;">{c_score}%</span>
                    </div>
                </td>
            </tr>
            """

        # Findings Rows
        findings_rows_html = ""
        for f in rep.findings:
            # Status Badge
            if f.status == Status.PASS:
                st_bg, st_fg = "#d1fae5", "#065f46"
            elif f.status == Status.FAIL:
                st_bg, st_fg = "#fee2e2", "#991b1b"
            elif f.status == Status.WARN:
                st_bg, st_fg = "#fef3c7", "#92400e"
            else:
                st_bg, st_fg = "#f3f4f6", "#374151"

            # Severity Badge
            if f.severity == Severity.CRITICAL:
                sev_bg, sev_fg = "#7f1d1d", "#ffffff"
            elif f.severity == Severity.HIGH:
                sev_bg, sev_fg = "#991b1b", "#ffffff"
            elif f.severity == Severity.MEDIUM:
                sev_bg, sev_fg = "#92400e", "#ffffff"
            elif f.severity == Severity.LOW:
                sev_bg, sev_fg = "#1e3a8a", "#ffffff"
            else:
                sev_bg, sev_fg = "#374151", "#ffffff"

            rec_safe = html.escape(str(f.recommendation))
            title_safe = html.escape(str(f.title))
            evidence_safe = html.escape(str(f.evidence))
            check_id_safe = html.escape(str(f.check_id))

            fix_html = f"<div class='remediation-text'><strong>Fix:</strong> {rec_safe}</div>" if f.status != Status.PASS else ""

            findings_rows_html += f"""
            <tr>
                <td><span class="badge" style="background-color: {st_bg}; color: {st_fg};">{html.escape(f.status.value)}</span></td>
                <td><span class="badge" style="background-color: {sev_bg}; color: {sev_fg};">{html.escape(f.severity.value)}</span></td>
                <td style="font-weight: 700; font-family: monospace;">{check_id_safe}</td>
                <td>
                    <div style="font-weight: 600; margin-bottom: 4px;">{title_safe}</div>
                    <div class="evidence-text"><strong>Evidence:</strong> {evidence_safe}</div>
                    {fix_html}
                </td>
            </tr>
            """

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Security Audit Report - Kartik Soni</title>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #0f172a;
            --border-color: #e2e8f0;
            --primary: #2563eb;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: #ffffff;
            padding: 24px 32px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        header h1 {{
            margin: 0 0 8px 0;
            font-size: 1.8rem;
            font-weight: 700;
        }}
        header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 0.95rem;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .grid-4 {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border-color);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }}
        .score-card {{
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .score-circle {{
            font-size: 3.5rem;
            font-weight: 800;
            color: {score_color};
            line-height: 1;
            margin: 12px 0;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 700;
            background-color: {risk_badge_bg};
            color: {risk_badge_fg};
            text-transform: uppercase;
        }}
        .stat-card {{
            text-align: center;
            padding: 16px;
        }}
        .stat-num {{
            font-size: 1.8rem;
            font-weight: 700;
            margin-top: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }}
        th {{
            background-color: #f1f5f9;
            font-weight: 700;
            color: #475569;
        }}
        .progress-bar-bg {{
            flex: 1;
            height: 10px;
            background-color: #e2e8f0;
            border-radius: 5px;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            height: 100%;
            border-radius: 5px;
            transition: width 0.3s ease;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-align: center;
        }}
        .pill {{
            background-color: #e2e8f0;
            color: #334155;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
        }}
        .evidence-text {{
            color: #475569;
            font-size: 0.85rem;
            margin-top: 2px;
        }}
        .remediation-text {{
            color: #991b1b;
            background-color: #fee2e2;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 0.85rem;
            margin-top: 6px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Linux Security Audit & Baseline Report</h1>
            <p>SmartED Internship Minor Project &bull; Candidate: Kartik Soni &bull; Scan Timestamp: {rep.timestamp}</p>
        </header>

        <div class="grid-2">
            <div class="card score-card">
                <div style="font-size: 0.9rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Overall Security Score</div>
                <div class="score-circle">{score} <span style="font-size: 1.5rem; color: #94a3b8;">/ 100</span></div>
                <div class="risk-badge">Risk Level: {risk}</div>
            </div>

            <div class="card">
                <h3 style="margin-top: 0;">Target System Information</h3>
                <table style="margin-top: 0;">
                    <tr><td><strong>Hostname:</strong></td><td>{html.escape(str(meta.hostname))}</td><td><strong>OS Release:</strong></td><td>{html.escape(str(meta.os_name))} {html.escape(str(meta.os_version))}</td></tr>
                    <tr><td><strong>Kernel:</strong></td><td>{html.escape(str(meta.kernel_version))}</td><td><strong>Architecture:</strong></td><td>{html.escape(str(meta.architecture))}</td></tr>
                    <tr><td><strong>CPU:</strong></td><td>{html.escape(str(meta.cpu_info))}</td><td><strong>Memory (RAM):</strong></td><td>{meta.memory_total_mb} MB ({meta.memory_free_mb} MB free)</td></tr>
                </table>
            </div>
        </div>

        <div class="grid-4">
            <div class="card stat-card">
                <div style="color: #64748b; font-size: 0.85rem;">Total Checks</div>
                <div class="stat-num">{s['total']}</div>
            </div>
            <div class="card stat-card" style="border-left: 4px solid #10b981;">
                <div style="color: #065f46; font-size: 0.85rem;">Passed</div>
                <div class="stat-num" style="color: #10b981;">{s['passed']}</div>
            </div>
            <div class="card stat-card" style="border-left: 4px solid #ef4444;">
                <div style="color: #991b1b; font-size: 0.85rem;">Failed</div>
                <div class="stat-num" style="color: #ef4444;">{s['failed']}</div>
            </div>
            <div class="card stat-card" style="border-left: 4px solid #f59e0b;">
                <div style="color: #92400e; font-size: 0.85rem;">Warnings / Skips</div>
                <div class="stat-num" style="color: #f59e0b;">{s['warnings']}</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 24px;">
            <h3 style="margin-top: 0;">Category Compliance Scorecard</h3>
            <table>
                <thead>
                    <tr>
                        <th>Category Name</th>
                        <th>Baseline Weight</th>
                        <th>Passed / Total</th>
                        <th>Failed</th>
                        <th>Compliance Score</th>
                    </tr>
                </thead>
                <tbody>
                    {cat_rows_html}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3 style="margin-top: 0;">Detailed Security Audit Findings</h3>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Check ID</th>
                        <th>Finding & Evidence Details</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows_html}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        return html_doc

    def export_to_file(self, output_path: Union[str, Path] = "reports/report.html") -> bool:
        """Writes the single-file HTML report to disk."""
        target_path = Path(output_path)
        content = self.generate_html_content()
        success = safe_write_file(target_path, content, mode=0o644)
        if success:
            logger.info(f"Successfully generated HTML audit report: '{target_path.resolve()}'")
        else:
            logger.error(f"Failed to export HTML report to '{output_path}'")
        return success
