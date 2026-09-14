# Phase 4: Scoring Engine & Multi-Format Reporters

**Project Title:** Linux Security Hardening and Automated Security Audit Toolkit (`secureaudit`)  
**Author:** Kartik Soni  
**Context:** SmartED Cybersecurity Internship Minor Project  

---

## 1. Overview of Phase 4 Components

Phase 4 implemented the deterministic security scoring engine and multi-format report generators (HTML, JSON, Console text):

```text
src/
├── core/
│   └── scoring.py                 # Deterministic scoring engine
└── reporters/
    ├── __init__.py
    ├── json_reporter.py           # Machine-readable JSON exporter
    ├── html_reporter.py           # Executive HTML dashboard with CSS scorecard
    └── console_reporter.py        # Terminal formatting and plain text report exporter
```

---

## 2. Component Design & Implementation Details

### 2.1 Deterministic Scoring Engine (`src/core/scoring.py`)
Calculates an overall security posture score out of 100 and category compliance scores based on finding severity deductions:

$$\text{Overall Score} = \max\left(0, 100 - \sum \text{Deduction}(\text{Severity})\right)$$

* **Severity Penalty Points:**
  * `CRITICAL`: -15 points penalty
  * `HIGH`: -10 points penalty
  * `MEDIUM`: -5 points penalty
  * `LOW`: -2 points penalty
  * `INFO`: 0 points penalty
* **Risk Classification:**
  * Score >= 85.0: `LOW` Risk
  * Score 70.0 – 84.9: `MEDIUM` Risk
  * Score 50.0 – 69.9: `HIGH` Risk
  * Score < 50.0: `CRITICAL` Risk

### 2.2 JSON Report Generator (`src/reporters/json_reporter.py`)
Exports complete audit report objects to machine-readable JSON files (`reports/report.json`). Contains tool metadata, scan timestamps, system metadata, overall score, risk level, summary dictionary, category compliance scores, and array of findings.

### 2.3 Executive HTML Report Generator (`src/reporters/html_reporter.py`)
Constructs a single-file, self-contained HTML document (`reports/report.html`) featuring:
* Executive scorecard card (large 0–100 score badge and color-coded risk pill badge).
* Key statistics grid (Total Checks, Passed, Failed, Warnings).
* Category compliance progress bars (visual percentage bars).
* System Information specifications table.
* Filterable findings table with status tags (`[PASS]`, `[FAIL]`, `[WARN]`, `[SKIP]`), severity badges, check IDs, title, evidence, and remediation advice.
* Self-contained styling (zero external CDN network requests for offline rendering).

### 2.4 Console & Text Report Generator (`src/reporters/console_reporter.py`)
Formats audit reports for high-contrast terminal display and plain text report exports (`reports/report.txt`).

---

## 3. Commands & Execution

```bash
# 1. Compute and display the security posture scorecard
python secureaudit.py score

# 2. Export multi-format audit reports (HTML, JSON, TXT)
python secureaudit.py report

# 3. Execute full audit with console findings and automatic report export
python secureaudit.py audit

# 4. Run full test suite (27 unit tests passing)
python -m pytest tests/ -v
```

---

## 4. Test Suite Verification

Phase 4 added 5 new test cases in `tests/test_scoring.py` and `tests/test_reporters.py`. All 27 unit tests pass:

```text
tests/test_reporters.py::test_json_reporter_export PASSED                [ 85%]
tests/test_reporters.py::test_html_reporter_export PASSED                [ 88%]
tests/test_reporters.py::test_console_reporter_export PASSED             [ 92%]
tests/test_scoring.py::test_scoring_engine_perfect_score PASSED          [ 96%]
tests/test_scoring.py::test_scoring_engine_penalty_deduction PASSED      [100%]

============================= 27 passed in 0.49s ==============================
```
