You are acting as a senior cybersecurity engineer, Python developer, Linux administrator, technical writer, and project mentor.

I am completing a Minor Project for my SmartED internship.

I want to build a REAL, WORKING cybersecurity project rather than a theoretical/demo-only project.

PROJECT TITLE:

"Linux Security Hardening and Automated Security Audit Toolkit"

PROJECT OBJECTIVE:

Develop a Linux security auditing and hardening toolkit that evaluates a Linux system against a configurable security baseline, identifies security weaknesses, assigns risk/severity, generates a detailed security report, and provides an optional controlled hardening mode to remediate selected configuration issues.

The project must be suitable for a student cybersecurity internship minor project and should demonstrate practical Linux administration, cybersecurity, scripting, automation, security auditing, risk assessment, testing, documentation, and secure software development.

IMPORTANT:

Do not create a toy project.

Do not create one enormous script.

Do not hardcode everything.

Use modular architecture, proper error handling, logging, configuration files, reusable functions, testing, documentation, and security-conscious implementation.

The project must actually run on a Linux virtual machine.

PREFERRED TECHNOLOGY STACK:

* Python 3
* Bash
* Linux
* Ubuntu or Debian as the primary audited/test operating system
* Kali Linux as the security testing/auditing environment where appropriate
* YAML or JSON for configurable security baselines
* HTML for the generated security report
* JSON for machine-readable audit results
* Git for version control
* pytest for testing

Do not introduce unnecessary frameworks.

==================================================

1. PROJECT SCOPE
   ==================================================

The toolkit should contain the following modules:

1. System Information Audit
2. User and Privilege Audit
3. Network Security Audit
4. Open Port Audit
5. Service Audit
6. Filesystem Permission Audit
7. SSH Security Audit
8. Firewall Audit
9. Patch/Update Audit
10. Logging and Authentication Audit
11. Security Baseline Evaluation
12. Risk/Severity Calculation
13. Security Score Calculation
14. Report Generation
15. Optional Hardening
16. Test Suite
17. CLI interface

==================================================
2. SYSTEM INFORMATION MODULE
============================

Collect and display:

* Hostname
* Operating system
* OS version
* Kernel version
* Architecture
* CPU information
* Memory information
* Disk usage
* Network interfaces
* IP addresses
* Default route

Do not expose sensitive information unnecessarily.

==================================================
3. USER AND PRIVILEGE AUDIT
===========================

Check:

* Local users
* UID 0 accounts
* Sudo-enabled users
* Login shells
* Locked accounts
* Accounts with potentially weak configuration
* Password policy where technically available
* Root account status
* Last login information where available

Findings should have:

* Check ID
* Description
* Status
* Severity
* Evidence
* Recommendation

Use the principle of least privilege.

==================================================
4. NETWORK SECURITY AUDIT
=========================

Check:

* Active network interfaces
* IP configuration
* Default gateway
* Listening TCP ports
* Listening UDP ports
* Firewall status
* SSH exposure
* Suspicious/unexpected listening services

Use safe local enumeration.

Do not perform unauthorized scanning of external systems.

==================================================
5. SERVICE AUDIT
================

Identify:

* Running services
* Enabled services
* Potentially unnecessary services

Do NOT automatically disable services in audit mode.

For hardening mode, only modify explicitly supported services and require confirmation before making changes.

==================================================
6. FILESYSTEM SECURITY
======================

Check important system files and directories.

Examples:

* /etc/passwd
* /etc/shadow
* /etc/group
* SSH configuration
* Sensitive configuration files
* World-writable files/directories
* SUID files
* SGID files
* Critical file permissions

Avoid expensive full-disk scans by default.

Allow configurable scan paths.

==================================================
7. SSH SECURITY AUDIT
=====================

Inspect SSH configuration and identify insecure settings such as:

* Root login enabled
* Password authentication enabled
* Empty passwords
* Weak/insecure configuration
* Unnecessary SSH exposure

Do not blindly overwrite sshd_config.

Create safe backups before any hardening modification.

Validate configuration before restarting SSH.

==================================================
8. FIREWALL AUDIT
=================

Detect available firewall technologies.

Support at minimum:

* UFW where available

Optionally detect:

* nftables
* iptables

Report:

* Whether firewall is active
* Current relevant rules
* Potentially exposed services

Hardening must avoid locking the user out of SSH.

Never blindly flush firewall rules.

==================================================
9. PATCH MANAGEMENT
===================

Determine:

* Whether package updates are available
* Package manager in use
* Relevant security updates where detectable
* Kernel version

Do not automatically upgrade packages during normal audit mode.

==================================================
10. LOGGING AND AUTHENTICATION AUDIT
====================================

Check available logs for:

* Failed login attempts
* SSH authentication events
* Authentication failures
* Relevant security events

Handle different Linux distributions gracefully.

Do not assume one exact log file exists.

==================================================
11. SECURITY BASELINE
=====================

Create a configurable file:

config/security_baseline.yaml

It should contain security checks and thresholds.

Example conceptual structure:

checks:
ssh_root_login:
enabled: true
severity: high

firewall:
enabled: true
severity: high

world_writable:
enabled: true
severity: medium

Make the baseline extensible.

==================================================
12. RISK SEVERITY
=================

Implement severity levels:

* INFO
* LOW
* MEDIUM
* HIGH
* CRITICAL

Each finding should contain:

* ID
* Category
* Severity
* Status
* Description
* Evidence
* Recommendation

Explain the scoring methodology in the documentation.

==================================================
13. SECURITY SCORE
==================

Create a deterministic scoring system.

Generate:

* Overall score out of 100
* Category scores
* Number of passed checks
* Number of failed checks
* Number of warnings
* Risk level

Example:

Overall Score: 82/100

Risk Level: MEDIUM

Categories:

System Configuration
User Security
Network Security
Filesystem Security
SSH Security
Patch Management
Logging

The exact scoring algorithm must be documented and implemented consistently.

==================================================
14. REPORT GENERATION
=====================

Generate at least:

reports/report.json
reports/report.html
reports/report.txt

The HTML report should contain:

* Project/tool information
* Scan timestamp
* Host information
* Overall security score
* Risk level
* Category scores
* Passed checks
* Failed checks
* Findings
* Severity
* Evidence
* Recommendations

Make the HTML professional and suitable for screenshots in an internship report.

==================================================
15. HARDENING MODE
==================

Implement two distinct modes:

AUDIT:

./secureaudit.py audit

and:

HARDEN:

./secureaudit.py harden

Audit mode must be read-only.

Hardening mode must:

1. Clearly display proposed changes.
2. Ask for confirmation.
3. Create backups before modification.
4. Validate configuration.
5. Apply only supported changes.
6. Log every modification.
7. Provide rollback information.
8. Avoid destructive actions.
9. Avoid breaking network connectivity.
10. Never disable SSH access blindly.

Include a --dry-run option.

Example:

./secureaudit.py harden --dry-run

==================================================
16. CLI DESIGN
==============

Design a professional CLI.

Examples:

secureaudit system-info
secureaudit audit
secureaudit audit --category network
secureaudit audit --category ssh
secureaudit report
secureaudit harden --dry-run
secureaudit harden
secureaudit score
secureaudit version

Provide:

--help
--verbose
--quiet
--output
--config

Use proper exit codes.

==================================================
17. LOGGING
===========

Implement application logging.

Log:

* Scan start/end
* Checks performed
* Errors
* Hardening actions
* Rollbacks
* Report generation

Do not log passwords, secrets, private keys, or sensitive credentials.

==================================================
18. SECURITY REQUIREMENTS
=========================

Follow secure development practices.

Requirements:

* Input validation
* Avoid shell injection
* Prefer subprocess argument arrays instead of shell=True
* Least privilege
* No hardcoded passwords
* No hardcoded secrets
* Safe file handling
* Permission checks
* Root privilege detection
* Graceful error handling
* Backups before configuration changes
* Configuration validation
* Safe subprocess execution
* Clear distinction between audit and modification modes

Explain why each important security decision was made.

==================================================
19. PROJECT STRUCTURE
=====================

Use a structure similar to:

linux-security-toolkit/

README.md
LICENSE
requirements.txt

src/
main.py
system_info.py
user_audit.py
network_audit.py
service_audit.py
filesystem_audit.py
ssh_audit.py
firewall_audit.py
patch_audit.py
logging_audit.py
scoring.py
hardening.py
reporter.py
utils.py

scripts/
install.sh
audit.sh
harden.sh

config/
security_baseline.yaml

reports/

tests/
test_scoring.py
test_parsers.py
test_checks.py

docs/
methodology.md
security-policy.md

screenshots/

==================================================
20. TEST ENVIRONMENT
====================

Create a safe isolated laboratory.

Recommended:

VM 1:
Ubuntu/Debian test system

VM 2:
Kali Linux security testing environment

Use host-only/internal networking where appropriate.

Do not attack real external systems.

The project should demonstrate:

BEFORE HARDENING
↓
AUDIT
↓
FINDINGS
↓
HARDENING
↓
AUDIT AGAIN
↓
BEFORE/AFTER COMPARISON

==================================================
21. INTENTIONALLY VULNERABLE TEST CONFIGURATION
===============================================

Provide a controlled method for creating test conditions inside the lab.

Examples:

* Firewall disabled
* SSH insecure configuration
* Unnecessary test service enabled
* Weak file permissions

Do not introduce dangerous malware, persistence, destructive payloads, credential theft, or real-world attack infrastructure.

Every weakness must be reversible.

==================================================
22. TESTING
===========

Create automated tests for:

* Scoring
* Severity calculation
* Configuration parsing
* Output generation
* Finding generation
* Error handling

Also provide manual validation commands.

Test:

1. Clean system
2. Vulnerable test configuration
3. Hardened system
4. Invalid configuration
5. Missing dependencies
6. Permission errors
7. Unsupported Linux environment

==================================================
23. BEFORE/AFTER RESULTS
========================

The project must generate measurable results.

Create a comparison such as:

## Metric                  Before       After

Security Score          47           88
Critical Findings       1            0
High Findings           4            1
Medium Findings         6            3
Firewall                OFF          ON
Root SSH Login          ON           OFF
Updates                 Pending      Updated
Weak Permissions        Found        Fixed

Do not fabricate these numbers.

They must come from actual execution of the toolkit.

==================================================
24. GRAPHS
==========

Generate useful graphs from actual project output.

Recommended:

1. Security score before vs after
2. Findings by severity
3. Findings by category
4. Category security scores

Use Python/matplotlib if needed.

Graphs must be generated from actual JSON report data.

==================================================
25. DOCUMENTATION
=================

Create:

README.md

Include:

* Project overview
* Features
* Architecture
* Requirements
* Installation
* Usage
* CLI examples
* Configuration
* Security considerations
* Testing
* Limitations
* Future improvements

Also create:

docs/methodology.md

Explain:

* Threat model
* Audit methodology
* Security baseline
* Risk classification
* Scoring
* Testing methodology

Also create:

docs/security-policy.md

Create a basic organizational Linux security policy covering:

* Access control
* Password management
* Patch management
* Firewall
* Logging
* Incident response
* Backups
* Acceptable use
* Security audits

==================================================
26. MINOR PROJECT REPORT
========================

Create the complete content for a professional PDF report.

The report must contain:

1. Cover Page
2. Certificate/Declaration placeholders
3. Acknowledgement
4. Abstract
5. Table of Contents
6. Introduction
7. Problem Statement
8. Motivation
9. Objectives
10. Scope
11. Existing System
12. Proposed System
13. Requirements
14. Hardware Requirements
15. Software Requirements
16. Technologies Used
17. System Architecture
18. Workflow
19. Methodology
20. Threat Model
21. Security Baseline
22. Module Design
23. Implementation
24. Important Code Explanations
25. Testing Methodology
26. Test Cases
27. Results
28. Before/After Security Comparison
29. Screenshots
30. Graphs
31. Security Analysis
32. Limitations
33. Future Enhancements
34. Conclusion
35. References

The report should sound like a genuine student internship project report, not an AI-generated generic essay.

==================================================
27. SCREENSHOT PLAN
===================

Tell me exactly which screenshots I need to capture.

For every screenshot specify:

* What command/application to open
* Exact command to run
* What should be visible
* What the screenshot demonstrates
* Where it should be placed in the report
* Suggested figure caption

Never fabricate screenshots.

==================================================
28. PRESENTATION
================

After completing the project, create a presentation outline of approximately 10-15 slides:

1. Title
2. Problem
3. Motivation
4. Objectives
5. Proposed Solution
6. Architecture
7. Technologies
8. Security Checks
9. Hardening
10. Before/After Results
11. Testing
12. Screenshots
13. Limitations
14. Future Scope
15. Conclusion

Include speaker notes for every slide.

==================================================
29. GIT
=======

Provide:

.gitignore

Recommended commit structure:

1. Initial project setup
2. System information module
3. User audit
4. Network audit
5. Filesystem audit
6. SSH audit
7. Firewall audit
8. Patch audit
9. Scoring
10. Reporting
11. Hardening
12. Testing
13. Documentation
14. Final release

==================================================
30. DEVELOPMENT PROCESS
=======================

DO NOT generate the entire project blindly in one step.

Work phase-by-phase.

First provide:

A. Final project specification
B. Architecture
C. Directory structure
D. Threat model
E. Security baseline
F. Development roadmap
G. Dependencies
H. Test environment setup
I. Expected final deliverables

Then implement the project module-by-module.

For every module:

1. Explain its purpose.
2. Provide complete production-quality code.
3. Explain important implementation decisions.
4. Provide commands to run it.
5. Provide test cases.
6. Identify expected output.
7. Identify security considerations.
8. Update README/documentation where necessary.

Do not leave placeholder functions such as:

pass
TODO
implement this later

unless they are explicitly identified as future optional functionality.

All core functionality must be implemented.

==================================================
31. QUALITY REQUIREMENTS
========================

The finished project must be:

* Functional
* Modular
* Testable
* Documented
* Secure by design
* Reproducible
* Suitable for a cybersecurity internship
* Suitable for a university minor project
* Demonstrable in a Linux VM
* Capable of generating actual measurable results

Avoid unnecessary complexity.

Prefer reliable Linux-native mechanisms over external services.

Do not require cloud APIs.

Do not require paid services.

==================================================
32. FINAL DELIVERABLE
=====================

The final project should be structured so that I can submit:

Linux-Security-Hardening-Kartik-Soni.zip

containing:

linux-security-toolkit/
source code
scripts
configuration
tests
documentation
screenshots
reports

and:

Linux-Security-Hardening-Kartik-Soni-Report.pdf

The report must document the actual implementation and actual test results.

==================================================
START
=====

Begin with Phase 1 only.

Do NOT generate the full source code yet.

Start by giving me:

1. Final project specification
2. Architecture
3. Complete directory structure
4. Threat model
5. Security baseline
6. Development roadmap
7. Hardware/software requirements
8. Test-lab topology
9. Expected final functionality
10. Complete list of final deliverables

After that, wait for me to proceed to Phase 2.
