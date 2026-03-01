```
  ____                     _         ____
 / ___|  ___ ___  _ __ _ __(_) ___   |  _ \ _ __ ___
 \___ \ / __/ _ \| '__| '_ \| |/ _ \  | |_) | '__/ _ \
  ___) | (_| (_) | |  | |_) | | (_) | |  __/| | | (_) |
 |____/ \___\___/|_|  | .__/|_|\___/  |_|   |_|  \___/
                       |_|
         State-of-the-art Penetration Testing & Security Auditing
```

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%2011%20%7C%20Ubuntu%20%7C%20Debian-lightgrey)](https://github.com/jsdosanj/scorpio-pro)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/jsdosanj/scorpio-pro)

**🦂 Scorpio Pro** — Know your attack surface before the adversary does.

</div>

---

## Table of Contents

1. [About / Overview](#about--overview)
2. [Key Features](#key-features)
3. [Supported Compliance Frameworks](#supported-compliance-frameworks)
4. [Architecture](#architecture)
5. [How It Works](#how-it-works)
6. [Installation](#installation)
7. [Quick Start](#quick-start)
8. [CLI Reference](#cli-reference)
9. [Scope Configuration](#scope-configuration)
10. [Scanner Modules](#scanner-modules)
11. [Cloud Scanning](#cloud-scanning)
12. [Report Formats](#report-formats)
13. [The Finding Object](#the-finding-object)
14. [Compliance Scoring Methodology](#compliance-scoring-methodology)
15. [Building Distributable Packages](#building-distributable-packages)
16. [Development](#development)
17. [Security Considerations](#security-considerations)
18. [Legal Disclaimer](#legal-disclaimer)
19. [Roadmap](#roadmap)
20. [Contributing](#contributing)
21. [License](#license)
22. [Acknowledgments](#acknowledgments)

---

## About / Overview

**Scorpio Pro** is a proactive, automated, blue-team security auditing and penetration testing toolkit written in Python. It was built on a simple but powerful premise: **secure yourself before anyone else can attack you.**

Most organisations discover their vulnerabilities _after_ a breach. Scorpio Pro flips that paradigm. It gives security teams, IT administrators, and compliance officers a single, extensible tool to continuously map their attack surface, enumerate misconfigurations, validate compliance posture, and produce audit-ready reports — all without requiring multiple disparate tools, expensive licenses, or deep platform-specific expertise.

### Philosophy

> _"The best defence is a thorough offence — against yourself."_

Scorpio Pro is built around three principles:

| Principle | What it means in practice |
|---|---|
| **Comprehensive** | Every scanner covers the full breadth of its domain. No cherry-picking easy checks. |
| **Automated** | From scope import to report generation, every step is scripted and repeatable. |
| **Compliance-mapped** | Every finding is tagged to real regulatory control IDs so audit prep becomes a by-product of security work, not extra effort. |

### Who It Is For

- 🔴 **Penetration Testers** — rapid host enumeration, service fingerprinting, vulnerability surface mapping
- 🔵 **SOC Analysts** — baseline deviation detection, anomaly evidence collection
- 🏢 **CISOs & Security Managers** — executive-ready HTML reports with risk scoring and compliance scorecards
- 📋 **Compliance Officers** — HIPAA, FERPA, NIST CSF 2.0, NIST AI RMF 1.0, and GDPR gap analysis at the press of a button
- 🖥️ **IT Administrators** — configuration audit, patch status, firewall review, shared drive hygiene
- 🔬 **Security Researchers** — extensible plugin architecture for developing and sharing new scanner modules

---

## Key Features

### 🖥️ System Auditing
- Hostname, all IP addresses, MAC addresses, BIOS/UEFI firmware metadata
- Operating system patch and update status (Windows Update / apt / yum / brew)
- Local user account enumeration — privileged accounts, inactive accounts, accounts without passwords
- Host-based firewall status and rule inventory (Windows Firewall / iptables / nftables / pf)
- Disk encryption status (BitLocker / FileVault / LUKS / dm-crypt)
- AV/EDR product detection and status (Windows Defender, CrowdStrike, SentinelOne, Carbon Black, and others)

### 🌐 Network Scanning
- **nmap integration** with graceful fallback to pure-Python TCP connect scanning when nmap is unavailable
- DNS enumeration: forward/reverse lookups, zone transfer attempts, subdomain discovery
- Service fingerprinting and version detection
- OS detection (with nmap aggressive mode)
- ARP-based host discovery on local subnets

### 🔓 Vulnerability Assessment
- **NVD/CVE lookups** for detected service versions
- **SSL/TLS cipher analysis**: weak cipher identification (RC4, DES, 3DES, EXPORT), protocol version checks (SSLv2/3, TLS 1.0/1.1 deprecation), certificate expiry and chain validation
- **HTTP security header auditing**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Default credential testing** against common services with a built-in credential list

### 📡 Remote Access Analysis
- **SSH auditing** via paramiko: cipher suite analysis, KEX algorithms, MAC algorithms, `sshd_config` local analysis, host key types, PermitRootLogin / PasswordAuthentication flags
- **RDP security**: NLA enforcement check, BlueKeep (CVE-2019-0708) exposure detection, encryption level enumeration
- **VPN configuration auditing**: OpenVPN config file analysis, WireGuard peer review, IPSec/IKE policy inspection
- Local `sshd_config` static analysis for common misconfigurations

### ☁️ Cloud Security
- **AWS**: IAM password policy strength, S3 bucket ACLs and public access blocks, CloudTrail logging, Security Group egress/ingress rules, unused IAM access keys, MFA enforcement
- **Azure**: RBAC role assignments, storage account public access, Network Security Group rules, Key Vault access policies, Azure AD MFA status
- **GCP**: IAM primitive roles (Owner/Editor at project level), GCS bucket public access, VPC firewall rules, KMS key rotation, service account key age
- **Intelligent credential auto-discovery**: environment variables → config files → interactive prompt → graceful degradation without credentials

### 📦 Application Security
- Cross-platform application inventory:
  - **Linux**: `dpkg -l`, `rpm -qa`
  - **macOS**: `system_profiler SPApplicationsDataType`
  - **Windows**: Registry-based installed software enumeration
- **Web server configuration audits**: Apache (`httpd.conf`, `.htaccess`) and Nginx (`nginx.conf`) — directory listing, server tokens, TLS config, security headers
- **Database configuration audits**: MySQL (`my.cnf`, user privilege review, anonymous accounts) and PostgreSQL (`pg_hba.conf`, `postgresql.conf`, superuser accounts)
- Runtime version checks: Python, Node.js, Java, Ruby, PHP — EOL detection

### 📂 Shared Drive Auditing
- **SMB/CIFS**: null session enumeration, open share discovery, guest access testing, share permission review
- **NFS**: export enumeration via `showmount`, world-readable export detection, `no_root_squash` identification
- **AFP**: Apple Filing Protocol detection and deprecation warnings
- Local Windows share enumeration, Unix mount analysis, permission audits

### ✅ Multi-Framework Compliance
Full control-level assessment against five frameworks with 0–100 scoring:

| Framework | Standard | Controls |
|---|---|---|
| HIPAA | 45 CFR Part 164 | 11+ Security Rule controls |
| FERPA | 20 U.S.C. § 1232g | 7 controls |
| NIST CSF | Version 2.0 | Govern / Identify / Protect / Detect / Respond / Recover |
| NIST AI RMF | Version 1.0 | Govern / Map / Measure / Manage — 10 controls |
| GDPR | Regulation (EU) 2016/679 | Articles 5, 17, 25, 28, 30, 32, 33, 34, 35 |

### 📊 Multi-Format Reporting
- **HTML**: dark-themed dashboard with risk score visualisation, colour-coded severity breakdown, compliance scorecards, and expandable finding details
- **JSON**: machine-readable output, SIEM-integration ready, includes all finding metadata
- **TXT**: plain-text format suitable for terminal viewing, email, and archival
- Generate any combination: `html`, `json`, `txt`, or all three simultaneously

### 🎯 Scope Control
- YAML-based scope configuration — define exactly what is authorised to be tested
- Mandatory legal authorisation prompt before any scan executes
- Exportable scope files for consistent multi-device deployment
- Per-engagement metadata: name, authorising party, date, time windows
- Explicit exclusion lists to protect fragile or out-of-scope hosts

### 🛡️ Graceful Degradation
Every scanner module works — at reduced capability — even when optional tools (nmap, smbclient, showmount, cloud SDKs) are unavailable. Scorpio Pro _never_ crashes due to a missing optional dependency; it logs a warning and continues.

---

## Supported Compliance Frameworks

### HIPAA Security Rule (45 CFR Part 164)

The Health Insurance Portability and Accountability Act Security Rule mandates administrative, physical, and technical safeguards for electronic Protected Health Information (ePHI). Scorpio Pro maps findings to the following controls:

| Control ID | Control Name | What Scorpio Pro Checks |
|---|---|---|
| 164.308(a)(1) | Security Management Process | Risk analysis evidence, security policy artefacts |
| 164.308(a)(5) | Security Awareness and Training | User account hygiene, training artefact discovery |
| 164.312(a)(1) | Access Control | User privilege review, least-privilege enforcement |
| 164.312(a)(2)(i) | Unique User Identification | Shared/generic account detection |
| 164.312(a)(2)(iii) | Automatic Logoff | Session timeout configuration review |
| 164.312(a)(2)(iv) | Encryption and Decryption | Disk encryption, TLS cipher strength |
| 164.312(b) | Audit Controls | Audit log presence, SIEM integration evidence |
| 164.312(c)(1) | Integrity | File integrity monitoring detection |
| 164.312(d) | Person or Entity Authentication | MFA enforcement, password policy strength |
| 164.312(e)(1) | Transmission Security | TLS configuration, VPN usage |
| 164.314(a)(2)(i) | Business Associate Contracts | Third-party access controls |

---

### FERPA (20 U.S.C. § 1232g)

The Family Educational Rights and Privacy Act governs the privacy of student education records. Scorpio Pro evaluates the following controls for educational institutions:

| Control | Description | Assessment Method |
|---|---|---|
| Student Data Access Controls | Role-based access to student record systems | User privilege and group membership review |
| Authentication Strength | MFA and password complexity for systems holding student data | Password policy analysis, MFA detection |
| Data Sharing Controls | Third-party data access agreements and API security | Network service enumeration, TLS review |
| Access Logging | Comprehensive logging of access to student records | Audit log configuration review |
| Data Encryption | Encryption of student data at rest and in transit | Disk encryption status, TLS cipher analysis |
| Breach Notification Readiness | Incident response plan and contact list availability | Configuration and policy artefact discovery |
| Third-Party Vendor Agreements | Cloud and SaaS vendor security posture | Cloud configuration review |

---

### NIST Cybersecurity Framework 2.0

The NIST CSF 2.0 organises security activities across six functions. Scorpio Pro maps findings to specific subcategory controls:

**GV — Govern**
- `GV.OC-1`: Organisational mission and risk tolerance documented
- `GV.RM-1`: Risk management strategy established

**ID — Identify**
- `ID.AM-1`: Software and hardware asset inventory
- `ID.AM-2`: Software platforms and applications inventoried
- `ID.AM-3`: Organisational communication and data flows mapped
- `ID.RA-1`: Vulnerabilities in assets identified

**PR — Protect**
- `PR.AC-1`: Identities and credentials managed (access control)
- `PR.AC-3`: Remote access managed
- `PR.AC-5`: Network integrity protected (segregation, segmentation)
- `PR.AC-7`: Users, devices, and other assets authenticated
- `PR.DS-2`: Data in transit protected
- `PR.IP-12`: Vulnerability management plan in place

**DE — Detect**
- `DE.CM-1`: Network activity monitored for adverse events
- `DE.CM-7`: Monitoring performed for unauthorised personnel/connections

**RS — Respond**
- `RS.RP-1`: Response plan executed during or after an incident

**RC — Recover**
- `RC.RP-1`: Recovery plan executed during or after an incident

---

### NIST AI Risk Management Framework 1.0

The NIST AI RMF addresses the unique risks introduced by AI and ML systems. Scorpio Pro evaluates AI system security posture across all four functions:

| Control ID | Name | Scorpio Pro Assessment |
|---|---|---|
| GOV-1 | AI Governance Structure | AI policy artefact discovery, ownership documentation |
| GOV-2 | AI Risk Accountability | Role and responsibility assignment for AI systems |
| MAP-1 | AI Context Identification | AI/ML software inventory, runtime version checks |
| MAP-2 | AI Risk Identification | Model exposure surface, API endpoint discovery |
| MEASURE-1 | Model Security Assessment | Model file permissions, encryption at rest |
| MEASURE-2 | Data Pipeline Integrity | Input validation, data store security review |
| MEASURE-3 | Bias and Fairness Testing | Testing framework discovery, audit log evidence |
| MANAGE-1 | AI Risk Treatment | Patch and update status for AI frameworks |
| MANAGE-2 | AI System Monitoring | Logging configuration for AI inference endpoints |
| MANAGE-3 | AI Incident Response | IR plan artefacts, runbook discovery |

---

### GDPR (Regulation (EU) 2016/679)

The General Data Protection Regulation imposes strict requirements on organisations processing EU personal data. Scorpio Pro assesses compliance with the following articles:

| Article | Requirement | Technical Controls Assessed |
|---|---|---|
| Art. 5 | Data Minimisation & Purpose Limitation | Data store enumeration, retention policy evidence |
| Art. 17 | Right to Erasure | Data deletion capability, log purging configuration |
| Art. 25 | Data Protection by Design and by Default | Encryption defaults, access control defaults |
| Art. 28 | Data Processing Agreements | Third-party cloud and service review |
| Art. 30 | Records of Processing Activities | Audit log completeness, data flow documentation |
| Art. 32 | Security of Processing | TLS strength, encryption at rest, access control |
| Art. 33 | Personal Data Breach Notification | IR capability, logging infrastructure |
| Art. 34 | Communication to Data Subjects | Notification mechanism discovery |
| Art. 35 | Data Protection Impact Assessment | DPIA artefact discovery, high-risk processing evidence |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        scorpio-pro CLI                          │
│          (Click-based: scan | scope commands)                   │
└────────────────────────────┬────────────────────────────────────┘
                             │  ScopeConfig (YAML)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       ScanEngine                                │
│    Orchestrates scanner discovery, execution, and reporting     │
│                                                                 │
│  PluginManager ──► discovers & loads scanner modules            │
└──────────┬──────────────────────────────────────────────────────┘
           │  scope object passed to each scanner
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Scanner Modules                              │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │SystemScanner│  │NetworkScanner│  │   VulnScanner        │   │
│  └─────────────┘  └──────────────┘  └──────────────────────┘   │
│  ┌──────────────────┐  ┌────────────┐  ┌──────────────────┐    │
│  │RemoteAccessScanner│  │CloudScanner│  │   AppScanner     │    │
│  └──────────────────┘  └────────────┘  └──────────────────┘    │
│                  ┌──────────────────────┐                       │
│                  │  SharedDriveScanner  │                       │
│                  └──────────────────────┘                       │
│                                                                  │
│  Each scanner returns: list[Finding]                             │
└──────────────────────────┬───────────────────────────────────────┘
                           │  aggregated findings
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   ComplianceEngine                               │
│                                                                  │
│  HIPAA ── FERPA ── NIST CSF ── NIST AI RMF ── GDPR             │
│                                                                  │
│  Evaluates each finding's compliance_tags against framework      │
│  control definitions → produces per-framework scorecards        │
└──────────────────────────┬───────────────────────────────────────┘
                           │  findings + scorecards
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   ReportGenerator                                │
│                                                                  │
│   HTML formatter  ──►  report.html  (dark-themed dashboard)     │
│   JSON formatter  ──►  report.json  (SIEM-ready)                │
│   TXT  formatter  ──►  report.txt   (plain text / archival)     │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
scope.yaml
    │
    ├─► ScopeConfig (validates IPs, CIDRs, exclusions, intensity)
    │
    ├─► AuthorizationPrompt ("YES I CONFIRM")
    │
    ├─► ScanEngine.run()
    │       ├─► PluginManager.discover_scanners()
    │       ├─► for each scanner:
    │       │       ├─► scanner.check_prerequisites()
    │       │       └─► scanner.run(scope) → [Finding, ...]
    │       └─► ComplianceEngine.evaluate(all_findings)
    │               └─► {framework: {score, control_results}}
    │
    └─► ReportGenerator.generate(findings, compliance, formats)
            └─► [report.html, report.json, report.txt]
```

---

## How It Works

### Step 1 — Create or Import a Scope Configuration

Before any scan runs, you define the engagement scope in a YAML file. This file specifies exactly which IPs, CIDR ranges, ports, services, applications, and cloud accounts are **authorised** to be tested.

```bash
scorpio-pro scope --create           # interactive wizard
# or
scorpio-pro scope --import example_scope.yaml --validate
```

### Step 2 — Mandatory Legal Authorisation

Every scan begins with a mandatory legal disclaimer and an explicit confirmation prompt. You must type `YES I CONFIRM` to proceed. This safeguard cannot be removed — it can only be bypassed with `--yes` for CI pipelines where written authorisation is documented externally.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              SCORPIO PRO — PENETRATION TESTING TOOL                        ║
║                     LEGAL DISCLAIMER & AUTHORISATION                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is intended EXCLUSIVELY for use on systems and networks that     ║
║  you OWN or have EXPLICIT, WRITTEN AUTHORISATION to test.                   ║
...
Do you confirm you are authorised to perform this scan? Type 'YES I CONFIRM' to proceed:
```

### Step 3 — Scanner Discovery

The `ScanEngine` uses `PluginManager` to automatically discover all available scanner modules. Scanners are discovered dynamically — adding a new scanner module to `scorpio_pro/scanners/` makes it available automatically.

### Step 4 — Prerequisite Checks

Before each scanner executes, `check_prerequisites()` is called. If a required external tool is missing (e.g., nmap is not installed), the scanner:
1. Logs a `WARNING` with the missing dependency name
2. Falls back to reduced-capability mode (e.g., pure TCP connect scan instead of nmap)
3. Or gracefully skips specific tests while completing the rest

**No scanner ever crashes the entire scan** due to a missing optional dependency.

### Step 5 — Parallel Scanner Execution

Each scanner runs against the scope and produces a list of `Finding` objects. Every finding contains:

| Field | Description |
|---|---|
| `title` | Short, searchable description of what was found |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Informational` |
| `description` | Detailed explanation of the issue |
| `evidence` | Raw output, command results, or data proving the finding |
| `remediation` | Specific, actionable steps to resolve the issue |
| `test_run` | Identifier of the specific test that produced this finding |
| `rationale` | Why this test matters from a security perspective |
| `methodology` | How the test was conducted (for audit trail) |
| `status` | `pass` / `fail` / `warning` |
| `compliance_tags` | List of framework control IDs (e.g., `["HIPAA-164.312(a)(2)(iv)", "GDPR-Art32"]`) |
| `metadata` | Arbitrary key-value pairs for scanner-specific supplementary data |

### Step 6 — Compliance Evaluation

The `ComplianceEngine` iterates over all five frameworks. Each framework's `evaluate()` method examines the aggregated findings and maps them to control definitions. For each control:
- **pass**: a finding with `status=pass` and a matching compliance tag exists
- **fail**: a finding with `status=fail` and a matching compliance tag exists
- **warning**: a finding with `status=warning` exists for the control
- **not_tested**: no findings mapped to this control (scanner may not have run or check not applicable)

A 0–100 score is computed per framework (see [Compliance Scoring Methodology](#compliance-scoring-methodology)).

### Step 7 — Report Generation

The `ReportGenerator` produces output in every requested format:
- **HTML**: Full dark-themed dashboard with risk score gauges, severity breakdown charts, per-framework compliance scorecards, and expandable finding details with evidence and remediation steps.
- **JSON**: Structured, machine-readable output suitable for ingestion into SIEMs, vulnerability management platforms, or custom pipelines.
- **TXT**: Clean plain-text report for terminal review and archival.

---

## Installation

### Prerequisites

| Dependency | Required | Purpose |
|---|---|---|
| Python 3.11+ | ✅ Required | Core runtime |
| pip | ✅ Required | Package installation |
| nmap | ⚡ Recommended | Full network scanning (fallback available) |
| smbclient | 🔵 Optional | SMB share enumeration |
| showmount | 🔵 Optional | NFS export enumeration |

---

### From Source (All Platforms)

```bash
git clone https://github.com/jsdosanj/scorpio-pro.git
cd scorpio-pro
pip install -e .
```

---

### From PyPI

```bash
pip install scorpio-pro
```

---

### Platform-Specific Prerequisites

**macOS**
```bash
brew install nmap
# Optional SMB tools (usually pre-installed):
# smbutil is available in macOS by default
```

**Ubuntu / Debian**
```bash
sudo apt update
sudo apt install nmap smbclient nfs-common
```

**Windows**
1. Download nmap from [https://nmap.org/download.html](https://nmap.org/download.html)
2. Run the installer and check "Add nmap to PATH"
3. Verify: `nmap --version` in a new terminal

---

### Optional Extras

**With scapy (advanced packet-level network analysis):**
```bash
pip install scorpio-pro[scapy]
```

**With all development dependencies:**
```bash
pip install scorpio-pro[dev]
```

**All extras at once:**
```bash
pip install scorpio-pro[scapy,dev]
```

---

### Verify Installation

```bash
scorpio-pro --version
# Output: scorpio-pro, version 1.0.0

scorpio-pro --help
```

---

## Quick Start

Get your first security scan running in under five minutes.

**Step 1: Install**
```bash
pip install scorpio-pro
```

**Step 2: Create a scope file**
```bash
scorpio-pro scope --create
```
Follow the interactive prompts to define your engagement name, in-scope IPs, and intensity level. A `scope.yaml` file will be created in the current directory.

**Step 3: Validate the scope**
```bash
scorpio-pro scope --import scope.yaml --validate
```

**Step 4: Run a scan**
```bash
scorpio-pro scan --scope-config scope.yaml --report-format html,json,txt --output-dir ./reports/
```

**Step 5: View the report**
```bash
# macOS
open reports/scorpio_report_*.html

# Linux
xdg-open reports/scorpio_report_*.html

# Windows
start reports/scorpio_report_*.html
```

The HTML report opens in your browser with a dark-themed dashboard showing risk scores, finding severity breakdowns, and per-framework compliance scorecards.

---

### Scan the Local Host (No Scope File)

For a quick local system assessment without any scope file:
```bash
scorpio-pro scan --report-format html
```
Scorpio Pro defaults to scanning `localhost` only.

---

## CLI Reference

### Global Options

```
scorpio-pro [OPTIONS] COMMAND [ARGS]...
```

| Flag | Description |
|---|---|
| `--version` | Print version and exit |
| `--help` | Show help message |

---

### `scan` — Run a Full Security Scan

```
scorpio-pro scan [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--scope-config PATH` | `-s` | _(localhost)_ | Path to YAML scope configuration file |
| `--report-format TEXT` | `-f` | `html,json,txt` | Comma-separated report formats: `html`, `json`, `txt` |
| `--output-dir PATH` | `-o` | `./reports` | Directory for generated reports |
| `--yes` | `-y` | `False` | Skip authorisation prompt (CI pipelines — ensure written auth exists) |
| `--log-level LEVEL` | — | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

**Examples:**

```bash
# Full scan with all report formats
scorpio-pro scan --scope-config scope.yaml --report-format html,json,txt --output-dir ./reports/

# HTML report only, verbose logging
scorpio-pro scan -s scope.yaml -f html -o ./output/ --log-level DEBUG

# Non-interactive mode for CI/CD pipelines
scorpio-pro scan --scope-config scope.yaml --yes --log-level WARNING

# Quick local scan with JSON output only
scorpio-pro scan -f json -o /tmp/audit/
```

---

### `scope` — Manage Scope Configuration Files

```
scorpio-pro scope [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--create` | — | — | Interactively create a new scope YAML file |
| `--export` | — | — | Export a loaded scope to YAML |
| `--import PATH` | — | — | Import and display an existing scope YAML file |
| `--validate` | — | `False` | Validate the imported scope file (use with `--import`) |
| `--output PATH` | `-o` | `scope.yaml` | Output file path for `--create` or `--export` |

**Examples:**

```bash
# Create a new scope interactively
scorpio-pro scope --create

# Create scope and save to a specific path
scorpio-pro scope --create --output engagements/acme_scope.yaml

# Import and display scope details
scorpio-pro scope --import example_scope.yaml

# Import and validate
scorpio-pro scope --import example_scope.yaml --validate

# Export current scope
scorpio-pro scope --export --output my_scope.yaml
```

---

## Scope Configuration

The scope configuration file is the foundation of every Scorpio Pro engagement. It defines the **authorised attack surface** — nothing outside this scope will ever be touched.

### Full Field Reference

```yaml
# ── Engagement Metadata ──────────────────────────────────────────────────────
engagement_name: "Example Corp Infrastructure Assessment"
authorised_by: "Jane Smith, CISO"
authorisation_date: "2024-01-15"

# ── Scan Intensity ─────────────────────────────────────────────────────────────
# Options: passive | moderate | aggressive
intensity: moderate

# ── In-Scope IP Addresses ──────────────────────────────────────────────────────
ips:
  - 192.168.1.10
  - 192.168.1.20
  - 10.0.0.5

# ── In-Scope CIDR Ranges ───────────────────────────────────────────────────────
cidr_ranges:
  - 192.168.1.0/28   # DMZ network (14 hosts)
  - 10.0.1.0/24      # Internal application servers

# ── In-Scope Subnets (descriptive) ─────────────────────────────────────────────
subnets:
  - "192.168.1.0/28 — DMZ"
  - "10.0.1.0/24 — App servers"

# ── Port Scope ────────────────────────────────────────────────────────────────
ports:
  - "1-1024"
  - "3306"    # MySQL
  - "3389"    # RDP
  - "5432"    # PostgreSQL
  - "6379"    # Redis
  - "8080"    # Alternate HTTP
  - "8443"    # Alternate HTTPS
  - "9200"    # Elasticsearch

# ── In-Scope Services ────────────────────────────────────────────────────────
services:
  - ssh
  - http
  - https
  - rdp
  - smb
  - ftp

# ── In-Scope Applications ─────────────────────────────────────────────────────
applications:
  - https://app.example.com
  - https://admin.example.com
  - http://legacy.example.internal:8080

# ── Exclusions ────────────────────────────────────────────────────────────────
exclusions:
  - 192.168.1.1      # Router — excluded by client request
  - 10.0.1.250       # Monitoring server — fragile, exclude

# ── Cloud Accounts ────────────────────────────────────────────────────────────
cloud_accounts:
  - provider: aws
    account_id: "123456789012"
    profile: "pen-test-readonly"
  - provider: azure
    subscription_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  - provider: gcp
    project_id: "my-gcp-project-id"

# ── Scan Time Windows ────────────────────────────────────────────────────────
time_windows:
  - start: "22:00"
    end: "06:00"
    days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
  - start: "00:00"
    end: "23:59"
    days: ["saturday", "sunday"]
```

### Field Descriptions

| Field | Type | Description |
|---|---|---|
| `engagement_name` | string | Human-readable name for the engagement (appears in reports) |
| `authorised_by` | string | Name and title of the authorising party (for audit trail) |
| `authorisation_date` | string | Date of written authorisation (ISO 8601: YYYY-MM-DD) |
| `intensity` | enum | Scan depth: `passive`, `moderate`, or `aggressive` (see below) |
| `ips` | list | Individual IPv4/IPv6 addresses to include in scope |
| `cidr_ranges` | list | CIDR notation subnets — all hosts unless excluded |
| `subnets` | list | Human-readable subnet descriptions (documentation only) |
| `ports` | list | Individual ports or ranges (`"80"`, `"1-1024"`) to scan |
| `services` | list | Named services to specifically target |
| `applications` | list | Web application URLs to test |
| `exclusions` | list | IPs or CIDRs to always skip, even if inside an in-scope range |
| `cloud_accounts` | list | Cloud provider accounts to audit (see Cloud Scanning) |
| `time_windows` | list | Restrict scanning to these time windows (UTC) |

### Intensity Levels

| Level | Description | Use Case |
|---|---|---|
| `passive` | No intrusive tests. Reconnaissance and enumeration only. No packets sent to test services. | Stealth recon, production environments during business hours |
| `moderate` | Standard penetration test profile. Service probing, vulnerability checks, credential testing. | Most engagements — the recommended default |
| `aggressive` | Full test including OS fingerprinting, deeper protocol analysis, more thorough enumeration. Noticeably noisier. | Lab environments, dedicated test windows, thorough assessments |

### Exclusions

Exclusions are critical for professional engagements. They protect:
- **Fragile infrastructure** (monitoring servers, SCADA/ICS devices)
- **Out-of-scope hosts** that happen to fall within an in-scope CIDR
- **Third-party systems** the client does not own (co-located servers, ISP equipment)

```yaml
exclusions:
  - 192.168.1.1       # Gateway — not in scope
  - 10.0.0.0/30       # ISP edge equipment
  - 192.168.100.50    # Medical device — client exclusion
```

### Cloud Accounts Configuration

Cloud accounts are optional. Scorpio Pro auto-discovers credentials from the environment (see [Cloud Scanning](#cloud-scanning)).

```yaml
cloud_accounts:
  - provider: aws
    account_id: "123456789012"      # optional — for documentation
    profile: "pen-test-readonly"    # AWS CLI named profile
  - provider: azure
    subscription_id: "xxxx-..."     # Azure subscription ID
  - provider: gcp
    project_id: "my-project-id"     # GCP project ID
```

### Time Windows

Time windows allow you to restrict scanning to approved maintenance windows. All times are in UTC.

```yaml
time_windows:
  - start: "22:00"
    end: "06:00"
    days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
  - start: "00:00"
    end: "23:59"
    days: ["saturday", "sunday"]
```

### Using Scope Files Across Multiple Devices

Scope files are designed to be portable. Export a validated scope from one workstation and import it on another:

```bash
# Workstation A: create and validate
scorpio-pro scope --create --output engagements/acme.yaml
scorpio-pro scope --import engagements/acme.yaml --validate

# Copy to Workstation B (via SCP, vault, etc.)
# Workstation B: import and scan
scorpio-pro scan --scope-config engagements/acme.yaml
```

---

## Scanner Modules

### 🖥️ System Scanner (`system_scanner.py`)

**Purpose**: Comprehensive host information gathering and local security configuration assessment.

**What it checks:**

| Check | Method | Compliance Tags |
|---|---|---|
| Hostname and DNS | `socket.gethostname()`, DNS resolution | ID.AM-1, ID.AM-2 |
| IP addresses and MACs | `psutil.net_if_addrs()` | ID.AM-3 |
| BIOS/UEFI info | Platform-specific (`dmidecode`, WMI, `system_profiler`) | ID.AM-1 |
| OS patch status | `apt`, `yum`, `Windows Update`, `brew outdated` | PR.IP-12, HIPAA-164.308(a)(1) |
| User accounts | `/etc/passwd`, `net user`, `dscl` | PR.AC-1, HIPAA-164.312(a)(1) |
| Privileged accounts | `sudo -l`, administrators group | PR.AC-1 |
| Host-based firewall | `ufw status`, `iptables -L`, Windows Firewall API | PR.AC-5 |
| Disk encryption | `lsblk`, `fdesetup`, BitLocker WMI query | HIPAA-164.312(a)(2)(iv), GDPR-Art32 |
| AV/EDR detection | Process list, service enumeration, registry | HIPAA-164.308(a)(1) |

**Platform support**: Linux, macOS, Windows (all checks have cross-platform implementations or graceful skips).

---

### 🌐 Network Scanner (`network_scanner.py`)

**Purpose**: Enumerate network topology, open services, and host inventory within the authorised scope.

**nmap Mode** (when nmap is available):
```
nmap -sV -sC -O --open -p <ports> <targets>
```
- Service version detection (`-sV`)
- Default script scanning (`-sC`)
- OS detection (`-O`) in `aggressive` intensity
- Only open ports reported

**Fallback TCP Connect Mode** (when nmap is unavailable):
- Pure Python `socket.connect_ex()` against each port in scope
- Banner grabbing for common protocols (HTTP, FTP, SSH, SMTP)
- No OS detection (requires raw sockets / nmap)

**DNS Enumeration**:
- Forward/reverse lookups for all in-scope IPs
- Zone transfer attempts (`AXFR`) against discovered DNS servers
- Common subdomain brute-force from a built-in wordlist

**ARP Discovery** (local subnets only):
- Uses `scapy` if available, falls back to `arping` or passive ARP cache inspection

---

### 🔓 Vulnerability Scanner (`vuln_scanner.py`)

**Purpose**: Identify known vulnerabilities in discovered services, validate cryptographic configurations, and test for default credentials.

**CVE Lookups**:
- Queries the NVD API for CVEs matching detected service name and version
- Returns CVSS score, description, and CWE categories
- Results cached locally to avoid redundant API calls

**SSL/TLS Analysis**:

| Check | What's Evaluated |
|---|---|
| Protocol versions | Checks for SSLv2, SSLv3, TLS 1.0, TLS 1.1 (deprecated) |
| Cipher suites | Flags weak ciphers: NULL, RC4, DES, 3DES, EXPORT, anon |
| Certificate validity | Expiry date, self-signed detection, CN vs hostname |
| Certificate chain | Intermediate CA presence, root CA trust |
| HSTS | Strict-Transport-Security header presence and max-age |

**HTTP Security Headers**:

| Header | Expected Value |
|---|---|
| `Strict-Transport-Security` | `max-age≥31536000; includeSubDomains` |
| `Content-Security-Policy` | Non-wildcard policy |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | Present and restrictive |

**Default Credentials**:
- Tests common default username/password pairs against SSH, FTP, HTTP Basic Auth, Telnet
- Built-in credential list covers router defaults, appliance defaults, and common weak passwords
- Rate-limited to avoid lockouts

---

### 📡 Remote Access Scanner (`remote_access_scanner.py`)

**Purpose**: Audit remote access services for cryptographic weaknesses, insecure configurations, and known vulnerabilities.

**SSH Analysis** (via `paramiko`):
- Connects to target SSH service and negotiates algorithms without authenticating
- Flags deprecated KEX algorithms: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
- Flags weak ciphers: `3des-cbc`, `blowfish-cbc`, `arcfour`
- Flags weak MACs: `hmac-md5`, `hmac-sha1-96`
- Reads local `sshd_config` for `PermitRootLogin`, `PasswordAuthentication`, `Protocol`, `MaxAuthTries`

**RDP Security**:
- Tests for Network Level Authentication (NLA) enforcement
- Checks encryption level (checks if `ENCRYPTION_LEVEL_LOW` is accepted)
- Probes for BlueKeep (CVE-2019-0708) vulnerability surface — detection only, no exploitation
- Reports RDP certificate details

**VPN Configuration Auditing**:
- **OpenVPN**: parses `.ovpn` and `server.conf` — checks `tls-auth`/`tls-crypt` presence, cipher, TLS version, `comp-lzo` deprecation
- **WireGuard**: enumerates `wg` interfaces, checks peer configurations, `AllowedIPs` scope
- **IPSec/IKEv2**: reads `ipsec.conf`, `strongswan.conf` — IKE cipher suites, PFS, DH group strength

---

### ☁️ Cloud Scanner (`cloud_scanner.py`)

**Purpose**: Assess cloud environment security posture across AWS, Azure, and GCP.

See [Cloud Scanning](#cloud-scanning) for the full dedicated section.

---

### 📦 Application Scanner (`app_scanner.py`)

**Purpose**: Inventory installed software and audit web server and database configurations.

**Application Inventory**:

| Platform | Method |
|---|---|
| Debian/Ubuntu | `dpkg -l` — name, version, description |
| RHEL/CentOS/Fedora | `rpm -qa --queryformat` |
| macOS | `system_profiler SPApplicationsDataType` |
| Windows | Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |

**Web Server Audits**:
- **Apache**: Checks `ServerTokens Prod`, `ServerSignature Off`, `Options -Indexes`, TLS `SSLProtocol`, `SSLCipherSuite`
- **Nginx**: Checks `server_tokens off`, `ssl_protocols`, `ssl_ciphers`, `autoindex off`

**Database Audits**:
- **MySQL**: `anonymous` user accounts, `test` database presence, `bind-address`, password validation plugin, `secure_file_priv`
- **PostgreSQL**: `pg_hba.conf` `trust` authentication entries, `listen_addresses`, superuser count, `log_connections`

**Runtime Version EOL Checks**:
- Python, Node.js, Java, Ruby, PHP
- Compares detected version against known EOL dates
- Flags versions that no longer receive security patches

---

### 📂 Shared Drive Scanner (`shared_drive_scanner.py`)

**Purpose**: Enumerate file shares and identify permission misconfigurations that could expose sensitive data.

**SMB/CIFS**:
- Null session enumeration (`smbclient -N`) — tests anonymous access without credentials
- Share discovery: lists all available shares and their descriptions
- Guest access testing: attempts access as the guest account
- Permission review: readable, writable, executable access per share

**NFS**:
- Export enumeration via `showmount -e <host>`
- World-readable export detection (`*(ro)`, `*(rw)`)
- `no_root_squash` identification — allows remote root to act as local root
- `insecure` export flag detection — allows unprivileged ports

**AFP (Apple Filing Protocol)**:
- Detects running AFP services (`netatalk`, `afpd`)
- Issues deprecation warning — AFP is end-of-life and should be replaced with SMB3

**Local Shares (Windows)**:
- Enumerates shares via `net share`
- Checks NTFS and share-level permissions
- Identifies administrative shares (`C$`, `ADMIN$`, `IPC$`) and their accessibility

---

## Cloud Scanning

Cloud scanning is designed to be maximally useful while operating safely. Scorpio Pro performs public-facing checks without credentials and deeper configuration checks with credentials.

### Credential Discovery Order

```
1. Environment Variables
   AWS:   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
   Azure: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
   GCP:   GOOGLE_APPLICATION_CREDENTIALS

2. Config Files / SDK Defaults
   AWS:   ~/.aws/credentials (profile from scope file or AWS_PROFILE)
   Azure: Azure CLI (~/.azure/), managed identity (if on Azure VM)
   GCP:   Application Default Credentials (~/.config/gcloud/application_default_credentials.json)

3. Scope File Profile
   Explicit profile/project specified in cloud_accounts section of scope.yaml

4. Interactive Prompt
   If no credentials discovered, Scorpio Pro prompts: "Enter AWS Access Key ID (or press Enter to skip):"

5. Graceful Degradation
   If user declines or credentials are unavailable, cloud checks that require
   authentication are skipped. Public-facing checks (open S3 buckets, public
   endpoints) still run without credentials.
```

### AWS Checks

| Check | API Call | What's Assessed |
|---|---|---|
| IAM Password Policy | `get-account-password-policy` | Min length, complexity, rotation, MFA |
| S3 Bucket ACLs | `list-buckets` + `get-bucket-acl` | Public read/write access |
| S3 Public Access Block | `get-public-access-block` | Account-level and bucket-level blocks |
| CloudTrail Logging | `describe-trails` | Multi-region, log validation, S3 delivery |
| Security Groups | `describe-security-groups` | `0.0.0.0/0` ingress rules |
| Unused IAM Keys | `list-access-keys` | Keys unused for >90 days |
| MFA Enforcement | `get-account-summary` + `list-virtual-mfa-devices` | Root MFA, user MFA |
| Root Account Usage | `get-account-summary` | Last root activity |

### Azure Checks

| Check | API / SDK | What's Assessed |
|---|---|---|
| RBAC Role Assignments | `role_assignments.list()` | Over-privileged roles (Owner at subscription level) |
| Storage Account Access | `storage_accounts.list()` | Public blob access, HTTPS enforcement |
| Network Security Groups | `network_security_groups.list()` | Any-to-any allow rules |
| Key Vault Access Policies | `vaults.list()` | Overly permissive access policies |
| Azure AD MFA | Graph API | MFA registration per user |
| Defender for Cloud | Security Center API | Security score, unhealthy resources |

### GCP Checks

| Check | API | What's Assessed |
|---|---|---|
| IAM Primitive Roles | `getIamPolicy` | Owner/Editor roles at project level |
| GCS Bucket Access | `storage.buckets.list` | `allUsers`/`allAuthenticatedUsers` ACLs |
| Firewall Rules | `compute.firewalls.list` | `0.0.0.0/0` ingress on sensitive ports |
| KMS Key Rotation | `cloudkms.cryptoKeys.list` | Keys without automatic rotation |
| Service Account Keys | `iam.serviceAccountKeys.list` | User-managed keys older than 90 days |
| Audit Logging | `logging.sinks.list` | Admin activity and data access audit logs |

### Checks Without Credentials

Even without any cloud credentials, Scorpio Pro performs:
- Public S3 bucket endpoint testing (anonymous HEAD/GET requests)
- Azure blob storage anonymous access testing
- Public-facing cloud service fingerprinting
- Cloud metadata endpoint exposure testing (checks if `169.254.169.254` is reachable from discovered hosts)

---

## Report Formats

### HTML Report

The HTML report is a self-contained, dark-themed security dashboard.

**Sections:**
- **Executive Summary**: overall risk score (0–100), total finding count by severity
- **Device Inventory**: all discovered hosts with OS, open ports, services
- **Compliance Scorecards**: per-framework score with control-level pass/fail/not-tested breakdown
- **Findings Detail**: every finding with title, severity badge, description, evidence (collapsible), remediation steps, and compliance tags
- **Methodology**: scan metadata, scope summary, time of scan

**Risk Score Colour Coding:**

| Score | Colour | Meaning |
|---|---|---|
| 90–100 | 🟢 Green | Excellent security posture |
| 70–89 | 🟡 Yellow | Good, minor gaps to address |
| 50–69 | 🟠 Orange | Moderate risk, prioritise remediation |
| 0–49 | 🔴 Red | Significant risk, immediate action needed |

Generate:
```bash
scorpio-pro scan -s scope.yaml -f html -o ./reports/
```

---

### JSON Report

The JSON report is designed for **SIEM integration, vulnerability management platforms, and custom tooling**.

**Structure:**
```json
{
  "metadata": {
    "engagement_name": "...",
    "scan_timestamp": "2024-01-15T22:00:00Z",
    "scorpio_version": "1.0.0",
    "scope_summary": {...}
  },
  "summary": {
    "total_findings": 47,
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 18,
    "informational": 4,
    "risk_score": 62
  },
  "compliance": {
    "hipaa": {"score": 71, "control_results": {...}},
    "gdpr":  {"score": 68, "control_results": {...}},
    ...
  },
  "findings": [
    {
      "title": "...",
      "severity": "High",
      "status": "fail",
      "compliance_tags": ["HIPAA-164.312(e)(1)", "GDPR-Art32"],
      ...
    }
  ]
}
```

Generate:
```bash
scorpio-pro scan -s scope.yaml -f json -o ./reports/
```

---

### TXT Report

The plain-text report is suitable for terminal viewing, email, ticketing systems, and long-term archival.

```
=============================================================
  SCORPIO PRO SECURITY ASSESSMENT REPORT
  Engagement: Example Corp Infrastructure Assessment
  Date: 2024-01-15T22:30:00Z
=============================================================

EXECUTIVE SUMMARY
-----------------
Total Findings : 47
Critical       : 2
High           : 8
Medium         : 15
Low            : 18
Informational  : 4
Overall Score  : 62/100

...
```

Generate:
```bash
scorpio-pro scan -s scope.yaml -f txt -o ./reports/
```

---

### Generating Multiple Formats Simultaneously

```bash
# HTML and JSON only
scorpio-pro scan -s scope.yaml -f html,json

# All three formats
scorpio-pro scan -s scope.yaml -f html,json,txt

# Shorthand for all formats (default)
scorpio-pro scan -s scope.yaml
```

---

## The Finding Object

Every scanner produces `Finding` objects — the atomic unit of Scorpio Pro's output. Understanding the `Finding` structure helps when building integrations or extending the tool.

### Dataclass Definition

```python
@dataclass
class Finding:
    title: str                      # Short, descriptive finding title
    severity: str                   # Critical | High | Medium | Low | Informational
    description: str                # Detailed explanation of the issue
    evidence: str                   # Raw data/output proving the finding
    remediation: str                # Specific steps to fix the issue
    test_run: str                   # Identifier of the test that produced this
    rationale: str                  # Why this test matters (security context)
    methodology: str                # How the test was conducted
    status: str                     # pass | fail | warning
    compliance_tags: list[str]      # Framework control IDs this maps to
    metadata: dict[str, Any]        # Scanner-specific supplementary data
```

### Example Finding

```json
{
  "title": "TLS 1.0 Protocol Enabled on HTTPS Service",
  "severity": "High",
  "description": "The HTTPS service on 192.168.1.10:443 accepts TLS 1.0 connections. TLS 1.0 is deprecated per RFC 8996 and is vulnerable to BEAST and POODLE attacks.",
  "evidence": "TLS handshake succeeded with protocol version TLSv1.0 using cipher TLS_RSA_WITH_AES_128_CBC_SHA.",
  "remediation": "Disable TLS 1.0 and TLS 1.1 in the web server configuration. Configure the minimum TLS version to TLS 1.2. Preferred: enable TLS 1.3 support. For Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3. For Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
  "test_run": "vuln_scanner.tls_protocol_check",
  "rationale": "Deprecated TLS versions are susceptible to known cryptographic attacks and should not be used to protect sensitive data.",
  "methodology": "Connected to the HTTPS endpoint using a Python ssl socket configured to offer TLS 1.0. Checked if the server completed the handshake successfully.",
  "status": "fail",
  "compliance_tags": [
    "HIPAA-164.312(e)(1)",
    "HIPAA-164.312(a)(2)(iv)",
    "GDPR-Art32",
    "NIST-PR.DS-2",
    "NIST-PR.AC-3"
  ],
  "metadata": {
    "target_host": "192.168.1.10",
    "target_port": 443,
    "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "protocol_version": "TLSv1.0"
  }
}
```

### Severity Levels

| Level | Numeric Score | Meaning |
|---|---|---|
| Critical | 5 | Immediate exploitation possible; direct path to full system compromise |
| High | 4 | Significant risk; exploitable with moderate effort |
| Medium | 3 | Notable risk; requires specific conditions or chaining |
| Low | 2 | Minor risk; limited impact or difficult to exploit |
| Informational | 1 | Observation, no direct security impact; best practice recommendation |

---

## Compliance Scoring Methodology

### Score Calculation

Each compliance framework is scored on a **0–100 scale** using the following formula:

```
score = (passed + not_tested × 0.5) / total_controls × 100
```

Where:
- **passed**: controls with at least one `status=pass` finding mapped to them
- **not_tested**: controls with no findings mapped (scanner may not have run, or check not applicable to this environment)
- **total_controls**: total number of controls defined in the framework

`not_tested` controls receive a **50% partial credit** rather than 0, because their absence of evidence is not evidence of failure — it reflects scope or environmental limitations rather than a confirmed gap.

### Control Result Statuses

| Status | Meaning |
|---|---|
| `pass` | A finding with `status=pass` was produced for a test mapped to this control |
| `fail` | A finding with `status=fail` exists — the control is not satisfied |
| `warning` | A finding with `status=warning` exists — partially satisfied or indeterminate |
| `not_tested` | No findings mapped to this control — may be out of scope or tool limitation |

### Gap Identification

Controls with `fail` or `warning` status in the compliance scorecard are treated as **gaps**. Each gap includes:
1. The specific control ID and description
2. The finding(s) that triggered the fail/warning
3. The remediation steps from those findings
4. A prioritisation based on finding severity

### Example Scorecard

```
HIPAA Security Rule Compliance Score: 71/100

 ✅ PASS  164.312(a)(2)(iv) - Encryption and Decryption (disk encryption enabled)
 ✅ PASS  164.312(b)        - Audit Controls (auditd running, logs present)
 ❌ FAIL  164.312(e)(1)     - Transmission Security (TLS 1.0 enabled)
 ⚠️  WARN  164.308(a)(1)     - Security Management Process (patch backlog detected)
 ➖ N/T   164.314(a)(2)(i)  - Business Associate Contracts (out of scope)
```

---

## Building Distributable Packages

Scorpio Pro includes platform-specific packaging scripts for distributing the tool without requiring users to install Python.

### macOS DMG

```bash
cd packaging/macos/
# Install PyInstaller
pip install pyinstaller

# Build the application bundle
./build_dmg.sh

# Output: scorpio-pro-1.0.0-macos.dmg
```

### Windows MSI

```powershell
cd packaging\windows\
# Requires WiX Toolset (https://wixtoolset.org/)
# Install PyInstaller
pip install pyinstaller

# Build MSI installer
.\build_msi.ps1

# Output: scorpio-pro-1.0.0-windows.msi
```

### Ubuntu / Debian DEB Package

```bash
cd packaging/linux/
# Install required tools
sudo apt install dpkg-dev

# Build .deb package
./build_deb.sh

# Output: scorpio-pro_1.0.0_amd64.deb
# Install:
sudo dpkg -i scorpio-pro_1.0.0_amd64.deb
```

### PyInstaller (Any Platform)

To create a standalone executable for the current platform:

```bash
pip install pyinstaller
pyinstaller --onefile --name scorpio-pro scorpio_pro/__main__.py

# Output in dist/
./dist/scorpio-pro --version
```

---

## Development

### Prerequisites

```bash
git clone https://github.com/jsdosanj/scorpio-pro.git
cd scorpio-pro
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
# or with coverage
pytest --cov=scorpio_pro --cov-report=html
```

### Linting

Scorpio Pro uses [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
ruff check .
ruff format .
```

Ruff configuration (from `pyproject.toml`):
- `line-length = 100`
- `target-version = "py311"`
- Selected rule sets: `E`, `F`, `W`, `I`, `N`, `UP`, `S`, `BLE`, `A`
- Ignored: `S101` (assert), `S603` (subprocess), `S607` (partial path)

### Type Checking

```bash
mypy scorpio_pro/
```

Scorpio Pro is typed with `mypy --strict` mode.

### Code Style

- **Python 3.11+** features are expected and encouraged
- Line length: 100 characters
- All public APIs must have type annotations
- All public APIs must have docstrings
- Follow Google-style docstrings

### Adding a New Scanner Module

1. Create `scorpio_pro/scanners/my_scanner.py`
2. Inherit from `BaseScanner`
3. Implement `name`, `description`, `check_prerequisites()`, and `run()`
4. Return a list of `Finding` objects
5. The `PluginManager` discovers and loads it automatically — no registration needed

```python
from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

class MyScanner(BaseScanner):
    name = "My Scanner"
    description = "Checks for XYZ vulnerabilities"

    def check_prerequisites(self) -> bool:
        # Return False if required tools are missing
        return True

    def run(self, scope) -> list[Finding]:
        findings = []
        # ... your checks ...
        findings.append(Finding(
            title="Example Finding",
            severity="High",
            description="...",
            evidence="...",
            remediation="...",
            test_run="my_scanner.example_check",
            rationale="...",
            methodology="...",
            status="fail",
            compliance_tags=["NIST-PR.AC-1"],
        ))
        return findings
```

### Adding a New Compliance Framework

1. Create `scorpio_pro/compliance/my_framework.py`
2. Inherit from `BaseComplianceFramework`
3. Define `framework_id`, `name`, and `controls`
4. Implement `evaluate(findings)` to return a scorecard
5. Register it in `scorpio_pro/compliance/engine.py`

### See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) — full contribution guide, code of conduct, PR process

---

## Security Considerations

### Credential Handling

- Cloud credentials (AWS keys, Azure tokens, GCP service account JSON) are **never written to disk** by Scorpio Pro
- Credentials held in memory are explicitly cleared after use
- Credentials are never included in scan reports or log output (masked as `****`)
- Default credential testing uses a **read-only** credential list — no write operations are attempted

### Scope Enforcement

- Scorpio Pro **strictly enforces** the scope defined in the configuration file
- No network packet is sent to any IP or CIDR not explicitly listed in `ips` or `cidr_ranges` (minus `exclusions`)
- Exclusions are checked before every scan action, not just at the start
- The scope config is validated for consistency before any scanner is invoked

### Authorisation Gate

- The legal disclaimer and confirmation prompt (`YES I CONFIRM`) is the first thing that runs
- In `--yes` / non-interactive mode, a log entry is written confirming that non-interactive mode was used, creating an audit trail

### Logging

- All scan actions are logged with timestamps to facilitate post-scan audit
- Log level `DEBUG` captures every test action, target, and result
- Log output can be redirected to a file: `scorpio-pro scan ... 2>&1 | tee scan.log`

### Running as a Non-Privileged User

- Most checks work without elevated privileges
- Some checks require root/admin (raw socket scanning, firewall rule enumeration, BIOS queries)
- Scorpio Pro clearly logs when a privilege-required check is skipped rather than failing silently

---

## Legal Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              SCORPIO PRO — PENETRATION TESTING TOOL                        ║
║                     LEGAL DISCLAIMER & AUTHORISATION                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is intended EXCLUSIVELY for use on systems and networks that     ║
║  you OWN or have EXPLICIT, WRITTEN AUTHORISATION to test.                   ║
║                                                                              ║
║  Unauthorised scanning or testing of systems is ILLEGAL and may result in   ║
║  criminal prosecution under the Computer Fraud and Abuse Act (18 U.S.C.    ║
║  § 1030), the Computer Misuse Act 1990 (UK), and equivalent laws worldwide. ║
║                                                                              ║
║  By proceeding you confirm that:                                             ║
║    1. You have written authorisation for all targets in scope.               ║
║    2. You will not exceed the agreed scope.                                  ║
║    3. You accept full legal responsibility for your actions.                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Important Legal Notice

⚠️ **USE THIS TOOL ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORISATION TO TEST.**

Unauthorised use of this tool against systems, networks, or services you do not own or have explicit written permission to test is a criminal offence in most jurisdictions, including but not limited to:

- **United States**: Computer Fraud and Abuse Act (18 U.S.C. § 1030) — up to 10 years imprisonment per count for first offences
- **United Kingdom**: Computer Misuse Act 1990 — up to 10 years imprisonment
- **European Union**: Directive on Attacks Against Information Systems (2013/40/EU)
- **Australia**: Criminal Code Act 1995 (Part 10.7 — Computer Offences)
- **Canada**: Criminal Code, Section 342.1

The authors and contributors of Scorpio Pro **bear no responsibility** for any illegal use of this software. By installing and using this tool, you agree to the terms above and accept full legal responsibility for your actions.

---

## Roadmap

The following capabilities are planned for future releases:

| Feature | Target Release | Description |
|---|---|---|
| 🕐 Scheduled / Daemon Mode | v1.1 | Run continuous or scheduled scans, compare against baselines, alert on delta |
| 🔌 Plugin Marketplace | v1.2 | Community-contributed scanner and compliance modules with version management |
| 🌐 Web Dashboard | v1.3 | Local web server with real-time scan progress, historical trend analysis, team-based reporting |
| 🐳 Kubernetes / Container Scanning | v1.4 | CIS Kubernetes Benchmark, container image scanning, RBAC audit, runtime security |
| 📡 SIEM Integration | v1.4 | Native syslog/CEF output, Splunk HEC connector, Elastic Beats format, Azure Sentinel DCR |
| 📋 Additional Frameworks | v1.5 | SOC 2 Type II, PCI DSS v4.0, ISO 27001:2022, CIS Controls v8 |
| 🤖 AI-Assisted Remediation | v2.0 | LLM-powered remediation recommendations with environment-specific context |
| 🔄 CI/CD Native Integration | v1.1 | GitHub Actions, GitLab CI, Jenkins, Azure DevOps plugins |

Contributions toward any roadmap item are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contributing

Contributions are warmly welcomed from security researchers, developers, and compliance experts.

### How to Contribute

1. **Read [CONTRIBUTING.md](CONTRIBUTING.md)** — it covers code standards, commit format, and the PR review process
2. **Fork** the repository and create a feature branch
3. **Write tests** for any new scanner checks or compliance controls
4. **Run the full test suite**: `pytest`
5. **Lint and format**: `ruff check . && ruff format .`
6. **Type check**: `mypy scorpio_pro/`
7. **Submit a Pull Request** with a clear description of what you added and why

### Adding a New Scanner — Quick Reference

- Place your scanner in `scorpio_pro/scanners/my_scanner.py`
- Inherit from `BaseScanner`, implement `run()` and `check_prerequisites()`
- Use graceful degradation — never let a missing tool crash the scanner
- Map findings to existing compliance control IDs wherever possible
- Document your methodology in the `methodology` field of each `Finding`

### Adding a New Compliance Framework — Quick Reference

- Place your framework in `scorpio_pro/compliance/my_framework.py`
- Inherit from `BaseComplianceFramework`
- Define every control with its ID, name, and description
- Map control IDs to the `compliance_tags` format used in existing scanners
- Register in `scorpio_pro/compliance/engine.py`

### Types of Contributions We Value

- 🐛 Bug reports and fixes
- ✨ New scanner checks for existing modules
- 🆕 New scanner modules for uncovered attack surface areas
- 📋 New compliance framework mappings
- 📝 Documentation improvements and corrections
- 🌍 Translations
- 🧪 Test coverage improvements

---

## License

```
MIT License

Copyright (c) 2024 jsdosanj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

This is open-source software. Attribution is appreciated — if you build something useful with Scorpio Pro, a mention in your project's README or documentation means a lot to the community.

---

## Acknowledgments

Scorpio Pro stands on the shoulders of giants. We gratefully acknowledge:

- 🐍 **The Python Security Community** — for decades of open-source security tooling, libraries, and knowledge sharing
- 🗺️ **The nmap Project** — for the world's most capable network scanner, without which none of this is possible ([https://nmap.org](https://nmap.org))
- 🏛️ **NIST** — for the Cybersecurity Framework, AI Risk Management Framework, and NVD, which provide the vocabulary and structure for meaningful security measurement
- 🏥 **HHS Office for Civil Rights** — for the HIPAA Security Rule guidance that protects patient data
- 🇪🇺 **The European Union** — for the GDPR, which has raised the global bar for privacy and data protection
- 🔐 **paramiko** — for the Python SSH implementation that powers remote access analysis ([https://www.paramiko.org](https://www.paramiko.org))
- 📦 **The Boto3 / Azure SDK / google-cloud-python teams** — for making cloud API access accessible from Python
- ✨ **The Rich library team** — for beautiful terminal output ([https://github.com/Textualize/rich](https://github.com/Textualize/rich))
- 🌐 **The open-source security tool community** — Metasploit, Burp Suite, OpenVAS, Nikto, and every tool that inspired what Scorpio Pro aspires to be

---

<div align="center">

**🦂 Scorpio Pro** — *Know your attack surface before the adversary does.*

[Report a Bug](https://github.com/jsdosanj/scorpio-pro/issues) · [Request a Feature](https://github.com/jsdosanj/scorpio-pro/issues) · [CONTRIBUTING.md](CONTRIBUTING.md)

</div>
