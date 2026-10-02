# MAFKit v3.1 — Mobile APK + Android Device Forensic Kit

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-132%20passed-brightgreen.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen.svg)](docs/TEST_REPORT.md)

**MAFKit** (**M**obile **A**PK + Android Device **F**orensic **Kit**) combines **repeatable static APK reverse engineering** with **non-destructive ADB evidence acquisition, USB phone security scanning, and incident correlation**. It is engineered specifically for malware triage, mobile financial fraud investigations, incident response, and forensic reporting.

MAFKit operates under a strict evidentiary model: **it never executes the APK**.

---

## Table of Contents

- [Key Capabilities](#key-capabilities)
- [Architecture & Repository Layout](#architecture--repository-layout)
- [Installation & Prerequisites](#installation--prerequisites)
- [Quick Start & Usage](#quick-start--usage)
  - [1. Static APK Analysis](#1-static-apk-analysis)
  - [2. Non-Destructive ADB Evidence Collection](#2-non-destructive-adb-evidence-collection)
  - [3. Tri-Factor Incident Correlation (APK + ADB + Timeline)](#3-tri-factor-incident-correlation-apk--adb--timeline)
  - [4. USB Connected Phone Safety Scanning & Removal](#4-usb-connected-phone-safety-scanning--removal)
- [Evidence & Correlation Model](#evidence--correlation-model)
- [Output Artifacts & Sample Reports](#output-artifacts--sample-reports)
- [Development & Testing](#development--testing)
- [Forensic Standards & Evidentiary Defensibility](#forensic-standards--evidentiary-defensibility)

---

## Key Capabilities

### Static Reverse Engineering & Bytecode Extraction
- **Cryptographic Hashing & Provenance**: MD5, SHA-1, and SHA-256 digests of APKs and carved DEX files.
- **Manifest & Certificate Analysis**: Automated extraction of package metadata, SDK levels, permissions, exported components, and X.509 certificate fingerprints.
- **DPT Shell Unpacking**: Automated identification of DPT Shell protection (`libdpt.so`, `assets/OoooooOooo`), payload extraction from `classes.dex`, and Dalvik method body restoration.
- **Deobfuscation**: Generic repeating-XOR candidate string recovery with heuristic scoring and classification.
- **Behavior Graph Construction**: Automated generation of DOT (Graphviz) and JSON call graphs for suspicious API references.
- **MITRE ATT&CK Mapping**: Semantic mapping of detected capabilities against MITRE ATT&CK Mobile tactics.

### Logical ADB Evidence Acquisition & USB Phone Scanner
- **Serial-Pinned Execution**: Explicit target device pinning (`adb -s <serial> ...`) to prevent multi-device cross-contamination.
- **System & Security State Triage**: Captures `getprop`, user-installed and system package inventories, secure/global settings, Accessibility services, and Device Policy Manager states.
- **Phone Safety Audit (`scan-phone`)**: Rapidly inspects installed third-party apps over ADB, generates risk scorecards (0–100), flags active accessibility/admin hooks, and provides interactive uninstallation (`remove-app`).
- **Runtime Activity & Logs**: Collects activity stacks, usage stats, notification histories, network connection stats, and filtered logcat buffers.
- **Integrity Manifest**: Automatically hashes every acquired artifact with SHA-256 and generates a detached `collection_manifest.sha256` signature.

---

## Architecture & Repository Layout

```text
MAFKit/
├── pyproject.toml              # Build system, dependencies, and entrypoints
├── README.md                   # Main project guide & quickstart
├── LICENSE                     # MIT License
├── .gitignore                  # Python/IDE ignore rules
├── .gitattributes
│
├── src/                        # Source directory (src-layout)
│   └── mafkit/                 # Core Python package (PEP 8 compliant)
│       ├── __init__.py         # Package version declaration
│       ├── __main__.py         # Package runner (python -m mafkit)
│       ├── adbcollect.py       # Serial-pinned ADB triage acquisition & manifest generator
│       ├── analyzers.py        # Static APK container, manifest, permission & IOC analyzers
│       ├── attack.py           # MITRE ATT&CK Mobile tactic & technique mapping
│       ├── behavior.py         # DOT/JSON call graph generation
│       ├── cli.py              # Main CLI entrypoint (analyze, collect-adb, scan-phone, remove-app)
│       ├── correlation.py      # Rule-based APK ↔ ADB ↔ Timeline correlation engine
│       ├── deobfuscation.py    # Repeating-XOR bytecode decryption scanner
│       ├── device.py           # Parsers for dumpsys, settings, packages, and CSV timelines
│       ├── dex.py              # Dalvik Executable (.dex) binary parser & ULEB128 decoder
│       ├── forensic.py         # Hashing, package validation, env snapshots, stable evidence IDs
│       ├── model.py            # Dataclasses for Findings and Reports
│       ├── phone_scan.py       # USB connected phone security scanner
│       ├── reporting.py        # Multi-format report generators (JSON, Markdown, HTML, JSONL)
│       ├── util.py             # Cryptographic hashing, entropy calculation, IOC regexes
│       └── plugins/
│           ├── __init__.py
│           ├── base.py         # Base plugin interface for unpackers
│           └── dpt.py          # DPT Shell unpacker and method restoration plugin
│
├── docs/                       # Guides, manuals, and technical reports
│   ├── ADB_ACQUISITION_GUIDE.md # Detailed guide for physical/logical ADB setup
│   ├── PHONE_SCANNER.md        # Guide for USB Android phone scanner
│   ├── PHONE_SCANNER_MANUAL.txt # Quick reference manual for phone scanner
│   ├── CODE_REVIEW.md          # Technical audit and vulnerability remediation notes
│   ├── TEST_REPORT.md          # Automated test verification results
│   ├── REGRESSION_REPORT.md    # Regression analysis and security checks
│   └── base-apk-behavior-report.md # Reference forensic behavior report
│
├── examples/                   # Sample outputs, timeline CSV templates, test fixtures
│   ├── timeline-template.csv
│   ├── adb-acquisition/
│   ├── sample-output/
│   └── sample-output-v3/
│
├── mafkit-output/              # Sample analysis output reports
│   ├── report.json             # Complete sample JSON report
│   ├── report.md               # Complete sample Markdown report
│   ├── report.html             # Styled sample HTML report
│   ├── evidence.jsonl          # Sample streaming JSONL findings
│   ├── behavior_graph.json     # Sample behavior call graph JSON
│   └── behavior_graph.dot      # Sample behavior call graph DOT
│
├── scripts/                    # Platform collection convenience scripts (.sh / .ps1)
└── tests/                      # Automated test suite (132 unit tests, 92% coverage)
```

---

## Installation & Prerequisites

### Requirements
- **Python**: `>= 3.10`
- **Platform**: Windows, Linux, or macOS

### Python Setup

```bash
# Clone the repository
git clone https://github.com/sashank/MAFKIT.git
cd MAFKIT

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\Activate.ps1    # Windows PowerShell

# Install in editable mode
pip install -e .
```

### Recommended External Tools
For enhanced analysis and optional decompilation:
- **Android Platform-Tools (`adb`)**: Required for `collect-adb` and `scan-phone`.
- **JADX / apktool**: Optional for external decompilation via `--decompile`.
- **Android Build-Tools (`aapt`, `apksigner`)**: Recommended for secondary certificate validation.

---

## Quick Start & Usage

The `mafkit` CLI provides four subcommands: `analyze`, `collect-adb`, `scan-phone`, and `remove-app`.

### 1. Static APK Analysis

Run deep static analysis on a suspicious APK:

```bash
mafkit analyze suspicious.apk -o case-001 --deep
```

Options:
- `-o, --out <DIR>`: Output directory (defaults to `mafkit-output`).
- `--deep`: Enables deep unpacking, repeating-XOR scanning, and behavior graph construction.
- `--decompile`: Attempts external decompilation using JADX/apktool if found in PATH.
- `--case-id <ID>`: Sets case identifier for chain of custody.
- `--examiner <NAME>`: Sets examiner name or callsign.

### 2. Non-Destructive ADB Evidence Collection

Acquire logical triage evidence from an authorized Android device:

```bash
mafkit collect-adb -o case-001-adb --package com.example.suspect --case-id CASE-2026-001 --examiner "Analyst A"
```

*Before connecting devices, review [ADB_ACQUISITION_GUIDE.md](docs/ADB_ACQUISITION_GUIDE.md) for step-by-step device preparation.*

### 3. Tri-Factor Incident Correlation (APK + ADB + Timeline)

Correlate static APK capabilities with acquired handset state and a financial fraud timeline:

```bash
mafkit analyze suspicious.apk \
  -o case-001-analysis \
  --deep \
  --adb-dir case-001-adb \
  --timeline incident-timeline.csv \
  --case-id CASE-2026-001 \
  --examiner "Analyst A"
```

#### Incident Timeline CSV Format
A standard CSV with header:
```csv
timestamp,event,type,notes
2026-10-01 14:32:00,Unauthorized wire transfer,fraud,Transaction via banking app
2026-10-01 14:32:45,OTP SMS received,sms,SMS from bank gateway
```
*(A template is provided at `examples/timeline-template.csv`).*

### 4. USB Connected Phone Safety Scanning & Removal

Perform an automated safety audit of all installed third-party applications on a connected Android phone:

```bash
# Scan third-party apps and output per-app risk scorecards
mafkit scan-phone -o phone-scan-output --third-party-only

# Interactively remove a confirmed unwanted app for user 0
mafkit remove-app com.suspicious.app
```

*(See [docs/PHONE_SCANNER.md](docs/PHONE_SCANNER.md) and [docs/PHONE_SCANNER_MANUAL.txt](docs/PHONE_SCANNER_MANUAL.txt) for phone scanner documentation).*

---

## Evidence & Correlation Model

MAFKit strictly separates three distinct evidentiary tiers:

1. **APK Capability**: What the binary code is statically capable of performing (e.g., Accessibility API calls, SMS interception primitives).
2. **Device Artifacts**: What state and historical logs were observed on the physical device (e.g., package presence, enabled Accessibility services, notification logs).
3. **Correlation**: The observed intersection between APK capabilities, device state, and incident timeline events.

### Evidentiary Anchors & Rule-Based Correlation

Rather than arbitrary additive scores, correlation strength is evaluated via rule-based independent anchors:

| Correlation Strength | Criteria | Evidentiary Basis |
| :--- | :--- | :--- |
| **STRONG** | Package Identity + Privileged State + Runtime History | The exact package is present, active in privileged state (Accessibility/Admin), and documented in runtime history logs. |
| **MODERATE** | Package Identity + (Privileged State OR Runtime History) | Exact package identity is verified along with at least one independent supporting evidence category. |
| **LIMITED** | Single Anchor Only | Package presence or state is observed without independent corroboration. |
| **NONE** | No Anchors | No package-specific correlation anchor established from acquired evidence. |

*Integrity Cap:* If acquisition artifacts are missing or hash verification fails against `collection_manifest.json`, the assessment is automatically capped at `LIMITED`.

---

## Output Artifacts & Sample Reports

Analysis runs generate multiple synchronized outputs within the target directory:

```text
mafkit-output/
├── report.json             # Complete machine-readable analysis results
├── report.md               # Formatted Markdown report for investigator review
├── report.html             # Self-contained HTML report with styling
├── evidence.jsonl          # Streaming newline-delimited JSON of all findings
├── behavior_graph.json     # Graph data of call relationships and indicators
├── behavior_graph.dot      # Graphviz DOT source for visual diagramming
└── recovered/              # Carved DEX files and restored bytecode (when --deep is used)
    └── dpt/
        ├── original/       # Embedded DEX binaries extracted from packed shell
        └── restored/       # Clean DEX binaries with patched method bodies
```

Sample outputs are tracked and viewable in:
- [mafkit-output/report.md](mafkit-output/report.md) or [examples/sample-output-v3/report.md](examples/sample-output-v3/report.md) (Markdown)
- [mafkit-output/report.json](mafkit-output/report.json) or [examples/sample-output-v3/report.json](examples/sample-output-v3/report.json) (JSON)
- [mafkit-output/behavior_graph.json](mafkit-output/behavior_graph.json) (Call Graph)
- [docs/base-apk-behavior-report.md](docs/base-apk-behavior-report.md) (Forensic Assessment Report)

Every finding is assigned a deterministic identifier (`finding:<sha256>`) based on canonical JSON serialization for defensible cross-referencing.

---

## Development & Testing

MAFKit enforces high code quality, typing standards, and comprehensive test coverage.

### Running Tests

```bash
# Run full test suite
pytest -q

# Run with test coverage measurement
coverage run -m pytest -q
coverage report -m
```

### Static Analysis & Byte-Compilation

```bash
# Verify syntax and compilation across all modules
python -m compileall -q src tests
```

---

## Forensic Standards & Evidentiary Defensibility

MAFKit is designed to be **technically defensible**: it emphasizes repeatability, provenance, integrity verification, bounded parsing, explicit limitations, and separation of observed facts from analyst inference. 

Admissibility and evidentiary weight depend on jurisdiction, chain of custody, preservation practices, and independent corroboration:

1. **Preserve Original Artifacts**: Keep original APK files and raw ADB acquisition folders read-only. Perform analysis exclusively on working copies.
2. **Cryptographic Verification**: Always verify acquisition SHA-256 hashes against `collection_manifest.sha256` before drawing conclusions.
3. **Document Device Changes**: Document every host interaction, including enabling USB debugging or authorizing keys.
4. **Distinguish Capability from Execution**: Static presence of an API (e.g., `AccessibilityService`) proves code capability, but does not prove that the code executed at a specific timestamp.
5. **Distinguish Correlation from Attribution**: Strong correlation with an incident timeline does not by itself prove who was physically or remotely operating the handset.

For full forensic guidance, consult [docs/ADB_ACQUISITION_GUIDE.md](docs/ADB_ACQUISITION_GUIDE.md) and [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md).
