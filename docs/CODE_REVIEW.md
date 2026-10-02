# MAFKit v3.1 — Forensic-Grade Code Review

## Review objective

This review hardens MAFKit for repeatable technical analysis where outputs may be supplied to investigators, banks, counsel, or law-enforcement personnel. It does **not** certify the software as a court-accredited forensic product, and it does not replace jurisdiction-specific evidence-handling procedures or examiner judgment.

## High-impact issues identified and remediated

### 1. Acquisition artifacts were not hashed at collection time — FIXED
Each ADB command output, pulled APK, ADB version output, device-list output, and bugreport is now inventoried with byte size and SHA-256. `collection_manifest.json` records these values and `collection_manifest.sha256` provides a detached hash for the manifest itself.

### 2. ADB commands were not pinned to the selected device — FIXED
The collector now selects exactly one authorized device and executes all subsequent device-specific commands using `adb -s <serial> ...`. This prevents evidence from silently coming from a different attached device.

### 3. Collection provenance was too sparse — FIXED
The collector now records UTC start/end times, case ID, examiner, selected-device metadata, ADB executable path/version, exact argv, duration, return code, errors, output hash, and output size.

### 4. Package names could become unsafe local filenames — FIXED
Android package names supplied by users are validated before use. Path separators, traversal strings, malformed identifiers, and overlong values are rejected.

### 5. Correlation used an arbitrary additive score — FIXED
`STRONG/MODERATE/LIMITED/NONE` is now rule-based. Strong correlation requires three independent package-specific evidence classes: exact package identity, exact privileged-state evidence, and independent historical package references. Timeline availability alone never increases correlation strength.

### 6. Timeline comparisons lacked defensible timezone handling — FIXED
When `persist.sys.timezone` is acquired, package and incident timestamps are normalized consistently. If timestamps cannot be defensibly compared, the report states that rather than inventing a conversion.

### 7. ZIP/APK scanning could consume unbounded decompressed content — FIXED
The analyzer now imposes entry-count, per-entry scan, total scan, and full-read limits. Extreme compression ratios are flagged. This reduces exposure to decompression bombs and hostile APK containers.

### 8. DEX parsing lacked systematic bounds checks — FIXED
DEX primitive reads, ULEB128 decoding, table bounds, code-item bounds, payload sizes, method indices, and array-data sizes now fail closed on malformed data.

### 9. DPT restoration trusted method-store structure too much — FIXED
DPT section counts, record counts, record sizes, embedded DEX sizes, and offsets are bounded. Restored DEX files now have SHA-256 recorded after checksum/signature repair.

### 10. Deobfuscated strings were phrased too conclusively — FIXED
Repeating-XOR outputs are explicitly classified as **candidate plaintext** and require analyst corroboration. Result truncation and parser errors are retained in the report.

### 11. IOC extraction lacked provenance language — FIXED
Raw IOC hits retain source-entry provenance in `ioc_evidence`. Reports label them **candidate indicators** and warn that benign libraries, test endpoints, localhost values, or unrelated resources can create false positives.

### 12. Reports lacked stable evidence identifiers — FIXED
Findings now receive deterministic SHA-256-derived evidence IDs based on canonical finding content. This helps cross-reference JSON, Markdown, HTML, and JSONL outputs.

### 13. Report language could imply capability execution — FIXED
Wording now distinguishes API/code presence from runtime execution, permission grant, actor identity, intent, and transaction causation.

### 14. Graph/deobfuscation truncation could be silent — FIXED
Behavior graphs and XOR recovery now state whether configured result limits were reached.

## Test strategy

The suite includes normal, boundary, malformed, hostile-input, failure-path, and evidentiary-semantics tests. Examples include:

- hash/entropy/string primitives
- Android package-name validation and path-traversal rejection
- ADB missing/multiple/unauthorized device handling
- ADB serial pinning and acquisition-manifest hashing
- timeout handling and partial-output preservation
- package token-boundary matching (`com.foo` vs `com.foobar`)
- device timezone and incident-timeline normalization
- rule-based correlation matrix and timeline non-inflation
- malformed ZIP/APK handling
- bounded ZIP entry reads
- malformed/truncated DEX and ULEB128 input
- synthetic Dalvik `const-string` parsing
- synthetic byte-array construction and XOR-call recovery
- DPT malformed stores, method-size mismatch, successful instruction restoration, and appended-DEX extraction
- repeating-XOR false-positive filtering and truncation
- behavior-graph generation/error handling
- HTML escaping against report-content injection
- JSON/Markdown report structure
- CLI path/package failure modes

## Current automated-test result

- Tests: **100 passed**
- Overall line coverage: **87%**
- Selected module coverage:
  - Correlation: 96%
  - Device acquisition parser: 90%
  - Deobfuscation: 93%
  - ADB acquisition: 89%
  - Reporting: 87%
  - DPT plugin: 74%
  - DEX parser: 58%

Coverage is a diagnostic, not a forensic-validity metric. DEX parsing receives byte-level synthetic tests even where complete valid-DEX construction would add test bulk without equivalent evidentiary value.

## Regression against the original investigation APK

SHA-256: `dd373a6c97d919fb41d41dd4a82a13c7de261178571ce0e6560bbbb47da14182`

The hardened build still recovers:

- DPT method bodies: **10,750**
- Candidate XOR plaintexts: **4,046**
- Behavior graph: **252 nodes / 220 edges**

The XOR count is slightly lower than the earlier prototype because v3.1 deliberately tightened plaintext-quality scoring to reduce false positives.

## Residual limitations / examiner responsibilities

1. **Logical ADB collection is not a physical acquisition.** Modern Android sandboxing prevents ordinary ADB from reading many private application artifacts.
2. **Enabling USB debugging changes device state.** The examiner should document the pre-acquisition state, authorization action, date/time, device identity, and any settings changed.
3. **Absence of evidence is not evidence of absence.** Android/OEM retention, log rotation, app uninstall, permissions, and shell restrictions can remove or hide artifacts.
4. **Static capability does not prove execution.** Runtime/device/network corroboration remains necessary.
5. **Automated IOC extraction is triage.** Every externally actionable IOC should be analyst-validated.
6. **Packer/deobfuscator support is family-specific.** DPT is supported; arbitrary commercial/custom packers are not generically solvable.
7. **ATT&CK mapping is semantic.** Exact current MITRE Mobile ATT&CK IDs should be independently validated before formal citation.
8. **Tool/version preservation matters.** Preserve the exact MAFKit archive, Python version, dependencies, Android platform-tools version, generated manifest, and input hashes with the case.
9. **Independent validation is recommended for high-stakes claims.** Where practical, corroborate key findings with a second tool or manual reverse engineering and record the corroborating method.

## Recommended evidence-handling practice

For an investigation, preserve the original APK read-only, record its hashes before analysis, collect to a new case directory, keep the raw ADB acquisition unchanged after collection, analyze a working copy, and retain `collection_manifest.json`, `collection_manifest.sha256`, `report.json`, `evidence.jsonl`, tool versions, and the exact MAFKit release used.
