# MAFKit Development Roadmap

This document outlines the strategic product vision and technical milestones for **MAFKit** (**M**obile **A**PK + Android Device **F**orensic **Kit**). 

The roadmap builds upon MAFKit's established static reverse engineering, unpacked bytecode recovery, and logical ADB triage foundation, expanding into **automated dynamic sandbox orchestration** and **comprehensive MITRE ATT&CK for Mobile matrix integration**.

---

## Strategic Goals

1. **Defensible Tri-Factor Forensics**: Seamlessly fuse static APK capabilities, dynamic sandbox telemetry, and physical handset artifacts into unified, cross-validated incident timelines.
2. **Deterministic & Containable**: Maintain strict evidentiary provenance, repeatable execution, and zero-compromise host/network containment during analysis.
3. **Standards-Aligned Intelligence**: Native integration with industry frameworks (MITRE ATT&CK Mobile, STIX 2.1, and MISP) for seamless SOC/IR and law enforcement workflow integration.

---

## Roadmap Milestones

```
┌────────────────────────────────────────────────────────────────────────┐
│  Phase 1: Dynamic Sandbox Orchestration (Automated Detonation)        │
├────────────────────────────────────────────────────────────────────────┤
│  Phase 2: Full MITRE ATT&CK Mobile Integration (Techniques & STIX 2.1) │
├────────────────────────────────────────────────────────────────────────┤
│  Phase 3: Deep Packer Unpacking & Native Shared Object (.so) Analysis   │
├────────────────────────────────────────────────────────────────────────┤
│  Phase 4: Threat Intelligence, Graph Visualization & Enterprise API    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Dynamic Sandbox Analysis Engine

**Objective**: Provide automated, safely isolated dynamic execution of suspicious Android applications without risking production hardware or investigator workstations.

### 1.1 Isolated Environment Orchestration
- **Supported Sandbox Backends**:
  - **Headless Android Emulator (AVD)**: Automated QEMU-based AVD spin-up with hardware snapshot rollback.
  - **Cuttlefish / Android Virtual Device**: Cloud-native, containerized Android virtual environments.
  - **Dedicated Physical Testbed**: Hardened, network-isolated physical reference handsets with automated factory state flashing.
- **Network Containment & Egress Control**:
  - Out-of-band proxying (mitmproxy integration) with simulated fake-DNS and configurable sinkholing.
  - Pcap packet capture per analysis session with automated TLS master secret extraction (SSLKEYLOGFILE).
  - Configurable network profiles: *Isolated (Air-gapped)*, *Simulated Internet (Sinkhole)*, and *Controlled Live Egress*.

### 1.2 Automated Interactive Detonation
- **Stimulus & Trigger Automation**:
  - Automated grant of runtime permissions (Camera, SMS, Location, Storage) via ADB/UIAutomator to surface hidden post-permission behaviors.
  - Simulation of incoming SMS (containing mock OTP/banking codes) and phone calls (`adb emu sms send`).
  - Broadcast triggering (`BOOT_COMPLETED`, `ACTION_POWER_CONNECTED`, `CONNECTIVITY_CHANGE`, custom receivers).
  - UI exploration agent: Autonomous click and navigation fuzzing to bypass idle detection and trigger dormant stages.

### 1.3 Runtime Hooking & Telemetry (Frida & eBPF)
- **Non-Invasive API Interception**:
  - Automated injection of lightweight, anti-detection Frida scripts:
    - **Crypto & Key Logging**: Interception of `Cipher.doFinal`, `SecretKeySpec`, and custom crypto routines to capture runtime keys.
    - **Dynamic Code Loading**: Hooking `DexClassLoader`, `InMemoryDexClassLoader`, and `PathClassLoader` to intercept payloads decrypted into memory.
    - **IPC & Component Inspection**: Intercepting `Intent` resolutions, `startActivity`, `startService`, and clipboard access.
    - **Anti-Analysis Bypass**: Bypassing common root checks, emulator detection strings, and debugger detection hooks.

---

## Phase 2: Comprehensive MITRE ATT&CK for Mobile Integration

**Objective**: Upgrade semantic capability classifications into formal, version-controlled mappings against the official **MITRE ATT&CK® for Mobile Matrix (v14+)**.

### 2.1 Precise Technique & Sub-Technique Mapping
- **Direct Technique Identification**:
  Map static capabilities, dynamic runtime behaviors, and acquired device state directly to official MITRE Mobile technique IDs:

| Tactic | Technique ID | Technique Name | Evidence Anchor |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1476` | Deliver Malicious App | Installer package / sideloaded APK artifact |
| **Execution** | `T1644` | Command and Scripting Interpreter | ProcessBuilder / `Runtime.exec` / shell commands |
| **Persistence** | `T1624.001` | Broadcast Receivers: BOOT_COMPLETED | Manifest receiver / active boot registration |
| **Privilege Escalation** | `T1453` | Device Administrator Permissions | `DeviceAdminReceiver` / active policy hits |
| **Defense Evasion** | `T1406` | Obfuscated/Packed Code | DPT Shell / XOR strings / native payload carving |
| **Credential Access** | `T1417.001` | Input Capture: Keylogging | Accessibility event logging / view inspection |
| **Credential Access** | `T1411` | Input Prompt Injection (Overlays) | `SYSTEM_ALERT_WINDOW` / overlay injection hits |
| **Collection** | `T1412` | Capture SMS Messages | `SmsManager` / `Telephony$Sms` / granted SMS permissions |
| **Collection** | `T1413` | Screen Capture | `MediaProjectionManager` / screenshot APIs |
| **Command & Control** | `T1437.001` | Application Layer Protocol: Web Protocols | WebSocket / HTTP endpoints recovered in bytecode |

### 2.2 ATT&CK Navigator Layer Generation
- Automated export of `attack_layer.json` for direct import into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
- Color-coded severity scores based on verified runtime execution vs. static-only code presence.

### 2.3 Structured Threat Sharing (STIX 2.1 / TAXII)
- Export full case findings as standardized **STIX 2.1 JSON** bundles:
  - `Malware` and `AttackPattern` objects linked with `Relationship` graphs (`uses`, `indicates`, `targets`).
  - `ObservedData` and `Indicator` objects for C2 domains, IPs, file hashes, and certificate fingerprints.
  - Native export format for ingestion by threat intelligence platforms (MISP, OpenCTI, and ThreatConnect).

---

## Phase 3: Advanced Bytecode Unpacking & Native Library Reverse Engineering

**Objective**: Expand automated unpacking capabilities beyond DPT Shell to cover commercial and nation-state packer variants.

### 3.1 Commercial & Open-Source Packer Signatures
- Automated signature detection and payload carving for:
  - **Bangcle (SecNeo / 梆梆安全)**
  - **Qihoo 360 (Jiagu / 奇虎360)**
  - **Tencent Legu (乐固)**
  - **DexGuard / Promon SHIELD**
  - **Baidu Protection**
- Memory-dump based DEX extraction via memory scraper in sandbox mode.

### 3.2 Native Shared Object (`.so`) Triage
- Parsing ELF headers and section tables for architecture (`arm64-v8a`, `armeabi-v7a`).
- Automated extraction of exported JNI function bindings (`JNI_OnLoad`, `Java_*`).
- Identification of anti-debugging hooks (`ptrace(PTRACE_TRACEME)`, `/proc/self/status` TracerPid polling).

---

## Phase 4: Enterprise Correlation & Interactive Analytics

**Objective**: Transition from single-case CLI utility to collaborative, enterprise-grade forensic platform.

### 4.1 Multi-Case Campaign Correlation
- Cluster recurring threat campaigns across multiple handsets and APK variants using:
  - Cryptographic signing certificate subject/serial reuse.
  - Shared C2 infrastructure and repeating-XOR decryptor algorithms.
  - Similar behavior graph topology and instruction hashes (ssdeep / TLSH).

### 4.2 Interactive Web Visualization
- Interactive browser-based behavior graph viewer (Cytoscape.js) to explore call dependencies and threat flows.
- Visual timeline playback comparing handset events (first install, accessibility grant) with financial transactions.

### 4.3 REST API & Automation Pipelines
- Dockerized worker containers (`mafkit-worker`) with Celery/Redis queue for batch intake.
- OpenAPI 3.0 compliant REST interface for programmatic submission from SIEM, SOAR, or MDM webhook triggers.

---

## Release Milestones & Target Versions

| Version | Focus | Key Deliverables |
| :---: | :--- | :--- |
| **v3.2** | **Formal ATT&CK Mobile Integration** | Full ATT&CK Mobile technique mapping, Navigator JSON export, and STIX 2.1 bundles. |
| **v3.3** | **Dynamic Sandbox Foundation** | Headless AVD orchestration, pcap network capture, and automated permission granting. |
| **v3.4** | **Frida Runtime Instrumentation** | Memory DEX carving, crypto interception, and dynamic API call graphs. |
| **v4.0** | **Multi-Packer & Enterprise Platform** | Multi-packer support (Qihoo/Bangcle), REST API, and multi-case campaign clustering. |

---

## Contributing & Feedback

Have ideas, feature requests, or want to contribute to the roadmap?
- Submit an issue or feature proposal on GitHub: [https://github.com/sashank/MAFKIT/issues](https://github.com/sashank/MAFKIT/issues)
- Review contribution and code standards in [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md).
