from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    evidence: list[str] = field(default_factory=list)
    interpretation: str = ""
    confidence: str = "high"
    evidence_id: str = ""

@dataclass
class Report:
    input_file: str
    version: str = "3.1-forensic-review"
    analysis: dict[str, Any] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    file_info: dict[str, Any] = field(default_factory=dict)
    package: dict[str, Any] = field(default_factory=dict)
    signing: dict[str, Any] = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    components: dict[str, list[str]] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    packer: dict[str, Any] = field(default_factory=dict)
    dex: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    ioc_evidence: list[dict[str, Any]] = field(default_factory=list)
    decoded_strings: list[dict[str, Any]] = field(default_factory=list)
    deobfuscation: dict[str, Any] = field(default_factory=dict)
    behavior_graph: dict[str, Any] = field(default_factory=dict)
    attack_mapping: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    tools: dict[str, Any] = field(default_factory=dict)
    device_evidence: dict[str, Any] = field(default_factory=dict)
    correlation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d
