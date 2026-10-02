"""Conservative ATT&CK-style semantic capability mapping for mobile forensic analysis.

Technique IDs are intentionally omitted: analysts should validate exact official
Mobile ATT&CK IDs against the current MITRE catalog.
"""

from __future__ import annotations

from typing import Any

MAP: dict[str, tuple[str, str]] = {
    'accessibility': (
        'Collection / Credential Access',
        'Input/UI capture and automated interaction',
    ),
    'sms': (
        'Collection',
        'SMS/message collection or manipulation',
    ),
    'device_admin': (
        'Persistence / Defense Evasion',
        'Elevated device administration',
    ),
    'screen_capture': (
        'Collection',
        'Screen capture',
    ),
    'websocket': (
        'Command and Control',
        'Bidirectional application-layer channel',
    ),
    'shell': (
        'Execution',
        'Command or shell execution',
    ),
    'keylogging': (
        'Credential Access / Collection',
        'Input capture / keylogging',
    ),
    'camera_mic_privacy_bypass': (
        'Defense Evasion',
        'Attempted privacy-indicator suppression',
    ),
    'file_transfer': (
        'Collection / Exfiltration',
        'File collection and transfer',
    ),
    'overlay_injection': (
        'Credential Access',
        'Phishing/overlay injection',
    ),
    'persistence': (
        'Persistence',
        'Boot/background-service persistence',
    ),
}


def map_capabilities(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    """Map detected APK capabilities to high-level ATT&CK tactics and behaviors."""
    out: list[dict[str, Any]] = []
    for k, v in capabilities.items():
        if v.get('detected') and k in MAP:
            tactic, behavior = MAP[k]
            out.append({
                'capability': k,
                'tactic': tactic,
                'behavior': behavior,
                'evidence': v.get('evidence', []),
            })
    return out
