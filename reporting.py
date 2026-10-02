"""Report generation in JSON, Markdown, HTML, and streaming JSONL formats."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .model import Report

SEV_ORDER: dict[str, int] = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
    'info': 4,
}


def write_json(report: Report, path: Path) -> None:
    """Serialize full report to formatted JSON."""
    data = json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True)
    path.write_text(data, encoding='utf-8')


def _md_escape(s: Any) -> str:
    return str(s).replace('`', '\\`')


def _md_list(items: list[str]) -> str:
    if not items:
        return '- None found'
    return '\n'.join(f'- `{_md_escape(x)}`' for x in items)


def write_markdown(report: Report, path: Path) -> None:
    """Generate Markdown report for investigator review."""
    d = report.to_dict()
    fs = sorted(d['findings'], key=lambda x: SEV_ORDER.get(x['severity'], 9))
    crit = sum(1 for f in fs if f['severity'] == 'critical')
    high = sum(1 for f in fs if f['severity'] == 'high')

    lines: list[str] = [
        '# Mobile APK + Device Forensic Analysis Report — MAFKit v3.1',
        '',
        '> Automated static APK analysis plus optional logical/read-oriented ADB correlation. '
        'Findings are technical indicators, not conclusions about actor identity, intent, or transaction causation.',
        '',
        '## Analysis Provenance',
        '',
    ]

    a = d.get('analysis', {})
    lines.extend([
        f"- **Started (UTC):** `{a.get('started_utc', '')}`",
        f"- **Completed (UTC):** `{a.get('completed_utc', '')}`",
        f"- **Case ID:** `{_md_escape(a.get('case_id', ''))}`",
        f"- **Examiner:** `{_md_escape(a.get('examiner', ''))}`",
        f"- **Input path:** `{_md_escape(d.get('input_file', ''))}`",
        '',
    ])

    lines.extend([
        '## Executive Summary',
        '',
        f'Automated analysis produced **{crit} critical** and **{high} high-severity indicators**. '
        'Severity reflects potential security impact if the associated capability is actually enabled/executed; '
        'it is not a malware verdict by itself.',
        '',
    ])

    if d.get('packer', {}).get('method_restoration', {}).get('restored'):
        r = d['packer']['method_restoration']
        lines.append(
            f"Deep recovery restored **{r.get('total_methods_restored', 0):,} method bodies** "
            f"across {len(r.get('dexes', []))} DEX files."
        )

    if d.get('deobfuscation', {}).get('xor_hits'):
        lines.append(
            f"Recovered **{len(d['deobfuscation']['xor_hits']):,} candidate repeating-XOR plaintext strings** "
            f"from restored bytecode."
        )

    if d.get('correlation'):
        c = d['correlation']
        lines.append(
            f"Device correlation assessment: **{c.get('correlation_strength', 'unknown').upper()}** "
            f"— {c.get('assessment_rationale', '')}"
        )

    lines.extend(['', '## Sample Identity', ''])
    for k, v in d['hashes'].items():
        lines.append(f'- **{k.upper()}**: `{v}`')
    for k, v in d['package'].items():
        lines.append(f"- **{k.replace('_', ' ').title()}**: `{_md_escape(v)}`")

    lines.extend(['', '## Findings', ''])
    for f in fs:
        lines.extend([
            f"### [{f['severity'].upper()}] {f['title']}",
            f"**Confidence:** {f['confidence']}  ",
            f"**Evidence ID:** `{f.get('evidence_id', '')}`",
            '',
            f['interpretation'],
            '',
            'Evidence:',
        ])
        lines.extend([f'- `{_md_escape(e)}`' for e in f['evidence']])
        lines.append('')

    if d.get('device_evidence'):
        dev = d['device_evidence']
        lines.extend(['## Device / ADB Acquisition', ''])
        man = dev.get('collection_manifest', {})
        if man:
            lines.extend([
                f"- **Collection start (UTC):** `{man.get('collection_start_utc', '')}`",
                f"- **Collection end (UTC):** `{man.get('collection_end_utc', '')}`",
                f"- **Selected device serial:** `{_md_escape(man.get('selected_device', {}).get('serial', ''))}`",
                f"- **Evidence artifacts in manifest:** **{len(man.get('artifacts', []))}**",
                '',
            ])
        for k, v in dev.get('device', {}).items():
            lines.append(f'- **{k}**: `{_md_escape(v)}`')
        lines.extend([
            '',
            f"- Evidence files independently inventoried by analyzer: **{len(dev.get('files', {}))}**",
            f"- Package first install: `{_md_escape(dev.get('package', {}).get('first_install_time', 'not available'))}`",
            f"- Package last update: `{_md_escape(dev.get('package', {}).get('last_update_time', 'not available'))}`",
            '',
        ])
        lines.extend(['### Security State', ''])
        for k, v in dev.get('security_state', {}).items():
            if v:
                lines.append(f'- **{k}**: `{_md_escape(str(v)[:1800])}`')

    if d.get('correlation'):
        c = d['correlation']
        lines.extend([
            '',
            '## APK ↔ Device Correlation',
            '',
            f"**Assessment:** {c.get('correlation_strength', 'unknown')}  ",
            f"**Basis:** {c.get('assessment_basis', '')}  ",
            f"**Rationale:** {c.get('assessment_rationale', '')}",
            '',
            c.get('interpretation', ''),
            '',
        ])
        for x in c.get('correlations', []):
            lines.extend([
                f"### {x['finding']}",
                f"**Confidence:** {x['confidence']} | **Category:** {x['category']}",
                '',
            ])
            lines.extend([f'- `{_md_escape(e)}`' for e in x.get('evidence', [])])
            lines.append('')

        if c.get('temporal_comparisons'):
            lines.extend(['### Temporal Comparisons', ''])
            for x in c['temporal_comparisons'][:100]:
                lines.append(
                    f"- `{_md_escape(x.get('timestamp', ''))}` — {_md_escape(x.get('event', ''))}; "
                    f"seconds after install: `{x.get('seconds_after_install')}`"
                )
        elif c.get('timeline'):
            lines.extend([
                '### Supplied Incident Timeline',
                '',
                '> Timeline supplied, but no defensible automatic temporal ordering was derived '
                'for one or more entries (for example, timezone or timestamp parsing limitations).',
                '',
            ])
            for x in c['timeline'][:100]:
                lines.append(
                    f"- `{_md_escape(x.get('timestamp', ''))}` — {_md_escape(x.get('event', ''))} "
                    f"({_md_escape(x.get('type', ''))})"
                )

    lines.extend([
        '',
        '## ATT&CK-style Behavior Mapping',
        '',
        '> Semantic analyst mapping only. Validate exact current MITRE Mobile ATT&CK '
        'technique IDs separately before citing them in formal proceedings.',
        '',
    ])
    for x in d.get('attack_mapping', []):
        lines.append(f"- **{x['tactic']}** — {x['behavior']} (`{x['capability']}`)")

    xr = d.get('deobfuscation', {}).get('xor_hits', [])
    lines.extend([
        '',
        '## Deep Deobfuscation',
        '',
        f'- Candidate repeating-XOR plaintexts recovered: **{len(xr)}**',
    ])
    if d.get('deobfuscation', {}).get('truncated'):
        lines.append('- **Note:** XOR result collection reached its configured maximum and is truncated.')
    for x in xr[:120]:
        lines.append(
            f"- `{_md_escape(x['decoded'][:300])}` — `{_md_escape(x['method'])}` — "
            f"{x.get('classification', 'candidate')}"
        )

    bg = d.get('behavior_graph', {})
    lines.extend([
        '',
        '## Behavior Graph',
        '',
        f"- Nodes: **{len(bg.get('nodes', []))}**",
        f"- Edges: **{len(bg.get('edges', []))}**",
        f"- Truncated: **{bool(bg.get('truncated'))}**",
        '- Machine-readable graph: `behavior_graph.json`',
        '- Graphviz source: `behavior_graph.dot`',
        '',
    ])

    lines.extend([
        '## Candidate Indicators of Compromise',
        '',
        '### URLs / WebSockets',
        _md_list(d['iocs'].get('urls', [])),
        '',
        '### Domains',
        _md_list(d['iocs'].get('domains', [])),
        '',
        '### IPv4',
        _md_list(d['iocs'].get('ipv4', [])),
        '',
        '> IOC extraction is automated. Validate routability, context, provenance, '
        'and benign-library origin before operational blocking or legal attribution.',
        '',
    ])

    lines.extend(['## Limitations', ''])
    lines.extend([f'- {x}' for x in d['limitations']])
    if d.get('device_evidence'):
        lines.extend([f'- {x}' for x in d['device_evidence'].get('limitations', [])])

    path.write_text('\n'.join(lines), encoding='utf-8')


def write_html(report: Report, path: Path) -> None:
    """Generate self-contained HTML forensic summary report."""
    d = report.to_dict()
    fs = sorted(d['findings'], key=lambda x: SEV_ORDER.get(x['severity'], 9))

    def esc(x: Any) -> str:
        return html.escape(str(x))

    rows = ''.join(
        f"<tr>"
        f"<td>{esc(f['severity'].upper())}</td>"
        f"<td>{esc(f['title'])}<br><small>Confidence: {esc(f['confidence'])}<br>Evidence ID: {esc(f.get('evidence_id', ''))}</small></td>"
        f"<td>{esc(f['interpretation'])}</td>"
        f"<td><code>{'<br>'.join(esc(e) for e in f['evidence'])}</code></td>"
        f"</tr>"
        for f in fs
    )

    hashes = ''.join(f'<li><b>{esc(k.upper())}</b>: <code>{esc(v)}</code></li>' for k, v in d['hashes'].items())
    pkg = ''.join(f'<li><b>{esc(k)}</b>: <code>{esc(v)}</code></li>' for k, v in d['package'].items())

    corr = ''
    if d.get('correlation'):
        c = d['correlation']
        cr = ''.join(
            f"<tr><td>{esc(x['confidence'])}</td><td>{esc(x['category'])}</td>"
            f"<td>{esc(x['finding'])}</td><td><code>{'<br>'.join(esc(e) for e in x.get('evidence', []))}</code></td></tr>"
            for x in c.get('correlations', [])
        )
        corr = (
            f"<h2>APK ↔ Device Correlation</h2>"
            f"<p><b>Assessment:</b> {esc(c.get('correlation_strength'))}</p>"
            f"<p><b>Basis:</b> {esc(c.get('assessment_basis', ''))}</p>"
            f"<p><b>Rationale:</b> {esc(c.get('assessment_rationale', ''))}</p>"
            f"<p>{esc(c.get('interpretation', ''))}</p>"
            f"<table><tr><th>Confidence</th><th>Category</th><th>Finding</th><th>Evidence</th></tr>{cr}</table>"
        )

    dev = ''
    if d.get('device_evidence'):
        x = d['device_evidence']
        dev_summary = {
            'device': x.get('device', {}),
            'package': x.get('package', {}),
            'security_state': x.get('security_state', {}),
            'collection_manifest': x.get('collection_manifest', {}),
            'evidence_file_count': len(x.get('files', {})),
        }
        dev = f"<h2>Device / ADB Acquisition</h2><pre>{esc(json.dumps(dev_summary, indent=2))}</pre>"

    atk = ''.join(
        f"<tr><td>{esc(x['tactic'])}</td><td>{esc(x['behavior'])}</td><td><code>{esc(x['capability'])}</code></td></tr>"
        for x in d.get('attack_mapping', [])
    )

    xor = ''.join(
        f"<tr><td><code>{esc(x['decoded'][:500])}</code></td><td><code>{esc(x['method'])}</code></td><td>{esc(x['score'])}</td></tr>"
        for x in d.get('deobfuscation', {}).get('xor_hits', [])[:200]
    )

    iocs = ''.join(
        f"<h3>{esc(k)}</h3><pre>{esc(chr(10).join(v) or 'None found')}</pre>"
        for k, v in d['iocs'].items()
    )

    a = d.get('analysis', {})
    prov_data = {
        'started_utc': a.get('started_utc'),
        'completed_utc': a.get('completed_utc'),
        'case_id': a.get('case_id'),
        'examiner': a.get('examiner'),
        'input_file': d.get('input_file'),
        'environment': a.get('environment', {}),
    }
    prov = esc(json.dumps(prov_data, indent=2))

    limitations_list = ''.join(
        f'<li>{esc(x)}</li>'
        for x in d['limitations'] + d.get('device_evidence', {}).get('limitations', [])
    )

    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MAFKit v3.1 Forensic Report</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 32px auto; line-height: 1.45; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; }}
td, th {{ border: 1px solid #d6d6d6; padding: 8px; vertical-align: top; }}
th {{ background: #f0f0f0; }}
code, pre {{ font-family: Consolas, monospace; white-space: pre-wrap; word-break: break-word; }}
.note {{ padding: 12px; background: #f4f6f8; border-left: 4px solid #555; }}
small {{ color: #666; }}
</style>
</head>
<body>
<h1>Mobile APK + Device Forensic Analysis Report — MAFKit v3.1</h1>
<div class="note">Automated static APK analysis plus optional logical/read-oriented ADB correlation. Technical indicators do not establish actor identity, intent, execution, or transaction causation without corroboration.</div>
<h2>Analysis Provenance</h2>
<pre>{prov}</pre>
<h2>Sample Identity</h2>
<ul>{hashes}{pkg}</ul>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Interpretation</th><th>Evidence</th></tr>{rows}</table>
{dev}
{corr}
<h2>ATT&amp;CK-style Behavior Mapping</h2>
<table><tr><th>Tactic</th><th>Behavior</th><th>Capability</th></tr>{atk}</table>
<h2>Deep Deobfuscation</h2>
<p>Recovered {len(d.get('deobfuscation', {}).get('xor_hits', []))} candidate repeating-XOR plaintext strings.</p>
<table><tr><th>Decoded string</th><th>Method</th><th>Score</th></tr>{xor}</table>
<h2>Candidate Indicators of Compromise</h2>
{iocs}
<p><i>Validate context and provenance before blocking or attribution.</i></p>
<h2>Limitations</h2>
<ul>{limitations_list}</ul>
</body>
</html>"""

    path.write_text(body, encoding='utf-8')
