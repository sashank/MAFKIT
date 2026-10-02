"""Behavior graph construction from DEX bytecode references."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .dex import Dex

SUSPICIOUS = re.compile(
    r'(Accessibility|Sms|DeviceAdmin|MediaProjection|Screenshot|WebSocket|Socket|'
    r'Runtime;->exec|ProcessBuilder|upload|download|inject|overlay|keylog|camera|'
    r'microphone|BOOT_COMPLETED|shell|telnet|ssh|File|Notification|Gesture|Input|Clipboard)',
    re.I,
)


def build_behavior_graph(
    dex_paths: list[Path | str],
    outdir: Path,
    max_nodes: int = 250,
) -> dict[str, Any]:
    """Construct DOT and JSON call behavior graphs from suspicious DEX method references."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    truncated = False

    for fp in dex_paths:
        try:
            d = Dex(fp)
        except Exception as exc:
            errors.append({'dex': str(fp), 'error': f'{type(exc).__name__}: {exc}'})
            continue

        for mid in d.code:
            caller = d.mstr(mid)
            refs = d.refs(mid)
            evidence = [r[2] for r in refs if SUSPICIOUS.search(str(r[2]))]
            if not evidence and not SUSPICIOUS.search(caller):
                continue

            nodes[caller] = {
                'id': caller,
                'dex': Path(fp).name,
                'evidence': evidence[:20],
            }

            for typ, idx, val in refs:
                if typ == 'invoke' and SUSPICIOUS.search(val):
                    nodes.setdefault(val, {'id': val, 'dex': 'referenced', 'evidence': []})
                    edges.append({'source': caller, 'target': val, 'type': 'invokes'})

            if len(nodes) >= max_nodes:
                truncated = True
                break

        if truncated:
            break

    graph = {
        'nodes': list(nodes.values()),
        'edges': edges[:1000],
        'truncated': truncated or len(edges) > 1000,
        'max_nodes': max_nodes,
        'errors': errors,
    }

    Path(outdir).mkdir(parents=True, exist_ok=True)
    json_path = Path(outdir) / 'behavior_graph.json'
    json_path.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding='utf-8')

    ids = {n['id']: f'n{i}' for i, n in enumerate(graph['nodes'])}
    lines = [
        'digraph behavior {',
        '  rankdir=LR;',
        '  node [shape=box,fontname="Arial",fontsize=9];',
    ]
    for n in graph['nodes']:
        label = (
            n['id']
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', ' ')[:180]
        )
        lines.append(f'  {ids[n["id"]]} [label="{label}"];')

    for e in graph['edges']:
        if e['source'] in ids and e['target'] in ids:
            lines.append(f'  {ids[e["source"]]} -> {ids[e["target"]]};')
    lines.append('}')

    dot_path = Path(outdir) / 'behavior_graph.dot'
    dot_path.write_text('\n'.join(lines), encoding='utf-8')

    return graph
