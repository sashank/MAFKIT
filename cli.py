"""Command-line interface for MAFKit: static analysis, deep unpacking, and ADB correlation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from .adbcollect import collect as adb_collect
from .analyzers import APKAnalyzer
from .attack import map_capabilities
from .behavior import build_behavior_graph
from .correlation import correlate
from .deobfuscation import scan_dex_xor
from .device import parse_device_acquisition, parse_timeline_csv
from .forensic import (
    environment_snapshot,
    stable_evidence_id,
    utc_now_iso,
    validate_package_name,
)
from .model import Finding, Report
from .plugins.dpt import DPTPlugin
from .reporting import write_html, write_json, write_markdown
from .util import DOMAIN_RE, IP_RE, URL_RE, WS_RE, uniq


def _enrich_iocs(report: Report, strings: list[str]) -> None:
    """Enrich candidate IOCs with domains, IPs, and URLs found in decoded strings."""
    raw = '\n'.join(strings).encode('utf-8', 'ignore')
    urls = uniq(
        report.iocs.get('urls', [])
        + [m.decode('utf-8', 'ignore') for m in URL_RE.findall(raw)]
        + [m.decode('utf-8', 'ignore') for m in WS_RE.findall(raw)]
    )
    domains = uniq(
        report.iocs.get('domains', [])
        + [m.decode('ascii', 'ignore') for m in DOMAIN_RE.findall(raw)]
    )
    ips = uniq(
        report.iocs.get('ipv4', [])
        + [m.decode('ascii', 'ignore') for m in IP_RE.findall(raw)]
    )
    report.iocs = {
        'urls': urls[:1000],
        'domains': domains[:1000],
        'ipv4': ips[:1000],
    }


def _finalize_findings(report: Report) -> None:
    """Assign stable, deterministic SHA-256 evidence identifiers to all findings."""
    for f in report.findings:
        if not f.evidence_id:
            f.evidence_id = stable_evidence_id('finding', {
                'category': f.category,
                'title': f.title,
                'evidence': f.evidence,
                'interpretation': f.interpretation,
                'confidence': f.confidence,
            })


def analyze(args: argparse.Namespace) -> Report:
    """Execute complete static APK analysis and optional device/timeline correlation."""
    if not args.apk.is_file():
        raise SystemExit('APK file not found')

    package_override = validate_package_name(getattr(args, 'package', None))
    args.out.mkdir(parents=True, exist_ok=True)

    report = Report(input_file=str(args.apk.resolve()))
    report.analysis = {
        'started_utc': utc_now_iso(),
        'completed_utc': None,
        'case_id': getattr(args, 'case_id', None) or '',
        'examiner': getattr(args, 'examiner', None) or '',
        'environment': environment_snapshot(),
        'mode': {
            'deep': bool(args.deep),
            'decompile': bool(args.decompile),
        },
    }

    analyzer = APKAnalyzer(args.apk, args.out)
    ctx = None
    try:
        ctx = analyzer.build_context()
        analyzer.analyze_base(report, ctx)

        for plugin in [DPTPlugin()]:
            try:
                plugin.analyze(ctx, report)
            except Exception as e:
                report.limitations.append(
                    f'Plugin {plugin.name} failed: {type(e).__name__}: {e}'
                )

        if report.packer.get('detected'):
            report.findings.append(Finding(
                severity='high',
                category='packer',
                title='Code packing/protection detected',
                evidence=report.packer.get('evidence', []),
                interpretation=(
                    'Packing/protection can conceal executable logic and configuration from '
                    'ordinary decompilation. Detection does not itself imply malicious intent.'
                ),
                confidence='high',
            ))

        dexes = [
            Path(x)
            for x in report.dex.get('analysis_dexes', [])
            if Path(x).is_file()
        ]

        if args.deep and dexes:
            xor_result = scan_dex_xor(dexes)
            hits = xor_result['hits']
            op_re = re.compile(
                r'(sms|otp|screen|access|admin|lock|cover|front|shell|exec|command|socket|'
                r'websocket|host|url|notification|upload|download|inject|overlay|keylog|'
                r'camera|microphone|device|client|server|bank|upi|pay|wallet|miner|file|'
                r'clip|chat|terminal|clone|fetch|record)',
                re.I,
            )
            operational: list[dict[str, Any]] = []
            seen: set[str] = set()

            for x in hits:
                value = x['decoded'].strip()
                if op_re.search(value) and len(value) <= 160 and value not in seen:
                    seen.add(value)
                    operational.append({
                        'value': value,
                        'method': x['method'],
                        'score': x['score'],
                        'classification': 'candidate operational string',
                    })

            report.deobfuscation = {
                'xor_hits': hits,
                'operational_strings': operational[:1000],
                'strategy': 'generic two-byte-array to String repeating-XOR candidate recovery',
                'truncated': xor_result['truncated'],
                'errors': xor_result['errors'],
            }
            _enrich_iocs(report, [x['decoded'] for x in hits])
            report.behavior_graph = build_behavior_graph(dexes, args.out)

            if hits:
                interesting = [
                    x['decoded'] for x in hits
                    if re.search(
                        r'(screen|sms|keylog|inject|overlay|websocket|shell|upload|download|'
                        r'admin|camera|microphone|lock|otp|bank|upi|pay)',
                        x['decoded'],
                        re.I,
                    )
                ]
                if interesting:
                    report.findings.append(Finding(
                        severity='high',
                        category='deobfuscation',
                        title='Candidate hidden operational strings recovered',
                        evidence=interesting[:40],
                        interpretation=(
                            'Static repeating-XOR reconstruction produced plausible operational '
                            'strings. These are analyst leads and should be corroborated with '
                            'code-path or runtime/device evidence.'
                        ),
                        confidence='medium',
                    ))
        elif args.deep:
            report.limitations.append(
                'Deep analysis requested but no restored/recoverable DEX set was available for bytecode-level analysis.'
            )

        report.attack_mapping = map_capabilities(report.capabilities)
        if args.decompile:
            analyzer.optional_decompile(report)

        if package_override and not report.package.get('package_name'):
            report.package['package_name'] = package_override

        if args.adb_dir:
            report.device_evidence = parse_device_acquisition(
                args.adb_dir,
                report.package.get('package_name'),
            )
            report.correlation = correlate(
                report,
                report.device_evidence,
                parse_timeline_csv(args.timeline),
            )
            if report.correlation.get('correlation_strength') in ('moderate', 'strong'):
                report.findings.append(Finding(
                    severity='high',
                    category='device_correlation',
                    title='Package-specific device artifacts support incident relevance',
                    evidence=[
                        x['finding']
                        for x in report.correlation.get('correlations', [])
                        if x.get('confidence') == 'high'
                    ][:15],
                    interpretation=(
                        'Independent package-specific device artifacts are consistent with the '
                        'analyzed APK being present or active in relevant device state. This does '
                        'not prove a particular user action or transaction cause.'
                    ),
                    confidence='high',
                ))
    finally:
        try:
            if ctx and ctx.get('zip'):
                ctx['zip'].close()
        except Exception:
            pass

    report.analysis['completed_utc'] = utc_now_iso()
    _finalize_findings(report)

    write_json(report, args.out / 'report.json')
    write_markdown(report, args.out / 'report.md')
    write_html(report, args.out / 'report.html')

    with (args.out / 'evidence.jsonl').open('w', encoding='utf-8') as fh:
        for f in report.to_dict()['findings']:
            fh.write(json.dumps({'type': 'finding', **f}, ensure_ascii=False, sort_keys=True) + '\n')
        for x in report.deobfuscation.get('operational_strings', []):
            fh.write(json.dumps({'type': 'deobfuscated_string', **x}, ensure_ascii=False, sort_keys=True) + '\n')
        for x in report.correlation.get('correlations', []):
            fh.write(json.dumps({'type': 'device_correlation', **x}, ensure_ascii=False, sort_keys=True) + '\n')

    summary = {
        'version': report.version,
        'output': str(args.out.resolve()),
        'sha256': report.hashes.get('sha256'),
        'package': report.package.get('package_name'),
        'findings': len(report.findings),
        'restored_methods': report.packer.get('method_restoration', {}).get('total_methods_restored', 0),
        'xor_strings': len(report.deobfuscation.get('xor_hits', [])),
        'graph_nodes': len(report.behavior_graph.get('nodes', [])),
        'device_correlation': report.correlation.get('correlation_strength', 'not-run'),
    }
    print(json.dumps(summary, indent=2))
    return report


def main(argv: Sequence[str] | None = None) -> None:
    """Main CLI entrypoint supporting `analyze` and `collect-adb` subcommands."""
    p = argparse.ArgumentParser(
        prog='mafkit',
        description='MAFKit v3.1 — forensic-reviewed APK analysis plus Android/ADB evidence correlation',
    )
    sub = p.add_subparsers(dest='command')

    a = sub.add_parser('analyze', help='Analyze APK and optionally correlate ADB evidence')
    a.add_argument('apk', type=Path, help='Path to target APK file')
    a.add_argument('-o', '--out', type=Path, default=Path('mafkit-output'), help='Output directory')
    a.add_argument('--deep', action='store_true', help='Enable deep unpacking and repeating-XOR scanning')
    a.add_argument('--decompile', action='store_true', help='Attempt external decompilation (jadx/apktool)')
    a.add_argument('--adb-dir', type=Path, help='Directory produced by mafkit collect-adb or supplied acquisition')
    a.add_argument('--package', help='Optional package-name override if APK manifest parsing is unavailable')
    a.add_argument('--timeline', type=Path, help='CSV timeline with timestamp,event,type columns')
    a.add_argument('--case-id', help='Case identifier for chain of custody and reporting')
    a.add_argument('--examiner', help='Examiner name or callsign')

    c = sub.add_parser('collect-adb', help='Non-destructive ADB evidence collection from one authorized Android device')
    c.add_argument('-o', '--out', type=Path, default=Path('adb-acquisition'), help='Output directory')
    c.add_argument('--package', help='Target package name for focused dumpsys/APK pull')
    c.add_argument('--no-bugreport', action='store_true', help='Skip bugreport collection')
    c.add_argument('--case-id', help='Case identifier')
    c.add_argument('--examiner', help='Examiner name')

    raw = sys.argv[1:] if argv is None else list(argv)
    if raw and raw[0] not in ('analyze', 'collect-adb', '-h', '--help'):
        raw = ['analyze', *raw]

    args = p.parse_args(raw)

    if args.command == 'collect-adb':
        manifest = adb_collect(
            out=args.out,
            package=args.package,
            bugreport=not args.no_bugreport,
            case_id=args.case_id,
            examiner=args.examiner,
        )
        print(json.dumps({
            'output': str(args.out.resolve()),
            'commands': len(manifest['commands']),
            'manifest': 'collection_manifest.json',
        }, indent=2))
        return

    if args.command == 'analyze':
        analyze(args)
        return

    p.print_help()


if __name__ == '__main__':
    main()
