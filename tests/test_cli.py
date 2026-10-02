"""Unit tests for MAFKit CLI arguments, orchestrator, and report generation."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import patch
import pytest

from mafkit.cli import _enrich_iocs, _finalize_findings, analyze, main
from mafkit.model import Finding, Report


def make_apk(p: Path, extra_entries: dict[str, bytes] | None = None) -> None:
    with zipfile.ZipFile(p, 'w') as z:
        z.writestr('x.txt', 'WebSocket ws://127.0.0.1:8080/')
        if extra_entries:
            for k, v in extra_entries.items():
                z.writestr(k, v)


def test_cli_basic_report(tmp_path: Path):
    apk = tmp_path / 'x.apk'
    out = tmp_path / 'out'
    make_apk(apk)
    main([
        'analyze',
        str(apk),
        '-o',
        str(out),
        '--case-id',
        'C1',
        '--examiner',
        'E',
    ])
    r = json.loads((out / 'report.json').read_text(encoding='utf-8'))
    assert r['analysis']['case_id'] == 'C1'
    assert r['hashes']['sha256']
    assert (out / 'report.md').is_file()
    assert (out / 'report.html').is_file()
    assert (out / 'evidence.jsonl').is_file()


def test_cli_invalid_package(tmp_path: Path):
    apk = tmp_path / 'x.apk'
    make_apk(apk)
    with pytest.raises(ValueError, match="Invalid Android package name"):
        main([
            'analyze',
            str(apk),
            '-o',
            str(tmp_path / 'out'),
            '--package',
            '../evil',
        ])


def test_cli_missing_apk(tmp_path: Path):
    with pytest.raises(SystemExit):
        main(['analyze', str(tmp_path / 'missing.apk')])


def test_enrich_iocs():
    r = Report(input_file="test.apk")
    strings = [
        "Connecting to https://api.threat.com/v1",
        "ws://c2.threat.com:8443",
        "Direct connection to 192.168.1.100 endpoint",
    ]
    _enrich_iocs(r, strings)
    assert any("https://api.threat.com/v1" in u for u in r.iocs['urls'])
    assert any("threat.com" in d for d in r.iocs['domains'])
    assert "192.168.1.100" in r.iocs['ipv4']


def test_finalize_findings():
    r = Report(input_file="test.apk")
    f = Finding(
        severity="high",
        category="test",
        title="Test finding",
        evidence=["ev1"],
        interpretation="interp",
        confidence="high",
    )
    r.findings.append(f)
    assert not f.evidence_id
    _finalize_findings(r)
    assert f.evidence_id.startswith("finding:")


def test_cli_deep_without_dexes_adds_limitation(tmp_path: Path):
    apk = tmp_path / 'no_dex.apk'
    out = tmp_path / 'out_no_dex'
    make_apk(apk)
    main(['analyze', str(apk), '-o', str(out), '--deep'])
    r = json.loads((out / 'report.json').read_text(encoding='utf-8'))
    assert any("no restored/recoverable DEX set was available" in x for x in r['limitations'])


def test_cli_deep_with_analysis_dexes(monkeypatch, tmp_path: Path):
    apk = tmp_path / 'sample.apk'
    out = tmp_path / 'out_deep'
    dex_path = tmp_path / 'fake.dex'
    dex_path.write_bytes(b'dex\nFAKE')
    make_apk(apk)

    # Monkeypatch APKAnalyzer.analyze_base to populate analysis_dexes
    from mafkit.analyzers import APKAnalyzer
    orig_analyze_base = APKAnalyzer.analyze_base

    def mock_analyze_base(self, report, ctx):
        orig_analyze_base(self, report, ctx)
        report.dex['analysis_dexes'] = [str(dex_path)]

    monkeypatch.setattr(APKAnalyzer, 'analyze_base', mock_analyze_base)
    monkeypatch.setattr('mafkit.cli.scan_dex_xor', lambda dexes: {
        'hits': [{
            'decoded': 'sms_interception_payload',
            'method': 'LTest;->run()V',
            'score': 0.95,
        }],
        'errors': [],
        'truncated': False,
    })
    monkeypatch.setattr('mafkit.cli.build_behavior_graph', lambda dexes, out: {
        'nodes': [{'id': 'n1', 'dex': 'fake.dex', 'evidence': []}],
        'edges': [],
    })

    main(['analyze', str(apk), '-o', str(out), '--deep'])
    r = json.loads((out / 'report.json').read_text(encoding='utf-8'))
    assert len(r['deobfuscation']['operational_strings']) == 1
    assert r['deobfuscation']['operational_strings'][0]['value'] == 'sms_interception_payload'
    assert any(f['category'] == 'deobfuscation' for f in r['findings'])


def test_cli_collect_adb_command(monkeypatch, tmp_path: Path):
    mock_manifest = {
        'collection_start_utc': '2026-10-02T12:00:00Z',
        'commands': [{'file': 'getprop.txt'}],
        'artifacts': [],
    }
    monkeypatch.setattr('mafkit.cli.adb_collect', lambda **kwargs: mock_manifest)
    out = tmp_path / 'adb_out'
    main(['collect-adb', '-o', str(out), '--case-id', 'CASE-99', '--examiner', 'Agent'])


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(['--help'])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "MAFKit" in captured.out
