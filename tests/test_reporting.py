"""Unit tests for reporting modules: JSON, Markdown, and HTML report rendering."""

from __future__ import annotations

import json
from pathlib import Path

from mafkit.model import Finding, Report
from mafkit.reporting import write_html, write_json, write_markdown


def sample() -> Report:
    r = Report('/tmp/a.apk')
    r.analysis = {
        'started_utc': '2026-10-02T10:00:00Z',
        'completed_utc': '2026-10-02T10:05:00Z',
        'case_id': 'C1',
        'examiner': 'E',
    }
    r.hashes = {'sha256': 'abc'}
    r.package = {'package_name': 'com.x.app'}
    r.iocs = {
        'urls': ['https://x.test?a=<b>'],
        'domains': ['x.test'],
        'ipv4': [],
    }
    r.findings = [
        Finding(
            severity='high',
            category='x',
            title='Title',
            evidence=['<script>alert(1)</script>'],
            interpretation='Interpret',
            confidence='high',
            evidence_id='finding:1',
        )
    ]
    return r


def test_json_roundtrip(tmp_path: Path):
    p = tmp_path / 'r.json'
    write_json(sample(), p)
    assert json.loads(p.read_text(encoding='utf-8'))['hashes']['sha256'] == 'abc'


def test_html_escapes_evidence(tmp_path: Path):
    p = tmp_path / 'r.html'
    write_html(sample(), p)
    s = p.read_text(encoding='utf-8')
    assert '<script>alert' not in s
    assert '&lt;script&gt;' in s


def test_markdown_contains_evidence_id(tmp_path: Path):
    p = tmp_path / 'r.md'
    write_markdown(sample(), p)
    assert 'finding:1' in p.read_text(encoding='utf-8')


def test_markdown_labels_candidate_iocs(tmp_path: Path):
    p = tmp_path / 'r.md'
    write_markdown(sample(), p)
    assert 'Candidate Indicators of Compromise' in p.read_text(encoding='utf-8')


def test_reporting_device_and_correlation_sections(tmp_path: Path):
    r = sample()
    r.device_evidence = {
        'device': {'ro.product.model': 'X'},
        'package': {},
        'security_state': {},
        'files': {},
        'limitations': [],
        'collection_manifest': {
            'collection_start_utc': 's',
            'collection_end_utc': 'e',
            'selected_device': {'serial': 'SER'},
            'artifacts': [],
        },
    }
    r.correlation = {
        'correlation_strength': 'limited',
        'assessment_basis': 'rule',
        'assessment_rationale': 'rationale',
        'interpretation': 'interp',
        'correlations': [],
        'timeline': [],
        'temporal_comparisons': [],
    }
    p = tmp_path / 'r.md'
    write_markdown(r, p)
    s = p.read_text(encoding='utf-8')
    assert 'Selected device serial' in s
    assert 'Assessment:' in s
    assert 'rationale' in s


def test_html_full_sections(tmp_path: Path):
    r = sample()
    r.attack_mapping = [
        {'tactic': 'Collection', 'behavior': 'Screen capture', 'capability': 'screen_capture'}
    ]
    r.deobfuscation = {
        'xor_hits': [
            {'decoded': 'secret_key', 'method': 'LTest;->dec()V', 'score': 0.98}
        ]
    }
    r.correlation = {
        'correlation_strength': 'strong',
        'assessment_basis': 'independent anchors',
        'assessment_rationale': 'rationale details',
        'interpretation': 'correlation interpretation',
        'correlations': [
            {
                'confidence': 'high',
                'category': 'package',
                'finding': 'Package present',
                'evidence': ['package:com.x.app'],
            }
        ],
    }
    r.device_evidence = {
        'device': {'ro.product.model': 'Pixel 7'},
        'files': {'f1.txt': {}},
    }

    p = tmp_path / 'full_report.html'
    write_html(r, p)
    content = p.read_text(encoding='utf-8')
    assert 'Pixel 7' in content
    assert 'Screen capture' in content
    assert 'secret_key' in content
    assert 'Package present' in content
