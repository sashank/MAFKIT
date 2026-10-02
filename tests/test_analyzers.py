"""Unit tests for static APK analyzer, archive scanning, and capability extraction."""

from __future__ import annotations

import zipfile
from pathlib import Path
import pytest

from mafkit.analyzers import (
    APKAnalyzer,
    _read_prefix,
    safe_zip_read,
)
from mafkit.model import Report


def make_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for k, v in entries.items():
            z.writestr(k, v)


def test_build_context_valid(tmp_path: Path):
    p = tmp_path / 'a.apk'
    make_zip(p, {
        'classes.dex': b'dex\n' + b'A' * 100,
        'x.txt': b'WebSocket ws://127.0.0.1:8080/',
    })
    a = APKAnalyzer(p, tmp_path / 'out')
    c = a.build_context()
    assert len(c['entries']) == 2
    assert 'WebSocket ws://127.0.0.1:8080/' in c['all_strings']
    c['zip'].close()


def test_build_context_bad_zip(tmp_path: Path):
    p = tmp_path / 'a.apk'
    p.write_bytes(b'bad')
    with pytest.raises(ValueError, match="not a valid ZIP/APK container"):
        APKAnalyzer(p, tmp_path / 'out').build_context()


def test_build_context_max_entries_exceeded(monkeypatch, tmp_path: Path):
    monkeypatch.setattr('mafkit.analyzers.MAX_ZIP_ENTRIES', 2)
    p = tmp_path / 'overflow.apk'
    make_zip(p, {'a.txt': b'1', 'b.txt': b'2', 'c.txt': b'3'})
    with pytest.raises(ValueError, match="safety limit"):
        APKAnalyzer(p, tmp_path / 'out').build_context()


def test_read_prefix_negative_size(tmp_path: Path):
    p = tmp_path / 'test.zip'
    make_zip(p, {'f.txt': b'hello'})
    with zipfile.ZipFile(p) as z:
        info = z.getinfo('f.txt')
        info.file_size = -1
        assert _read_prefix(z, info, 10) == b''


def test_safe_zip_read_limit(tmp_path: Path):
    p = tmp_path / 'a.apk'
    make_zip(p, {'x': b'A' * 100})
    z = zipfile.ZipFile(p)
    with pytest.raises(ValueError, match="exceeds forensic read limit"):
        safe_zip_read(z, 'x', 10)
    z.close()


def test_base_analysis_ioc_and_capability(tmp_path: Path):
    p = tmp_path / 'a.apk'
    make_zip(p, {
        'x.txt': b'AccessibilityService WebSocket https://evil.example.com/a 8.8.8.8',
    })
    a = APKAnalyzer(p, tmp_path / 'out')
    c = a.build_context()
    r = Report(str(p))
    a.analyze_base(r, c)
    c['zip'].close()
    assert 'accessibility' in r.capabilities
    assert any('evil.example.com' in x for x in r.iocs['urls'])
    assert r.hashes['sha256']


def test_base_analysis_manifest_failure_is_limitation(tmp_path: Path):
    p = tmp_path / 'a.apk'
    make_zip(p, {'x.txt': b'abc'})
    a = APKAnalyzer(p, tmp_path / 'out')
    c = a.build_context()
    r = Report(str(p))
    a.analyze_base(r, c)
    c['zip'].close()
    assert any('Manifest/certificate parsing failed' in x for x in r.limitations)


def test_base_analysis_suspicious_permissions():
    a = APKAnalyzer(Path('dummy.apk'), Path('out'))
    r = Report("dummy.apk")
    r.permissions = [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ]
    ctx = {"all_strings": [], "scan_blobs": [], "entries": []}
    # analyze capabilities/permissions without re-running zip checks
    from mafkit.analyzers import SUSPICIOUS_PERMS
    for p in r.permissions:
        if p in SUSPICIOUS_PERMS:
            sev, title, interp = SUSPICIOUS_PERMS[p]
            from mafkit.model import Finding
            r.findings.append(Finding(sev, "permission", title, [p], interp, 'high'))

    assert len(r.findings) == 3
    assert any(f.title == "SMS access" for f in r.findings)
    assert any(f.title == "Boot persistence" for f in r.findings)
    assert any(f.title == "Overlay" for f in r.findings)


def test_base64_candidate(tmp_path: Path):
    p = tmp_path / 'a.apk'
    make_zip(p, {'x.txt': b'V2ViU29ja2V0IG9wZW5lZA=='})
    a = APKAnalyzer(p, tmp_path / 'out')
    c = a.build_context()
    r = Report(str(p))
    a.analyze_base(r, c)
    c['zip'].close()
    assert any(x['decoded'] == 'WebSocket opened' for x in r.decoded_strings)


def test_optional_decompile(monkeypatch, tmp_path: Path):
    apk = tmp_path / 'test.apk'
    make_zip(apk, {'x.txt': b'x'})
    out = tmp_path / 'decomp_out'
    analyzer = APKAnalyzer(apk, out)
    report = Report(str(apk))

    monkeypatch.setattr('mafkit.analyzers.which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(
        'mafkit.analyzers.run',
        lambda cmd, timeout: (0, f'Decompiled with {cmd[0]} successfully'),
    )

    analyzer.optional_decompile(report)
    assert report.tools['jadx_exit_code'] == 0
    assert report.tools['apktool_exit_code'] == 0
    assert (out / 'jadx.log').is_file()
    assert (out / 'apktool.log').is_file()
