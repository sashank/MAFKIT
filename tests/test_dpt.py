"""Unit tests for DPT Shell unpacker plugin and method restoration."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
from pathlib import Path
import pytest

from mafkit.plugins.dpt import DPTPlugin


def test_short_store_rejected(tmp_path: Path):
    assert DPTPlugin()._restore_methods(b'\x00', [], tmp_path)['restored'] is False


def test_bad_section_count_rejected(tmp_path: Path):
    # version=1, count=0
    assert DPTPlugin()._restore_methods(b'\x01\x00\x00\x00', [], tmp_path)['restored'] is False


def test_malformed_offset_returns_failure(tmp_path: Path):
    # version=1 count=1 offset=999 beyond data
    s = b'\x01\x00\x01\x00' + (999).to_bytes(4, 'little')
    r = DPTPlugin()._restore_methods(s, [], tmp_path)
    assert not r['restored']


def test_restore_methods_count_exceeds_limit(monkeypatch, tmp_path: Path):
    monkeypatch.setattr('mafkit.plugins.dpt.MAX_RECORDS_PER_DEX', 5)
    p = tmp_path / 'orig.dex'
    p.write_bytes(b'dex\n' + b'\x00' * 100)
    store = struct.pack('<HHI', 1, 1, 8) + struct.pack('<H', 10)
    r = DPTPlugin()._restore_methods(store, [p], tmp_path)
    assert r['restored'] is False
    assert 'safety limit' in r['reason']


def test_restore_methods_record_size_exceeds_limit(tmp_path: Path):
    p = tmp_path / 'orig.dex'
    p.write_bytes(b'dex\n' + b'\x00' * 100)
    # sz = 17 MB > 16 MB limit
    store = struct.pack('<HHI', 1, 1, 8) + struct.pack('<HII', 1, 0, 17 * 1024 * 1024)
    r = DPTPlugin()._restore_methods(store, [p], tmp_path)
    assert r['restored'] is False
    assert 'malformed method store' in r['reason']


def test_code_offsets_unreasonable_size():
    b = bytearray(0x70)
    struct.pack_into('<I', b, 0x60, 6_000_000)  # class_defs_size > 5_000_000
    with pytest.raises(ValueError, match="class_defs_size unreasonable"):
        DPTPlugin()._code_offsets(b)


def test_code_offsets_parsing():
    b = bytearray(0x100)
    struct.pack_into('<II', b, 0x60, 1, 0x70)  # class_defs_size=1, class_defs_off=0x70
    # class_def: offset 0x70 + 24 = 0x88 -> class_data_off = 0x90
    struct.pack_into('<I', b, 0x88, 0x90)
    # class_data at 0x90: static_fields=0, instance_fields=0, direct_methods=1, virtual_methods=0
    b[0x90:0x94] = b'\x00\x00\x01\x00'
    # direct_method: diff=0, access=1, code_off=0x50
    b[0x94:0x97] = b'\x00\x01\x50'
    offsets = DPTPlugin()._code_offsets(b)
    assert offsets == {0: 0x50}


def test_restore_methods_patches_and_hashes(monkeypatch, tmp_path: Path):
    p = tmp_path / 'orig.dex'
    b = bytearray(80)
    b[:4] = b'dex\n'
    struct.pack_into('<I', b, 44, 2)
    b[48:52] = b'\x00' * 4
    p.write_bytes(b)

    plug = DPTPlugin()
    monkeypatch.setattr(plug, '_code_offsets', lambda data: {0: 32})

    # version=1, count=1, offset[0]=8, then cnt=1, mid=0, sz=4, instruction bytes
    store = struct.pack('<HHI', 1, 1, 8) + struct.pack('<HII', 1, 0, 4) + b'\x01\x02\x03\x04'
    out = tmp_path / 'out'
    out.mkdir()
    r = plug._restore_methods(store, [p], out)
    assert r['restored'] and r['total_methods_restored'] == 1
    patched = (out / 'classes.dex').read_bytes()
    assert patched[48:52] == b'\x01\x02\x03\x04'
    assert r['dexes'][0]['sha256'] == hashlib.sha256(patched).hexdigest()


def test_restore_size_mismatch_unpatched(monkeypatch, tmp_path: Path):
    p = tmp_path / 'orig.dex'
    b = bytearray(80)
    b[:4] = b'dex\n'
    struct.pack_into('<I', b, 44, 3)
    p.write_bytes(b)

    plug = DPTPlugin()
    monkeypatch.setattr(plug, '_code_offsets', lambda data: {0: 32})
    store = struct.pack('<HHI', 1, 1, 8) + struct.pack('<HII', 1, 0, 4) + b'abcd'
    out = tmp_path / 'o'
    out.mkdir()
    r = plug._restore_methods(store, [p], out)
    assert not r['restored']


def test_analyze_recovers_embedded_dex(tmp_path: Path):
    embedded = io.BytesIO()
    with zipfile.ZipFile(embedded, 'w') as z:
        z.writestr('classes.dex', b'dex\nFAKE')

    apk = tmp_path / 'a.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('classes.dex', b'HEADER' + embedded.getvalue())
        z.writestr('assets/d_shell_data_001', b'x')

    z = zipfile.ZipFile(apk)

    class R:
        packer = {}
        dex = {}
        limitations = []

    r = R()
    ctx = {
        'zip': z,
        'all_strings': ['ProxyApplication'],
        'outdir': tmp_path / 'out',
        'safe_zip_read': lambda zz, n, m: zz.read(n),
    }
    DPTPlugin().analyze(ctx, r)
    z.close()
    assert r.packer['detected'] and r.packer['recovered_dex'] and r.dex['recovered_original']


def test_analyze_shell_read_failure_appends_limitation(tmp_path: Path):
    apk = tmp_path / 'b.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('x.txt', b'x')

    z = zipfile.ZipFile(apk)

    class R:
        packer = {}
        dex = {}
        limitations = []

    r = R()

    def bad_safe_read(zz, name, limit):
        raise RuntimeError("Simulated read failure")

    ctx = {
        'zip': z,
        'all_strings': [],
        'outdir': tmp_path / 'out',
        'safe_zip_read': bad_safe_read,
    }
    DPTPlugin().analyze(ctx, r)
    z.close()
    assert any('DPT shell read failed' in x for x in r.limitations)
