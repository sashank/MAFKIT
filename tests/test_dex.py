"""Unit tests for low-level Dalvik Executable (DEX) parsing and bytecode inspection."""

from __future__ import annotations

import struct
from pathlib import Path
import pytest

from mafkit.deobfuscation import repeating_xor
from mafkit.dex import Dex, mutf8_at, signed, u16, u32, uleb


def test_uleb_one_byte():
    assert uleb(b'\x7f', 0) == (127, 1)


def test_uleb_multi_byte():
    # 0x80 0x01 -> 128
    assert uleb(b'\x80\x01', 0) == (128, 2)


def test_uleb_truncated():
    with pytest.raises(ValueError, match="Out-of-bounds"):
        uleb(b'\x80', 0)


def test_uleb_too_long():
    with pytest.raises(ValueError, match="ULEB128 too long"):
        uleb(b'\x80' * 6, 0)


def test_u16_bounds():
    assert u16(b'\x34\x12', 0) == 0x1234
    with pytest.raises(ValueError, match="Out-of-bounds"):
        u16(b'\x00', 0)


def test_u32_bounds():
    assert u32(b'\x78\x56\x34\x12', 0) == 0x12345678
    with pytest.raises(ValueError, match="Out-of-bounds"):
        u32(b'\x00\x01', 0)


def test_signed_conversion():
    assert signed(0x7, 4) == 7
    assert signed(0x8, 4) == -8
    assert signed(0xF, 4) == -1
    assert signed(0x7FFF, 16) == 32767
    assert signed(0x8000, 16) == -32768
    assert signed(0xFFFFFFFF, 32) == -1


def test_mutf8_at():
    # Length 5 (uleb 5), 'hello', null terminator
    buf = b'\x05hello\x00'
    assert mutf8_at(buf, 0) == 'hello'


def test_mutf8_at_unterminated():
    buf = b'\x05hello'
    with pytest.raises(ValueError, match="Unterminated DEX string"):
        mutf8_at(buf, 0)


def test_dex_rejects_short(tmp_path: Path):
    p = tmp_path / 'x.dex'
    p.write_bytes(b'dex\n')
    with pytest.raises(ValueError, match="Not a valid DEX header"):
        Dex(p)


def test_dex_rejects_non_dex(tmp_path: Path):
    p = tmp_path / 'x.dex'
    p.write_bytes(b'X' * 200)
    with pytest.raises(ValueError, match="Not a valid DEX header"):
        Dex(p)


def test_dex_header_file_size_exceeds(tmp_path: Path):
    p = tmp_path / 'x.dex'
    b = bytearray(0x70)
    b[:4] = b'dex\n'
    struct.pack_into('<I', b, 0x20, 1000)  # file_size = 1000 > len(b)
    p.write_bytes(b)
    with pytest.raises(ValueError, match="file_size exceeds"):
        Dex(p)


def test_dex_table_limit_exceeded(tmp_path: Path):
    p = tmp_path / 'x.dex'
    b = bytearray(0x70)
    b[:4] = b'dex\n'
    struct.pack_into('<I', b, 0x20, 0x70)
    struct.pack_into('<I', b, 0x38, 6_000_000)  # string_ids_size > 5_000_000
    p.write_bytes(b)
    with pytest.raises(ValueError, match="table exceeds limit"):
        Dex(p)


def test_mstr_bounds():
    d = object.__new__(Dex)
    d.methods = []
    with pytest.raises(ValueError, match="Method index out of range"):
        d.mstr(0)


def test_refs_const_string():
    d = object.__new__(Dex)
    d.b = bytearray(80)
    d.code = {0: 16}
    d.strings = ['hello']
    d.types = []
    d.methods = []
    # insns_size = 2 code units, const-string v0, string@0
    struct.pack_into('<I', d.b, 28, 2)
    struct.pack_into('<HH', d.b, 32, 0x001A, 0)
    assert d.refs(0) == [('string', 0, 'hello')]


def test_refs_const_string_jumbo_and_invoke():
    d = object.__new__(Dex)
    d.b = bytearray(100)
    d.code = {0: 16}
    d.strings = ['jumbo_str']
    d.types = ['LTarget;']
    d.methods = [('LTarget;', 'testMethod', ('V', []))]

    # insns_size = 6 code units (12 bytes)
    struct.pack_into('<I', d.b, 28, 6)
    # const-string/jumbo v0, string@0 (3 code units: op 0x1B, low 16, hi 16)
    struct.pack_into('<HI', d.b, 32, 0x001B, 0)
    # invoke-virtual {v0}, method@0 (3 code units: op 0x6E)
    struct.pack_into('<HHH', d.b, 38, 0x106E, 0, 0x0000)

    refs = d.refs(0)
    assert ('string', 0, 'jumbo_str') in refs
    assert any(r[0] == 'invoke' and 'testMethod' in r[2] for r in refs)


def test_refs_payload_handling():
    d = object.__new__(Dex)
    d.b = bytearray(120)
    d.code = {0: 16}
    d.strings = ['after_payload']
    d.types = []
    d.methods = []

    # insns_size = 14 code units
    struct.pack_into('<I', d.b, 28, 14)
    # pseudo-instruction payload: op 0x00, hi 0x01 (fill-array-data payload)
    # size=2, width is 4 + size*2 = 8 code units (16 bytes)
    struct.pack_into('<HH', d.b, 32, 0x0100, 2)
    # At offset 32 + 16 = 48: const-string v0, string@0 (2 code units)
    struct.pack_into('<HH', d.b, 48, 0x001A, 0)

    refs = d.refs(0)
    assert refs == [('string', 0, 'after_payload')]


def test_xor_call_candidate_recovers_arrays():
    d = object.__new__(Dex)
    d.b = bytearray(120)
    d.code = {0: 16}
    d.strings = []
    d.types = ['[B']
    d.methods = [('Lx;', 'dec', ('Ljava/lang/String;', ['[B', '[B']))]
    b = d.b
    base = 32

    # const/4 v1, 5
    struct.pack_into('<H', b, base, 0x5112)
    # new-array v0, v1, type@0
    struct.pack_into('<HH', b, base + 2, 0x1023, 0)
    # fill-array-data v0, +12 code units -> payload at 62
    struct.pack_into('<HI', b, base + 6, 0x0026, 12)
    # const/4 v3, 3
    struct.pack_into('<H', b, base + 12, 0x3312)
    # new-array v2, v3, type@0
    struct.pack_into('<HH', b, base + 14, 0x3223, 0)
    # fill-array-data v2, +13 code units -> payload at 76
    struct.pack_into('<HI', b, base + 18, 0x0226, 13)
    # invoke-static {v0, v2}, method@0
    struct.pack_into('<HHH', b, base + 24, 0x2071, 0, 0x0020)

    cipher = repeating_xor(b'hello', b'key')
    # payload1 0x0300, elem_width=1, size=5
    struct.pack_into('<HHI', b, 62, 0x0300, 1, 5)
    b[70:75] = cipher
    # payload2
    struct.pack_into('<HHI', b, 76, 0x0300, 1, 3)
    b[84:87] = b'key'
    # total instruction area 56 bytes = 28 code units
    struct.pack_into('<I', b, 28, 28)

    calls = d.xor_call_candidates(0)
    assert calls
    assert calls[0][1] == cipher
    assert calls[0][2] == b'key'


def test_xor_call_candidates_move_and_const_variants():
    d = object.__new__(Dex)
    d.b = bytearray(150)
    d.code = {0: 16}
    d.strings = []
    d.types = ['[B']
    d.methods = [('Lx;', 'dec', ('Ljava/lang/String;', ['[B', '[B']))]
    b = d.b
    base = 32

    # const/16 v4, 4 (op 0x13, reg 4, lit 4) -> 2 code units
    struct.pack_into('<HH', b, base, 0x0413, 4)
    # move v1, v4 (op 0x01, A=1, B=4) -> 1 code unit
    struct.pack_into('<H', b, base + 4, 0x4101)
    # new-array v0, v1, type@0 (op 0x23) -> 2 code units
    struct.pack_into('<HH', b, base + 6, 0x1023, 0)
    # fill-array-data v0, +13 code units -> payload at 62
    struct.pack_into('<HI', b, base + 10, 0x0026, 13)

    # const v5, 3 (op 0x14, reg 5, lit 3) -> 3 code units
    struct.pack_into('<HI', b, base + 16, 0x0514, 3)
    # move/from16 v3, v5 (op 0x02, A=3, B=5) -> 2 code units
    struct.pack_into('<HH', b, base + 22, 0x0302, 5)
    # new-array v2, v3, type@0 -> 2 code units
    struct.pack_into('<HH', b, base + 26, 0x3223, 0)
    # fill-array-data v2, +12 code units -> payload at 76
    struct.pack_into('<HI', b, base + 30, 0x0226, 12)

    # invoke-virtual/range {v0 .. v1}, method@0 (op 0x74, count 2, method 0, start 0) -> 3 code units
    struct.pack_into('<HHH', b, base + 36, 0x0274, 0, 0)

    # payload1 at 62: elem_width=1, size=4
    struct.pack_into('<HHI', b, 62, 0x0300, 1, 4)
    b[70:74] = b'data'
    # payload2 at 76: elem_width=1, size=3
    struct.pack_into('<HHI', b, 76, 0x0300, 1, 3)
    b[84:87] = b'key'

    # total instruction area 70 bytes = 35 code units
    struct.pack_into('<I', b, 28, 35)

    # When invoking {v0, v1}, v1 is int 4, so it should not match ([B, [B)
    calls = d.xor_call_candidates(0)
    assert calls == []


def test_dex_full_parse(tmp_path: Path):
    """Test full DEX initialization from a valid synthetic binary."""
    p = tmp_path / 'classes.dex'
    b = bytearray(0x200)
    b[:4] = b'dex\n'
    struct.pack_into('<I', b, 0x20, len(b))  # file_size

    # Strings: 2 strings
    struct.pack_into('<II', b, 0x38, 2, 0x80)  # string_ids_size=2, string_ids_off=0x80
    # Types: 2 types
    struct.pack_into('<II', b, 0x40, 2, 0x90)  # type_ids_size=2, type_ids_off=0x90
    # Protos: 1 proto
    struct.pack_into('<II', b, 0x48, 1, 0xA0)  # proto_ids_size=1, proto_ids_off=0xA0
    # Methods: 1 method
    struct.pack_into('<II', b, 0x58, 1, 0xB0)  # method_ids_size=1, method_ids_off=0xB0
    # Classes: 1 class
    struct.pack_into('<II', b, 0x60, 1, 0xC0)  # class_defs_size=1, class_defs_off=0xC0

    # String data
    # String 0: "LMyClass;" at 0x100
    struct.pack_into('<I', b, 0x80, 0x100)
    b[0x100:0x10B] = b'\x09LMyClass;\x00'
    # String 1: "myMethod" at 0x110
    struct.pack_into('<I', b, 0x84, 0x110)
    b[0x110:0x11A] = b'\x08myMethod\x00'

    # Type 0 -> string 0 ("LMyClass;")
    struct.pack_into('<I', b, 0x90, 0)
    # Type 1 -> string 0 ("LMyClass;")
    struct.pack_into('<I', b, 0x94, 0)

    # Proto 0 -> shorty_idx=1, return_type_idx=0, parameters_off=0
    struct.pack_into('<III', b, 0xA0, 1, 0, 0)

    # Method 0 -> class_idx=0, proto_idx=0, name_idx=1
    struct.pack_into('<HHI', b, 0xB0, 0, 0, 1)

    # Class 0: class_idx=0, access_flags=1, superclass_idx=0, interfaces_off=0, source_file_idx=0, annotations_off=0, class_data_off=0x130, static_values_off=0
    struct.pack_into('<IIIIIIII', b, 0xC0, 0, 1, 0, 0, 0, 0, 0x130, 0)

    # Class data at 0x130: static_fields=0, instance_fields=0, direct_methods=1, virtual_methods=0
    # uleb128 for 0, 0, 1, 0
    b[0x130:0x134] = b'\x00\x00\x01\x00'
    # direct_method[0]: method_idx_diff=0, access_flags=1, code_off=0x150
    # uleb128 for 0, 1, 0x150 (0x150 = 336 = 0xD0 0x02)
    b[0x134:0x138] = b'\x00\x01\xd0\x02'

    # Code item at 0x150: registers_size=2, ins_size=0, outs_size=0, tries_size=0, debug_info_off=0, insns_size=1
    struct.pack_into('<HHIIII', b, 0x150, 2, 0, 0, 0, 0, 1)
    # Instruction: return-void (0x0E)
    struct.pack_into('<H', b, 0x160, 0x000E)

    p.write_bytes(b)
    dex = Dex(p)
    assert dex.strings == ['LMyClass;', 'myMethod']
    assert dex.types == ['LMyClass;', 'LMyClass;']
    assert len(dex.methods) == 1
    assert dex.mstr(0) == 'LMyClass;->myMethod()LMyClass;'
    assert 0 in dex.code
    assert dex.code[0] == 0x150
