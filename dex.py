"""Low-level Dalvik Executable (DEX) file parsing and bytecode inspection."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

MAX_DEX_SIZE = 512 * 1024 * 1024
MAX_TABLE_ITEMS = 5_000_000


def _need(b: bytes | bytearray, o: int, n: int) -> None:
    """Ensure buffer `b` has at least `n` bytes starting at offset `o`."""
    if o < 0 or n < 0 or o + n > len(b):
        raise ValueError(f'Out-of-bounds DEX read at {o}+{n} (size {len(b)})')


def u16(b: bytes | bytearray, o: int) -> int:
    """Read an unsigned 16-bit little-endian integer from `b` at offset `o`."""
    _need(b, o, 2)
    return struct.unpack_from('<H', b, o)[0]


def u32(b: bytes | bytearray, o: int) -> int:
    """Read an unsigned 32-bit little-endian integer from `b` at offset `o`."""
    _need(b, o, 4)
    return struct.unpack_from('<I', b, o)[0]


def signed(x: int, bits: int) -> int:
    """Convert an unsigned integer with given bit-width to signed representation."""
    if x & (1 << (bits - 1)):
        return x - (1 << bits)
    return x


def uleb(b: bytes | bytearray, o: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 integer from `b` starting at offset `o`.

    Returns:
        (value, next_offset)
    """
    v = 0
    s = 0
    for _ in range(5):
        _need(b, o, 1)
        x = b[o]
        o += 1
        v |= (x & 0x7F) << s
        if not (x & 0x80):
            return v, o
        s += 7
    raise ValueError('ULEB128 too long')


def mutf8_at(b: bytes | bytearray, o: int) -> str:
    """Decode a MUTF-8 null-terminated string from DEX buffer `b` at offset `o`."""
    _, p = uleb(b, o)
    e = b.find(b'\0', p)
    if e < 0:
        raise ValueError('Unterminated DEX string')
    return b[p:e].decode('utf-8', 'replace')


# Instruction width table (in 16-bit code units) indexed by opcode byte
WIDTH: dict[int, int] = {}


def _set_widths(keys: Any, width: int) -> None:
    for k in keys:
        WIDTH[k] = width


_set_widths(range(0x00, 0x02), 1)
_set_widths([0x02], 2)
_set_widths([0x03], 3)
_set_widths([0x04], 1)
_set_widths([0x05], 2)
_set_widths([0x06], 3)
_set_widths([0x07], 1)
_set_widths([0x08], 2)
_set_widths([0x09], 3)
_set_widths(range(0x0A, 0x13), 1)
_set_widths([0x13], 2)
_set_widths([0x14], 3)
_set_widths([0x15], 2)
_set_widths([0x16], 2)
_set_widths([0x17], 3)
_set_widths([0x18], 5)
_set_widths([0x19], 2)
_set_widths([0x1A], 2)
_set_widths([0x1B], 3)
_set_widths([0x1C], 2)
_set_widths([0x1D, 0x1E], 1)
_set_widths([0x1F, 0x20], 2)
_set_widths([0x21], 1)
_set_widths([0x22, 0x23], 2)
_set_widths([0x24, 0x25, 0x26], 3)
_set_widths([0x27, 0x28], 1)
_set_widths([0x29], 2)
_set_widths([0x2A, 0x2B, 0x2C], 3)
_set_widths(range(0x2D, 0x3E), 2)
_set_widths(range(0x3E, 0x44), 1)
_set_widths(range(0x44, 0x6E), 2)
_set_widths(range(0x6E, 0x73), 3)
_set_widths([0x73], 1)
_set_widths(range(0x74, 0x79), 3)
_set_widths(range(0x79, 0x7B), 1)
_set_widths(range(0x7B, 0x90), 1)
_set_widths(range(0x90, 0xB0), 2)
_set_widths(range(0xB0, 0xD0), 1)
_set_widths(range(0xD0, 0xD8), 2)
_set_widths(range(0xD8, 0xE3), 2)
_set_widths(range(0xE3, 0xFA), 1)
_set_widths([0xFA, 0xFB], 4)
_set_widths([0xFC, 0xFD], 3)
_set_widths([0xFE, 0xFF], 2)


class Dex:
    """Parser for Android Dalvik Executable (.dex) binaries."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        size = self.path.stat().st_size
        if size > MAX_DEX_SIZE:
            raise ValueError(f'DEX exceeds size limit: {size}')

        self.b = self.path.read_bytes()
        b = self.b
        if len(b) < 0x70 or b[:4] != b'dex\n':
            raise ValueError('Not a valid DEX header')

        file_size = u32(b, 0x20)
        if file_size and file_size > len(b):
            raise ValueError('DEX header file_size exceeds available bytes')

        self.string_ids_size = u32(b, 0x38)
        self.string_ids_off = u32(b, 0x3C)
        self.type_ids_size = u32(b, 0x40)
        self.type_ids_off = u32(b, 0x44)
        self.proto_ids_size = u32(b, 0x48)
        self.proto_ids_off = u32(b, 0x4C)
        self.method_ids_size = u32(b, 0x58)
        self.method_ids_off = u32(b, 0x5C)
        self.class_defs_size = u32(b, 0x60)
        self.class_defs_off = u32(b, 0x64)

        for name, n in [
            ('strings', self.string_ids_size),
            ('types', self.type_ids_size),
            ('protos', self.proto_ids_size),
            ('methods', self.method_ids_size),
            ('classes', self.class_defs_size),
        ]:
            if n > MAX_TABLE_ITEMS:
                raise ValueError(f'DEX {name} table exceeds limit')

        _need(b, self.string_ids_off, self.string_ids_size * 4)
        _need(b, self.type_ids_off, self.type_ids_size * 4)
        _need(b, self.proto_ids_off, self.proto_ids_size * 12)
        _need(b, self.method_ids_off, self.method_ids_size * 8)
        _need(b, self.class_defs_off, self.class_defs_size * 32)

        self.strings = [
            mutf8_at(b, u32(b, self.string_ids_off + i * 4))
            for i in range(self.string_ids_size)
        ]
        self.types = [
            self.strings[u32(b, self.type_ids_off + i * 4)]
            for i in range(self.type_ids_size)
        ]

        self.protos: list[tuple[str, list[str]]] = []
        for i in range(self.proto_ids_size):
            o = self.proto_ids_off + i * 12
            ret = u32(b, o + 4)
            po = u32(b, o + 8)
            params: list[str] = []
            if ret >= len(self.types):
                raise ValueError('DEX proto return type out of range')
            if po:
                n = u32(b, po)
                _need(b, po + 4, n * 2)
                params = [self.types[u16(b, po + 4 + 2 * j)] for j in range(n)]
            self.protos.append((self.types[ret], params))

        self.methods: list[tuple[str, str, tuple[str, list[str]]]] = []
        for i in range(self.method_ids_size):
            o = self.method_ids_off + i * 8
            ci = u16(b, o)
            pi = u16(b, o + 2)
            ni = u32(b, o + 4)
            if ci >= len(self.types) or pi >= len(self.protos) or ni >= len(self.strings):
                raise ValueError('DEX method id out of range')
            self.methods.append((self.types[ci], self.strings[ni], self.protos[pi]))

        self.code: dict[int, int] = {}
        for i in range(self.class_defs_size):
            o = self.class_defs_off + i * 32
            cdo = u32(b, o + 24)
            if not cdo:
                continue

            p = cdo
            sf, p = uleb(b, p)
            inf, p = uleb(b, p)
            dm, p = uleb(b, p)
            vm, p = uleb(b, p)

            # Skip static and instance fields
            for n in (sf, inf):
                idx = 0
                for _ in range(n):
                    d, p = uleb(b, p)
                    idx += d
                    _, p = uleb(b, p)

            # Parse direct and virtual methods
            for n in (dm, vm):
                idx = 0
                for _ in range(n):
                    d, p = uleb(b, p)
                    idx += d
                    _, p = uleb(b, p)
                    co, p = uleb(b, p)
                    if idx >= self.method_ids_size:
                        raise ValueError('Encoded method index out of range')
                    if co:
                        _need(b, co, 16)
                        self.code[idx] = co

    def mstr(self, i: int) -> str:
        """Format method at index `i` as `Lclass;->methodName(paramTypes)ReturnType`."""
        if i < 0 or i >= len(self.methods):
            raise ValueError('Method index out of range')
        c, n, (r, p) = self.methods[i]
        return f'{c}->{n}({"".join(p)}){r}'

    def refs(self, mid: int) -> list[tuple[str, int, str]]:
        """Extract string and method invocation references from method `mid`."""
        b = self.b
        co = self.code.get(mid, 0)
        if not co:
            return []

        insns_count = u32(b, co + 12)
        p = co + 16
        end = p + insns_count * 2
        _need(b, p, insns_count * 2)
        out: list[tuple[str, int, str]] = []

        while p < end:
            cu = u16(b, p)
            op = cu & 0xFF
            hi = cu >> 8

            # Handle payload pseudo-instructions (fill-array-data, packed-switch, sparse-switch)
            if op == 0 and hi in (1, 2, 3):
                if hi == 1:
                    size = u16(b, p + 2)
                    w = 4 + size * 2
                elif hi == 2:
                    size = u16(b, p + 2)
                    w = 2 + size * 4
                else:
                    ew = u16(b, p + 2)
                    size = u32(b, p + 4)
                    w = 4 + ((ew * size + 1) // 2)

                if p + w * 2 > end:
                    break
                p += w * 2
                continue

            w = WIDTH.get(op, 1)
            if p + w * 2 > end:
                break

            try:
                # const-string
                if op == 0x1A:
                    idx = u16(b, p + 2)
                    if idx < len(self.strings):
                        out.append(('string', idx, self.strings[idx]))
                # const-string/jumbo
                elif op == 0x1B:
                    idx = u32(b, p + 2)
                    if idx < len(self.strings):
                        out.append(('string', idx, self.strings[idx]))
                # invoke-kind
                elif (0x6E <= op <= 0x72) or (0x74 <= op <= 0x78) or (op in (0xFA, 0xFB)):
                    idx = u16(b, p + 2)
                    if idx < len(self.methods):
                        out.append(('invoke', idx, self.mstr(idx)))
            except (ValueError, struct.error):
                pass

            p += w * 2

        return out

    def xor_call_candidates(self, mid: int) -> list[tuple[str, bytes, bytes]]:
        """Identify candidate calls to repeating-XOR decryptors `([B[B)Ljava/lang/String;`."""
        b = self.b
        co = self.code.get(mid, 0)
        if not co:
            return []

        insns_count = u32(b, co + 12)
        base = co + 16
        end = base + insns_count * 2
        _need(b, base, insns_count * 2)

        regs: dict[int, Any] = {}
        out: list[tuple[str, bytes, bytes]] = []
        p = base

        while p < end:
            cu = u16(b, p)
            op = cu & 0xFF
            hi = cu >> 8

            # Handle payload pseudo-instructions
            if op == 0 and hi in (1, 2, 3):
                try:
                    if hi == 1:
                        size = u16(b, p + 2)
                        w = 4 + size * 2
                    elif hi == 2:
                        size = u16(b, p + 2)
                        w = 2 + size * 4
                    else:
                        ew = u16(b, p + 2)
                        size = u32(b, p + 4)
                        w = 4 + ((ew * size + 1) // 2)
                except ValueError:
                    break
                if p + w * 2 > end:
                    break
                p += w * 2
                continue

            w = WIDTH.get(op, 1)
            if p + w * 2 > end:
                break

            try:
                # move & move-object
                if op in (0x01, 0x07):
                    reg_a = hi & 0xF
                    reg_b = (hi >> 4) & 0xF
                    regs[reg_a] = regs.get(reg_b)
                elif op in (0x02, 0x08):
                    reg_a = hi
                    reg_b = u16(b, p + 2)
                    regs[reg_a] = regs.get(reg_b)
                elif op in (0x03, 0x09):
                    reg_a = u16(b, p + 2)
                    reg_b = u16(b, p + 4)
                    regs[reg_a] = regs.get(reg_b)
                # const/4
                elif op == 0x12:
                    reg_a = hi & 0xF
                    regs[reg_a] = signed((hi >> 4) & 0xF, 4)
                # const/16
                elif op == 0x13:
                    regs[hi] = signed(u16(b, p + 2), 16)
                # const
                elif op == 0x14:
                    regs[hi] = signed(u32(b, p + 2), 32)
                # const/high16
                elif op == 0x15:
                    regs[hi] = signed(u16(b, p + 2), 16) << 16
                # new-array
                elif op == 0x23:
                    reg_a = hi & 0xF
                    reg_b = (hi >> 4) & 0xF
                    tidx = u16(b, p + 2)
                    ln = regs.get(reg_b)
                    if (
                        tidx < len(self.types)
                        and self.types[tidx] == '[B'
                        and isinstance(ln, int)
                        and 0 <= ln < 1_000_000
                    ):
                        regs[reg_a] = bytearray(ln)
                # fill-array-data
                elif op == 0x26:
                    reg_a = hi
                    off = signed(u32(b, p + 2), 32)
                    payload_pos = p + off * 2
                    elem_width = u16(b, payload_pos + 2)
                    size = u32(b, payload_pos + 4)
                    total = elem_width * size
                    if total <= 1_000_000:
                        _need(b, payload_pos + 8, total)
                        if elem_width == 1:
                            regs[reg_a] = bytearray(b[payload_pos + 8 : payload_pos + 8 + total])
                # invoke-kind
                elif 0x6E <= op <= 0x72:
                    count = (cu >> 12) & 0xF
                    reg_g = (cu >> 8) & 0xF
                    idx = u16(b, p + 2)
                    rr = u16(b, p + 4)
                    if idx >= len(self.methods):
                        raise ValueError('invoke method out of range')
                    reg_list = [
                        rr & 0xF,
                        (rr >> 4) & 0xF,
                        (rr >> 8) & 0xF,
                        (rr >> 12) & 0xF,
                        reg_g,
                    ][:count]
                    vals = [regs.get(x) for x in reg_list]
                    ms = self.mstr(idx)
                    if (
                        ms.endswith('([B[B)Ljava/lang/String;')
                        and len(vals) >= 2
                        and all(isinstance(v, (bytes, bytearray)) for v in vals[:2])
                    ):
                        out.append((ms, bytes(vals[0]), bytes(vals[1])))
                # invoke-kind/range
                elif 0x74 <= op <= 0x78:
                    count = hi
                    idx = u16(b, p + 2)
                    start = u16(b, p + 4)
                    if idx >= len(self.methods) or count > 256:
                        raise ValueError('invoke/range invalid')
                    vals = [regs.get(x) for x in range(start, start + count)]
                    ms = self.mstr(idx)
                    if (
                        ms.endswith('([B[B)Ljava/lang/String;')
                        and len(vals) >= 2
                        and all(isinstance(v, (bytes, bytearray)) for v in vals[:2])
                    ):
                        out.append((ms, bytes(vals[0]), bytes(vals[1])))
            except (ValueError, struct.error, OverflowError):
                pass

            p += w * 2

        return out
