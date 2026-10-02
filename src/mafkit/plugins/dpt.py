"""DPT Shell packer detection, DEX extraction, and bytecode method restoration."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..dex import u16, u32, uleb
from .base import Plugin

if TYPE_CHECKING:
    from ..model import Report

MAX_SHELL = 256 * 1024 * 1024
MAX_STORE = 256 * 1024 * 1024
MAX_EMBEDDED_DEX = 256 * 1024 * 1024
MAX_RECORDS_PER_DEX = 1_000_000


class DPTPlugin(Plugin):
    """Plugin to unpack DPT Shell packed Android applications and restore stripped methods."""

    name = "dpt-shell"

    def _code_offsets(self, b: bytes | bytearray) -> dict[int, int]:
        """Extract mapping from method index to code_item offset in DEX buffer."""
        class_defs_size = u32(b, 0x60)
        class_defs_off = u32(b, 0x64)
        out: dict[int, int] = {}

        if class_defs_size > 5_000_000:
            raise ValueError('class_defs_size unreasonable')

        for i in range(class_defs_size):
            cdo = u32(b, class_defs_off + i * 32 + 24)
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

            # Direct and virtual methods
            for n in (dm, vm):
                idx = 0
                for _ in range(n):
                    d, p = uleb(b, p)
                    idx += d
                    _, p = uleb(b, p)
                    co, p = uleb(b, p)
                    if co:
                        out[idx] = co

        return out

    def _restore_methods(
        self,
        store: bytes,
        dex_paths: list[Path],
        outdir: Path,
    ) -> dict[str, Any]:
        """Restore stripped bytecode instructions from DPT method store `assets/OoooooOooo`."""
        if len(store) < 4:
            return {'restored': False, 'reason': 'method store too short'}

        version = u16(store, 0)
        count = u16(store, 2)
        if count < 1 or count > 128 or len(store) < 4 + 4 * count:
            return {'restored': False, 'reason': 'unrecognized method-store header'}

        offs = [u32(store, 4 + i * 4) for i in range(count)]
        restored: list[dict[str, Any]] = []
        total = 0

        for di, o in enumerate(offs):
            if di >= len(dex_paths) or o + 2 > len(store):
                break

            cnt = u16(store, o)
            if cnt > MAX_RECORDS_PER_DEX:
                return {
                    'restored': False,
                    'reason': 'method record count exceeds safety limit',
                }

            p = o + 2
            records: list[tuple[int, int, bytes]] = []
            try:
                for _ in range(cnt):
                    mid = u32(store, p)
                    sz = u32(store, p + 4)
                    p += 8
                    if sz > 16 * 1024 * 1024 or p + sz > len(store):
                        raise ValueError('invalid/truncated instruction record')
                    ins = store[p : p + sz]
                    p += sz
                    records.append((mid, sz, ins))
            except Exception as exc:
                return {'restored': False, 'reason': f'malformed method store: {exc}'}

            src = Path(dex_paths[di])
            b = bytearray(src.read_bytes())
            codeoffs = self._code_offsets(b)
            patched = 0
            bad = 0

            for mid, sz, ins in records:
                co = codeoffs.get(mid)
                if co is None or co + 16 > len(b):
                    bad += 1
                    continue
                expected = u32(b, co + 12) * 2
                if expected != sz or co + 16 + sz > len(b):
                    bad += 1
                    continue
                b[co + 16 : co + 16 + sz] = ins
                patched += 1

            if patched:
                # Recalculate SHA-1 signature and Adler32 checksum
                b[12:32] = hashlib.sha1(b[32:]).digest()
                b[8:12] = struct.pack('<I', zlib.adler32(b[12:]) & 0xFFFFFFFF)
                dst = Path(outdir) / ('classes.dex' if di == 0 else f'classes{di + 1}.dex')
                dst.write_bytes(b)
                total += patched
                restored.append({
                    'dex': dst.name,
                    'records': cnt,
                    'patched': patched,
                    'unpatched': bad,
                    'path': str(dst),
                    'sha256': hashlib.sha256(b).hexdigest(),
                })

        return {
            'restored': bool(restored),
            'store_version': version,
            'dex_sections': count,
            'total_methods_restored': total,
            'dexes': restored,
        }

    def analyze(self, ctx: dict[str, Any], report: Report) -> None:
        """Detect DPT Shell, carve hidden ZIP/DEX payload, and restore stripped method bodies."""
        names = set(ctx["zip"].namelist())
        markers = ["assets/OoooooOooo", "assets/d_shell_data_001"]
        hit = [m for m in markers if m in names]
        proxy = any(
            "ProxyApplication" in s or "libdpt.so" in s
            for s in ctx.get("all_strings", [])
        )

        if hit or proxy:
            report.packer.update({
                "detected": True,
                "family": "DPT Shell",
                "evidence": hit + (["ProxyApplication/libdpt.so"] if proxy else []),
            })

        safe = ctx.get('safe_zip_read')
        try:
            shell = (
                safe(ctx['zip'], 'classes.dex', MAX_SHELL)
                if safe
                else ctx['zip'].read('classes.dex')
            )
        except Exception as exc:
            report.limitations.append(f'DPT shell read failed: {exc}')
            return

        # Locate embedded ZIP signatures in classes.dex
        offs: list[int] = []
        start = 0
        while len(offs) < 1024:
            i = shell.find(b"PK\x03\x04", start)
            if i < 0:
                break
            offs.append(i)
            start = i + 1

        recovered: list[dict[str, Any]] = []
        recovered_paths: list[Path] = []

        for off in offs:
            try:
                with zipfile.ZipFile(io.BytesIO(shell[off:])) as z:
                    dexinfos = [
                        x for x in z.infolist()
                        if x.filename.endswith('.dex') and x.file_size <= MAX_EMBEDDED_DEX
                    ]
                    if not dexinfos:
                        continue

                    outdir = ctx['outdir'] / 'recovered' / 'dpt' / 'original'
                    outdir.mkdir(parents=True, exist_ok=True)
                    seen: set[str] = set()

                    for n, info in enumerate(dexinfos):
                        data = z.read(info)
                        base = Path(info.filename).name or f'classes{n + 1}.dex'
                        if base in seen:
                            base = f'{n}_{base}'
                        seen.add(base)
                        dst = outdir / base
                        dst.write_bytes(data)
                        recovered_paths.append(dst)
                        recovered.append({
                            'name': info.filename,
                            'size': len(data),
                            'offset': off,
                            'path': str(dst),
                            'sha256': hashlib.sha256(data).hexdigest(),
                        })
                    break
            except Exception:
                continue

        if recovered:
            report.packer['recovered_dex'] = recovered
            report.dex['recovered_original'] = [str(x) for x in recovered_paths]

        if recovered_paths and 'assets/OoooooOooo' in names:
            try:
                store = (
                    safe(ctx['zip'], 'assets/OoooooOooo', MAX_STORE)
                    if safe
                    else ctx['zip'].read('assets/OoooooOooo')
                )
                outdir = ctx['outdir'] / 'recovered' / 'dpt' / 'restored'
                outdir.mkdir(parents=True, exist_ok=True)
                res = self._restore_methods(store, recovered_paths, outdir)
                report.packer['method_restoration'] = res
                if res.get('restored'):
                    report.dex['analysis_dexes'] = [x['path'] for x in res['dexes']]
            except Exception as e:
                report.limitations.append(
                    f"DPT method restoration failed: {type(e).__name__}: {e}"
                )
