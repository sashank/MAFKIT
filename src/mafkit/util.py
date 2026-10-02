"""Utility helpers for MAFKit: hashing, entropy, IOC regexes, and shell execution."""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Sequence, TypeVar

T = TypeVar("T")

URL_RE = re.compile(rb'https?://[^\x00\s"\'<>]{3,300}', re.I)
WS_RE = re.compile(rb'wss?://[^\x00\s"\'<>]{3,300}', re.I)
DOMAIN_RE = re.compile(
    rb'(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    rb'(?:com|net|org|io|app|xyz|top|info|online|site|live|cc|me|ru|cn|in|co|dev|cloud|work)(?![A-Za-z0-9_-])',
    re.I,
)
IP_RE = re.compile(
    rb'(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)'
)
ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')


def hashes(path: Path) -> dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 digests for a file."""
    hs = {k: hashlib.new(k) for k in ("md5", "sha1", "sha256")}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hs.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hs.items()}


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte slice."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def which(name: str) -> str | None:
    """Return path to executable if available in PATH."""
    return shutil.which(name)


def run(cmd: Sequence[str], timeout: int = 30) -> tuple[int, str]:
    """Execute a subprocess safely and return (exit_code, combined_stdout_stderr)."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 127, str(e)


def printable_strings(data: bytes) -> list[str]:
    """Extract printable ASCII strings (>= 4 chars) from raw bytes."""
    return [m.group().decode("utf-8", "replace") for m in ASCII_RE.finditer(data)]


def uniq(seq: Iterable[T]) -> list[T]:
    """Preserve order deduplication for an iterable sequence."""
    out: list[T] = []
    seen: set[T] = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
