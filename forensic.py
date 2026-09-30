from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import importlib.metadata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKAGE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$')


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_package_name(package: str | None) -> str | None:
    if package is None:
        return None
    package = package.strip()
    if len(package) > 255 or not PACKAGE_RE.fullmatch(package):
        raise ValueError(f'Invalid Android package name: {package!r}')
    return package


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def stable_evidence_id(kind: str, payload: Any) -> str:
    digest = hashlib.sha256(kind.encode() + b'\0' + canonical_json_bytes(payload)).hexdigest()
    return f'{kind}:{digest[:20]}'


def environment_snapshot() -> dict[str, Any]:
    packages={}
    for name in ('mafkit','androguard','cryptography'):
        try: packages[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: packages[name]='not-installed'
    return {
        'python': sys.version.split()[0],
        'implementation': platform.python_implementation(),
        'platform': platform.platform(),
        'machine': platform.machine(),
        'hostname': platform.node(),
        'pid': os.getpid(),
        'python_packages': packages,
    }
