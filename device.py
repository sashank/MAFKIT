"""Parsers for Android device triage artifacts (dumpsys, settings, packages, logcat) and timeline CSVs."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .forensic import validate_package_name


def _read(path: Path) -> str:
    """Read file content as UTF-8 with replacement for invalid characters."""
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''


def _sha256(path: Path) -> str:
    """Compute SHA-256 digest of file."""
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _find_first(root: Path, names: list[str]) -> Path | None:
    """Find first matching file path in root directory or nested subdirectories."""
    for n in names:
        p = root / n
        if p.exists() and p.is_file():
            return p
    wanted = set(names)
    for p in root.rglob('*'):
        if p.is_file() and p.name in wanted:
            return p
    return None


def parse_timeline_csv(path: Path | None) -> list[dict[str, Any]]:
    """Parse CSV incident timeline containing event timestamps and descriptions."""
    if not path or not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(newline='', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []
        for i, r in enumerate(reader, start=2):
            item = {
                str(k).strip(): (v or '').strip()
                for k, v in r.items()
                if k is not None
            }
            item['_source_line'] = i
            rows.append(item)
    return rows


def parse_package_dumpsys(text: str, package: str | None = None) -> dict[str, Any]:
    """Parse package manager dumpsys output for install/update timestamps and metadata."""
    out: dict[str, Any] = {}
    keys = {
        'firstInstallTime': 'first_install_time',
        'lastUpdateTime': 'last_update_time',
        'installerPackageName': 'installer_package',
        'versionName': 'version_name',
        'versionCode': 'version_code',
        'userId': 'uid',
        'codePath': 'code_path',
        'dataDir': 'data_dir',
    }
    for line in text.splitlines():
        s = line.strip()
        for src, dst in keys.items():
            if s.startswith(src + '='):
                out[dst] = s.split('=', 1)[1].strip()
        if 'pkgFlags=[' in s:
            out['pkg_flags'] = s.split('pkgFlags=[', 1)[1].split(']', 1)[0]
    return out


def extract_package_presence(text: str, package: str) -> list[str]:
    """Match exact package token to avoid false prefix/substring matching."""
    rx = re.compile(r'(?<![A-Za-z0-9_.])' + re.escape(package) + r'(?![A-Za-z0-9_.])')
    return [ln.strip() for ln in text.splitlines() if rx.search(ln)][:200]


def extract_setting(text: str, key: str) -> list[str]:
    """Extract lines containing setting key from settings dump."""
    vals: list[str] = []
    key_l = key.lower()
    for ln in text.splitlines():
        if key_l in ln.lower():
            vals.append(ln.strip())
    return vals[:200]


def parse_android_local_time(
    value: str,
    timezone_name: str | None = None,
) -> datetime | None:
    """Parse Android timestamp string into datetime, optionally localized with timezone."""
    value = (value or '').strip()
    if not value:
        return None

    formats = (
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f%z',
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None and timezone_name:
                dt = dt.replace(tzinfo=ZoneInfo(timezone_name))
            return dt
        except (ValueError, KeyError):
            continue

    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None and timezone_name:
            dt = dt.replace(tzinfo=ZoneInfo(timezone_name))
        return dt
    except Exception:
        return None


def parse_device_acquisition(
    root: Path | str,
    package: str | None = None,
) -> dict[str, Any]:
    """Parse and verify artifacts in an ADB acquisition directory."""
    package = validate_package_name(package)
    root_path = Path(root)
    result: dict[str, Any] = {
        'source_dir': str(root_path.resolve()),
        'files': {},
        'device': {},
        'package': {},
        'security_state': {},
        'usage': {},
        'network': {},
        'evidence_hits': [],
        'limitations': [],
        'collection_manifest': {},
    }

    if not root_path.exists():
        result['limitations'].append('ADB acquisition directory does not exist.')
        return result

    manifest = _find_first(root_path, ['collection_manifest.json'])
    if manifest:
        try:
            result['collection_manifest'] = json.loads(_read(manifest))
        except Exception as exc:
            result['limitations'].append(f'collection_manifest.json could not be parsed: {exc}')

    # Re-verify acquisition integrity against collection_manifest.sha256
    integ: dict[str, Any] = {
        'manifest_verified': None,
        'artifacts_verified': 0,
        'artifacts_missing': [],
        'artifacts_mismatched': [],
    }
    manifest_sha = _find_first(root_path, ['collection_manifest.sha256'])
    if manifest and manifest_sha:
        try:
            expected = _read(manifest_sha).split()[0].lower()
            actual = _sha256(manifest).lower()
            integ['manifest_verified'] = (expected == actual)
            if expected != actual:
                result['limitations'].append(
                    'collection_manifest.json hash does not match collection_manifest.sha256.'
                )
        except Exception as exc:
            result['limitations'].append(
                f'Collection manifest detached hash could not be verified: {exc}'
            )

    if result.get('collection_manifest'):
        for rec in result['collection_manifest'].get('artifacts', []):
            rel = rec.get('path', '')
            expected = rec.get('sha256', '').lower()
            expected_size = rec.get('size')
            if not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:
                integ['artifacts_mismatched'].append({
                    'path': rel,
                    'reason': 'unsafe manifest path',
                })
                continue

            fp = root_path / rel
            if not fp.is_file():
                integ['artifacts_missing'].append(rel)
                continue

            try:
                actual = _sha256(fp).lower()
                size = fp.stat().st_size
                if actual != expected or (expected_size is not None and size != expected_size):
                    integ['artifacts_mismatched'].append({
                        'path': rel,
                        'expected_sha256': expected,
                        'actual_sha256': actual,
                        'expected_size': expected_size,
                        'actual_size': size,
                    })
                else:
                    integ['artifacts_verified'] += 1
            except Exception as exc:
                integ['artifacts_mismatched'].append({'path': rel, 'reason': str(exc)})

        if integ['artifacts_missing'] or integ['artifacts_mismatched']:
            result['limitations'].append(
                'One or more acquisition artifacts are missing or do not match the collection manifest; '
                'treat device correlation as integrity-compromised until resolved.'
            )
    result['integrity_verification'] = integ

    for p in sorted(root_path.rglob('*')):
        if p.is_file():
            try:
                result['files'][str(p.relative_to(root_path))] = {
                    'size': p.stat().st_size,
                    'sha256': _sha256(p),
                }
            except Exception:
                pass

    props = _read(_find_first(root_path, ['getprop.txt']) or Path('/nonexistent'))
    for k in [
        'ro.product.manufacturer',
        'ro.product.model',
        'ro.build.version.release',
        'ro.build.version.sdk',
        'ro.build.fingerprint',
        'ro.serialno',
        'persist.sys.timezone',
    ]:
        m = re.search(r'\[' + re.escape(k) + r'\]: \[(.*?)\]', props)
        if m:
            result['device'][k] = m.group(1)

    settings = '\n'.join(
        _read(p)
        for p in [
            _find_first(root_path, ['settings_secure.txt']),
            _find_first(root_path, ['settings_global.txt']),
            _find_first(root_path, ['settings_system.txt']),
        ]
        if p
    )
    result['security_state']['enabled_accessibility_services'] = extract_setting(
        settings, 'enabled_accessibility_services'
    )
    result['security_state']['accessibility_enabled'] = extract_setting(
        settings, 'accessibility_enabled'
    )
    result['security_state']['notification_listeners'] = extract_setting(
        settings, 'enabled_notification_listeners'
    )
    result['security_state']['default_input_method'] = extract_setting(
        settings, 'default_input_method'
    )

    devpol = _read(
        _find_first(root_path, ['dumpsys_device_policy.txt']) or Path('/nonexistent')
    )
    result['security_state']['device_policy_hits'] = [
        ln.strip()
        for ln in devpol.splitlines()
        if any(x in ln.lower() for x in ['admin', 'active', 'owner'])
    ][:300]

    roles = _read(_find_first(root_path, ['roles.txt']) or Path('/nonexistent'))
    result['security_state']['roles'] = roles.splitlines()[:300]

    pkgs = '\n'.join(
        _read(p)
        for p in [
            _find_first(root_path, ['packages_all.txt']),
            _find_first(root_path, ['packages_third_party.txt']),
        ]
        if p
    )
    if package:
        result['package']['presence'] = extract_package_presence(pkgs, package)
        pkg_dump = _read(
            _find_first(
                root_path,
                [f'package_{package}.txt', 'dumpsys_package_target.txt'],
            )
            or Path('/nonexistent')
        )
        result['package'].update(parse_package_dumpsys(pkg_dump, package))

        for filename, key in [
            ('dumpsys_usagestats.txt', 'usage'),
            ('dumpsys_activity.txt', 'activity'),
            ('dumpsys_notification.txt', 'notifications'),
            ('logcat.txt', 'logcat'),
        ]:
            txt = _read(_find_first(root_path, [filename]) or Path('/nonexistent'))
            hits = extract_package_presence(txt, package)[:500]
            result['usage'][key] = hits
            if hits:
                result['evidence_hits'].append({
                    'source': filename,
                    'type': 'exact_package_reference',
                    'count': len(hits),
                    'examples': hits[:25],
                })

    for filename in [
        'dumpsys_accessibility.txt',
        'dumpsys_device_policy.txt',
        'dumpsys_activity.txt',
        'dumpsys_notification.txt',
        'dumpsys_usagestats.txt',
        'logcat.txt',
    ]:
        p = _find_first(root_path, [filename])
        txt = _read(p or Path('/nonexistent'))
        keywords = [
            'AccessibilityService',
            'DeviceAdmin',
            'MediaProjection',
            'BOOT_COMPLETED',
            'SmsManager',
            'screen capture',
            'keylog',
            'websocket',
        ]
        hits = [
            ln.strip()
            for ln in txt.splitlines()
            if any(k.lower() in ln.lower() for k in keywords)
        ][:500]
        if hits:
            result['evidence_hits'].append({
                'source': filename,
                'type': 'behavior_keyword',
                'count': len(hits),
                'examples': hits[:30],
            })

    for filename, key in [
        ('dumpsys_netstats.txt', 'netstats'),
        ('dumpsys_connectivity.txt', 'connectivity'),
        ('dumpsys_wifi.txt', 'wifi'),
    ]:
        txt = _read(_find_first(root_path, [filename]) or Path('/nonexistent'))
        result['network'][key] = (
            extract_package_presence(txt, package)[:300] if package else []
        )

    bug = _find_first(root_path, ['bugreport.zip'])
    if not bug:
        bugs = sorted(root_path.glob('bugreport*.zip'))
        bug = bugs[0] if bugs else None
    if bug:
        result['bugreport'] = {
            'path': str(bug),
            'sha256': _sha256(bug),
            'size': bug.stat().st_size,
        }
    else:
        result['limitations'].append('No bugreport ZIP found; some system history may be unavailable.')

    result['limitations'].append(
        "ADB without root cannot reliably read another app's private /data/data directory on modern Android."
    )
    result['limitations'].append(
        'SMS/call/notification content access varies by Android version, OEM, role state, '
        'and shell permissions; absence is not proof of absence.'
    )
    result['limitations'].append(
        'ADB acquisition is a logical/read-oriented collection and is not equivalent to a full physical filesystem acquisition.'
    )

    return result
