from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import shutil
import subprocess
import time

from .forensic import utc_now_iso, validate_package_name, sha256_file, environment_snapshot

COMMANDS = [
 ('getprop.txt',['shell','getprop']),
 ('packages_all.txt',['shell','pm','list','packages','-f','-U','-i']),
 ('packages_third_party.txt',['shell','pm','list','packages','-3','-f','-U','-i']),
 ('settings_secure.txt',['shell','settings','list','secure']),
 ('settings_global.txt',['shell','settings','list','global']),
 ('settings_system.txt',['shell','settings','list','system']),
 ('dumpsys_accessibility.txt',['shell','dumpsys','accessibility']),
 ('dumpsys_device_policy.txt',['shell','dumpsys','device_policy']),
 ('dumpsys_activity.txt',['shell','dumpsys','activity']),
 ('dumpsys_usagestats.txt',['shell','dumpsys','usagestats']),
 ('dumpsys_notification.txt',['shell','dumpsys','notification']),
 ('dumpsys_netstats.txt',['shell','dumpsys','netstats']),
 ('dumpsys_connectivity.txt',['shell','dumpsys','connectivity']),
 ('dumpsys_wifi.txt',['shell','dumpsys','wifi']),
 ('dumpsys_jobscheduler.txt',['shell','dumpsys','jobscheduler']),
 ('dumpsys_alarm.txt',['shell','dumpsys','alarm']),
 ('dumpsys_batterystats.txt',['shell','dumpsys','batterystats']),
 ('dumpsys_deviceidle.txt',['shell','dumpsys','deviceidle']),
 ('roles.txt',['shell','cmd','role','get-role-holders','android.app.role.SMS']),
 ('logcat.txt',['logcat','-d','-v','threadtime']),
]


def _run(adb: str, serial: str | None, args: list[str], timeout: int = 90) -> tuple[int, bytes, float, str | None]:
    cmd = [adb]
    if serial:
        cmd += ['-s', serial]
    cmd += args
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return p.returncode, p.stdout, time.monotonic() - started, None
    except subprocess.TimeoutExpired as exc:
        data = (exc.stdout or b'') + (exc.stderr or b'')
        return 124, data, time.monotonic() - started, f'timeout after {timeout}s'
    except Exception as exc:
        return 255, str(exc).encode('utf-8', 'replace'), time.monotonic() - started, f'{type(exc).__name__}: {exc}'


def _artifact_record(path: Path, root: Path) -> dict[str, Any]:
    return {
        'path': str(path.relative_to(root)),
        'size': path.stat().st_size,
        'sha256': sha256_file(path),
    }


def _write_and_record(root: Path, filename: str, data: bytes) -> dict[str, Any]:
    path = root / filename
    path.write_bytes(data)
    return _artifact_record(path, root)


def _parse_authorized_devices(data: bytes) -> list[dict[str, str]]:
    out = []
    for line in data.decode('utf-8', 'replace').splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 2 or parts[1] != 'device':
            continue
        item = {'serial': parts[0], 'state': parts[1], 'raw': line}
        for token in parts[2:]:
            if ':' in token:
                k, v = token.split(':', 1)
                item[k] = v
        out.append(item)
    return out


def collect(out: Path, package: str | None = None, bugreport: bool = True,
            case_id: str | None = None, examiner: str | None = None) -> dict[str, Any]:
    package = validate_package_name(package)
    adb = shutil.which('adb')
    if not adb:
        raise RuntimeError('adb not found in PATH. Install Android SDK Platform-Tools.')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    start_utc = utc_now_iso()

    # `adb devices` must not be serial-scoped because its purpose is to select exactly one device.
    rc, devices, duration, err = _run(adb, None, ['devices', '-l'])
    device_rec = _write_and_record(out, 'adb_devices.txt', devices)
    authorized = _parse_authorized_devices(devices)
    if rc != 0:
        raise RuntimeError(f'adb devices failed with return code {rc}; see adb_devices.txt')
    if len(authorized) != 1:
        raise RuntimeError(f'Expected exactly one authorized ADB device, found {len(authorized)}. See adb_devices.txt')
    serial = authorized[0]['serial']

    vrc, vdata, vdur, verr = _run(adb, None, ['version'], timeout=30)
    adb_version_rec = _write_and_record(out, 'adb_version.txt', vdata)

    manifest: dict[str, Any] = {
        'schema': 'mafkit-adb-acquisition-v2',
        'collection_start_utc': start_utc,
        'collection_end_utc': None,
        'case_id': case_id or '',
        'examiner': examiner or '',
        'package': package,
        'adb_path': str(Path(adb).resolve()),
        'adb_version_returncode': vrc,
        'selected_device': authorized[0],
        'collection_method': 'authorized USB/Wireless ADB; non-root; read-oriented commands plus optional bugreport and APK pull',
        'commands': [],
        'artifacts': [device_rec, adb_version_rec],
        'warnings': [],
        'collector_environment': environment_snapshot(),
    }

    def execute_to_file(filename: str, args: list[str], timeout: int = 90) -> tuple[int, bytes]:
        started_utc = utc_now_iso()
        rc2, data, dur, error = _run(adb, serial, args, timeout=timeout)
        rec = _write_and_record(out, filename, data)
        manifest['artifacts'].append(rec)
        manifest['commands'].append({
            'file': filename,
            'argv': ['adb', '-s', serial, *args],
            'started_utc': started_utc,
            'duration_seconds': round(dur, 3),
            'returncode': rc2,
            'error': error,
            'output_sha256': rec['sha256'],
            'output_size': rec['size'],
        })
        if rc2 != 0:
            manifest['warnings'].append(f'Command for {filename} returned {rc2}' + (f' ({error})' if error else ''))
        return rc2, data

    for filename, args in COMMANDS:
        execute_to_file(filename, args)

    if package:
        execute_to_file(f'package_{package}.txt', ['shell', 'dumpsys', 'package', package])
        _, data = execute_to_file(f'package_{package}_paths.txt', ['shell', 'pm', 'path', package])
        for i, line in enumerate(data.decode('utf-8', 'replace').splitlines()):
            if not line.startswith('package:'):
                continue
            remote = line.split(':', 1)[1].strip()
            # Remote path is an adb argument, not a local path. Local destination is fixed by us.
            local = out / f'device_apk_{i}.apk'
            started_utc = utc_now_iso()
            started = time.monotonic()
            try:
                p = subprocess.run([adb, '-s', serial, 'pull', remote, str(local)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=120, check=False)
                output = p.stdout
                prc, perr = p.returncode, None
            except subprocess.TimeoutExpired as exc:
                output = (exc.stdout or b'') + (exc.stderr or b'')
                prc, perr = 124, 'timeout after 120s'
            except Exception as exc:
                output = str(exc).encode('utf-8', 'replace')
                prc, perr = 255, f'{type(exc).__name__}: {exc}'
            logrec = _write_and_record(out, f'adb_pull_{i}.log', output)
            manifest['artifacts'].append(logrec)
            cmdrec = {
                'file': f'adb_pull_{i}.log', 'argv': ['adb', '-s', serial, 'pull', remote, f'device_apk_{i}.apk'],
                'started_utc': started_utc, 'duration_seconds': round(time.monotonic() - started, 3),
                'returncode': prc, 'error': perr, 'output_sha256': logrec['sha256'], 'output_size': logrec['size'],
            }
            if local.is_file():
                apkrec = _artifact_record(local, out)
                manifest['artifacts'].append(apkrec)
                cmdrec['pulled_artifact'] = apkrec
            manifest['commands'].append(cmdrec)
            if prc != 0:
                manifest['warnings'].append(f'APK pull {i} returned {prc}' + (f' ({perr})' if perr else ''))

    if bugreport:
        target = out / 'bugreport.zip'
        started_utc = utc_now_iso()
        rc3, output, dur, error = _run(adb, serial, ['bugreport', str(target)], timeout=600)
        logrec = _write_and_record(out, 'bugreport_command.log', output)
        manifest['artifacts'].append(logrec)
        # Different platform-tools versions may vary in output naming. Record whatever exists.
        candidates = sorted(out.glob('bugreport*.zip'), key=lambda p: p.stat().st_mtime_ns if p.exists() else 0)
        bugrec = _artifact_record(candidates[-1], out) if candidates else None
        if bugrec:
            manifest['artifacts'].append(bugrec)
        manifest['commands'].append({
            'file': 'bugreport_command.log', 'argv': ['adb', '-s', serial, 'bugreport', 'bugreport.zip'],
            'started_utc': started_utc, 'duration_seconds': round(dur, 3), 'returncode': rc3,
            'error': error, 'output_sha256': logrec['sha256'], 'output_size': logrec['size'],
            'bugreport_artifact': bugrec,
        })
        if rc3 != 0 or not bugrec:
            manifest['warnings'].append('Bugreport acquisition did not produce a verified ZIP artifact.')

    manifest['collection_end_utc'] = utc_now_iso()
    # Sort artifact inventory for deterministic inspection. Do not include the manifest itself to avoid recursive hashing.
    dedup: dict[str, dict[str, Any]] = {x['path']: x for x in manifest['artifacts']}
    manifest['artifacts'] = [dedup[k] for k in sorted(dedup)]
    manifest_path = out / 'collection_manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True), encoding='utf-8')
    manifest_hash = sha256_file(manifest_path)
    (out / 'collection_manifest.sha256').write_text(f'{manifest_hash}  collection_manifest.json\n', encoding='ascii')
    return manifest
