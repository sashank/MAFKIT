from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .analyzers import APKAnalyzer
from .forensic import environment_snapshot, sha256_file, utc_now_iso
from .model import Report
from .plugins.dpt import DPTPlugin

DEVICE_LINE_RE = re.compile(r'^([^\s]+)\s+(device|unauthorized|offline)\b(.*)$')
PACKAGE_LINE_RE = re.compile(r'^(?:(?P<apk>.+?)=)?(?P<package>[A-Za-z_][A-Za-z0-9_.]+)(?P<rest>(?:\s+.*)?)$')
PERMISSION_RE = re.compile(r'^\s*(android\.permission\.[A-Z0-9_]+)(?::\s+granted=(true|false))?', re.I)

PERMISSION_RISK = {
    'android.permission.READ_SMS': (18, 'Can expose SMS and one-time passcodes'),
    'android.permission.RECEIVE_SMS': (16, 'Can receive and potentially intercept SMS'),
    'android.permission.SEND_SMS': (18, 'Can send SMS messages'),
    'android.permission.READ_CALL_LOG': (10, 'Can read call history'),
    'android.permission.WRITE_CALL_LOG': (10, 'Can modify call history'),
    'android.permission.CALL_PHONE': (8, 'Can initiate phone calls'),
    'android.permission.RECORD_AUDIO': (8, 'Can record audio'),
    'android.permission.CAMERA': (7, 'Can use the camera'),
    'android.permission.MANAGE_EXTERNAL_STORAGE': (12, 'Can access broad shared storage'),
    'android.permission.SYSTEM_ALERT_WINDOW': (14, 'Can draw overlays above other apps'),
    'android.permission.REQUEST_INSTALL_PACKAGES': (8, 'Can request installation of other packages'),
    'android.permission.REQUEST_DELETE_PACKAGES': (5, 'Can request removal of packages'),
    'android.permission.RECEIVE_BOOT_COMPLETED': (5, 'Can receive boot notifications'),
    'android.permission.READ_CONTACTS': (7, 'Can read contacts'),
    'android.permission.READ_PHONE_STATE': (5, 'Can read phone or subscriber state'),
    'android.permission.ACCESS_FINE_LOCATION': (8, 'Can access precise location'),
    'android.permission.ACCESS_COARSE_LOCATION': (5, 'Can access approximate location'),
}

CAPABILITY_RISK = {
    'accessibility': (12, 'Accessibility APIs can inspect or control the UI'),
    'sms': (10, 'SMS-related APIs or strings are present in the APK'),
    'device_admin': (9, 'Device-administration APIs are present'),
    'screen_capture': (12, 'Screen-capture APIs are present'),
    'websocket': (8, 'WebSocket communication APIs are present'),
    'shell': (18, 'Shell or process-execution indicators are present'),
    'keylogging': (15, 'Keylogging indicators are present'),
    'camera_mic_privacy_bypass': (12, 'Privacy-indicator configuration is referenced'),
    'file_transfer': (5, 'File upload or download indicators are present'),
    'overlay_injection': (12, 'Overlay or injection indicators are present'),
    'persistence': (4, 'Boot or background-service indicators are present'),
}


def _run(command: list[str], timeout: int = 45) -> tuple[int, str, float, str | None]:
    started = time.monotonic()
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
        return result.returncode, result.stdout.decode('utf-8', 'replace'), time.monotonic() - started, None
    except subprocess.TimeoutExpired as exc:
        data = exc.stdout or b''
        return 124, data.decode('utf-8', 'replace'), time.monotonic() - started, f'timeout after {timeout}s'
    except OSError as exc:
        return 255, str(exc), time.monotonic() - started, f'{type(exc).__name__}: {exc}'


def parse_devices(output: str) -> list[dict[str, str]]:
    devices = []
    for line in output.splitlines()[1:]:
        match = DEVICE_LINE_RE.match(line.strip())
        if match:
            devices.append({'serial': match.group(1), 'state': match.group(2), 'details': match.group(3).strip()})
    return devices


def parse_package_inventory(output: str) -> list[dict[str, Any]]:
    packages = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('package:'):
            line = line[len('package:'):]
        match = PACKAGE_LINE_RE.match(line)
        if not match:
            continue
        item: dict[str, Any] = {'package': match.group('package'), 'apk_path': match.group('apk') or None}
        rest = match.group('rest') or ''
        uid = re.search(r'\buid:(\d+)', rest)
        installer = re.search(r'\binstaller=(\S+)', rest)
        if uid:
            item['uid'] = int(uid.group(1))
        if installer:
            item['installer'] = installer.group(1)
        path = item['apk_path'] or ''
        item['system_app'] = path.startswith(('/system/', '/product/', '/vendor/', '/system_ext/'))
        packages.append(item)
    return packages


def parse_package_permissions(dump: str) -> tuple[list[str], dict[str, bool]]:
    requested: set[str] = set()
    granted: dict[str, bool] = {}
    in_requested = False
    for line in dump.splitlines():
        stripped = line.strip()
        if re.match(r'^[a-z][a-z ]* permissions:\s*$', stripped, re.I):
            in_requested = stripped.lower().startswith('requested permissions:')
            continue
        match = PERMISSION_RE.match(line)
        if not match:
            continue
        permission, state = match.groups()
        if in_requested:
            requested.add(permission)
        if state is not None:
            granted[permission] = state.lower() == 'true'
    return sorted(requested | set(granted)), granted


def calculate_safety_score(permissions: list[str], granted: dict[str, bool], capabilities: dict[str, Any],
                           accessibility_enabled: bool = False, device_admin_active: bool = False,
                           packed: bool = False) -> dict[str, Any]:
    factors = []
    points = 0
    for permission in sorted(set(permissions)):
        risk = PERMISSION_RISK.get(permission)
        if not risk or not granted.get(permission, False):
            continue
        weight, explanation = risk
        points += weight
        factors.append({'type': 'granted_permission', 'name': permission, 'points': weight, 'detail': explanation})
    for name, (weight, explanation) in CAPABILITY_RISK.items():
        if name in capabilities:
            points += weight
            factors.append({'type': 'static_capability', 'name': name, 'points': weight, 'detail': explanation})
    if accessibility_enabled:
        points += 18
        factors.append({'type': 'active_device_setting', 'name': 'accessibility_service', 'points': 18,
                        'detail': 'This package appears in the device active-accessibility-service list'})
    if device_admin_active:
        points += 16
        factors.append({'type': 'active_device_setting', 'name': 'device_admin', 'points': 16,
                        'detail': 'This package appears in active device-administrator policy output'})
    if packed:
        points += 10
        factors.append({'type': 'static_indicator', 'name': 'packed_code', 'points': 10,
                        'detail': 'Packed or concealed-code indicators were detected'})
    score = max(0, 100 - min(points, 100))
    if score >= 85:
        band = 'Low observed risk'
    elif score >= 65:
        band = 'Review'
    elif score >= 35:
        band = 'Elevated'
    else:
        band = 'High'
    return {'score': score, 'band': band, 'risk_points': min(points, 100), 'factors': factors,
            'method': 'Heuristic indicator score; higher is safer. This is not a malware verdict or reputation score.'}


def _component_packages(text: str) -> set[str]:
    return {match.group(1) for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_.]+)/[A-Za-z_.$][A-Za-z0-9_.$]*', text)}


def _dump_app(adb: str, serial: str, package: str) -> tuple[str, list[str]]:
    rc, dump, _, error = _run([adb, '-s', serial, 'shell', 'dumpsys', 'package', package])
    warnings = []
    if rc:
        warnings.append(f'Package metadata command failed (exit {rc})' + (f': {error}' if error else ''))
    return dump, warnings


def _apk_paths(adb: str, serial: str, package: str) -> tuple[list[str], str | None]:
    rc, output, _, error = _run([adb, '-s', serial, 'shell', 'pm', 'path', package])
    if rc:
        return [], f'Could not list APK paths (exit {rc})' + (f': {error}' if error else '')
    paths = [line.partition(':')[2].strip() for line in output.splitlines() if line.startswith('package:')]
    return paths, None if paths else 'Device returned no APK paths for this package'


def _static_scan(apk: Path, workdir: Path) -> dict[str, Any]:
    analyzer = APKAnalyzer(apk, workdir)
    ctx = None
    report = Report(input_file=str(apk))
    try:
        ctx = analyzer.build_context()
        analyzer.analyze_base(report, ctx)
        try:
            DPTPlugin().analyze(ctx, report)
        except Exception as exc:
            report.limitations.append(f'DPT plugin failed: {type(exc).__name__}: {exc}')
        return {
            'sha256': report.hashes.get('sha256'),
            'size_bytes': apk.stat().st_size,
            'capabilities': report.capabilities,
            'findings': [{'severity': f.severity, 'category': f.category, 'title': f.title,
                          'evidence': f.evidence, 'confidence': f.confidence} for f in report.findings],
            'packed': bool(report.packer.get('detected')),
            'packer': report.packer,
            'iocs': report.iocs,
            'limitations': report.limitations,
        }
    finally:
        if ctx and ctx.get('zip'):
            ctx['zip'].close()


def scan_phone(out: Path, serial: str | None = None, include_system: bool = True,
               max_apps: int | None = None) -> dict[str, Any]:
    adb = shutil.which('adb')
    if not adb:
        raise RuntimeError('adb was not found. Install Android SDK Platform-Tools and ensure adb is in PATH.')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rc, device_output, _, error = _run([adb, 'devices', '-l'], timeout=20)
    if rc:
        raise RuntimeError(f'adb devices failed (exit {rc})' + (f': {error}' if error else ''))
    devices = parse_devices(device_output)
    authorized = [device for device in devices if device['state'] == 'device']
    if serial:
        authorized = [device for device in authorized if device['serial'] == serial]
        if not authorized:
            raise RuntimeError(f'No authorized device found with serial {serial!r}; check USB debugging authorization.')
    elif len(authorized) != 1:
        states = ', '.join(f"{d['serial']} ({d['state']})" for d in devices) or 'none detected'
        raise RuntimeError(f'Expected exactly one authorized device, found {len(authorized)}. Devices: {states}. Use --serial when multiple devices are connected.')
    device = authorized[0]
    selected_serial = device['serial']
    rc, inventory_text, _, error = _run([adb, '-s', selected_serial, 'shell', 'pm', 'list', 'packages', '-f', '-U', '-i'])
    if rc:
        raise RuntimeError(f'Package enumeration failed (exit {rc})' + (f': {error}' if error else '') + f'. Device output: {inventory_text[:500]}')
    packages = parse_package_inventory(inventory_text)
    third_party_rc, third_party_text, _, third_party_error = _run(
        [adb, '-s', selected_serial, 'shell', 'pm', 'list', 'packages', '-3'])
    third_party_packages = {line.strip().removeprefix('package:') for line in third_party_text.splitlines()} if third_party_rc == 0 else None
    if third_party_packages is not None:
        for package in packages:
            package['system_app'] = package['package'] not in third_party_packages
    else:
        print('Warning: could not classify system apps from Package Manager; using APK install paths.')
    if not include_system:
        packages = [package for package in packages if not package['system_app']]
    if max_apps is not None:
        packages = packages[:max_apps]
    rc, accessibility_text, _, _ = _run([adb, '-s', selected_serial, 'shell', 'dumpsys', 'accessibility'])
    rc_policy, policy_text, _, _ = _run([adb, '-s', selected_serial, 'shell', 'dumpsys', 'device_policy'])
    accessibility_packages = _component_packages(accessibility_text) if rc == 0 else set()
    admin_packages = _component_packages(policy_text) if rc_policy == 0 else set()
    app_results = []
    apk_root = out / 'pulled_apks'
    work_root = out / '.scan_work'
    apk_root.mkdir(exist_ok=True)
    work_root.mkdir(exist_ok=True)
    for index, app in enumerate(packages, 1):
        package = app['package']
        print(f'[{index}/{len(packages)}] Scanning {package}')
        dump, warnings = _dump_app(adb, selected_serial, package)
        requested, granted = parse_package_permissions(dump)
        apk_paths, path_warning = _apk_paths(adb, selected_serial, package)
        static_reports = []
        pulled_files = []
        if path_warning:
            warnings.append(path_warning)
        for apk_index, remote_path in enumerate(apk_paths):
            filename = 'base.apk' if remote_path.endswith('/base.apk') else f'split-{apk_index}.apk'
            local_dir = apk_root / package
            local_dir.mkdir(parents=True, exist_ok=True)
            local_path = local_dir / filename
            pull_rc, pull_text, _, pull_error = _run([adb, '-s', selected_serial, 'pull', remote_path, str(local_path)], timeout=180)
            if pull_rc or not local_path.is_file():
                warnings.append(f'APK pull failed for {remote_path} (exit {pull_rc})' + (f': {pull_error}' if pull_error else f': {pull_text[-300:]}'))
                continue
            pulled_files.append({'device_path': remote_path, 'local_path': str(local_path.relative_to(out)),
                                 'sha256': sha256_file(local_path), 'size_bytes': local_path.stat().st_size})
            try:
                static_reports.append(_static_scan(local_path, work_root / package / str(apk_index)))
            except Exception as exc:
                warnings.append(f'Static APK scan failed for {remote_path}: {type(exc).__name__}: {exc}')
        merged_capabilities = {}
        findings = []
        for static in static_reports:
            merged_capabilities.update(static.get('capabilities', {}))
            findings.extend(static.get('findings', []))
        score = calculate_safety_score(requested, granted, merged_capabilities,
                                       package in accessibility_packages, package in admin_packages,
                                       any(result.get('packed') for result in static_reports))
        app_results.append({
            **app,
            'requested_permissions': requested,
            'granted_permissions': sorted(permission for permission in requested if granted.get(permission, False)),
            'permission_grants_known': sorted(granted),
            'accessibility_service_active': package in accessibility_packages,
            'device_admin_active': package in admin_packages,
            'apks': pulled_files,
            'static_analysis': static_reports,
            'capabilities': merged_capabilities,
            'findings': findings,
            'safety': score,
            'coverage': 'complete' if pulled_files and not warnings else 'partial' if requested or pulled_files else 'metadata-only',
            'warnings': warnings,
        })
    result = {
        'schema': 'mafkit-phone-scan-v1',
        'scan_started_utc': utc_now_iso(),
        'scan_completed_utc': None,
        'collection_method': 'USB ADB, non-root, read-only device commands; pulled APKs analyzed offline',
        'selected_device': device,
        'include_system_apps': include_system,
        'apps_scanned': len(app_results),
        'apps': sorted(app_results, key=lambda item: (item['safety']['score'], item['package'])),
        'limitations': [
            'This score is a static heuristic, not a malware verdict or a guarantee of safety.',
            'Private app data and protected system areas are not accessible through ordinary non-root ADB and are not scanned.',
            'Only installed APK files and package metadata are inspected; running app behavior is not monitored.',
            'Each APK can contain split APKs; every path returned by Package Manager is scanned separately.',
            'Use Android settings to review special access such as accessibility, overlay, notification access, and device administration.',
        ],
        'environment': environment_snapshot(),
    }
    if third_party_rc:
        result['limitations'].append('Third-party package classification failed; system-app detection fell back to APK install paths.' + (f' {third_party_error}' if third_party_error else ''))
    result['scan_completed_utc'] = utc_now_iso()
    result_path = out / 'phone_scan.json'
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True), encoding='utf-8')
    from .reporting import write_phone_scan_markdown
    write_phone_scan_markdown(result, out / 'phone_scan.md')
    return result


def uninstall_user_app(package: str, serial: str | None = None) -> str:
    adb = shutil.which('adb')
    if not adb:
        raise RuntimeError('adb was not found. Install Android SDK Platform-Tools and ensure adb is in PATH.')
    from .forensic import validate_package_name
    package = validate_package_name(package)
    rc, output, _, error = _run([adb, 'devices', '-l'], timeout=20)
    if rc:
        raise RuntimeError(f'adb devices failed (exit {rc})' + (f': {error}' if error else ''))
    devices = [device for device in parse_devices(output) if device['state'] == 'device']
    if serial:
        devices = [device for device in devices if device['serial'] == serial]
    if len(devices) != 1:
        raise RuntimeError(f'Expected exactly one authorized target device, found {len(devices)}. Use --serial to select a device.')
    selected_serial = devices[0]['serial']
    rc, inventory, _, error = _run([adb, '-s', selected_serial, 'shell', 'pm', 'list', 'packages', '-3'])
    if rc:
        raise RuntimeError(f'Could not verify third-party package status (exit {rc})' + (f': {error}' if error else ''))
    installed = {line.strip().removeprefix('package:') for line in inventory.splitlines()}
    if package not in installed:
        raise RuntimeError('Refusing removal: package is not listed as a third-party app. System apps are never removed by this command.')
    confirmation = input(f"Remove {package} and its private app data for Android user 0? Type the exact package name to continue: ")
    if confirmation.strip() != package:
        return 'Cancelled; no device changes were made.'
    rc, output, _, error = _run([adb, '-s', selected_serial, 'shell', 'pm', 'uninstall', '--user', '0', package], timeout=90)
    if rc or 'success' not in output.lower():
        raise RuntimeError(f'Uninstall action failed (exit {rc})' + (f': {error}' if error else f': {output.strip()}'))
    return f'Removed {package} and its private app data for user 0. Shared storage files are not removed automatically. Device response: {output.strip()}'