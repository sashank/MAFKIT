from __future__ import annotations
from pathlib import Path
from typing import Any
from datetime import datetime
from zoneinfo import ZoneInfo
import csv
import hashlib
import re

from .forensic import validate_package_name


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''


def _sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def _find_first(root: Path, names: list[str]) -> Path|None:
    for n in names:
        p=root/n
        if p.exists() and p.is_file(): return p
    wanted=set(names)
    for p in root.rglob('*'):
        if p.is_file() and p.name in wanted: return p
    return None


def parse_timeline_csv(path: Path|None) -> list[dict[str,Any]]:
    if not path or not path.exists(): return []
    rows=[]
    with path.open(newline='', encoding='utf-8-sig', errors='replace') as f:
        reader=csv.DictReader(f)
        if reader.fieldnames is None: return []
        for i,r in enumerate(reader, start=2):
            item={str(k).strip():(v or '').strip() for k,v in r.items() if k is not None}
            item['_source_line']=i
            rows.append(item)
    return rows


def parse_package_dumpsys(text: str, package: str|None=None) -> dict[str,Any]:
    out={}
    keys={
        'firstInstallTime':'first_install_time','lastUpdateTime':'last_update_time',
        'installerPackageName':'installer_package','versionName':'version_name','versionCode':'version_code',
        'userId':'uid','codePath':'code_path','dataDir':'data_dir'
    }
    for line in text.splitlines():
        s=line.strip()
        for src,dst in keys.items():
            if s.startswith(src+'='):
                out[dst]=s.split('=',1)[1].strip()
        if 'pkgFlags=[' in s: out['pkg_flags']=s.split('pkgFlags=[',1)[1].split(']',1)[0]
    return out


def extract_package_presence(text: str, package: str) -> list[str]:
    # Match package as a token to avoid com.foo matching com.foobar.
    rx=re.compile(r'(?<![A-Za-z0-9_.])'+re.escape(package)+r'(?![A-Za-z0-9_.])')
    return [ln.strip() for ln in text.splitlines() if rx.search(ln)][:200]


def extract_setting(text: str, key: str) -> list[str]:
    vals=[]
    key_l=key.lower()
    for ln in text.splitlines():
        if key_l in ln.lower(): vals.append(ln.strip())
    return vals[:200]


def parse_android_local_time(value: str, timezone_name: str|None=None) -> datetime|None:
    value=(value or '').strip()
    if not value: return None
    formats=('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M:%S.%f','%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M:%S%z','%Y-%m-%dT%H:%M:%S.%f%z')
    for fmt in formats:
        try:
            dt=datetime.strptime(value,fmt)
            if dt.tzinfo is None and timezone_name:
                dt=dt.replace(tzinfo=ZoneInfo(timezone_name))
            return dt
        except (ValueError, KeyError):
            continue
    try:
        dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        if dt.tzinfo is None and timezone_name: dt=dt.replace(tzinfo=ZoneInfo(timezone_name))
        return dt
    except Exception:
        return None


def parse_device_acquisition(root: Path, package: str|None=None) -> dict[str,Any]:
    package=validate_package_name(package)
    root=Path(root)
    result={
        'source_dir':str(root.resolve()), 'files':{}, 'device':{}, 'package':{},
        'security_state':{}, 'usage':{}, 'network':{}, 'evidence_hits':[], 'limitations':[],
        'collection_manifest':{},
    }
    if not root.exists():
        result['limitations'].append('ADB acquisition directory does not exist.')
        return result

    manifest=_find_first(root,['collection_manifest.json'])
    if manifest:
        try:
            import json
            result['collection_manifest']=json.loads(_read(manifest))
        except Exception as exc:
            result['limitations'].append(f'collection_manifest.json could not be parsed: {exc}')

    # Re-verify acquisition integrity before using artifacts. The manifest itself is checked
    # against the detached collection_manifest.sha256 when available.
    integ={'manifest_verified':None,'artifacts_verified':0,'artifacts_missing':[],'artifacts_mismatched':[]}
    manifest_sha=_find_first(root,['collection_manifest.sha256'])
    if manifest and manifest_sha:
        try:
            expected=_read(manifest_sha).split()[0].lower()
            actual=_sha256(manifest).lower()
            integ['manifest_verified']=(expected==actual)
            if expected!=actual: result['limitations'].append('collection_manifest.json hash does not match collection_manifest.sha256.')
        except Exception as exc:
            result['limitations'].append(f'Collection manifest detached hash could not be verified: {exc}')
    if result.get('collection_manifest'):
        for rec in result['collection_manifest'].get('artifacts',[]):
            rel=rec.get('path',''); expected=rec.get('sha256','').lower(); expected_size=rec.get('size')
            if not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:
                integ['artifacts_mismatched'].append({'path':rel,'reason':'unsafe manifest path'}); continue
            fp=root/rel
            if not fp.is_file():
                integ['artifacts_missing'].append(rel); continue
            try:
                actual=_sha256(fp).lower(); size=fp.stat().st_size
                if actual!=expected or (expected_size is not None and size!=expected_size):
                    integ['artifacts_mismatched'].append({'path':rel,'expected_sha256':expected,'actual_sha256':actual,'expected_size':expected_size,'actual_size':size})
                else: integ['artifacts_verified']+=1
            except Exception as exc:
                integ['artifacts_mismatched'].append({'path':rel,'reason':str(exc)})
        if integ['artifacts_missing'] or integ['artifacts_mismatched']:
            result['limitations'].append('One or more acquisition artifacts are missing or do not match the collection manifest; treat device correlation as integrity-compromised until resolved.')
    result['integrity_verification']=integ

    for p in sorted(root.rglob('*')):
        if p.is_file():
            try: result['files'][str(p.relative_to(root))]={'size':p.stat().st_size,'sha256':_sha256(p)}
            except Exception: pass

    props=_read(_find_first(root,['getprop.txt']) or Path('/nonexistent'))
    for k in ['ro.product.manufacturer','ro.product.model','ro.build.version.release','ro.build.version.sdk','ro.build.fingerprint','ro.serialno','persist.sys.timezone']:
        m=re.search(r'\['+re.escape(k)+r'\]: \[(.*?)\]', props)
        if m: result['device'][k]=m.group(1)

    settings='\n'.join(_read(p) for p in [
        _find_first(root,['settings_secure.txt']), _find_first(root,['settings_global.txt']), _find_first(root,['settings_system.txt'])
    ] if p)
    result['security_state']['enabled_accessibility_services']=extract_setting(settings,'enabled_accessibility_services')
    result['security_state']['accessibility_enabled']=extract_setting(settings,'accessibility_enabled')
    result['security_state']['notification_listeners']=extract_setting(settings,'enabled_notification_listeners')
    result['security_state']['default_input_method']=extract_setting(settings,'default_input_method')

    devpol=_read(_find_first(root,['dumpsys_device_policy.txt']) or Path('/nonexistent'))
    result['security_state']['device_policy_hits']=[ln.strip() for ln in devpol.splitlines() if any(x in ln.lower() for x in ['admin','active','owner'])][:300]

    roles=_read(_find_first(root,['roles.txt']) or Path('/nonexistent'))
    result['security_state']['roles']=roles.splitlines()[:300]

    pkgs='\n'.join(_read(p) for p in [_find_first(root,['packages_all.txt']), _find_first(root,['packages_third_party.txt'])] if p)
    if package:
        result['package']['presence']=extract_package_presence(pkgs, package)
        pkg_dump=_read(_find_first(root,[f'package_{package}.txt','dumpsys_package_target.txt']) or Path('/nonexistent'))
        result['package'].update(parse_package_dumpsys(pkg_dump, package))
        for filename,key in [('dumpsys_usagestats.txt','usage'),('dumpsys_activity.txt','activity'),('dumpsys_notification.txt','notifications'),('logcat.txt','logcat')]:
            txt=_read(_find_first(root,[filename]) or Path('/nonexistent'))
            hits=extract_package_presence(txt,package)[:500]
            result['usage'][key]=hits
            if hits: result['evidence_hits'].append({'source':filename,'type':'exact_package_reference','count':len(hits),'examples':hits[:25]})

    for filename in ['dumpsys_accessibility.txt','dumpsys_device_policy.txt','dumpsys_activity.txt','dumpsys_notification.txt','dumpsys_usagestats.txt','logcat.txt']:
        p=_find_first(root,[filename]); txt=_read(p or Path('/nonexistent'))
        keywords=['AccessibilityService','DeviceAdmin','MediaProjection','BOOT_COMPLETED','SmsManager','screen capture','keylog','websocket']
        hits=[ln.strip() for ln in txt.splitlines() if any(k.lower() in ln.lower() for k in keywords)][:500]
        if hits: result['evidence_hits'].append({'source':filename,'type':'behavior_keyword','count':len(hits),'examples':hits[:30]})

    for filename,key in [('dumpsys_netstats.txt','netstats'),('dumpsys_connectivity.txt','connectivity'),('dumpsys_wifi.txt','wifi')]:
        txt=_read(_find_first(root,[filename]) or Path('/nonexistent'))
        result['network'][key]=extract_package_presence(txt,package)[:300] if package else []

    bug=_find_first(root,['bugreport.zip'])
    if not bug:
        bugs=sorted(root.glob('bugreport*.zip'))
        bug=bugs[0] if bugs else None
    if bug: result['bugreport']={'path':str(bug),'sha256':_sha256(bug),'size':bug.stat().st_size}
    else: result['limitations'].append('No bugreport ZIP found; some system history may be unavailable.')
    result['limitations'].append("ADB without root cannot reliably read another app's private /data/data directory on modern Android.")
    result['limitations'].append('SMS/call/notification content access varies by Android version, OEM, role state, and shell permissions; absence is not proof of absence.')
    result['limitations'].append('ADB acquisition is a logical/read-oriented collection and is not equivalent to a full physical filesystem acquisition.')
    return result
