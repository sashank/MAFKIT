from __future__ import annotations
from typing import Any
from datetime import timezone
import re

from .device import parse_android_local_time


def _exact_pkg_lines(lines: list[str], pkg: str) -> list[str]:
    rx=re.compile(r'(?<![A-Za-z0-9_.])'+re.escape(pkg)+r'(?![A-Za-z0-9_.])')
    return [x for x in lines if rx.search(str(x))]


def _timeline_notes(timeline: list[dict[str,Any]]) -> list[dict[str,Any]]:
    out=[]
    for row in timeline:
        ts=row.get('timestamp') or row.get('time') or row.get('date_time') or row.get('datetime') or ''
        desc=row.get('event') or row.get('description') or row.get('notes') or ''
        if ts or desc:
            out.append({'timestamp':ts,'event':desc,'type':row.get('type',''),'source_line':row.get('_source_line')})
    return out


def correlate(report, device: dict[str,Any], timeline: list[dict[str,Any]]) -> dict[str,Any]:
    pkg=report.package.get('package_name') or ''
    caps=report.capabilities or {}
    correlations=[]
    integrity=device.get('integrity_verification',{})
    integrity_compromised=bool(integrity.get('artifacts_missing') or integrity.get('artifacts_mismatched') or integrity.get('manifest_verified') is False)
    anchors={'exact_package_identity':False,'exact_privileged_state':False,'historical_reference':False,'temporal_support':False}

    presence=device.get('package',{}).get('presence',[])
    if pkg and presence:
        anchors['exact_package_identity']=True
        correlations.append({'confidence':'high','category':'package','finding':'Exact analyzed package identifier is present in acquired package inventory','evidence':presence[:20]})

    sec=device.get('security_state',{})
    acc_hits=_exact_pkg_lines(sec.get('enabled_accessibility_services',[]),pkg) if pkg else []
    if acc_hits:
        anchors['exact_privileged_state']=True
        correlations.append({'confidence':'high','category':'accessibility','finding':'Exact analyzed package identifier appears in enabled Accessibility service state','evidence':acc_hits[:30]})
    elif caps.get('accessibility') and sec.get('enabled_accessibility_services'):
        correlations.append({'confidence':'low','category':'accessibility_context','finding':'Accessibility state was acquired, but the analyzed package was not directly matched','evidence':sec.get('enabled_accessibility_services',[])[:20]})

    dp_hits=_exact_pkg_lines(sec.get('device_policy_hits',[]),pkg) if pkg else []
    if dp_hits:
        anchors['exact_privileged_state']=True
        correlations.append({'confidence':'high','category':'device_admin','finding':'Exact analyzed package identifier appears in acquired Device Policy / administrator state','evidence':dp_hits[:30]})

    usage=device.get('usage',{})
    history_sources=[]
    for source,hits in usage.items():
        exact=_exact_pkg_lines(hits,pkg) if pkg else []
        if exact:
            history_sources.append(source)
            correlations.append({'confidence':'high','category':'device_history','finding':f'Exact package references found in {source} evidence','evidence':exact[:30]})
    if history_sources:
        anchors['historical_reference']=True

    # Generic keyword bridges are context only and never raise the correlation assessment by themselves.
    generic=[]
    for item in device.get('evidence_hits',[]):
        if item.get('type')=='behavior_keyword': generic.append(item)
    if generic:
        correlations.append({'confidence':'low','category':'context','finding':'Generic behavior-related strings are present in acquired device artifacts; these are not package-specific','evidence':[f"{x.get('source')}: {x.get('count')} hits" for x in generic[:20]]})

    pkg_times={k:v for k,v in device.get('package',{}).items() if k in ('first_install_time','last_update_time') and v}
    timeline_notes=_timeline_notes(timeline)
    tzname=device.get('device',{}).get('persist.sys.timezone') or None
    temporal=[]
    install_dt=parse_android_local_time(pkg_times.get('first_install_time',''),tzname)
    for x in timeline_notes:
        event_dt=parse_android_local_time(x.get('timestamp',''),tzname)
        if not install_dt or not event_dt:
            continue
        # Compare only if both are aware or both are naive. If a device timezone was captured, both become aware.
        if (install_dt.tzinfo is None) != (event_dt.tzinfo is None):
            continue
        delta=(event_dt-install_dt).total_seconds()
        temporal.append({'event':x.get('event',''),'timestamp':x.get('timestamp',''),'seconds_after_install':delta})
        if delta >= 0:
            anchors['temporal_support']=True
    if pkg_times and timeline_notes:
        correlations.append({
            'confidence':'medium' if temporal else 'low', 'category':'timeline',
            'finding':'Package timestamps and supplied incident timeline are available for temporal comparison' + (' using captured device timezone' if tzname else ' without an independently captured timezone'),
            'evidence':[f'{k}={v}' for k,v in pkg_times.items()] + [f"{x['timestamp']} {x['event']}" for x in timeline_notes[:20]],
        })

    # Rule-based assessment. Timeline alone never increases identity/behavior correlation.
    if anchors['exact_package_identity'] and anchors['exact_privileged_state'] and anchors['historical_reference']:
        level='strong'
        rationale='Exact package identity, exact privileged-state evidence, and independent historical package references are all present.'
    elif anchors['exact_package_identity'] and (anchors['exact_privileged_state'] or anchors['historical_reference']):
        level='moderate'
        rationale='Exact package identity is present together with one independent supporting evidence class.'
    elif anchors['exact_package_identity'] or anchors['exact_privileged_state'] or anchors['historical_reference']:
        level='limited'
        rationale='Only one package-specific evidence class is presently established.'
    else:
        level='none'
        rationale='No package-specific correlation anchor was established from the supplied acquisition.'

    if integrity_compromised and level in ('moderate','strong'):
        level='limited'
        rationale='Acquisition integrity verification reported missing/mismatched evidence; correlation is capped at LIMITED until evidence integrity is resolved.'
        correlations.append({'confidence':'high','category':'evidence_integrity','finding':'Acquisition integrity verification failed or is incomplete','evidence':[str(integrity)]})

    return {
        'package':pkg,
        'correlation_strength':level,
        'correlation_score':None,
        'assessment_basis':'rule-based independent-evidence classes; no additive score',
        'assessment_rationale':rationale,
        'anchors':anchors,
        'integrity_compromised':integrity_compromised,
        'correlations':correlations,
        'timeline':timeline_notes,
        'temporal_comparisons':temporal,
        'device_timezone':tzname,
        'interpretation':'Correlation strength describes consistency between the analyzed APK identity/capabilities and acquired device artifacts. It does not establish who operated the device, prove that a capability executed, or prove causation of a specific transaction.'
    }
