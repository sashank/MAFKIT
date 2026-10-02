import html, json
from pathlib import Path
SEV_ORDER={'critical':0,'high':1,'medium':2,'low':3,'info':4}

def write_json(report,path:Path):
    path.write_text(json.dumps(report.to_dict(),indent=2,ensure_ascii=False,sort_keys=True),encoding='utf-8')

def _md_escape(s):
    return str(s).replace('`','\\`')

def _md_list(items): return '\n'.join(f'- `{_md_escape(x)}`' for x in items) if items else '- None found'

def write_markdown(report,path:Path):
    d=report.to_dict(); fs=sorted(d['findings'],key=lambda x:SEV_ORDER.get(x['severity'],9)); crit=sum(1 for f in fs if f['severity']=='critical'); high=sum(1 for f in fs if f['severity']=='high')
    lines=['# Mobile APK + Device Forensic Analysis Report — MAFKit v3.1','', '> Automated static APK analysis plus optional logical/read-oriented ADB correlation. Findings are technical indicators, not conclusions about actor identity, intent, or transaction causation.','', '## Analysis Provenance','']
    a=d.get('analysis',{}); lines += [f"- **Started (UTC):** `{a.get('started_utc','')}`",f"- **Completed (UTC):** `{a.get('completed_utc','')}`",f"- **Case ID:** `{_md_escape(a.get('case_id',''))}`",f"- **Examiner:** `{_md_escape(a.get('examiner',''))}`",f"- **Input path:** `{_md_escape(d.get('input_file',''))}`",'']
    lines += ['## Executive Summary','',f'Automated analysis produced **{crit} critical** and **{high} high-severity indicators**. Severity reflects potential security impact if the associated capability is actually enabled/executed; it is not a malware verdict by itself.','']
    if d.get('packer',{}).get('method_restoration',{}).get('restored'):
        r=d['packer']['method_restoration']; lines.append(f"Deep recovery restored **{r.get('total_methods_restored',0):,} method bodies** across {len(r.get('dexes',[]))} DEX files.")
    if d.get('deobfuscation',{}).get('xor_hits'): lines.append(f"Recovered **{len(d['deobfuscation']['xor_hits']):,} candidate repeating-XOR plaintext strings** from restored bytecode.")
    if d.get('correlation'):
        c=d['correlation']; lines.append(f"Device correlation assessment: **{c.get('correlation_strength','unknown').upper()}** — {c.get('assessment_rationale','')}")
    lines += ['','## Sample Identity','']
    for k,v in d['hashes'].items(): lines.append(f'- **{k.upper()}**: `{v}`')
    for k,v in d['package'].items(): lines.append(f"- **{k.replace('_',' ').title()}**: `{_md_escape(v)}`")
    lines += ['','## Findings','']
    for f in fs:
        lines += [f"### [{f['severity'].upper()}] {f['title']}",f"**Confidence:** {f['confidence']}  ",f"**Evidence ID:** `{f.get('evidence_id','')}`",'',f['interpretation'],'','Evidence:']+[f'- `{_md_escape(e)}`' for e in f['evidence']]+['']
    if d.get('device_evidence'):
        dev=d['device_evidence']; lines += ['## Device / ADB Acquisition','']
        man=dev.get('collection_manifest',{})
        if man:
            lines += [f"- **Collection start (UTC):** `{man.get('collection_start_utc','')}`",f"- **Collection end (UTC):** `{man.get('collection_end_utc','')}`",f"- **Selected device serial:** `{_md_escape(man.get('selected_device',{}).get('serial',''))}`",f"- **Evidence artifacts in manifest:** **{len(man.get('artifacts',[]))}**",'']
        for k,v in dev.get('device',{}).items(): lines.append(f'- **{k}**: `{_md_escape(v)}`')
        lines += ['',f"- Evidence files independently inventoried by analyzer: **{len(dev.get('files',{}))}**",f"- Package first install: `{_md_escape(dev.get('package',{}).get('first_install_time','not available'))}`",f"- Package last update: `{_md_escape(dev.get('package',{}).get('last_update_time','not available'))}`",'']
        lines += ['### Security State','']
        for k,v in dev.get('security_state',{}).items():
            if v: lines.append(f'- **{k}**: `{_md_escape(str(v)[:1800])}`')
    if d.get('correlation'):
        c=d['correlation']; lines += ['','## APK ↔ Device Correlation','',f"**Assessment:** {c.get('correlation_strength','unknown')}  ",f"**Basis:** {c.get('assessment_basis','')}  ",f"**Rationale:** {c.get('assessment_rationale','')}",'',c.get('interpretation',''),'']
        for x in c.get('correlations',[]):
            lines += [f"### {x['finding']}",f"**Confidence:** {x['confidence']} | **Category:** {x['category']}",'']+[f'- `{_md_escape(e)}`' for e in x.get('evidence',[])]+['']
        if c.get('temporal_comparisons'):
            lines += ['### Temporal Comparisons','']
            for x in c['temporal_comparisons'][:100]: lines.append(f"- `{_md_escape(x.get('timestamp',''))}` — {_md_escape(x.get('event',''))}; seconds after install: `{x.get('seconds_after_install')}`")
        elif c.get('timeline'):
            lines += ['### Supplied Incident Timeline','', '> Timeline supplied, but no defensible automatic temporal ordering was derived for one or more entries (for example, timezone or timestamp parsing limitations).','']
            for x in c['timeline'][:100]: lines.append(f"- `{_md_escape(x.get('timestamp',''))}` — {_md_escape(x.get('event',''))} ({_md_escape(x.get('type',''))})")
    lines += ['','## ATT&CK-style Behavior Mapping','', '> Semantic analyst mapping only. Validate exact current MITRE Mobile ATT&CK technique IDs separately before citing them in formal proceedings.','']
    for x in d.get('attack_mapping',[]): lines.append(f"- **{x['tactic']}** — {x['behavior']} (`{x['capability']}`)")
    xr=d.get('deobfuscation',{}).get('xor_hits',[]); lines += ['','## Deep Deobfuscation','',f'- Candidate repeating-XOR plaintexts recovered: **{len(xr)}**']
    if d.get('deobfuscation',{}).get('truncated'): lines.append('- **Note:** XOR result collection reached its configured maximum and is truncated.')
    for x in xr[:120]: lines.append(f"- `{_md_escape(x['decoded'][:300])}` — `{_md_escape(x['method'])}` — {x.get('classification','candidate')}")
    bg=d.get('behavior_graph',{}); lines += ['','## Behavior Graph','',f"- Nodes: **{len(bg.get('nodes',[]))}**",f"- Edges: **{len(bg.get('edges',[]))}**",f"- Truncated: **{bool(bg.get('truncated'))}**",'- Machine-readable graph: `behavior_graph.json`','- Graphviz source: `behavior_graph.dot`','']
    lines += ['## Candidate Indicators of Compromise','','### URLs / WebSockets',_md_list(d['iocs'].get('urls',[])),'','### Domains',_md_list(d['iocs'].get('domains',[])),'','### IPv4',_md_list(d['iocs'].get('ipv4',[])),'', '> IOC extraction is automated. Validate routability, context, provenance, and benign-library origin before operational blocking or legal attribution.','']
    lines += ['## Limitations','']+[f'- {x}' for x in d['limitations']]
    if d.get('device_evidence'): lines += [f'- {x}' for x in d['device_evidence'].get('limitations',[])]
    path.write_text('\n'.join(lines),encoding='utf-8')

def write_html(report,path:Path):
    d=report.to_dict(); fs=sorted(d['findings'],key=lambda x:SEV_ORDER.get(x['severity'],9)); esc=lambda x:html.escape(str(x))
    rows=''.join(f"<tr><td>{esc(f['severity'].upper())}</td><td>{esc(f['title'])}<br><small>Confidence: {esc(f['confidence'])}<br>Evidence ID: {esc(f.get('evidence_id',''))}</small></td><td>{esc(f['interpretation'])}</td><td><code>{'<br>'.join(esc(e) for e in f['evidence'])}</code></td></tr>" for f in fs)
    hashes=''.join(f'<li><b>{esc(k.upper())}</b>: <code>{esc(v)}</code></li>' for k,v in d['hashes'].items()); pkg=''.join(f'<li><b>{esc(k)}</b>: <code>{esc(v)}</code></li>' for k,v in d['package'].items())
    corr=''
    if d.get('correlation'):
        c=d['correlation']; cr=''.join(f"<tr><td>{esc(x['confidence'])}</td><td>{esc(x['category'])}</td><td>{esc(x['finding'])}</td><td><code>{'<br>'.join(esc(e) for e in x.get('evidence',[]))}</code></td></tr>" for x in c.get('correlations',[])); corr=f"<h2>APK ↔ Device Correlation</h2><p><b>Assessment:</b> {esc(c.get('correlation_strength'))}</p><p><b>Basis:</b> {esc(c.get('assessment_basis',''))}</p><p><b>Rationale:</b> {esc(c.get('assessment_rationale',''))}</p><p>{esc(c.get('interpretation',''))}</p><table><tr><th>Confidence</th><th>Category</th><th>Finding</th><th>Evidence</th></tr>{cr}</table>"
    dev=''
    if d.get('device_evidence'):
        x=d['device_evidence']; dev=f"<h2>Device / ADB Acquisition</h2><pre>{esc(json.dumps({'device':x.get('device',{}),'package':x.get('package',{}),'security_state':x.get('security_state',{}),'collection_manifest':x.get('collection_manifest',{}),'evidence_file_count':len(x.get('files',{}))},indent=2))}</pre>"
    atk=''.join(f"<tr><td>{esc(x['tactic'])}</td><td>{esc(x['behavior'])}</td><td><code>{esc(x['capability'])}</code></td></tr>" for x in d.get('attack_mapping',[])); xor=''.join(f"<tr><td><code>{esc(x['decoded'][:500])}</code></td><td><code>{esc(x['method'])}</code></td><td>{esc(x['score'])}</td></tr>" for x in d.get('deobfuscation',{}).get('xor_hits',[])[:200]); iocs=''.join(f"<h3>{esc(k)}</h3><pre>{esc(chr(10).join(v) or 'None found')}</pre>" for k,v in d['iocs'].items())
    a=d.get('analysis',{}); prov=esc(json.dumps({'started_utc':a.get('started_utc'),'completed_utc':a.get('completed_utc'),'case_id':a.get('case_id'),'examiner':a.get('examiner'),'input_file':d.get('input_file'),'environment':a.get('environment',{})},indent=2))
    body=f'''<!doctype html><meta charset="utf-8"><title>MAFKit v3.1 Forensic Report</title><style>body{{font-family:Arial,sans-serif;max-width:1200px;margin:32px auto;line-height:1.45}}table{{border-collapse:collapse;width:100%;margin:12px 0 28px}}td,th{{border:1px solid #d6d6d6;padding:8px;vertical-align:top}}th{{background:#f0f0f0}}code,pre{{font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-word}}.note{{padding:12px;background:#f4f6f8;border-left:4px solid #555}}small{{color:#666}}</style><h1>Mobile APK + Device Forensic Analysis Report — MAFKit v3.1</h1><div class="note">Automated static APK analysis plus optional logical/read-oriented ADB correlation. Technical indicators do not establish actor identity, intent, execution, or transaction causation without corroboration.</div><h2>Analysis Provenance</h2><pre>{prov}</pre><h2>Sample Identity</h2><ul>{hashes}{pkg}</ul><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Interpretation</th><th>Evidence</th></tr>{rows}</table>{dev}{corr}<h2>ATT&amp;CK-style Behavior Mapping</h2><table><tr><th>Tactic</th><th>Behavior</th><th>Capability</th></tr>{atk}</table><h2>Deep Deobfuscation</h2><p>Recovered {len(d.get('deobfuscation',{}).get('xor_hits',[]))} candidate repeating-XOR plaintext strings.</p><table><tr><th>Decoded string</th><th>Method</th><th>Score</th></tr>{xor}</table><h2>Candidate Indicators of Compromise</h2>{iocs}<p><i>Validate context and provenance before blocking or attribution.</i></p><h2>Limitations</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in d['limitations'] + d.get('device_evidence',{}).get('limitations',[]))}</ul>'''
    path.write_text(body,encoding='utf-8')


def write_phone_scan_markdown(result:dict,path:Path):
    apps=result.get('apps',[])
    lines=['# MAFKit USB Phone Safety Scan','',
           '> Static, non-root ADB scan. Scores are heuristic indicators, not malware verdicts or guarantees of safety.','',
           '## Scan Summary','',
           f"- **Started (UTC):** `{result.get('scan_started_utc','')}`",
           f"- **Completed (UTC):** `{result.get('scan_completed_utc','')}`",
           f"- **Device serial:** `{result.get('selected_device',{}).get('serial','')}`",
           f"- **Applications scanned:** {result.get('apps_scanned',len(apps))}",
           f"- **System applications included:** {'Yes' if result.get('include_system_apps') else 'No'}",'',
           'The score runs from 0 to 100; higher means fewer risk indicators were observed. A high score does not prove an app is safe. Unscanned APKs and inaccessible private app data are not covered.','',
           '## App Overview','',
           '| Score | Assessment | Coverage | Package | App source | Granted sensitive permissions |',
           '|---:|---|---|---|---|---|']
    for app in apps:
        safety=app.get('safety',{})
        granted=', '.join(p.removeprefix('android.permission.') for p in app.get('granted_permissions',[])) or 'None observed'
        source=app.get('installer') or ('System image' if app.get('system_app') else 'Unknown')
        lines.append(f"| {safety.get('score','N/A')} | {_md_escape(safety.get('band','Not scored'))} | {app.get('coverage','unknown')} | `{_md_escape(app.get('package',''))}` | `{_md_escape(source)}` | {_md_escape(granted)} |")
    for app in apps:
        safety=app.get('safety',{})
        lines += ['',f"## {_md_escape(app.get('package','Unknown package'))}",'',
                  f"- **Score:** {safety.get('score','N/A')}/100, {safety.get('band','Not scored')}",
                  f"- **Coverage:** {app.get('coverage','unknown')}",
                  f"- **Install source:** `{_md_escape(app.get('installer') or 'unknown')}`",
                  f"- **UID:** `{app.get('uid','unknown')}`",
                  f"- **APK files scanned:** {len(app.get('static_analysis',[]))} of {len(app.get('apks',[]))} pulled",
                  f"- **Accessibility service active:** {'Yes' if app.get('accessibility_service_active') else 'No evidence observed'}",
                  f"- **Device administrator active:** {'Yes' if app.get('device_admin_active') else 'No evidence observed'}",'',
                  '### Permissions','',
                  '| Permission | State | Risk note |','|---|---|---|']
        grants=set(app.get('granted_permissions',[]))
        known=set(app.get('permission_grants_known',[]))
        from .phone_scan import PERMISSION_RISK
        for permission in app.get('requested_permissions',[]):
            state='Granted' if permission in grants else 'Not granted' if permission in known else 'Requested; grant state unavailable'
            risk=PERMISSION_RISK.get(permission)
            note=risk[1] if risk else 'No elevated weighting in this scanner'
            lines.append(f"| `{_md_escape(permission)}` | {state} | {_md_escape(note)} |")
        if not app.get('requested_permissions'):
            lines.append('| No requested permissions parsed | Unknown | Metadata may be incomplete |')
        lines += ['', '### Risk factors','']
        factors=safety.get('factors',[])
        if factors:
            for factor in factors:
                lines.append(f"- **+{factor['points']} risk points** — `{_md_escape(factor['name'])}`: {_md_escape(factor['detail'])}")
        else:
            lines.append('- No weighted risk indicators were observed in the collected metadata and APK contents.')
        findings=app.get('findings',[])
        if findings:
            lines += ['', '### Static findings','']
            for finding in findings:
                ev=', '.join(finding.get('evidence',[])) or 'No matched strings recorded'
                lines.append(f"- **{finding.get('severity','info').upper()}** { _md_escape(finding.get('title','Finding')) } ({finding.get('confidence','unknown')} confidence): `{_md_escape(ev)}`")
        if app.get('apks'):
            lines += ['', '### APK fingerprints','']
            for apk in app['apks']:
                lines.append(f"- `{_md_escape(apk['local_path'])}` — SHA-256 `{apk['sha256']}`, {apk['size_bytes']:,} bytes")
        if app.get('warnings'):
            lines += ['', '### Coverage warnings','']+[f'- {_md_escape(warning)}' for warning in app['warnings']]
    lines += ['', '## Scoring Guide','',
              '- **85–100:** Low observed risk; not a safety certification.',
              '- **65–84:** Review permissions and app purpose.',
              '- **35–64:** Elevated; investigate before trusting.',
              '- **0–34:** High; prioritize manual review and possible removal.', '',
              'Points are added for granted sensitive permissions, static API/string capabilities, packed-code indicators, and active accessibility/device-admin state. A requested permission that is not granted does not receive the granted-permission penalty. Independent indicators can overlap; the result is intentionally conservative and explainable, not a probability.','',
              '## What This Scan Cannot See','']
    lines.extend(f'- {_md_escape(item)}' for item in result.get('limitations',[]))
    lines += ['', '## Suggested Response','',
              'For an app you recognize and need, review its permissions and active special access in Android Settings. For an app you judge unwanted, use `mafkit remove-app PACKAGE` to remove it for Android user 0 after an exact-name confirmation; Android removes that user’s private app data. The scanner does not automatically delete apps, files, or user data.','']
    path.write_text('\n'.join(lines),encoding='utf-8')
