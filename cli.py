import argparse, json, re
from pathlib import Path
from .model import Report, Finding
from .analyzers import APKAnalyzer
from .plugins.dpt import DPTPlugin
from .deobfuscation import scan_dex_xor
from .behavior import build_behavior_graph
from .attack import map_capabilities
from .reporting import write_json, write_markdown, write_html
from .util import uniq, URL_RE, WS_RE, DOMAIN_RE, IP_RE
from .device import parse_device_acquisition, parse_timeline_csv
from .correlation import correlate
from .adbcollect import collect as adb_collect
from .forensic import utc_now_iso, environment_snapshot, stable_evidence_id, validate_package_name
from .phone_scan import scan_phone, uninstall_user_app


def _enrich_iocs(report, strings):
    raw='\n'.join(strings).encode('utf-8','ignore')
    urls=uniq(report.iocs.get('urls',[])+[m.decode('utf-8','ignore') for m in URL_RE.findall(raw)]+[m.decode('utf-8','ignore') for m in WS_RE.findall(raw)])
    domains=uniq(report.iocs.get('domains',[])+[m.decode('ascii','ignore') for m in DOMAIN_RE.findall(raw)])
    ips=uniq(report.iocs.get('ipv4',[])+[m.decode('ascii','ignore') for m in IP_RE.findall(raw)])
    report.iocs={'urls':urls[:1000],'domains':domains[:1000],'ipv4':ips[:1000]}


def _finalize_findings(report):
    for f in report.findings:
        if not f.evidence_id:
            f.evidence_id=stable_evidence_id('finding',{'category':f.category,'title':f.title,'evidence':f.evidence,'interpretation':f.interpretation,'confidence':f.confidence})


def _positive_int(value):
    number=int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be at least 1')
    return number


def analyze(args):
    if not args.apk.is_file(): raise SystemExit('APK file not found')
    package_override=validate_package_name(getattr(args,'package',None))
    args.out.mkdir(parents=True,exist_ok=True)
    report=Report(input_file=str(args.apk.resolve()))
    report.analysis={'started_utc':utc_now_iso(),'completed_utc':None,'case_id':getattr(args,'case_id',None) or '', 'examiner':getattr(args,'examiner',None) or '', 'environment':environment_snapshot(), 'mode':{'deep':bool(args.deep),'decompile':bool(args.decompile)}}
    analyzer=APKAnalyzer(args.apk,args.out)
    try:
        ctx=analyzer.build_context(); analyzer.analyze_base(report,ctx)
        for plugin in [DPTPlugin()]:
            try: plugin.analyze(ctx,report)
            except Exception as e: report.limitations.append(f'Plugin {plugin.name} failed: {type(e).__name__}: {e}')
        if report.packer.get('detected'):
            report.findings.append(Finding('high','packer','Code packing/protection detected',report.packer.get('evidence',[]),'Packing/protection can conceal executable logic and configuration from ordinary decompilation. Detection does not itself imply malicious intent.','high'))
        dexes=[Path(x) for x in report.dex.get('analysis_dexes',[]) if Path(x).is_file()]
        if args.deep and dexes:
            xor_result=scan_dex_xor(dexes); hits=xor_result['hits']
            op_re=re.compile(r'(sms|otp|screen|access|admin|lock|cover|front|shell|exec|command|socket|websocket|host|url|notification|upload|download|inject|overlay|keylog|camera|microphone|device|client|server|bank|upi|pay|wallet|miner|file|clip|chat|terminal|clone|fetch|record)',re.I)
            operational=[]; seen=set()
            for x in hits:
                value=x['decoded'].strip()
                if op_re.search(value) and len(value)<=160 and value not in seen:
                    seen.add(value); operational.append({'value':value,'method':x['method'],'score':x['score'],'classification':'candidate operational string'})
            report.deobfuscation={'xor_hits':hits,'operational_strings':operational[:1000],'strategy':'generic two-byte-array to String repeating-XOR candidate recovery','truncated':xor_result['truncated'],'errors':xor_result['errors']}
            _enrich_iocs(report,[x['decoded'] for x in hits]); report.behavior_graph=build_behavior_graph(dexes,args.out)
            if hits:
                interesting=[x['decoded'] for x in hits if re.search(r'(screen|sms|keylog|inject|overlay|websocket|shell|upload|download|admin|camera|microphone|lock|otp|bank|upi|pay)',x['decoded'],re.I)]
                if interesting: report.findings.append(Finding('high','deobfuscation','Candidate hidden operational strings recovered',interesting[:40],'Static repeating-XOR reconstruction produced plausible operational strings. These are analyst leads and should be corroborated with code-path or runtime/device evidence.','medium'))
        elif args.deep: report.limitations.append('Deep analysis requested but no restored/recoverable DEX set was available for bytecode-level analysis.')
        report.attack_mapping=map_capabilities(report.capabilities)
        if args.decompile: analyzer.optional_decompile(report)
        if package_override and not report.package.get('package_name'): report.package['package_name']=package_override
        if args.adb_dir:
            report.device_evidence=parse_device_acquisition(args.adb_dir, report.package.get('package_name'))
            report.correlation=correlate(report,report.device_evidence,parse_timeline_csv(args.timeline))
            if report.correlation.get('correlation_strength') in ('moderate','strong'):
                report.findings.append(Finding('high','device_correlation','Package-specific device artifacts support incident relevance',[x['finding'] for x in report.correlation.get('correlations',[]) if x.get('confidence')=='high'][:15],'Independent package-specific device artifacts are consistent with the analyzed APK being present or active in relevant device state. This does not prove a particular user action or transaction cause.','high'))
    finally:
        try:
            if 'ctx' in locals() and ctx.get('zip'): ctx['zip'].close()
        except Exception: pass
    report.analysis['completed_utc']=utc_now_iso(); _finalize_findings(report)
    write_json(report,args.out/'report.json'); write_markdown(report,args.out/'report.md'); write_html(report,args.out/'report.html')
    with (args.out/'evidence.jsonl').open('w',encoding='utf-8') as fh:
        for f in report.to_dict()['findings']: fh.write(json.dumps({'type':'finding',**f},ensure_ascii=False,sort_keys=True)+'\n')
        for x in report.deobfuscation.get('operational_strings',[]): fh.write(json.dumps({'type':'deobfuscated_string',**x},ensure_ascii=False,sort_keys=True)+'\n')
        for x in report.correlation.get('correlations',[]): fh.write(json.dumps({'type':'device_correlation',**x},ensure_ascii=False,sort_keys=True)+'\n')
    print(json.dumps({'version':report.version,'output':str(args.out.resolve()),'sha256':report.hashes.get('sha256'),'package':report.package.get('package_name'),'findings':len(report.findings),'restored_methods':report.packer.get('method_restoration',{}).get('total_methods_restored',0),'xor_strings':len(report.deobfuscation.get('xor_hits',[])),'graph_nodes':len(report.behavior_graph.get('nodes',[])),'device_correlation':report.correlation.get('correlation_strength','not-run')},indent=2))


def main(argv=None):
    p=argparse.ArgumentParser(prog='mafkit',description='MAFKit — static APK analysis and USB-connected Android app scanner')
    sub=p.add_subparsers(dest='command')
    a=sub.add_parser('analyze',help='Analyze APK and optionally correlate ADB evidence')
    a.add_argument('apk',type=Path); a.add_argument('-o','--out',type=Path,default=Path('mafkit-output')); a.add_argument('--deep',action='store_true'); a.add_argument('--decompile',action='store_true')
    a.add_argument('--adb-dir',type=Path,help='Directory produced by mafkit collect-adb or supplied acquisition'); a.add_argument('--package',help='Optional package-name override if APK manifest parsing is unavailable'); a.add_argument('--timeline',type=Path,help='CSV timeline with timestamp,event,type columns'); a.add_argument('--case-id'); a.add_argument('--examiner')
    c=sub.add_parser('collect-adb',help='Non-destructive ADB evidence collection from one authorized Android device')
    c.add_argument('-o','--out',type=Path,default=Path('adb-acquisition')); c.add_argument('--package',help='Target package name for focused dumpsys/APK pull'); c.add_argument('--no-bugreport',action='store_true'); c.add_argument('--case-id'); c.add_argument('--examiner')
    s=sub.add_parser('scan-phone',help='Scan installed Android apps over USB ADB and write per-app safety reports')
    s.add_argument('-o','--out',type=Path,default=Path('phone-scan-output')); s.add_argument('--serial',help='ADB serial when selecting among connected devices'); s.add_argument('--third-party-only',action='store_true',help='Skip system apps'); s.add_argument('--max-apps',type=_positive_int,help='Limit the number of apps (useful for a quick test)')
    r=sub.add_parser('remove-app',help='Interactively remove one confirmed third-party app for Android user 0')
    r.add_argument('package',help='Exact Android package name to remove'); r.add_argument('--serial',help='ADB serial when selecting among connected devices')
    import sys
    raw=sys.argv[1:] if argv is None else list(argv)
    if raw and raw[0] not in ('analyze','collect-adb','scan-phone','remove-app','-h','--help'): raw=['analyze',*raw]
    args=p.parse_args(raw)
    if args.command=='collect-adb':
        manifest=adb_collect(args.out,args.package,not args.no_bugreport,args.case_id,args.examiner); print(json.dumps({'output':str(args.out.resolve()),'commands':len(manifest['commands']),'manifest':'collection_manifest.json'},indent=2)); return
    if args.command=='scan-phone':
        try: result=scan_phone(args.out,args.serial,not args.third_party_only,args.max_apps)
        except (RuntimeError, ValueError) as exc: raise SystemExit(str(exc)) from exc
        print(json.dumps({'output':str(args.out.resolve()),'apps_scanned':result['apps_scanned'],'markdown':'phone_scan.md','json':'phone_scan.json','device':result['selected_device']['serial']},indent=2)); return
    if args.command=='remove-app':
        try: print(uninstall_user_app(args.package,args.serial))
        except (RuntimeError, ValueError) as exc: raise SystemExit(str(exc)) from exc
        return
    if args.command=='analyze': analyze(args); return
    p.print_help()

if __name__=='__main__': main()
