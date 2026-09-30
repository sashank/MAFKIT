from pathlib import Path
import json, re
from .dex import Dex

SUSPICIOUS=re.compile(r'(Accessibility|Sms|DeviceAdmin|MediaProjection|Screenshot|WebSocket|Socket|Runtime;->exec|ProcessBuilder|upload|download|inject|overlay|keylog|camera|microphone|BOOT_COMPLETED|shell|telnet|ssh|File|Notification|Gesture|Input|Clipboard)',re.I)

def build_behavior_graph(dex_paths, outdir, max_nodes=250):
    nodes={}; edges=[]; errors=[]; truncated=False
    for fp in dex_paths:
        try: d=Dex(fp)
        except Exception as exc:
            errors.append({'dex':str(fp),'error':f'{type(exc).__name__}: {exc}'}); continue
        for mid in d.code:
            caller=d.mstr(mid); refs=d.refs(mid); evidence=[r[2] for r in refs if SUSPICIOUS.search(str(r[2]))]
            if not evidence and not SUSPICIOUS.search(caller): continue
            nodes[caller]={'id':caller,'dex':Path(fp).name,'evidence':evidence[:20]}
            for typ,idx,val in refs:
                if typ=='invoke' and SUSPICIOUS.search(val):
                    nodes.setdefault(val,{'id':val,'dex':'referenced','evidence':[]}); edges.append({'source':caller,'target':val,'type':'invokes'})
            if len(nodes)>=max_nodes: truncated=True; break
        if truncated: break
    graph={'nodes':list(nodes.values()),'edges':edges[:1000],'truncated':truncated or len(edges)>1000,'max_nodes':max_nodes,'errors':errors}
    Path(outdir).mkdir(parents=True,exist_ok=True); (Path(outdir)/'behavior_graph.json').write_text(json.dumps(graph,indent=2,ensure_ascii=False),encoding='utf-8')
    ids={n['id']:f'n{i}' for i,n in enumerate(graph['nodes'])}; lines=['digraph behavior {','  rankdir=LR;','  node [shape=box,fontname="Arial",fontsize=9];']
    for n in graph['nodes']:
        label=n['id'].replace('\\','\\\\').replace('"','\\"').replace('\n',' ')[:180]; lines.append(f'  {ids[n["id"]]} [label="{label}"];')
    for e in graph['edges']:
        if e['source'] in ids and e['target'] in ids: lines.append(f'  {ids[e["source"]]} -> {ids[e["target"]]};')
    lines.append('}'); (Path(outdir)/'behavior_graph.dot').write_text('\n'.join(lines),encoding='utf-8')
    return graph
