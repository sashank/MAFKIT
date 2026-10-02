from mafkit.behavior import build_behavior_graph

def test_invalid_dex_is_reported(tmp_path):
    p=tmp_path/'bad.dex'; p.write_bytes(b'bad'); g=build_behavior_graph([p],tmp_path/'out'); assert g['errors'] and not g['nodes']

def test_behavior_graph_with_fake_dex(monkeypatch,tmp_path):
    import mafkit.behavior as mod, json
    class F:
        code={0:1}
        def __init__(self,p): pass
        def mstr(self,mid): return 'Lx;->AccessibilityThing()V'
        def refs(self,mid): return [('invoke',0,'Landroid/telephony/SmsManager;->send()V'),('string',0,'WebSocket')]
    monkeypatch.setattr(mod,'Dex',F); g=mod.build_behavior_graph([tmp_path/'x.dex'],tmp_path/'out'); assert len(g['nodes'])>=2 and g['edges']; assert json.loads((tmp_path/'out'/'behavior_graph.json').read_text())['nodes']
