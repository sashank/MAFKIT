from mafkit.deobfuscation import repeating_xor, text_score, scan_dex_xor

def test_repeating_xor_roundtrip():
    p=b'ws://example.com:8080/'; k=b'key'; c=repeating_xor(p,k); assert repeating_xor(c,k)==p
def test_empty_key_safe(): assert repeating_xor(b'abc',b'')==b''
def test_text_score_plain_over_binary(): assert text_score('WebSocket opened') > text_score('\x01\x02\x03')
def test_text_score_operational_bonus(): assert text_score('screen upload') > text_score('zzzz qqqq')
def test_scan_invalid_dex_reports_error(tmp_path):
    p=tmp_path/'bad.dex'; p.write_bytes(b'notdex'); r=scan_dex_xor([p]); assert r['hits']==[] and r['errors']

def test_scan_with_fake_dex(monkeypatch,tmp_path):
    import mafkit.deobfuscation as mod
    class F:
        code={0:1}
        def __init__(self,p): pass
        def xor_call_candidates(self,mid): return [('Lx;->d([B[B)Ljava/lang/String;', repeating_xor(b'WebSocket opened',b'k'), b'k')]
        def mstr(self,mid): return 'Lx;->caller()V'
    monkeypatch.setattr(mod,'Dex',F); r=mod.scan_dex_xor([tmp_path/'x.dex']); assert r['hits'][0]['decoded']=='WebSocket opened' and not r['truncated']

def test_scan_truncation(monkeypatch,tmp_path):
    import mafkit.deobfuscation as mod
    class F:
        code={0:1,1:1}
        def __init__(self,p): pass
        def xor_call_candidates(self,mid): return [('Lx;->d([B[B)Ljava/lang/String;', repeating_xor(f'screen{mid}'.encode(),b'k'), b'k')]
        def mstr(self,mid): return f'Lx;->m{mid}()V'
    monkeypatch.setattr(mod,'Dex',F); r=mod.scan_dex_xor([tmp_path/'x.dex'],max_hits=1); assert r['truncated'] and len(r['hits'])==1
