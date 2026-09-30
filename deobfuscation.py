import re
from pathlib import Path
from .dex import Dex

INTERESTING=re.compile(r'(https?://|wss?://|sms|otp|screen|access|admin|lock|cover|front|shell|exec|command|socket|host|url|notification|upload|download|inject|overlay|keylog|camera|microphone|device|client|server|bank|upi|pay|wallet|miner|file|websocket)',re.I)

def text_score(s):
    if not s: return 0.0
    good=sum(ch.isprintable() or ch in '\r\n\t' for ch in s)/len(s)
    asciiish=sum(32 <= ord(ch) < 127 for ch in s)/len(s)
    alnumish=sum(ch.isalnum() or ch in " .,:;_-/[](){}@?=&+%#'\"\\\r\n\t" for ch in s)/len(s)
    bonus=.20 if INTERESTING.search(s) else 0
    penalty=.20 if len(s)>8 and alnumish<.55 else 0
    return good*.40+asciiish*.35+alnumish*.25+bonus-penalty

def repeating_xor(a,k):
    if not k: return b''
    return bytes(x ^ k[i%len(k)] for i,x in enumerate(a))

def scan_dex_xor(dex_paths, max_hits=10000):
    hits=[]; errors=[]
    for fp in dex_paths:
        try: d=Dex(fp)
        except Exception as exc:
            errors.append({'dex':str(fp),'error':f'{type(exc).__name__}: {exc}'}); continue
        for mid in d.code:
            try: calls=d.xor_call_candidates(mid)
            except Exception as exc:
                errors.append({'dex':Path(fp).name,'method_index':mid,'error':f'{type(exc).__name__}: {exc}'}); continue
            for callee,a,k in calls:
                if not k or len(k)>65536 or len(a)>4*1024*1024: continue
                dec=repeating_xor(a,k)
                for enc in ('utf-8','latin-1'):
                    try: s=dec.decode(enc)
                    except Exception: continue
                    score=text_score(s)
                    if score>=.88 and 1 <= len(s) <= 4096:
                        hits.append({'dex':Path(fp).name,'method':d.mstr(mid),'decryptor':callee,'decoded':s,'score':round(score,3),'cipher_len':len(a),'key_len':len(k),'encoding':enc,'classification':'candidate repeating-XOR plaintext'})
                        break
                if len(hits)>=max_hits:
                    return {'hits':_dedup(hits),'errors':errors,'truncated':True,'max_hits':max_hits}
    return {'hits':_dedup(hits),'errors':errors,'truncated':False,'max_hits':max_hits}

def _dedup(hits):
    seen=set(); out=[]
    for h in hits:
        key=(h['method'],h['decoded'])
        if key not in seen: seen.add(key); out.append(h)
    return out
