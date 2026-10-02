from mafkit.deobfuscation import repeating_xor, text_score
from mafkit.attack import map_capabilities

def test_repeating_xor_roundtrip():
    p=b'ws://example.com:8080/'; k=b'key'; c=repeating_xor(p,k)
    assert repeating_xor(c,k)==p

def test_text_score_prefers_plaintext():
    assert text_score('WebSocket opened') > text_score('\x01\x02\x03')

def test_attack_mapping():
    x=map_capabilities({'sms':{'detected':True,'evidence':['SmsManager']}})
    assert x and x[0]['capability']=='sms'
