from mafkit.util import entropy, uniq, hashes, printable_strings, run
from pathlib import Path
import math

def test_entropy_zero(): assert entropy(b'\x00'*100)==0.0
def test_entropy_uniform_256(): assert math.isclose(entropy(bytes(range(256))),8.0,abs_tol=1e-9)
def test_entropy_empty(): assert entropy(b'')==0.0
def test_uniq_preserves_order(): assert uniq([1,2,1,3,2])==[1,2,3]
def test_hashes(tmp_path):
    p=tmp_path/'x'; p.write_bytes(b'abc'); h=hashes(p); assert h['sha256'].startswith('ba7816bf') and len(h['md5'])==32 and len(h['sha1'])==40
def test_printable_strings(): assert printable_strings(b'\x00hello\x00abc\x00WORLD!')==['hello','WORLD!']
def test_run_success():
    rc,out=run(['python','-c','print("ok")']); assert rc==0 and 'ok' in out
def test_run_missing_binary():
    rc,out=run(['definitely-no-such-binary-xyz']); assert rc==127 and out
