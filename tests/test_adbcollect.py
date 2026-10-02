from mafkit import adbcollect
from pathlib import Path
from types import SimpleNamespace
import json, hashlib, pytest

class FakeRun:
    def __init__(self): self.calls=[]
    def __call__(self,cmd,stdout=None,stderr=None,timeout=None,check=False,**kw):
        self.calls.append(cmd)
        if cmd[-2:]==['devices','-l'] or cmd[-1:] == ['devices']:
            return SimpleNamespace(returncode=0,stdout=b'List of devices attached\nSER123\tdevice product:p model:m device:d\n')
        if cmd[-1:] == ['version']:
            return SimpleNamespace(returncode=0,stdout=b'Android Debug Bridge version 1.0.41\n')
        if 'bugreport' in cmd:
            target=Path(cmd[-1]); target.write_bytes(b'PK\x03\x04bug'); return SimpleNamespace(returncode=0,stdout=b'bugreport ok')
        if 'pull' in cmd:
            Path(cmd[-1]).write_bytes(b'APKDATA'); return SimpleNamespace(returncode=0,stdout=b'1 file pulled')
        if cmd[-3:-1]==['pm','path'] or ('pm' in cmd and 'path' in cmd):
            return SimpleNamespace(returncode=0,stdout=b'package:/data/app/com.x.app/base.apk\n')
        return SimpleNamespace(returncode=0,stdout=b'ok\n')

def test_collection_manifest_hashes_and_serial(monkeypatch,tmp_path):
    fake=FakeRun(); monkeypatch.setattr(adbcollect.shutil,'which',lambda x:'/usr/bin/adb'); monkeypatch.setattr(adbcollect.subprocess,'run',fake)
    m=adbcollect.collect(tmp_path,'com.x.app',bugreport=True,case_id='CASE1',examiner='Examiner')
    assert m['selected_device']['serial']=='SER123'; assert m['case_id']=='CASE1'; assert all(x['sha256'] for x in m['artifacts']); assert (tmp_path/'collection_manifest.sha256').exists(); assert any(['-s','SER123'] == c[1:3] for c in fake.calls if len(c)>3)
    line=(tmp_path/'collection_manifest.sha256').read_text().split()[0]; assert line==hashlib.sha256((tmp_path/'collection_manifest.json').read_bytes()).hexdigest()
def test_exactly_one_device_required(monkeypatch,tmp_path):
    monkeypatch.setattr(adbcollect.shutil,'which',lambda x:'/usr/bin/adb')
    def f(cmd,**kw): return SimpleNamespace(returncode=0,stdout=b'List of devices attached\nA\tdevice\nB\tdevice\n')
    monkeypatch.setattr(adbcollect.subprocess,'run',f)
    with pytest.raises(RuntimeError): adbcollect.collect(tmp_path,bugreport=False)
def test_unauthorized_not_counted(monkeypatch,tmp_path):
    monkeypatch.setattr(adbcollect.shutil,'which',lambda x:'/usr/bin/adb')
    def f(cmd,**kw): return SimpleNamespace(returncode=0,stdout=b'List of devices attached\nA\tunauthorized\n')
    monkeypatch.setattr(adbcollect.subprocess,'run',f)
    with pytest.raises(RuntimeError): adbcollect.collect(tmp_path,bugreport=False)
def test_invalid_package_before_adb(monkeypatch,tmp_path):
    with pytest.raises(ValueError): adbcollect.collect(tmp_path,'../evil',bugreport=False)
def test_missing_adb(monkeypatch,tmp_path):
    monkeypatch.setattr(adbcollect.shutil,'which',lambda x:None)
    with pytest.raises(RuntimeError): adbcollect.collect(tmp_path,bugreport=False)

def test_run_timeout(monkeypatch):
    import subprocess
    monkeypatch.setattr(adbcollect.subprocess,'run',lambda *a,**k: (_ for _ in ()).throw(subprocess.TimeoutExpired(a[0],1,output=b'partial')))
    rc,data,dur,err=adbcollect._run('/adb','SER',['shell','x'],timeout=1); assert rc==124 and b'partial' in data and 'timeout' in err
