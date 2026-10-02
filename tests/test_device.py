from pathlib import Path
from mafkit.device import parse_package_dumpsys, parse_device_acquisition, parse_timeline_csv, extract_package_presence, parse_android_local_time
import json


def test_package_dumpsys_full():
    t='''versionName=1.2\nversionCode=12 minSdk=23\nfirstInstallTime=2026-09-27 10:15:00\nlastUpdateTime=2026-09-27 10:16:00\ninstallerPackageName=com.android.packageinstaller\nuserId=10422\ncodePath=/data/app/x\ndataDir=/data/user/0/x\npkgFlags=[ HAS_CODE DEBUGGABLE ]\n'''
    d=parse_package_dumpsys(t); assert d['first_install_time'].startswith('2026-09-27'); assert d['installer_package']=='com.android.packageinstaller'; assert d['uid']=='10422'; assert 'DEBUGGABLE' in d['pkg_flags']

def test_package_presence_token_exact():
    t='package:com.foo\npackage:com.foobar\nx com.foo/.Svc\n'; assert len(extract_package_presence(t,'com.foo'))==2

def test_timeline_utf8_bom(tmp_path):
    p=tmp_path/'t.csv'; p.write_text('\ufefftimestamp,event,type\n2026-01-01 10:00:00,Fraud,financial\n',encoding='utf-8'); rows=parse_timeline_csv(p); assert rows[0]['event']=='Fraud' and rows[0]['_source_line']==2

def test_timeline_missing(tmp_path): assert parse_timeline_csv(tmp_path/'missing.csv')==[]
def test_parse_time_naive(): assert parse_android_local_time('2026-09-27 10:15:00').tzinfo is None
def test_parse_time_zone():
    d=parse_android_local_time('2026-09-27 10:15:00','Asia/Kolkata'); assert d.utcoffset().total_seconds()==19800

def test_parse_device_inventory_hashes(tmp_path):
    (tmp_path/'getprop.txt').write_text('[ro.product.model]: [Pixel]\n[persist.sys.timezone]: [Asia/Kolkata]\n')
    (tmp_path/'packages_all.txt').write_text('package:/data/app/x/base.apk=cinder.yonder.nature\n')
    (tmp_path/'settings_secure.txt').write_text('enabled_accessibility_services=cinder.yonder.nature/.Svc\n')
    d=parse_device_acquisition(tmp_path,'cinder.yonder.nature'); assert d['device']['ro.product.model']=='Pixel'; assert d['files']['getprop.txt']['sha256']; assert d['package']['presence']

def test_manifest_loaded(tmp_path):
    (tmp_path/'collection_manifest.json').write_text(json.dumps({'schema':'x','artifacts':[]})); d=parse_device_acquisition(tmp_path); assert d['collection_manifest']['schema']=='x'

def test_bad_manifest_is_limitation(tmp_path):
    (tmp_path/'collection_manifest.json').write_text('{bad'); d=parse_device_acquisition(tmp_path); assert any('could not be parsed' in x for x in d['limitations'])

def test_no_bugreport_limitation(tmp_path): assert any('No bugreport ZIP' in x for x in parse_device_acquisition(tmp_path)['limitations'])
def test_bugreport_detected(tmp_path):
    (tmp_path/'bugreport.zip').write_bytes(b'PKfake'); d=parse_device_acquisition(tmp_path); assert d['bugreport']['size']==6

def test_invalid_package_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError): parse_device_acquisition(tmp_path,'../evil')

def test_integrity_verification_success(tmp_path):
    import hashlib, json
    (tmp_path/'e.txt').write_text('evidence')
    h=hashlib.sha256((tmp_path/'e.txt').read_bytes()).hexdigest()
    man={'artifacts':[{'path':'e.txt','size':8,'sha256':h}]}
    (tmp_path/'collection_manifest.json').write_text(json.dumps(man,sort_keys=True))
    mh=hashlib.sha256((tmp_path/'collection_manifest.json').read_bytes()).hexdigest()
    (tmp_path/'collection_manifest.sha256').write_text(f'{mh}  collection_manifest.json\n')
    d=parse_device_acquisition(tmp_path); assert d['integrity_verification']['manifest_verified'] is True and d['integrity_verification']['artifacts_verified']==1

def test_integrity_verification_detects_tamper(tmp_path):
    import hashlib, json
    (tmp_path/'e.txt').write_text('tampered')
    man={'artifacts':[{'path':'e.txt','size':8,'sha256':'0'*64}]}
    (tmp_path/'collection_manifest.json').write_text(json.dumps(man))
    mh=hashlib.sha256((tmp_path/'collection_manifest.json').read_bytes()).hexdigest(); (tmp_path/'collection_manifest.sha256').write_text(f'{mh}  collection_manifest.json\n')
    d=parse_device_acquisition(tmp_path); assert d['integrity_verification']['artifacts_mismatched'] and any('integrity-compromised' in x for x in d['limitations'])
