from mafkit.forensic import validate_package_name, canonical_json_bytes, stable_evidence_id, utc_now_iso, sha256_bytes
import pytest

@pytest.mark.parametrize('pkg',['com.example.app','cinder.yonder.nature','_x.a1','a.b_c'])
def test_valid_packages(pkg): assert validate_package_name(pkg)==pkg
@pytest.mark.parametrize('pkg',['','com','../evil','com.foo/../../x','com..x','1bad.pkg','com.bad-name.app',' com.ok '])
def test_invalid_packages(pkg):
    if pkg==' com.ok ':
        assert validate_package_name(pkg)=='com.ok'; return
    with pytest.raises(ValueError): validate_package_name(pkg)
def test_stable_evidence_id_order_independent():
    assert stable_evidence_id('x',{'b':2,'a':1})==stable_evidence_id('x',{'a':1,'b':2})
def test_evidence_id_changes(): assert stable_evidence_id('x',{'a':1})!=stable_evidence_id('x',{'a':2})
def test_utc_iso():
    s=utc_now_iso(); assert s.endswith('Z') and 'T' in s
def test_sha256_bytes_known(): assert sha256_bytes(b'abc')=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
