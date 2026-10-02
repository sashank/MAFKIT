from types import SimpleNamespace
from mafkit.correlation import correlate

PKG='cinder.yonder.nature'
def report(caps=None): return SimpleNamespace(package={'package_name':PKG},capabilities=caps or {})
def device(pres=False,acc=False,admin=False,history=False,tz='Asia/Kolkata'):
    return {'package':{'presence':['package:'+PKG] if pres else [],'first_install_time':'2026-09-27 10:15:00'},'security_state':{'enabled_accessibility_services':[f'enabled_accessibility_services={PKG}/.Svc'] if acc else [],'device_policy_hits':[f'Active admin {PKG}/.Admin'] if admin else []},'usage':{'usage':[f'pkg={PKG}'] if history else [],'activity':[]},'evidence_hits':[],'device':{'persist.sys.timezone':tz} if tz else {}}

def test_none_without_package_specific(): assert correlate(report(),device(),[])['correlation_strength']=='none'
def test_limited_package_only(): assert correlate(report(),device(pres=True),[])['correlation_strength']=='limited'
def test_moderate_package_plus_accessibility(): assert correlate(report(),device(pres=True,acc=True),[])['correlation_strength']=='moderate'
def test_moderate_package_plus_history(): assert correlate(report(),device(pres=True,history=True),[])['correlation_strength']=='moderate'
def test_strong_requires_three_classes(): assert correlate(report(),device(pres=True,acc=True,history=True),[])['correlation_strength']=='strong'
def test_admin_counts_as_privileged_state(): assert correlate(report(),device(pres=True,admin=True,history=True),[])['correlation_strength']=='strong'
def test_timeline_alone_does_not_raise_strength():
    c=correlate(report(),device(),[{'timestamp':'2026-09-27 10:45:00','event':'fraud'}]); assert c['correlation_strength']=='none' and c['anchors']['temporal_support']
def test_temporal_delta():
    c=correlate(report(),device(pres=True),[{'timestamp':'2026-09-27 10:45:00','event':'fraud'}]); assert c['temporal_comparisons'][0]['seconds_after_install']==1800
def test_exact_package_boundary():
    d=device(); d['security_state']['enabled_accessibility_services']=['enabled_accessibility_services=cinder.yonder.natureevil/.Svc']; assert correlate(report(),d,[])['anchors']['exact_privileged_state'] is False
def test_generic_keyword_context_never_strengthens():
    d=device(); d['evidence_hits']=[{'type':'behavior_keyword','source':'logcat.txt','count':3}]; assert correlate(report(),d,[])['correlation_strength']=='none'

def test_integrity_failure_caps_strong_to_limited():
    d=device(pres=True,acc=True,history=True); d['integrity_verification']={'manifest_verified':False,'artifacts_missing':[],'artifacts_mismatched':[]}; c=correlate(report(),d,[]); assert c['correlation_strength']=='limited' and c['integrity_compromised']
