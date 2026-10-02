from pathlib import Path
from types import SimpleNamespace
from mafkit.device import parse_package_dumpsys, parse_device_acquisition, parse_timeline_csv
from mafkit.correlation import correlate


def test_package_dumpsys():
    t='''versionName=1.2\nfirstInstallTime=2026-09-27 10:15:00\nlastUpdateTime=2026-09-27 10:15:00\ninstallerPackageName=com.android.packageinstaller\nuserId=10422\n'''
    d=parse_package_dumpsys(t)
    assert d['first_install_time'].startswith('2026-09-27')
    assert d['installer_package']=='com.android.packageinstaller'


def test_device_correlation(tmp_path):
    (tmp_path/'packages_all.txt').write_text('package:/data/app/x/base.apk=cinder.yonder.nature installer=com.android.packageinstaller uid:10422')
    (tmp_path/'settings_secure.txt').write_text('enabled_accessibility_services=cinder.yonder.nature/.Svc\naccessibility_enabled=1')
    (tmp_path/'package_cinder.yonder.nature.txt').write_text('firstInstallTime=2026-09-27 10:15:00\nlastUpdateTime=2026-09-27 10:15:00')
    dev=parse_device_acquisition(tmp_path,'cinder.yonder.nature')
    report=SimpleNamespace(package={'package_name':'cinder.yonder.nature'},capabilities={'accessibility':{'detected':True}})
    c=correlate(report,dev,[{'timestamp':'2026-09-27 10:45:00','event':'UPI fraud','type':'financial'}])
    assert c['correlation_strength'] in ('moderate','strong')
    assert any(x['category']=='accessibility' for x in c['correlations'])
