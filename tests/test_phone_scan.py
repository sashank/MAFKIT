import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT.parent))
scanner = importlib.import_module(f'{PROJECT_ROOT.name}.phone_scan')


class PhoneScanTests(unittest.TestCase):
    def test_parse_devices_keeps_unauthorized_state_visible(self):
        parsed = scanner.parse_devices(
            'List of devices attached\nusb-1 device product:pixel model:Pixel\nusb-2 unauthorized usb:2\n'
        )
        self.assertEqual([device['state'] for device in parsed], ['device', 'unauthorized'])
        self.assertEqual(parsed[0]['serial'], 'usb-1')

    def test_parse_package_inventory_extracts_apk_uid_and_installer(self):
        parsed = scanner.parse_package_inventory(
            'package:/data/app/~~abc/com.example.app-xyz/base.apk=com.example.app uid:10123 installer=com.android.vending\n'
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['package'], 'com.example.app')
        self.assertEqual(parsed[0]['uid'], 10123)
        self.assertEqual(parsed[0]['installer'], 'com.android.vending')
        self.assertFalse(parsed[0]['system_app'])

    def test_parse_requested_and_granted_permissions(self):
        requested, grants = scanner.parse_package_permissions(
            'requested permissions:\n'
            '  android.permission.CAMERA\n'
            '  android.permission.RECORD_AUDIO\n'
            'install permissions:\n'
            'runtime permissions:\n'
            '  android.permission.CAMERA: granted=true, flags=[ USER_SET ]\n'
            '  android.permission.RECORD_AUDIO: granted=false, flags=[ USER_SET ]\n'
        )
        self.assertEqual(requested, ['android.permission.CAMERA', 'android.permission.RECORD_AUDIO'])
        self.assertTrue(grants['android.permission.CAMERA'])
        self.assertFalse(grants['android.permission.RECORD_AUDIO'])

    def test_score_explains_granted_permission_and_active_accessibility(self):
        result = scanner.calculate_safety_score(
            ['android.permission.CAMERA'],
            {'android.permission.CAMERA': True},
            {},
            accessibility_enabled=True,
        )
        self.assertEqual(result['score'], 75)
        self.assertEqual(result['band'], 'Review')
        self.assertEqual([factor['name'] for factor in result['factors']],
                         ['android.permission.CAMERA', 'accessibility_service'])

    @patch.object(scanner, '_static_scan', return_value={
        'sha256': 'a' * 64, 'size_bytes': 3, 'capabilities': {}, 'findings': [], 'packed': False,
        'packer': {}, 'iocs': {}, 'limitations': [],
    })
    @patch.object(scanner, '_run')
    @patch.object(scanner.shutil, 'which', return_value='/usr/bin/adb')
    def test_scan_writes_inventory_and_readable_reports(self, _which, run, _static):
        def command_result(command, timeout=45):
            if command[-2:] == ['devices', '-l']:
                return 0, 'List of devices attached\nusb-test device product:pixel\n', 0.01, None
            if command[-6:] == ['pm', 'list', 'packages', '-f', '-U', '-i']:
                return 0, 'package:/data/app/example/base.apk=com.example.test uid:10123 installer=com.android.vending\n', 0.01, None
            if command[-4:] == ['pm', 'list', 'packages', '-3']:
                return 0, 'package:com.example.test\n', 0.01, None
            if command[-2:] in (['dumpsys', 'accessibility'], ['dumpsys', 'device_policy']):
                return 0, '', 0.01, None
            if command[-3:] == ['dumpsys', 'package', 'com.example.test']:
                return 0, 'requested permissions:\n  android.permission.CAMERA\nruntime permissions:\n  android.permission.CAMERA: granted=true\n', 0.01, None
            if command[-3:] == ['pm', 'path', 'com.example.test']:
                return 0, 'package:/data/app/example/base.apk\n', 0.01, None
            if command[-3] == 'pull':
                Path(command[-1]).write_bytes(b'apk')
                return 0, '1 file pulled\n', 0.01, None
            self.fail(f'Unexpected ADB command: {command}')

        run.side_effect = command_result
        with tempfile.TemporaryDirectory() as temp:
            result = scanner.scan_phone(Path(temp) / 'scan')
            self.assertEqual(result['apps_scanned'], 1)
            app = result['apps'][0]
            self.assertEqual(app['package'], 'com.example.test')
            self.assertEqual(app['safety']['score'], 93)
            self.assertEqual(app['coverage'], 'complete')
            markdown = (Path(temp) / 'scan' / 'phone_scan.md').read_text(encoding='utf-8')
            self.assertIn('App Overview', markdown)
            self.assertIn('android.permission.CAMERA', markdown)
            self.assertTrue((Path(temp) / 'scan' / 'phone_scan.json').is_file())


if __name__ == '__main__':
    unittest.main()