import json
import subprocess
import unittest
from unittest.mock import patch

from wifiscope.collect import collect_local
from wifiscope.demo import demo_report


class CollectTests(unittest.TestCase):
    def test_denied_reads_are_structured_and_never_keep_errors(self):
        with patch('wifiscope.collect.platform.system', return_value='Windows'), patch('wifiscope.collect.subprocess.run', side_effect=PermissionError('PRIVATE-ERROR')):
            report = collect_local()
        self.assertEqual(report['schema_version'], 1)
        for key in ('wifi', 'interfaces', 'routes', 'firewall', 'connectivity', 'findings', 'gaps'):
            self.assertIsInstance(report[key], list)
        self.assertEqual(report['wifi'], [])
        self.assertTrue(report['gaps'])
        self.assertNotIn('PRIVATE-ERROR', json.dumps(report))

    def test_windows_reads_whitelisted_fields_and_proxy_boolean(self):
        seen = []

        def fake_run(args, **kwargs):
            seen.append((args, kwargs))
            command = ' '.join(args)
            if args[0] == 'netsh':
                content = 'SSID 1 : Lab\nAuthentication : Open\nEncryption : None\nBSSID 1 : 02:00:00:00:00:01\nSignal : 30%'
            elif 'Get-NetIPConfiguration' in command:
                content = json.dumps([dict(name='Synthetic Adapter', mac='02:00:00:00:00:09', addresses=['192.0.2.2', '2001:db8::2'], dns=['192.0.2.53'], raw='SECRET')])
            elif 'Get-NetRoute' in command:
                content = json.dumps([dict(destination='0.0.0.0/0', gateway='192.0.2.1', interface='Synthetic Adapter', metric=10)])
            elif 'Get-NetFirewallProfile' in command:
                content = json.dumps([dict(name='Public', enabled=False)])
            else:
                raise AssertionError(command)
            return subprocess.CompletedProcess(args, 0, content.encode(), b'IGNORED-STDERR')

        with patch('wifiscope.collect.platform.system', return_value='Windows'), patch('wifiscope.collect.subprocess.run', side_effect=fake_run), patch.dict('os.environ', {'HTTPS_PROXY': 'http://SECRET:password@example.invalid'}, clear=True):
            report = collect_local()
        self.assertEqual(report['interfaces'][0]['addresses'], ['192.0.2.2', '2001:db8::2'])
        self.assertEqual(report['firewall'], [dict(name='Public', enabled=False)])
        self.assertEqual(report['environment'], {'proxy_configured': True})
        self.assertEqual(report['routes'][0]['gateway'], '192.0.2.1')
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('IGNORED-STDERR', json.dumps(report))
        self.assertTrue(all(0 < kwargs['timeout'] <= 10 and not kwargs.get('shell') for _, kwargs in seen))

    def test_linux_ip_json_and_no_rescan(self):
        def fake_run(args, **kwargs):
            if args[0] == 'nmcli':
                self.assertIn('--rescan', args)
                self.assertIn('no', args)
                content = 'Lab:02\\:00\\:00\\:00\\:00\\:01:WPA2:50:6'
            elif 'address' in args:
                content = json.dumps([dict(ifname='test0', address='02:00:00:00:00:09', addr_info=[dict(local='192.0.2.2'), dict(local='2001:db8::2')])])
            else:
                content = json.dumps([dict(dst='default', gateway='192.0.2.1', dev='test0', metric=10)])
            return subprocess.CompletedProcess(args, 0, content.encode(), b'')
        with patch('wifiscope.collect.platform.system', return_value='Linux'), patch('wifiscope.collect.subprocess.run', side_effect=fake_run):
            report = collect_local()
        self.assertEqual(report['wifi'][0]['ssid'], 'Lab')
        self.assertEqual(report['interfaces'][0]['addresses'], ['192.0.2.2', '2001:db8::2'])
        self.assertTrue(report['gaps'])  # firewall and DNS remain unavailable

    def test_bad_json_and_timeout_remain_unknown(self):
        with patch('wifiscope.collect.platform.system', return_value='Windows'), patch('wifiscope.collect.subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'{bad SECRET', b'')):
            report = collect_local()
        self.assertEqual(report['interfaces'], [])
        self.assertNotIn('SECRET', json.dumps(report))
        with patch('wifiscope.collect.platform.system', return_value='Linux'), patch('wifiscope.collect.subprocess.run', side_effect=subprocess.TimeoutExpired('SECRET', 1)):
            self.assertTrue(collect_local()['gaps'])

    def test_unsupported_platform_and_demo_are_offline(self):
        with patch('wifiscope.collect.platform.system', return_value='Other'), patch('wifiscope.collect.subprocess.run', side_effect=AssertionError('must stay offline')):
            report = collect_local()
            demo = demo_report()
        self.assertTrue(report['gaps'])
        self.assertEqual({x['family'] for x in demo['connectivity'][0]['tcp']}, {'IPv4', 'IPv6'})
        demo['wifi'].clear()
        self.assertTrue(demo_report()['wifi'])

    def test_malformed_linux_structures_are_gaps_not_crashes(self):
        def fake_run(args, **kwargs):
            content = b'[{"ifname":"test0","addr_info":null}]' if 'address' in args else b'null' if args[0] == 'ip' else b''
            return subprocess.CompletedProcess(args, 0, content, b'')
        with patch('wifiscope.collect.platform.system', return_value='Linux'), patch('wifiscope.collect.subprocess.run', side_effect=fake_run):
            report = collect_local()
        self.assertEqual(report['interfaces'][0]['addresses'], [])
        self.assertIn('interface-addresses-unavailable', report['gaps'])

    def test_firewall_reports_effective_active_policy(self):
        def fake_run(args, **kwargs):
            command = ' '.join(args)
            if 'Get-NetFirewallProfile' in command:
                # Simulate a GPO override: persistent disabled, active enabled.
                effective = '-PolicyStore ActiveStore' in command
                content = json.dumps([dict(name='Public', enabled=effective)])
            else:
                content = '' if args[0] == 'netsh' else '[]'
            return subprocess.CompletedProcess(args, 0, content.encode(), b'')
        with patch('wifiscope.collect.platform.system', return_value='Windows'), patch('wifiscope.collect.subprocess.run', side_effect=fake_run):
            report = collect_local()
        self.assertEqual(report['firewall'], [dict(name='Public', enabled=True)])
        self.assertNotIn('firewall-disabled', {item['code'] for item in report['findings']})

    def test_unknown_active_firewall_state_is_not_boolean_coerced(self):
        def fake_run(args, **kwargs):
            command = ' '.join(args)
            if 'Get-NetFirewallProfile' in command:
                # A cast loses the distinction between an unknown policy value
                # and a measured Boolean; simulate that PowerShell boundary.
                state = True if '[bool]$_.Enabled' in command else None
                content = json.dumps([dict(name='Public', enabled=state)])
            else:
                content = '' if args[0] == 'netsh' else '[]'
            return subprocess.CompletedProcess(args, 0, content.encode(), b'')
        with patch('wifiscope.collect.platform.system', return_value='Windows'), patch('wifiscope.collect.subprocess.run', side_effect=fake_run):
            report = collect_local()
        self.assertEqual(report['firewall'], [dict(name='Public', enabled=None)])
        self.assertIn('firewall-unavailable', {item['code'] for item in report['findings']})
