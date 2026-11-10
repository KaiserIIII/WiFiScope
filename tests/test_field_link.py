import json
import subprocess
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

from wifiscope import field_link


class FieldLinkTests(unittest.TestCase):
    module = field_link

    @staticmethod
    def completed(argv, output='', code=0):
        if not isinstance(output, str):
            output = json.dumps(output)
        return subprocess.CompletedProcess(argv, code, output.encode(), b'')

    def test_windows_link_uses_connected_wlan_and_matching_ip_adapter(self):
        association = """
    名称                   : 无线网卡
    状态                   : 已连接
    SSID                   :  Campus: Lab
    AP BSSID               : 1a:20:30:40:50:60
    身份验证               : WPA2-企业
    密码                   : 无
    信道                   : 44
    信号                   : 78%

    名称                   : Wi-Fi 2
    状态                   : 已断开连接
    SSID                   : Previous
    BSSID                  : 22:20:30:40:50:60
"""
        local = {
            'interfaces': [
                {'name': 'Ethernet', 'index': 4, 'addresses': ['192.0.2.2/24']},
                {'name': '无线网卡', 'index': 11,
                 'addresses': ['198.51.100.24/24', 'fe80::4%11/64', 'bad'],
                 'dns': ['198.51.100.53', '2001:db8::53', 'malformed']},
            ],
            'routes': [
                {'index': 4, 'destination': '0.0.0.0/0', 'gateway': '192.0.2.1', 'metric': 1},
                {'index': 11, 'destination': '0.0.0.0/0', 'gateway': '198.51.100.1', 'metric': 20},
                {'index': 11, 'destination': '::/0', 'gateway': 'fe80::1%11', 'metric': 10},
                {'index': 11, 'destination': '2001:db8::/32', 'gateway': 'fe80::3', 'metric': 1},
            ],
            'dhcp': [{'index': 11, 'enabled': True, 'seconds': 28800, 'remaining': 12800}],
            'tcp': [{'port': 445, 'address': '0.0.0.0'}, {'port': 7001, 'address': '127.0.0.1'}],
            'udp': [{'port': 5353, 'address': '198.51.100.24'}],
            'firewall': [{'name': 'Public', 'enabled': True}],
            'wininet_proxy': True,
        }

        def run(argv, **options):
            self.assertFalse(options['shell'])
            if argv == ['netsh.exe', 'wlan', 'show', 'interfaces']:
                return self.completed(argv, association)
            if argv == ['netsh.exe', 'winhttp', 'show', 'proxy']:
                return self.completed(argv, 'Direct access (no proxy server).')
            return self.completed(argv, local)

        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'run', side_effect=run),
              patch.dict(self.module.os.environ, {}, clear=True)):
            link = self.module.read_link()
        self.assertEqual(link['interface'], '无线网卡')
        self.assertEqual(link['ssid'], ' Campus: Lab')
        self.assertEqual(link['bssid'], '1a:20:30:40:50:60')
        self.assertEqual(link['authentication'], 'WPA2-企业')
        self.assertEqual(link['cipher'], 'None')
        self.assertEqual(link['channel'], 44)
        self.assertEqual(link['signal_percent'], 78)
        self.assertIsNone(link['signal_dbm'])
        self.assertEqual(link['addresses'], ['198.51.100.24/24', 'fe80::4/64'])
        self.assertEqual(link['gateways'], ['198.51.100.1', 'fe80::1'])
        self.assertEqual(link['dns'], ['198.51.100.53', '2001:db8::53'])
        self.assertEqual(link['lease_seconds'], 28800)
        self.assertEqual(link['lease_remaining_seconds'], 12800)
        self.assertEqual(link['firewall'], {'Public': True})
        self.assertTrue(link['proxy_configured'])
        self.assertEqual(link['listeners'], [
            {'protocol': 'tcp', 'port': 445, 'bind': 'wildcard'},
            {'protocol': 'tcp', 'port': 7001, 'bind': 'loopback'},
            {'protocol': 'udp', 'port': 5353, 'bind': 'interface'},
        ])

    def test_windows_ambiguous_association_requires_selection_and_does_not_pick_ethernet(self):
        association = """
    Name : Wi-Fi A
    State : connected
    SSID : Campus A
    BSSID : 1a:20:30:40:50:60
    Name : Wi-Fi B
    State : connected
    SSID : Campus B
    BSSID : 1a:20:30:40:50:61
"""
        local = {'interfaces': [{'name': 'Ethernet', 'addresses': ['192.0.2.2/24']},
                                {'name': 'Wi-Fi B', 'addresses': ['198.51.100.2/24']}]}

        def run(argv, **_):
            if 'wlan' in argv:
                return self.completed(argv, association)
            if 'winhttp' in argv:
                return self.completed(argv, 'Direct access (no proxy server).')
            return self.completed(argv, local)

        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'run', side_effect=run)):
            self.assertIn('association-ambiguous', self.module.read_link()['gaps'])
            selected = self.module.read_link('wi-fi b')
        self.assertEqual(selected['ssid'], 'Campus B')
        self.assertEqual(selected['addresses'], ['198.51.100.2/24'])

    def test_windows_explicit_adapter_preserves_verified_ip_evidence_without_wlan(self):
        def run(argv, **_):
            if 'wlan' in argv:
                return self.completed(argv, code=1)
            if 'winhttp' in argv:
                return self.completed(argv, 'Direct access (no proxy server).')
            return self.completed(argv, {'interfaces': [
                {'name': 'Wi-Fi', 'index': 11, 'addresses': ['198.51.100.2/24'],
                 'dns': ['198.51.100.53']},
            ], 'routes': [{'index': 11, 'destination': '0.0.0.0/0', 'gateway': '198.51.100.1'}]})

        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'run', side_effect=run)):
            selected = self.module.read_link('wi-fi')
            missing = self.module.read_link('unknown')
            automatic = self.module.read_link()
        self.assertEqual(selected['interface'], 'Wi-Fi')
        self.assertEqual(selected['addresses'], ['198.51.100.2/24'])
        self.assertEqual(selected['gateways'], ['198.51.100.1'])
        self.assertEqual(selected['dns'], ['198.51.100.53'])
        self.assertIsNone(selected['bssid'])
        self.assertIn('association-unavailable', selected['gaps'])
        self.assertIsNone(missing['interface'])
        self.assertIsNone(automatic['interface'])

    def test_linux_uses_live_iw_association_and_does_not_fabricate_security(self):
        outputs = {
            ('iw', 'dev'): 'phy#0\n\tInterface wlan0\n\t\ttype managed\n',
            ('iw', 'dev', 'wlan0', 'link'): ('Connected to 12:23:34:45:56:67 (on wlan0)\n'
                                             '\tSSID: Campus\n\tfreq: 5180\n\tsignal: -57 dBm\n'),
            ('ip', '-j', 'address', 'show', 'dev', 'wlan0'): [
                {'ifname': 'wlan0', 'addr_info': [{'local': '198.51.100.2', 'prefixlen': 24}]}],
            ('ip', '-4', '-j', 'route', 'show', 'default', 'dev', 'wlan0'): [
                {'dev': 'wlan0', 'gateway': '198.51.100.1', 'metric': 100}],
            ('ip', '-6', '-j', 'route', 'show', 'default', 'dev', 'wlan0'): [],
            ('nmcli', '-t', '-e', 'no', '-f', 'IP4.DNS,IP6.DNS,DHCP4.OPTION', 'device', 'show', 'wlan0'):
                ('IP4.DNS[1]:198.51.100.53\nIP6.DNS[1]:2001:db8::53\n'
                 'DHCP4.OPTION[1]:dhcp_lease_time = 3600\n'),
            ('ss', '-H', '-lntu'): 'udp UNCONN 0 0 [::]:5353 [::]:*\n',
        }
        with (patch.object(self.module.platform, 'system', return_value='Linux'),
              patch.object(self.module.subprocess, 'run', side_effect=lambda argv, **_:
                           self.completed(argv, outputs[tuple(argv)]))):
            link = self.module.read_link()
        self.assertEqual(link['interface'], 'wlan0')
        self.assertEqual(link['signal_dbm'], -57)
        self.assertEqual(link['channel'], 36)
        self.assertIsNone(link['cipher'])
        self.assertIn('cipher-unavailable', link['gaps'])
        self.assertEqual(link['dns'], ['198.51.100.53', '2001:db8::53'])
        self.assertEqual(link['lease_seconds'], 3600)
        self.assertEqual(link['listeners'], [{'protocol': 'udp', 'port': 5353, 'bind': 'wildcard'}])

    def test_linux_explicit_adapter_keeps_ip_data_if_iw_is_unavailable(self):
        def run(argv, **_):
            if argv[0] in ('iw', 'nmcli', 'ss'):
                raise FileNotFoundError()
            if 'address' in argv:
                return self.completed(argv, [{'ifname': 'wlan0', 'addr_info': [
                    {'local': '198.51.100.4', 'prefixlen': 24},
                ]}])
            return self.completed(argv, [])

        with (patch.object(self.module.platform, 'system', return_value='Linux'),
              patch.object(self.module.subprocess, 'run', side_effect=run)):
            link = self.module.read_link('wlan0')
        self.assertEqual(link['interface'], 'wlan0')
        self.assertEqual(link['addresses'], ['198.51.100.4/24'])
        self.assertIsNone(link['ssid'])
        self.assertIn('association-unavailable', link['gaps'])
        self.assertIn('tcp-listeners-unavailable', link['gaps'])

    def test_neighbor_compares_only_same_interface_on_link_usable_entries(self):
        def entry(ip, mac, alias='Wi-Fi', state='Reachable'):
            return {'interface': alias, 'ip': ip, 'mac': mac, 'state': state}

        cached = [
            entry('198.51.100.1', '12-23-34-45-56-67'),
            entry('198.51.100.2', '12:23:34:45:56:67'),
            entry('198.51.100.2', '22-23-34-45-56-67', 'Ethernet'),
            entry('198.51.100.3', '22-23-34-45-56-67'),
            entry('198.51.100.4', '12-23-34-45-56-67', state='Unreachable'),
            entry('198.51.100.7', '00-00-00-00-00-00'),
            entry('203.0.113.2', '12-23-34-45-56-67'),
            entry('2001:db8::8', '12-23-34-45-56-67'),
        ]
        link = {'interface': 'Wi-Fi', 'addresses': ['198.51.100.10/24', '2001:db8::2/64'],
                'gateways': ['198.51.100.1', 'fe80::1']}
        targets = ['198.51.100.2', '198.51.100.3', '198.51.100.4', '198.51.100.7',
                   '203.0.113.2', '2001:db8::8', '198.51.100.1', '198.51.100.10']
        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'run', return_value=self.completed([], cached))):
            comparison = self.module.neighbor_comparison(link, targets)
        self.assertEqual(comparison, {'status': 'observed', 'rows': [
            {'target': '198.51.100.2', 'class': 'shared_gateway_mac'},
            {'target': '198.51.100.3', 'class': 'different_gateway_mac'},
            {'target': '198.51.100.4', 'class': 'no_target_entry'},
            {'target': '198.51.100.7', 'class': 'no_target_entry'},
            {'target': '203.0.113.2', 'class': 'not_on_link'},
            {'target': '2001:db8::8', 'class': 'no_gateway_entry'},
            {'target': '198.51.100.1', 'class': 'gateway_target'},
            {'target': '198.51.100.10', 'class': 'local_target'},
        ]})

    def test_neighbor_without_eligible_peer_does_not_query_cache(self):
        link = {'interface': 'Wi-Fi', 'addresses': ['198.51.100.10/24'], 'gateways': ['198.51.100.1']}
        with patch.object(self.module.subprocess, 'run', side_effect=AssertionError('unexpected OS command')):
            result = self.module.neighbor_comparison(link, ['203.0.113.2'])
        self.assertEqual(result, {'status': 'not_applicable', 'rows': [
            {'target': '203.0.113.2', 'class': 'not_on_link'},
        ]})

    def test_windows_echo_requires_success_from_exact_address(self):
        for reply, code, expected in [
            ({'status': 'Success', 'address': '198.51.100.2', 'ms': 4}, 0, {'status': 'reply', 'ms': 4}),
            ({'status': 'Success', 'address': '198.51.100.1', 'ms': 4}, 0, {'status': 'unavailable'}),
            ({'status': 'DestinationHostUnreachable'}, 0, {'status': 'unreachable'}),
            ({'status': 'TimedOut'}, 0, {'status': 'timeout'}),
            ('Reply from 198.51.100.1: Destination host unreachable.', 0, {'status': 'unavailable'}),
            ({'status': 'Success', 'address': '198.51.100.2', 'ms': 4}, 1, {'status': 'unavailable'}),
        ]:
            with (self.subTest(reply=reply, code=code),
                  patch.object(self.module.platform, 'system', return_value='Windows'),
                  patch.object(self.module.subprocess, 'run', return_value=self.completed([], reply, code))):
                self.assertEqual(self.module.echo_probe('198.51.100.2'), expected)

    def test_linux_echo_matches_numeric_sender_and_sequence(self):
        for line, code, expected in [
            ('64 bytes from 2001:db8::2: icmp_seq=1 ttl=63 time=1.25 ms', 0, {'status': 'reply', 'ms': 1.25}),
            ('64 bytes from 2001:db8::3: icmp_seq=1 ttl=63 time=1.25 ms', 0, {'status': 'unavailable'}),
            ('From 2001:db8::1 icmp_seq=1 Destination unreachable: No route', 1, {'status': 'unreachable'}),
            ('1 packets transmitted, 0 received, 100% packet loss', 1, {'status': 'timeout'}),
            ('ping: socket: Operation not permitted', 2, {'status': 'unavailable'}),
        ]:
            with (self.subTest(line=line),
                  patch.object(self.module.platform, 'system', return_value='Linux'),
                  patch.object(self.module.subprocess, 'run', return_value=self.completed([], line, code))):
                self.assertEqual(self.module.echo_probe('2001:db8::2'), expected)

    def test_echo_rejects_hostname_and_cancelled_job_before_launch(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(self.module.subprocess, 'run', side_effect=AssertionError('unexpected OS command')):
            self.assertEqual(self.module.echo_probe('campus.example'), {'status': 'invalid_target'})
            self.assertEqual(self.module.echo_probe('fe80::1%evil'), {'status': 'invalid_target'})
            self.assertEqual(self.module.echo_probe('198.51.100.2', cancel=cancelled), {'status': 'cancelled'})


    def test_source_is_passed_to_bound_windows_ipv4_probe(self):
        def run(argv, **options):
            self.assertEqual(argv[0], sys.executable)
            self.assertEqual(argv[-3:], ['198.51.100.2', '198.51.100.10', '1000'])
            self.assertFalse(options['shell'])
            return self.completed(argv, {'status': 0, 'address': '198.51.100.2', 'ms': 3})

        with patch.object(self.module.platform, 'system', return_value='Windows'), \
                patch.object(self.module.subprocess, 'run', side_effect=run):
            self.assertEqual(self.module.echo_probe('198.51.100.2', source='198.51.100.10'),
                             {'status': 'reply', 'ms': 3})

    def test_source_is_passed_to_bound_windows_ipv6_probe(self):
        def run(argv, **options):
            self.assertEqual(argv[-3:], ['-S', '2001:db8::10', '2001:db8::2'])
            self.assertFalse(options['shell'])
            return self.completed(argv, '来自 2001:db8::2 的回复: 时间<1ms')

        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'run', side_effect=run)):
            self.assertEqual(self.module.echo_probe('2001:db8::2', source='2001:db8::10'),
                             {'status': 'reply', 'ms': 1})

    def test_source_family_mismatch_does_not_start_probe(self):
        with patch.object(self.module.subprocess, 'run', side_effect=AssertionError('unexpected OS command')):
            self.assertEqual(self.module.echo_probe('198.51.100.2', source='2001:db8::3'),
                             {'status': 'invalid_target'})

    def test_local_link_cancel_terminates_running_os_query(self):
        cancelled = threading.Event()
        process = MagicMock()
        process.poll.return_value = None

        def running(*, timeout):
            cancelled.set()
            raise subprocess.TimeoutExpired('netsh.exe', timeout)

        process.communicate.side_effect = running
        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.subprocess, 'Popen') as launch):
            launch.return_value.__enter__.return_value = process
            link = self.module.read_link(cancel=cancelled)
        process.kill.assert_called_once()
        launch.assert_called_once()
        self.assertIn('local-cancelled', link['gaps'])

    def test_neighborhood_cancel_skips_cache_query(self):
        cancelled = threading.Event()
        cancelled.set()
        link = {'interface': 'Wi-Fi', 'addresses': ['198.51.100.10/24'], 'gateways': ['198.51.100.1']}
        with patch.object(self.module.subprocess, 'Popen', side_effect=AssertionError('unexpected OS command')):
            result = self.module.neighbor_comparison(link, ['198.51.100.2'], cancel=cancelled)
        self.assertEqual(result['status'], 'cancelled')

    def test_local_queries_share_a_total_deadline(self):
        elapsed = [0]
        budgets = []

        def run(argv, *, timeout, **_):
            budgets.append(timeout)
            if 'wlan' in argv:
                elapsed[0] += 5
                return self.completed(argv, 'Name : Wi-Fi\nState : connected\nSSID : Campus')
            if 'winhttp' in argv:
                return self.completed(argv, 'Direct access (no proxy server).')
            elapsed[0] += 13
            return self.completed(argv, {'interfaces': [{'name': 'Wi-Fi', 'index': 1,
                                                         'addresses': ['198.51.100.2/24']}]})

        with (patch.object(self.module.platform, 'system', return_value='Windows'),
              patch.object(self.module.time, 'monotonic', side_effect=lambda: elapsed[0]),
              patch.object(self.module.subprocess, 'run', side_effect=run)):
            link = self.module.read_link()
        self.assertEqual(link['addresses'], ['198.51.100.2/24'])
        self.assertEqual(budgets, [6, 14, 2])


if __name__ == '__main__':
    unittest.main()
