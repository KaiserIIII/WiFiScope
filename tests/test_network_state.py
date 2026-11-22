import json
import unittest
from unittest.mock import patch

from wifiscope import network_state as state


class LocalNetworkTests(unittest.TestCase):
    def test_windows_inventory_preserves_nondefault_routes_with_cached_neighbors_and_bindings(self):
        evidence = {
            'interfaces': [{'interface': 'Ethernet', 'index': 8, 'addresses': ['192.0.2.4/24'],
                            'dns': ['192.0.2.53']}],
            'routes': [{'destination': '0.0.0.0/0', 'gateway': '192.0.2.1', 'interface': 'Ethernet',
                        'index': 8, 'metric': 20},
                       {'destination': '192.0.2.0/24', 'gateway': '0.0.0.0', 'interface': 'Ethernet',
                        'index': 8, 'metric': 256}],
            'neighbors': [{'ip': '192.0.2.1', 'mac': '02-11-22-33-44-55', 'interface': 'Ethernet',
                           'index': 8, 'state': 'Stale'},
                          {'ip': '192.0.2.3', 'mac': '00-00-00-00-00-00', 'interface': 'Ethernet',
                           'index': 8, 'state': 'Incomplete'}],
            'tcp': [{'address': '0.0.0.0', 'port': 8080, 'pid': 1234}],
            'udp': [],
        }
        with (patch.object(state.platform, 'system', return_value='Windows'),
              patch.object(state, '_text', return_value=json.dumps(evidence)) as run):
            report = state.read_local_network()
        command = run.call_args.args[0][-1]
        self.assertIn('Get-NetRoute', command)
        self.assertIn('Get-NetNeighbor', command)
        self.assertGreater(run.call_args.kwargs['timeout'], 30)
        self.assertNotIn('Where-Object {$_.DestinationPrefix', command)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['routes'][1]['destination'], '192.0.2.0/24')
        self.assertIsNone(report['routes'][1]['gateway'])
        self.assertEqual(report['neighbors'][0]['mac'], '02:11:22:33:44:55')
        self.assertEqual(report['neighbors'][1]['state'], ['incomplete'])
        self.assertIsNone(report['neighbors'][1]['mac'])
        self.assertEqual(report['listeners'], [{'protocol': 'tcp', 'address': '0.0.0.0', 'port': 8080,
                                                'bind': 'wildcard', 'pid': 1234}])

    def test_linux_inventory_captures_both_families_and_reports_unavailable_neighbor_query(self):
        commands = {
            ('ip', '-j', 'address', 'show'): json.dumps([{'ifindex': 2, 'ifname': 'eth0', 'operstate': 'UP',
                'addr_info': [{'local': '192.0.2.4', 'prefixlen': 24}, {'local': 'fe80::1', 'prefixlen': 64}]}]),
            ('ip', '-4', '-j', 'route', 'show', 'table', 'all'): json.dumps([
                {'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'eth0', 'metric': 12},
                {'dst': '192.0.2.4', 'type': 'local', 'table': 'local', 'dev': 'eth0'}]),
            ('ip', '-6', '-j', 'route', 'show', 'table', 'all'): json.dumps([
                {'dst': 'default', 'metric': 512, 'nexthops': [
                    {'gateway': 'fe80::2', 'dev': 'eth0', 'weight': 1},
                    {'gateway': 'fe80::3', 'dev': 'eth0', 'weight': 2}]}]),
            ('ip', '-j', 'neigh', 'show'): None,
            ('ss', '-H', '-lntu'): 'tcp LISTEN 0 32 [::]:443 [::]:*\n',
        }
        with (patch.object(state.platform, 'system', return_value='Linux'),
              patch.object(state, '_text', side_effect=lambda cmd, **kwargs: commands[tuple(cmd)])):
            report = state.read_local_network()
        self.assertEqual(report['status'], 'partial')
        self.assertIn('neighbors-unavailable', report['gaps'])
        self.assertEqual([route['destination'] for route in report['routes']],
                         ['0.0.0.0/0', '192.0.2.4/32', '::/0'])
        self.assertEqual(report['routes'][2]['nexthops'][1]['gateway'], 'fe80::3')
        self.assertEqual(report['listeners'][0]['address'], '::')


class TraceTests(unittest.TestCase):
    def test_windows_trace_keeps_missing_hop_and_real_rtt_without_name_resolution(self):
        output = ('Tracing route to 192.0.2.9 over a maximum of 4 hops\r\n\r\n'
                  '  1    <1 ms     1 ms     2 ms  192.0.2.1\r\n'
                  '  2     *        *        *     Request timed out.\r\n'
                  '  3     4 ms     5 ms     *     192.0.2.9\r\n\r\nTrace complete.\r\n')
        with (patch.object(state.platform, 'system', return_value='Windows'),
              patch.object(state, '_invoke', return_value=('complete', 0, output)) as run):
            result = state.trace_path('192.0.2.9', timeout=.2, max_hops=4, authorized=True)
        self.assertEqual(run.call_args.args[0], ['tracert.exe', '-d', '-4', '-h', '4', '-w', '200', '192.0.2.9'])
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['hops'][0]['rtt_ms'], [1.0, 1.0, 2.0])
        self.assertEqual(result['hops'][0]['rtt_less_than'], [True, False, False])
        self.assertEqual(result['hops'][1]['status'], 'no_reply')
        self.assertEqual(result['hops'][2]['addresses'], ['192.0.2.9'])

    def test_linux_trace_stops_at_limit_and_reports_mixed_evidence(self):
        output = ('traceroute to 192.0.2.9 (192.0.2.9), 2 hops max\n'
                  ' 1  192.0.2.1  1.010 ms\n'
                  ' 2  192.0.2.2  4.20 ms !H\n'
                  ' 3  192.0.2.9  5.0 ms\n')
        with (patch.object(state.platform, 'system', return_value='Linux'),
              patch.object(state, '_invoke', return_value=('complete', 0, output)) as run):
            result = state.trace_path('192.0.2.9', timeout=.5, max_hops=2, source='192.0.2.5', authorized=True)
        self.assertEqual(run.call_args.args[0], ['traceroute', '-4', '-n', '-I', '-q', '1', '-m', '2', '-w', '0.500',
                                                 '-s', '192.0.2.5', '192.0.2.9'])
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['reached'])
        self.assertEqual(result['hops'][1]['status'], 'unreachable')

    def test_windows_ipv4_tracert_preserves_explicit_source_requirement(self):
        with (patch.object(state.platform, 'system', return_value='Windows'),
              patch.object(state, '_invoke', side_effect=AssertionError('unbound trace'))):
            result = state.trace_path('192.0.2.9', source='192.0.2.5', timeout=.2, max_hops=4, authorized=True)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['observation'], 'source_binding_unavailable')


if __name__ == '__main__':
    unittest.main()
