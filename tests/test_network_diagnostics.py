import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from wifiscope import network_diagnostics as diagnostics


def link_fixture():
    return {'interface': 'Wi-Fi', 'ssid': 'Field Lab', 'bssid': '02:00:00:00:00:01',
            'channel': 11, 'signal_percent': 80, 'addresses': ['192.0.2.5/24'],
            'dns': ['192.0.2.53'], 'gateways': ['192.0.2.1'], 'routes': [], 'gaps': []}


def inventory_fixture():
    return {'status': 'ok', 'interfaces': [{'interface': 'Wi-Fi', 'addresses': ['192.0.2.5/24']}],
            'routes': [{'destination': '0.0.0.0/0', 'gateway': '192.0.2.1', 'interface': 'Wi-Fi'},
                       {'destination': '192.0.2.0/24', 'gateway': None, 'interface': 'Wi-Fi'}],
            'neighbors': [{'ip': '192.0.2.1', 'interface': 'Wi-Fi', 'state': ['reachable']}],
            'listeners': [{'protocol': 'tcp', 'address': '127.0.0.1', 'port': 9000}], 'gaps': []}


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.link_reader = self.enterContext(patch.object(diagnostics, 'read_link', return_value=link_fixture()))
        self.inventory_reader = self.enterContext(patch.object(diagnostics, 'read_local_network',
                                                               return_value=inventory_fixture()))

    def test_no_active_targets_are_inferred_from_local_evidence(self):
        with (patch.object(diagnostics, 'echo_probe', side_effect=AssertionError('unexpected ICMP')),
              patch.object(diagnostics, 'trace_path', side_effect=AssertionError('unexpected trace')),
              patch.object(diagnostics, 'path_checks', side_effect=AssertionError('unexpected network check'))):
            result = diagnostics.diagnose_network()
        self.assertFalse(result['plan']['requires_authorization'])
        stages = result['samples'][0]['stages']
        self.assertEqual(stages['link']['status'], 'ok')
        self.assertEqual(stages['local']['routes'][1]['destination'], '192.0.2.0/24')
        self.assertEqual(stages['local']['neighbors'][0]['ip'], '192.0.2.1')
        self.assertEqual(stages['local']['listeners'][0]['port'], 9000)
        for stage in ('gateway', 'peer', 'dns', 'path', 'application'):
            self.assertEqual(stages[stage]['status'], 'not_requested')
        json.dumps(result, allow_nan=False)

    def test_active_plan_requires_authorization_before_any_collection(self):
        plan = diagnostics.diagnostic_plan(trace='192.0.2.9', dns='192.0.2.53')
        self.assertTrue(plan['requires_authorization'])
        self.assertEqual(plan['trace'], '192.0.2.9')
        self.assertEqual(plan['dns'], '192.0.2.53:53')
        with self.assertRaisesRegex(ValueError, 'authorization'):
            diagnostics.diagnose_network(trace='192.0.2.9')
        self.link_reader.assert_not_called()
        self.inventory_reader.assert_not_called()

    def test_selected_wired_interface_can_report_a_link_without_wifi_association(self):
        self.link_reader.return_value = {'interface': 'Ethernet', 'addresses': [], 'gaps': ['association-unavailable']}
        self.inventory_reader.return_value = {**inventory_fixture(), 'platform': 'Windows', 'interfaces': [
            {'interface': 'Ethernet', 'state': 'Up'}, {'interface': 'Wi-Fi', 'state': 'Disconnected'},
        ]}
        result = diagnostics.diagnose_network(interface='ethernet')
        link = result['samples'][0]['stages']['link']
        self.assertEqual(link['status'], 'ok')
        self.assertEqual(link['interface_states'], [{'interface': 'Ethernet', 'state': 'Up'}])

    def test_unbounded_or_ambiguous_plan_is_rejected_before_observation(self):
        for options in ({'trace': '192.0.2.0/24'}, {'gateway': '224.0.0.3'}, {'peers': '192.0.2.2'},
                        {'peers': [f'192.0.2.{i}' for i in range(1, 10)]}, {'max_hops': 31},
                        {'samples': 0}, {'samples': 61}, {'interval': float('nan')}, {'timeout': float('inf')},
                        {'failure_threshold': 0}, {'interface': 'Wi-Fi', 'trace': '192.0.2.1'},
                        {'source': '192.0.2.5', 'trace': '2001:db8::1'}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                diagnostics.diagnostic_plan(**options)
        self.link_reader.assert_not_called()

    def test_selected_source_must_be_observed_before_sending(self):
        with patch.object(diagnostics, 'echo_probe', side_effect=AssertionError('bound to wrong source')):
            result = diagnostics.diagnose_network(interface='Wi-Fi', source='192.0.2.55',
                                                  gateway='192.0.2.1', authorized=True)
        sample = result['samples'][0]
        self.assertEqual(sample['source_status'], 'source_unavailable')
        self.assertEqual(sample['stages']['gateway']['status'], 'unknown')

    def test_known_local_broadcast_target_is_never_probed(self):
        with patch.object(diagnostics, 'echo_probe', side_effect=AssertionError('broadcast sent')):
            result = diagnostics.diagnose_network(gateway='192.0.2.255', authorized=True)
        check = result['samples'][0]['stages']['gateway']['checks'][0]
        self.assertEqual((check['status'], check['observation']), ('unknown', 'local_broadcast_target'))

    def test_monitor_alerts_after_consecutive_failures_and_recovers_once(self):
        statuses = ['timeout', 'unavailable', 'timeout', 'timeout', 'unavailable', 'reply', 'reply']
        seen = []
        with patch.object(diagnostics, 'echo_probe', side_effect=[{'status': status} for status in statuses]):
            result = diagnostics.monitor_network(gateway='192.0.2.1', authorized=True, samples=7,
                                                 interval=0, failure_threshold=2, on_sample=seen.append)
        self.assertEqual([sample['sequence'] for sample in seen], list(range(1, 8)))
        self.assertEqual([(alert['type'], alert['stage'], alert['target'], alert['sequence'])
                          for alert in result['alerts']],
                         [('failure', 'gateway', '192.0.2.1', 4), ('recovery', 'gateway', '192.0.2.1', 6)])

    def test_cancel_after_first_sample_skips_wait_and_remaining_observations(self):
        cancel = threading.Event()
        result = diagnostics.monitor_network(samples=3, interval=120, cancel=cancel,
                                             on_sample=lambda sample: cancel.set())
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(len(result['samples']), 1)
        self.assertEqual(self.link_reader.call_count, 1)

    def test_dns_stage_records_a_response_from_the_configured_loopback_endpoint(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(2)

            def answer():
                try:
                    query, address = server.recvfrom(512)
                    server.sendto(query[:2] + bytes.fromhex('8180') + query[4:], address)
                except OSError:
                    return

            thread = threading.Thread(target=answer, daemon=True)
            thread.start()
            try:
                result = diagnostics.diagnose_network(dns=server.getsockname(), authorized=True)
            finally:
                thread.join(2)
        stage = result['samples'][0]['stages']['dns']
        self.assertEqual(stage['status'], 'ok')
        self.assertGreaterEqual(stage['latency_ms'], 0)
        self.assertEqual(stage['checks'][0]['dns_rcode'], 0)

    def test_application_records_loopback_redirect_without_following_it(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/redirected')
                self.end_headers()

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = diagnostics.diagnose_network(application=f'http://127.0.0.1:{server.server_port}/health',
                                                      authorized=True)
            finally:
                server.shutdown()
                thread.join(2)
        stage = result['samples'][0]['stages']['application']
        self.assertEqual(requests, ['/health'])
        self.assertEqual(stage['status'], 'partial')
        self.assertEqual(stage['checks'][0]['http_status'], 302)


if __name__ == '__main__':
    unittest.main()
