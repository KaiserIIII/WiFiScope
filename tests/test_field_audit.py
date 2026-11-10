import contextlib
import http.server
import io
import json
import socketserver
import threading
import unittest
from typing import ClassVar
from unittest.mock import patch


class _Redirect(http.server.BaseHTTPRequestHandler):
    calls: ClassVar[list[str]] = []

    def do_HEAD(self):
        self.calls.append(self.path)
        self.send_response(302 if self.path == '/entry' else 200)
        if self.path == '/entry':
            self.send_header('Location', '/destination?secret=test-secret')
        self.send_header('Set-Cookie', 'secret=test-cookie')
        self.end_headers()

    def log_message(self, *args):
        pass


class _Telnet(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'\xff\xfb\x01User Access Verification\r\nUsername:')


def _run_server(test, factory, handler):
    server = factory(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    test.addCleanup(thread.join, 3)
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return server.server_address[1]


class FieldAuditTests(unittest.TestCase):
    def test_unbound_selected_interface_and_unrelated_source_are_rejected(self):
        from wifiscope.field_audit import run_field

        with self.assertRaisesRegex(ValueError, 'source address'):
            run_field(interface='WLAN', gateway='192.0.2.1', authorized=True)
        link = {'interface': 'WLAN', 'addresses': ['192.0.2.10/24'], 'gaps': []}
        with (patch('wifiscope.field_audit.read_link', return_value=link),
              self.assertRaisesRegex(ValueError, 'source address')):
            run_field(interface='WLAN', gateway='192.0.2.1', source='198.51.100.4',
                      authorized=True)

    def test_portal_timeline_retries_dns_after_a_transient_failure(self):
        from wifiscope.field_audit import run_field

        _Redirect.calls.clear()
        port = _run_server(self, http.server.HTTPServer, _Redirect)
        answers = [('timeout', []), ('ok', [{'family': 'IPv4', 'address': '127.0.0.1'}])]
        with patch('wifiscope.field_audit.read_link', return_value={'gaps': []}), \
                patch('wifiscope.probe._resolve', side_effect=answers):
            report = run_field(portals=(f'http://example.test:{port}/entry',),
                               samples=2, interval=.25, authorized=True)
        self.assertEqual([row['status'] for row in report['portal']], ['timeout', 'redirect'])
        self.assertEqual(_Redirect.calls, ['/entry'])

    def test_portal_rejects_an_ambiguous_bracketed_authority(self):
        from wifiscope.probe import validate_request

        for url in ('http://junk[::1]:1234/', 'http://[::1]ignored/', 'http://[v1.example]/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_request([], [], 1, 1, [url])

    def test_cli_requires_authorization_before_live_checks(self):
        from wifiscope.cli import main

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            try:
                code = main(['field', 'audit', '--gateway', '127.0.0.1'])
            except SystemExit as error:
                code = error.code
        self.assertEqual(code, 2)
        self.assertIn('authorization', errors.getvalue())

    def test_samples_portal_without_following_and_distinguishes_telnet_protocol(self):
        from wifiscope.field_audit import run_field
        from wifiscope.field_report import project_field

        _Redirect.calls.clear()
        portal = _run_server(self, http.server.HTTPServer, _Redirect)
        port = _run_server(self, socketserver.TCPServer, _Telnet)
        link = {'ssid': 'private SSID', 'interface': 'private interface',
                'bssid': '02:00:00:00:00:01', 'addresses': ['127.0.0.1/8'],
                'gateways': ['127.0.0.1'], 'gaps': []}
        with patch('wifiscope.field_audit.read_link', return_value=link):
            report = run_field(gateway='127.0.0.1', gateway_ports=(port,),
                               portals=(f'http://127.0.0.1:{portal}/entry',),
                               samples=2, interval=.25, timeout=1, authorized=True)
        self.assertEqual(report['gateway']['ports'][0]['protocol'], 'telnet')
        self.assertEqual(report['gateway']['ports'][0]['login_prompt'], True)
        self.assertEqual([x['http_status'] for x in report['portal']], [302, 302])
        self.assertEqual(_Redirect.calls, ['/entry', '/entry'])
        self.assertTrue(all(x['observed_at'] for x in report['portal']))
        projected = json.dumps(project_field(report))
        for secret in ('127.0.0.1', 'private SSID', 'test-secret', 'test-cookie',
                       'User Access Verification', '/entry'):
            self.assertNotIn(secret, projected)

    def test_peer_timeout_with_shared_gateway_stays_inconclusive(self):
        from wifiscope.field_audit import isolation_state

        neighbor = {'class': 'shared_gateway_mac'}
        self.assertEqual(isolation_state([{'icmp': {'status': 'reply'}, 'tcp': []}],
                                         [neighbor]), 'icmp-only')
        self.assertEqual(isolation_state([{'icmp': {'status': 'timeout'},
                                         'tcp': [{'status': 'timeout'}]}],
                                         [neighbor]), 'inconclusive')
        self.assertEqual(isolation_state([], []), 'not-tested')

    def test_shared_mac_only_qualifies_the_matching_reachable_target(self):
        from wifiscope.field_audit import isolation_state

        rows = [{'target': '192.0.2.7', 'icmp': {'status': 'timeout'},
                 'tcp': [{'status': 'reachable'}]}]
        neighbor = {'target': '192.0.2.8', 'class': 'shared_gateway_mac'}
        self.assertEqual(isolation_state(rows, [neighbor]), 'tcp-reachable')
        self.assertEqual(isolation_state(rows, [dict(neighbor, target='192.0.2.7')]),
                         'tcp-reachable-with-shared-mac')
