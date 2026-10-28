import contextlib
import errno
import json
import socket
import ssl
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from wifiscope import probe


@contextlib.contextmanager
def server(response=None, family=socket.AF_INET, pause=0):
    listener = socket.socket(family)
    listener.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
    listener.listen()
    listener.settimeout(.05)
    stopped = threading.Event()
    received = []

    def serve():
        while not stopped.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(.4)
                if response is not None:
                    try:
                        request = conn.recv(4096)
                        if not request:
                            continue
                        received.append(request)
                        if pause:
                            stopped.wait(pause)
                        pieces = response if isinstance(response, list) else [response]
                        for piece in pieces:
                            conn.sendall(piece)
                    except OSError:
                        pass

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield listener.getsockname()[1], received
    finally:
        stopped.set()
        listener.close()
        worker.join(1)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.probe = probe

    def test_authorization_precedes_dns(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('DNS forbidden')):
            with self.assertRaises(ValueError):
                self.probe.probe_hosts(['127.0.0.1'], [80])

    def test_invalid_requests_have_no_network_side_effects(self):
        cases = [(['*.invalid'], [80], 1, 1, []),
                 (['127.0.0.0/24'], [80], 1, 1, []),
                 (['0.0.0.0'], [80], 1, 1, []),
                 (['224.0.0.1'], [80], 1, 1, []),
                 (['255.255.255.255'], [80], 1, 1, []),
                 (['::'], [80], 1, 1, []),
                 (['ff02::1'], [80], 1, 1, []),
                 (['bad_name.invalid'], [80], 1, 1, []),
                 (['bad\r\nhost'], [80], 1, 1, []),
                 (['-bad.invalid'], [80], 1, 1, []),
                 (['127.1'], [80], 1, 1, []),
                 (['1.2.3.999'], [80], 1, 1, []),
                 (['a', 'b', 'c', 'd', 'e'], [80], 1, 1, []),
                 (['localhost'], list(range(1, 10)), 1, 1, []),
                 (['localhost'], [True], 1, 1, []),
                 (['localhost'], [0], 1, 1, []),
                 (['localhost'], [65536], 1, 1, []),
                 (['localhost'], [80], 6, 1, []),
                 (['localhost'], [80], True, 1, []),
                 (['localhost'], [80], 1, float('nan'), []),
                 (['localhost'], [80], 1, .19, []),
                 (['localhost'], [80], 1, 5.01, []),
                 ([], [], 1, 1, []),
                 ([], [], 1, 1, ['http://user:secret@localhost/']),
                 ([], [], 1, 1, ['ftp://localhost/']),
                 ([], [], 1, 1, ['http://localhost/?secret']),
                 ([], [], 1, 1, ['http://localhost/#secret']),
                 ([], [], 1, 1, ['http://localhost/?']),
                 ([], [], 1, 1, ['http://localhost/\n']),
                 ([], [], 1, 1, ['http://localhost\\evil/']),
                 ([], [], 1, 1, ['http://localhost:0/']),
                 ([], [], 1, 1, ['http://localhost/' + 'x' * 2048]),
                 ([], [], 1, 1, ['http://localhost/'] * 5)]
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), patch.object(subprocess, 'Popen', side_effect=AssertionError('DNS forbidden')):
            for args in cases:
                with self.subTest(args=args):
                    with self.assertRaises(ValueError):
                        self.probe.probe_hosts(args[0], args[1], authorized=True,
                                               attempts=args[2], timeout=args[3], urls=args[4])

    def test_validation_normalizes_and_derives_url_hosts_without_default_ports(self):
        hosts, ports, urls = self.probe.validate_request([], [], 1, .2,
                                                       ['http://LOCALHOST:8080/path'])
        self.assertEqual(hosts, ['localhost'])
        self.assertEqual(ports, [])
        self.assertEqual(urls, ['http://localhost:8080/path'])
        self.assertEqual(self.probe.validate_request(['::1', 'localhost.'], [80, 80], 5, 5)[:2],
                         (['::1', 'localhost'], [80]))

    def test_loopback_tcp_statistics_and_refusal(self):
        with server() as (port, _):
            result = self.probe.probe_hosts(['127.0.0.1'], [port], authorized=True,
                                            attempts=2, timeout=.3)[0]
        row = result['tcp'][0]
        self.assertEqual((row['status'], row['attempts'], row['successes'], row['failure_percent']),
                         ('ok', 2, 2, 0))
        self.assertLessEqual(row['rtt_min_ms'], row['rtt_mean_ms'])
        self.assertLessEqual(row['rtt_mean_ms'], row['rtt_max_ms'])
        self.assertGreaterEqual(row['jitter_ms'], 0)
        # Windows can delay refusal beyond a short operation deadline; inject
        # the OS refusal boundary to verify its categorical mapping reliably.
        with patch.object(self.probe, '_connect', side_effect=ConnectionRefusedError):
            result = self.probe.probe_hosts(['127.0.0.1'], [port], authorized=True,
                                            attempts=1, timeout=.2)[0]
        self.assertEqual(result['tcp'][0]['status'], 'refused')
        self.assertIsNone(result['tcp'][0]['rtt_mean_ms'])

    def test_ipv4_ipv6_remain_separate_and_addresses_are_capped(self):
        answers = [dict(family=family, address=address)
                   for family, address in [('IPv4', '127.0.0.1'), ('IPv4', '127.0.0.2'),
                                           ('IPv4', '127.0.0.3'), ('IPv6', '::1'),
                                           ('IPv6', '::2'), ('IPv6', '::3')]]
        with patch.object(self.probe, '_resolve', return_value=('ok', answers)), patch.object(self.probe, '_connect', side_effect=ConnectionRefusedError):
            result = self.probe.probe_hosts(['test.invalid'], [80], authorized=True,
                                            attempts=1, timeout=.2)[0]
        self.assertEqual(len(result['dns']['answers']), 4)
        self.assertEqual([r['family'] for r in result['tcp']], ['IPv4', 'IPv4', 'IPv6', 'IPv6'])

    def test_real_ipv6_loopback_when_available(self):
        try:
            with server(family=socket.AF_INET6) as (port, _):
                result = self.probe.probe_hosts(['::1'], [port], authorized=True,
                                                attempts=1, timeout=.3)[0]
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        self.assertEqual(result['tcp'][0]['family'], 'IPv6')
        self.assertEqual(result['tcp'][0]['status'], 'ok')

    def test_resolved_budget_rejected_before_any_target_socket(self):
        answers = [dict(family='IPv4', address='127.0.0.' + str(i)) for i in (1, 2)]
        answers += [dict(family='IPv6', address='::' + str(i)) for i in (1, 2)]
        with patch.object(self.probe, '_resolve', return_value=('ok', answers)), patch.object(self.probe, '_connect', side_effect=AssertionError('over budget')):
            with self.assertRaises(ValueError):
                self.probe.probe_hosts(['a.invalid', 'b.invalid', 'c.invalid', 'd.invalid'],
                                       [80, 81], authorized=True, attempts=5, timeout=.2)

    def test_dns_deadline_terminates_and_reaps_child(self):
        class Child:
            returncode = None
            killed = False
            waited = False
            def communicate(self, timeout=None):
                if self.killed:
                    self.waited = True
                    return b'', b''
                time.sleep(min(timeout, .02))
                raise subprocess.TimeoutExpired('private command', timeout)
            def kill(self):
                self.killed = True
        child = Child()
        started = time.monotonic()
        with patch.object(subprocess, 'Popen', return_value=child):
            result = self.probe.probe_hosts(['test.invalid'], [80], authorized=True,
                                           attempts=1, timeout=.2)[0]
        self.assertLess(time.monotonic() - started, .7)
        self.assertEqual(result['dns']['status'], 'timeout')
        self.assertTrue(child.killed and child.waited)
        self.assertIn('dns-timeout', result['gaps'])

    def test_localhost_dns_uses_bounded_child(self):
        with server() as (port, _):
            result = self.probe.probe_hosts(['localhost'], [port], authorized=True,
                                            attempts=1, timeout=2)[0]
        self.assertEqual(result['dns']['status'], 'ok')
        self.assertTrue(result['dns']['answers'])
        self.assertIn('ok', {r['status'] for r in result['tcp']})

    def test_pre_cancelled_request_opens_no_socket_or_dns(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('DNS forbidden')), patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')):
            result = self.probe.probe_hosts(['test.invalid'], [80], authorized=True,
                                            cancel=cancelled)[0]
        self.assertEqual(result['dns']['status'], 'cancelled')
        self.assertIn('dns-cancelled', result['gaps'])

    def test_timeout_and_partial_cancellation_are_categorical(self):
        event = threading.Event()
        def connect(*args):
            event.set()
            raise TimeoutError('PRIVATE exception')
        with patch.object(self.probe, '_connect', side_effect=connect):
            result = self.probe.probe_hosts(['127.0.0.1'], [80], authorized=True,
                                            attempts=3, timeout=.2, cancel=event)[0]
        self.assertEqual(result['tcp'][0]['attempts'], 1)
        self.assertEqual(result['tcp'][0]['status'], 'cancelled')
        self.assertIn('tcp-cancelled', result['gaps'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_cancellation_before_socket_creation_counts_zero_attempts(self):
        event = threading.Event()
        real_wait = self.probe._Limiter.wait
        def cancel_after_limiter(limiter):
            real_wait(limiter)
            event.set()
        with patch.object(self.probe._Limiter, 'wait', cancel_after_limiter), patch.object(socket, 'socket', side_effect=AssertionError('no target socket may start')):
            result = self.probe.probe_hosts(['127.0.0.1'], [80], authorized=True,
                                            attempts=3, timeout=.2, cancel=event)[0]
        row = result['tcp'][0]
        self.assertEqual(row['status'], 'cancelled')
        self.assertEqual(row['attempts'], 0)
        self.assertEqual(row['successes'], 0)
        self.assertIsNone(row['failure_percent'])
        self.assertIn('tcp-cancelled', result['gaps'])

    def test_cancellation_during_started_connect_counts_one_attempt(self):
        event = threading.Event()
        class Socket:
            calls = 0
            closed = False
            def setblocking(inner, value):
                pass
            def connect_ex(inner, target):
                inner.calls += 1
                event.set()
                return errno.EINPROGRESS
            def close(inner):
                inner.closed = True
        transport = Socket()
        with patch.object(socket, 'socket', return_value=transport):
            result = self.probe.probe_hosts(['127.0.0.1'], [80], authorized=True,
                                            attempts=3, timeout=.2, cancel=event)[0]
        row = result['tcp'][0]
        self.assertEqual(transport.calls, 1)
        self.assertTrue(transport.closed)
        self.assertEqual((row['status'], row['attempts'], row['successes']), ('cancelled', 1, 0))
        self.assertEqual(row['failure_percent'], 100)

    def test_hsts_validates_full_directives_and_exact_names(self):
        cases = [(b'max-age=100; includeSubDomains; includeSubDomains', False),
                 (b'max-age=100; includeSubDomains; INCLUDESUBDOMAINS', False),
                 (b'max-age=100; invalid directive', False),
                 (b'max-age=100; max-age-policy=custom', True),
                 (b'max-age=100; custom="a;b"', True),
                 (b'max-age=100; custom="a\\\";b"', True),
                 (b'max-age="1\\0\\0"; includeSubDomains', True),
                 (b'max-age=100; custom=one; CUSTOM=two', False),
                 (b'max-age=100; custom=', False),
                 (b'max-age=100; custom="unterminated', False),
                 (b'max-age=100; includeSubDomains=yes', False),
                 (b'; ; MAX-AGE = "100" ; includeSubDomains; ', True)]
        for value, expected in cases:
            with self.subTest(value=value), server(b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: ' + value + b'\r\n\r\n') as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
            checks = result['http'][0]['security_checks']
            self.assertTrue(checks['hsts'])
            self.assertEqual(checks['hsts_positive_max_age'], expected)

    def test_frame_protection_uses_restrictive_supported_first_directive(self):
        cases = [(b'frame-ancestors *', False),
                 (b"frame-ancestors 'unsafe-inline'", None),
                 (b"frame-ancestors 'self'", True),
                 (b"frame-ancestors 'none'", True),
                 (b'frame-ancestors https://embed.example.invalid', True),
                 (b'frame-ancestors https://*.example.invalid:443/', True),
                 (b"frame-ancestors *; frame-ancestors 'none'", False),
                 (b"frame-ancestors 'none'; FRAME-ANCESTORS *", True),
                 (b'frame-ancestors https:', None),
                 (b'frame-ancestors https://host.invalid:invalid', None),
                 (b"default-src 'none'", False)]
        for policy, expected in cases:
            with self.subTest(policy=policy), server(b'HTTP/1.1 200 OK\r\nContent-Security-Policy: ' + policy + b'\r\n\r\n') as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
            self.assertIs(result['http'][0]['security_checks']['frame_protection'], expected)

    def test_frame_ancestors_precedes_xfo_and_multiple_policies_intersect(self):
        cases = [(b'Content-Security-Policy: frame-ancestors *\r\nX-Frame-Options: DENY\r\n', False),
                 (b'Content-Security-Policy: frame-ancestors *\r\nContent-Security-Policy: frame-ancestors \'self\'\r\n', True),
                 (b'Content-Security-Policy: frame-ancestors *, frame-ancestors \'none\'\r\n', True),
                 (b'X-Frame-Options: DENY\r\n', True),
                 (b'X-Frame-Options: SAMEORIGIN\r\n', True)]
        for headers, expected in cases:
            with self.subTest(headers=headers), server(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n') as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
            self.assertIs(result['http'][0]['security_checks']['frame_protection'], expected)

    def test_head_uses_pinned_address_original_host_and_no_proxy(self):
        response = [b'HTTP/1.1 200 O', b'K\r\nContent-Type: text/html; charset=utf-8\r\n',
                    b'X-Content-Type-Options: nosniff\r\n\r\nPRIVATE BODY']
        with server(response) as (port, received), patch.object(self.probe, '_resolve', return_value=('ok', [dict(family='IPv4', address='127.0.0.1')])), patch.dict('os.environ', {'HTTP_PROXY': 'http://192.0.2.1:1'}):
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=.4, urls=[f'http://test.invalid:{port}/check'])[0]
        self.assertEqual(len(result['tcp']), 1)
        self.assertEqual(result['http'][0]['status_code'], 200)
        self.assertEqual(result['http'][0]['content_kind'], 'html')
        self.assertTrue(result['http'][0]['security_checks']['nosniff'])
        self.assertIn(f'Host: test.invalid:{port}\r\n'.encode(), received[0])
        self.assertTrue(received[0].startswith(b'HEAD /check HTTP/1.1\r\n'))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_head_security_checks_use_values_and_all_cookie_attributes(self):
        examples = [
            (b'Strict-Transport-Security: max-age=31536000; includeSubDomains\r\nContent-Security-Policy: frame-ancestors \'none\'\r\nX-Content-Type-Options: nosniff\r\nSet-Cookie: a=private; Secure; HttpOnly\r\nSet-Cookie: b=private; Secure; HttpOnly\r\n',
             dict(hsts=True, hsts_positive_max_age=True, csp=True, frame_protection=True,
                  nosniff=True, cookies_secure=True, cookies_httponly=True)),
            (b'Strict-Transport-Security: max-age=0\r\nX-Frame-Options: ALLOWALL\r\nX-Content-Type-Options: sniff\r\nSet-Cookie: a=private; Secure; HttpOnly\r\nSet-Cookie: b=private\r\n',
             dict(hsts=True, hsts_positive_max_age=False, csp=False, frame_protection=False,
                  nosniff=False, cookies_secure=False, cookies_httponly=False)),
            (b'X-Frame-Options: SAMEORIGIN\r\n',
             dict(hsts=False, hsts_positive_max_age=False, csp=False, frame_protection=True,
                  nosniff=False, cookies_secure=None, cookies_httponly=None)),
            (b'Strict-Transport-Security: max-age=invalid\r\nContent-Security-Policy: default-src \'self\'\r\n',
             dict(hsts=True, hsts_positive_max_age=False, csp=True, frame_protection=False,
                  nosniff=False, cookies_secure=None, cookies_httponly=None)),
        ]
        for headers, expected in examples:
            with self.subTest(headers=headers), server(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n') as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.3, urls=[f'http://127.0.0.1:{port}/'])[0]
            self.assertEqual(result['http'][0]['security_checks'], expected)
            self.assertNotIn('private', json.dumps(result))

    def test_redirect_not_followed_and_error_checks_not_evaluated(self):
        for code in (302, 404):
            with server(f'HTTP/1.1 {code} Response\r\nLocation: http://192.0.2.1/private\r\n\r\n'.encode()) as (port, received):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.3, urls=[f'http://127.0.0.1:{port}/'])[0]
            row = result['http'][0]
            self.assertEqual(row['status'], 'redirect' if code == 302 else 'http_error')
            self.assertTrue(all(v is None for v in row['security_checks'].values()))
            self.assertEqual(len(received), 1)
            self.assertNotIn('192.0.2.1', json.dumps(result))

    def test_head_rejects_malformed_and_oversized_headers(self):
        for response in (b'PRIVATE not HTTP\r\n\r\n', b'HTTP/1.1 200 OK\nX: value\n\n',
                         b'HTTP/1.1 200 OK\r\nBad header\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 20000 + b'\r\n\r\n'):
            with self.subTest(response=response[:40]), server(response) as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
            self.assertEqual(result['http'][0]['status'], 'invalid_response')
            self.assertIn('http-unavailable', result['gaps'])

    def test_head_total_deadline_and_cancellation(self):
        with server(b'HTTP/1.1 200 OK\r\n\r\n', pause=.5) as (port, _):
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
        self.assertEqual(result['http'][0]['status'], 'timeout')
        event = threading.Event()
        with server(b'HTTP/1.1 200 OK\r\n\r\n', pause=2) as (port, _):
            timer = threading.Timer(.35, event.set)
            timer.start()
            started = time.monotonic()
            try:
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=2, urls=[f'http://127.0.0.1:{port}/'], cancel=event)[0]
            finally:
                timer.cancel()
        self.assertLess(time.monotonic() - started, 1.2)
        self.assertEqual(result['http'][0]['status'], 'cancelled')

    def test_tls_rejection_preserves_verification_and_original_sni(self):
        class Context:
            def wrap_socket(inner, sock, *, server_hostname, do_handshake_on_connect):
                self.assertEqual(server_hostname, 'test.invalid')
                self.assertFalse(do_handshake_on_connect)
                raise ssl.SSLCertVerificationError('PRIVATE certificate')
        with server() as (port, _), patch.object(self.probe, '_resolve', return_value=('ok', [dict(family='IPv4', address='127.0.0.1')])), patch.object(ssl, 'create_default_context', return_value=Context()):
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=.2, urls=[f'https://test.invalid:{port}/'])[0]
        self.assertEqual(result['tls'][0]['status'], 'certificate_error')
        self.assertFalse(result['tls'][0]['verified'])
        self.assertEqual(result['http'][0]['status'], 'certificate_error')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_verified_tls_metadata_at_transport_boundary(self):
        class TLS:
            def __init__(inner, sock):
                inner.sock = sock
            def getpeercert(inner, binary_form=False):
                return b'verified-der' if binary_form else {'notAfter': 'Jan  1 00:00:00 2030 GMT'}
            def version(inner):
                return 'TLSv1.3'
            def cipher(inner):
                return ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            def __getattr__(inner, name):
                return getattr(inner.sock, name)
        with server(b'HTTP/1.1 200 OK\r\n\r\n') as (port, _), patch.object(self.probe, '_start_tls', side_effect=lambda sock, *args: TLS(sock)):
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=.3, urls=[f'https://127.0.0.1:{port}/'])[0]
        row = result['tls'][0]
        self.assertTrue(row['verified'])
        self.assertEqual(row['version'], 'TLSv1.3')
        self.assertEqual(row['not_after'], '2030-01-01T00:00:00+00:00')
        self.assertEqual(len(row['certificate_sha256']), 64)
        self.assertGreater(row['days_remaining'], 0)
        self.assertEqual(row['cipher'], 'TLS_AES_256_GCM_SHA384')

    def test_urls_apply_only_to_their_host_and_port(self):
        with server(b'HTTP/1.1 200 OK\r\n\r\n') as (one, received_one), server() as (two, received_two):
            results = self.probe.probe_hosts(['127.0.0.2'], [two], authorized=True,
                                             attempts=1, timeout=.2,
                                             urls=[f'http://127.0.0.1:{one}/'])
        keyed = {r['host']: r for r in results}
        self.assertEqual([r['port'] for r in keyed['127.0.0.1']['tcp']], [one])
        self.assertEqual([r['port'] for r in keyed['127.0.0.2']['tcp']], [two])
        self.assertEqual(keyed['127.0.0.2']['http'], [])
        self.assertEqual(len(received_one), 1)
        self.assertEqual(received_two, [])

    def test_rate_limit_shared_across_tcp_tls_and_head(self):
        starts = []
        real_connect = self.probe._connect
        def observed(*args):
            starts.append(time.monotonic())
            return real_connect(*args)
        with server(b'HTTP/1.1 200 OK\r\n\r\n') as (port, _), patch.object(self.probe, '_connect', side_effect=observed):
            self.probe.probe_hosts([], [], authorized=True, attempts=2, timeout=.2,
                                   urls=[f'http://127.0.0.1:{port}/'])
        self.assertEqual(len(starts), 3)
        self.assertTrue(all(b - a >= .24 for a, b in zip(starts, starts[1:])))

    def test_hsts_rejects_unmatched_quotes_and_duplicate_max_age(self):
        for value in (b'max-age="100', b'max-age=100"', b'max-age=100; max-age=100'):
            with server(b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: ' + value + b'\r\n\r\n') as (port, _):
                result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                                timeout=.2, urls=[f'http://127.0.0.1:{port}/'])[0]
            self.assertFalse(result['http'][0]['security_checks']['hsts_positive_max_age'])

    def test_dns_cancellation_kills_and_reaps_running_child(self):
        event = threading.Event()
        class Child:
            returncode = None
            killed = False
            reaped = False
            def communicate(inner, timeout=None):
                if inner.killed:
                    inner.reaped = True
                    return b'', b''
                event.set()
                raise subprocess.TimeoutExpired('private', timeout)
            def kill(inner):
                inner.killed = True
        child = Child()
        with patch.object(subprocess, 'Popen', return_value=child):
            result = self.probe.probe_hosts(['test.invalid'], [80], authorized=True,
                                            timeout=.2, cancel=event)[0]
        self.assertEqual(result['dns']['status'], 'cancelled')
        self.assertTrue(child.killed and child.reaped)

    def test_tls_connections_share_rate_limit_with_tcp_and_https_head(self):
        starts = []
        def refused(*args):
            starts.append(time.monotonic())
            raise ConnectionRefusedError
        with patch.object(self.probe, '_connect', side_effect=refused):
            self.probe.probe_hosts([], [], authorized=True, attempts=1, timeout=.2,
                                   urls=['https://127.0.0.1:8443/'])
        self.assertEqual(len(starts), 3)
        self.assertTrue(all(b - a >= .24 for a, b in zip(starts, starts[1:])))

    def test_validation_rejects_multiple_trailing_dots(self):
        with self.assertRaises(ValueError):
            self.probe.validate_request(['localhost..'], [80], 1, .2)

    def test_total_connection_budget_includes_tls_and_head(self):
        answers = [dict(family='IPv4', address='127.0.0.' + str(i)) for i in (1, 2)]
        answers += [dict(family='IPv6', address='::' + str(i)) for i in (1, 2)]
        # TCP alone is exactly 128; sixteen additional TLS handshakes must be
        # included before a single target connection may be opened.
        with patch.object(self.probe, '_resolve', return_value=('ok', answers)), patch.object(self.probe, '_connect', side_effect=AssertionError('over budget')):
            with self.assertRaises(ValueError):
                self.probe.probe_hosts(['a.invalid', 'b.invalid', 'c.invalid', 'd.invalid'],
                                       [443, 80, 81, 82, 83, 84, 85, 86],
                                       authorized=True, attempts=1, timeout=.2)

    def test_absolute_deadline_stops_unstarted_head_without_counting_attempt(self):
        with server(b'HTTP/1.1 200 OK\r\n\r\n') as (port, received):
            start = time.monotonic()
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=2, deadline=start + .12,
                                            urls=[f'http://127.0.0.1:{port}/'])[0]
        self.assertLess(time.monotonic() - start, .5)
        self.assertEqual(result['tcp'][0]['attempts'], 1)
        self.assertEqual(result['http'][0]['status'], 'not_run')
        self.assertEqual(received, [])
        self.assertIn('probe-timeout', result['gaps'])
        self.assertIn('http-timeout', result['gaps'])

    def test_absolute_deadline_reduces_head_read_deadline(self):
        with server(b'HTTP/1.1 200 OK\r\n\r\n', pause=1) as (port, _):
            start = time.monotonic()
            result = self.probe.probe_hosts([], [], authorized=True, attempts=1,
                                            timeout=2, deadline=start + .4,
                                            urls=[f'http://127.0.0.1:{port}/'])[0]
        self.assertLess(time.monotonic() - start, .8)
        self.assertEqual(result['http'][0]['status'], 'timeout')
        self.assertIn('probe-timeout', result['gaps'])

    def test_expired_deadline_prevents_dns_and_connections(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('DNS forbidden')), patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            result = self.probe.probe_hosts(['test.invalid'], [80], authorized=True,
                                            deadline=time.monotonic() - 1)[0]
        self.assertEqual(result['dns']['status'], 'not_run')
        self.assertIn('probe-timeout', result['gaps'])
        for deadline in (True, float('nan'), float('inf'), 'bad'):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                self.probe.probe_hosts(['127.0.0.1'], [80], authorized=True, deadline=deadline)

    def test_ipv4_mapped_forbidden_literals_are_rejected(self):
        for host in ('::ffff:0.0.0.0', '::ffff:224.0.0.1', '::ffff:255.255.255.255'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.probe.validate_request([host], [80], 1, .2)


if __name__ == '__main__':
    unittest.main()
