import contextlib
import os
import socket
import struct
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wifiscope import field_path

QUESTION = b'\x07example\x03com\x00\x00\x01\x00\x01'
ANSWER = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01'


def dns_reply(query, flags=0x8180, question=QUESTION, answer=ANSWER):
    return query[:2] + struct.pack('!5H', flags, 1, bool(answer), 0, 0) + question + answer


def ntp_reply(query, first=0x24, cookie=None, stratum=2):
    return bytes([first, stratum]) + bytes(22) + (query[-8:] if cookie is None else cookie) + bytes(range(1, 17))


@contextlib.contextmanager
def udp_server(reply, host='127.0.0.1'):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as listener:
        listener.bind((host, 0))
        listener.settimeout(1)
        received = []

        def serve():
            try:
                packet, address = listener.recvfrom(2048)
                received.append((packet, address[0]))
                response = reply(packet)
                if response:
                    listener.sendto(response, address)
            except OSError:
                pass

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield (host, listener.getsockname()[1]), received
        finally:
            worker.join()


@contextlib.contextmanager
def http_server(respond):
    # Replace TLS only at the wire boundary. The endpoint validator, TCP source
    # bind, request, response framing, deadlines and limits still run normally.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(1)
        received = []
        stopped = threading.Event()

        def serve():
            try:
                conn, address = listener.accept()
                with conn, conn.makefile('rb') as stream:
                    conn.settimeout(1)
                    request = stream.readline()
                    headers = {}
                    for line in iter(stream.readline, b'\r\n'):
                        if not line:
                            return
                        name, value = line.split(b':', 1)
                        headers[name.lower()] = value.strip()
                    body = stream.read(int(headers.get(b'content-length', b'0')))
                    received.append((request, headers, body, address[0]))
                    respond(conn, body, stopped)
            except OSError:
                pass

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with patch.object(field_path, '_start_tls', side_effect=lambda sock, *_: sock):
                yield f'https://127.0.0.1:{listener.getsockname()[1]}', received
        finally:
            stopped.set()
            worker.join()


def http_response(code, headers, body=b''):
    return f'HTTP/1.1 {code}\r\n{headers}\r\n\r\n'.encode('ascii') + body


class PathChecksTests(unittest.TestCase):
    def test_default_inactive_and_complete_validation_precedes_traffic(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('unexpected traffic')):
            self.assertEqual(field_path.path_checks(), dict.fromkeys(('dns', 'ntp', 'doh', 'download')))
            with self.assertRaises(ValueError):
                field_path.path_checks(dns='127.0.0.1')
            for invalid in (
                {'download': 'http://127.0.0.1/'}, {'doh': 'https://user@localhost/dns-query'},
                {'doh': 'https://[::1]suffix/dns-query'}, {'doh': 'https://localhost/?dns=private'},
                {'doh': 'https://[v1.example]/dns-query'},
                {'source': '::1'}, {'source': 'localhost'}, {'ntp': 'localhost'},
                {'ntp': '224.0.0.1'}, {'timeout': float('nan')}, {'timeout': 10**1000},
            ):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    field_path.path_checks(dns='127.0.0.1', authorized=True, **invalid)
            field_path.validate_path_plan(dns='[::1]:8053', ntp='127.0.0.1:8123',
                                          doh='https://localhost/dns-query')

    def test_dns_requires_matching_question_transaction_and_framing(self):
        scenarios = (
            ('ok', dns_reply),
            ('dns_error', lambda q: dns_reply(q, flags=0x8183, answer=b'')),
            ('truncated', lambda q: dns_reply(q, flags=0x8380, answer=b'')),
            ('invalid_response', lambda q: dns_reply(q, question=QUESTION[:-3] + b'\x1c\x00\x01')),
            ('invalid_response', lambda q: bytes([q[0] ^ 1]) + dns_reply(q)[1:]),
            ('invalid_response', lambda q: dns_reply(q)[:-1]),
        )
        for status, response in scenarios:
            with self.subTest(status=status), udp_server(response) as (endpoint, received):
                row = field_path.path_checks(dns=endpoint, source='127.0.0.1', authorized=True)['dns']
                self.assertEqual(row['status'], status)
                self.assertEqual(row['method'], 'udp-dns')
                self.assertGreaterEqual(row['ms'], 0)
                self.assertTrue(row['timestamp'].endswith('+00:00'))
                self.assertEqual(received[0][0][2:], b'\x01\x00\x00\x01' + bytes(6) + QUESTION)
                self.assertEqual(received[0][1], '127.0.0.1')
                self.assertNotIn('127.0.0.1', repr(row))
                self.assertNotIn('example.com', repr(row))

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 unsupported')
    def test_dns_ipv6(self):
        try:
            with udp_server(dns_reply, '::1') as (endpoint, _):
                row = field_path.path_checks(dns=f'[{endpoint[0]}]:{endpoint[1]}',
                                             source='::1', authorized=True)['dns']
        except OSError as error:
            self.skipTest(f'IPv6 loopback unavailable ({error.errno})')
        self.assertEqual(row['status'], 'ok')

    def test_ntp_validates_originate_and_server_mode(self):
        scenarios = (
            ('ok', ntp_reply),
            ('kiss_of_death', lambda q: ntp_reply(q, stratum=0)),
            ('invalid_response', lambda q: ntp_reply(q, first=0x25)),
            ('invalid_response', lambda q: ntp_reply(q, cookie=bytes([q[-8] ^ 1]) + q[-7:])),
        )
        for status, response in scenarios:
            with self.subTest(status=status), udp_server(response) as (endpoint, received):
                row = field_path.path_checks(ntp=endpoint, authorized=True)['ntp']
                self.assertEqual(row['status'], status)
                self.assertEqual(row['method'], 'udp-ntp')
                self.assertEqual(row['bytes'], 48)
                self.assertEqual(received[0][0][:40], b'\x23' + bytes(39))
                self.assertIn('clock-synchronization-not-tested', row['gaps'])

    def test_cancelled_checks_open_no_socket(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(socket, 'socket', side_effect=AssertionError('unexpected traffic')):
            row = field_path.path_checks(ntp='127.0.0.1', authorized=True, cancel=cancel)['ntp']
        self.assertEqual(row['status'], 'cancelled')
        self.assertIsNone(row['bytes'])

    def test_doh_checks_media_type_and_dns_reply(self):
        cases = (
            ('ok', 'application/dns-message', dns_reply),
            ('invalid_response', 'text/html', dns_reply),
            ('invalid_response', 'application/dns-message', lambda q: dns_reply(q)[1:]),
        )
        for expected, media, make_body in cases:
            def respond(conn, request_body, _, make_body=make_body, media=media):
                body = make_body(request_body)
                conn.sendall(http_response('200 OK', f'Content-Type: {media}\r\nContent-Length: {len(body)}', body))

            with self.subTest(expected=expected, media=media), http_server(respond) as (base, received):
                with patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:1'}):
                    row = field_path.path_checks(doh=base + '/dns-query', authorized=True, source='127.0.0.1')['doh']
                self.assertEqual(row['status'], expected)
                request, headers, body, source = received[0]
                self.assertEqual(request, b'POST /dns-query HTTP/1.1\r\n')
                self.assertEqual(headers[b'content-type'], b'application/dns-message')
                self.assertEqual(body, b'\x00\x00\x01\x00\x00\x01' + bytes(6) + QUESTION)
                self.assertEqual(source, '127.0.0.1')
                self.assertEqual(row['http_status'], 200)
                self.assertNotIn('/dns-query', repr(row))

    def test_redirect_is_reported_without_following(self):
        def respond(conn, _body, _stop):
            conn.sendall(http_response('302 Found', 'Location: https://127.0.0.1:1/other\r\nContent-Length: 0'))

        with http_server(respond) as (base, received):
            row = field_path.path_checks(download=base + '/initial', authorized=True)['download']
        self.assertEqual(row['status'], 'redirect')
        self.assertEqual(row['http_status'], 302)
        self.assertEqual(len(received), 1)
        self.assertNotIn('/other', repr(row))

    def test_download_requests_and_checks_partial_content(self):
        for range_header, status in (('bytes 0-4/2097152', 'ok'), ('bytes 2-6/2097152', 'invalid_response')):
            def respond(conn, _body, _stop, range_header=range_header):
                conn.sendall(http_response('206 Partial Content',
                                           f'Content-Range: {range_header}\r\nContent-Length: 5', b'abcde'))

            with self.subTest(range_header=range_header), http_server(respond) as (base, received):
                row = field_path.path_checks(download=base + '/sample', authorized=True)['download']
            self.assertEqual(row['status'], status)
            self.assertEqual(received[0][1][b'range'], b'bytes=0-1048575')
            if status == 'ok':
                self.assertEqual(row['bytes'], 5)
                self.assertIn('download-sample-capped', row['gaps'])

    def test_download_binds_requested_loopback_source(self):
        with socket.socket() as check:
            try:
                check.bind(('127.0.0.2', 0))
            except OSError as error:
                self.skipTest(f'Alternate loopback source unavailable ({error.errno})')

        def respond(conn, _body, _stop):
            conn.sendall(http_response('200 OK', 'Content-Length: 1', b'x'))

        with http_server(respond) as (base, received):
            row = field_path.path_checks(download=base + '/sample', source='127.0.0.2', authorized=True)['download']
        self.assertEqual(row['status'], 'ok')
        self.assertEqual(received[0][3], '127.0.0.2')
        self.assertNotIn('127.0.0.2', repr(row))

    def test_download_sample_is_capped_and_counted_without_content(self):
        def respond(conn, _body, _stop):
            conn.sendall(http_response('200 OK', 'Content-Length: 2097152', b'x' * 2097152))

        with http_server(respond) as (base, received):
            row = field_path.path_checks(download=base + '/sample', authorized=True)['download']
        self.assertEqual(received[0][0], b'GET /sample HTTP/1.1\r\n')
        self.assertEqual(row['status'], 'ok')
        self.assertEqual(row['bytes'], 1048576)
        self.assertGreater(row['mbps'], 0)
        self.assertIn('download-sample-capped', row['gaps'])
        self.assertNotIn('xxxx', repr(row))

    def test_download_rate_works_with_coarse_deadline_clock(self):
        def respond(conn, _body, _stop):
            conn.sendall(http_response('200 OK', 'Content-Length: 1', b'x'))

        with http_server(respond) as (base, _):
            now = time.monotonic()
            coarse_clock = SimpleNamespace(monotonic=lambda: now, perf_counter=time.perf_counter)
            with patch.object(field_path, 'time', coarse_clock):
                row = field_path.path_checks(download=base + '/sample', authorized=True)['download']
        self.assertEqual(row['status'], 'ok')
        self.assertGreater(row['ms'], 0)
        self.assertGreater(row['mbps'], 0)

    def test_download_wall_clock_bound_even_with_continuous_data(self):
        def respond(conn, _body, stopped):
            conn.sendall(http_response('200 OK', 'Content-Length: 1024'))
            while not stopped.wait(.02):
                conn.sendall(b'x')

        with http_server(respond) as (base, _):
            started = time.monotonic()
            row = field_path.path_checks(download=base + '/sample', timeout=.2, authorized=True)['download']
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, .6)
        self.assertEqual(row['status'], 'timeout')
        self.assertGreater(row['bytes'], 0)
        self.assertIsNone(row['mbps'])

    def test_download_decodes_chunk_framing_without_counting_it(self):
        def respond(conn, _body, _stop):
            conn.sendall(http_response('200 OK', 'Transfer-Encoding: chunked', b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n'))

        with http_server(respond) as (base, _):
            row = field_path.path_checks(download=base + '/sample', authorized=True)['download']
        self.assertEqual(row['status'], 'ok')
        self.assertEqual(row['bytes'], 5)


if __name__ == '__main__':
    unittest.main()
