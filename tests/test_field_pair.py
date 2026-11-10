import contextlib
import queue
import re
import socket
import threading
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from wifiscope import field_pair

LOOPBACK = '127.0.0.1'
CODE = 'ca' * 16


@contextlib.contextmanager
def running_peer(address=LOOPBACK, expected_peer=LOOPBACK, seconds=2):
    ready = queue.Queue()
    result = queue.Queue()
    cancel = threading.Event()

    def run():
        result.put(field_pair.serve_peer(address, expected_peer, authorized=True,
                                         seconds=seconds, ready=ready.put, cancel=cancel))

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        yield ready.get(timeout=2), result, cancel
    finally:
        cancel.set()
        worker.join(timeout=2)


@contextlib.contextmanager
def other_service(challenge, respond):
    with socket.socket() as listener:
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        listener.settimeout(2)
        received = queue.Queue()
        release = threading.Event()

        def run():
            with listener.accept()[0] as conn:
                conn.settimeout(2)
                conn.sendall(challenge)
                request = bytearray()
                while chunk := conn.recv(128):
                    request.extend(chunk)
                received.put(bytes(request))
                respond(conn, bytes(request), release)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1], received
        finally:
            release.set()
            worker.join(timeout=2)


class FieldPairTests(unittest.TestCase):
    def assert_result(self, result, status, port):
        self.assertEqual(set(result), {'status', 'port', 'timestamp'})
        self.assertEqual(result['status'], status)
        self.assertIs(type(result['port']), int)
        self.assertEqual(result['port'], port)
        self.assertEqual(datetime.fromisoformat(result['timestamp']).utcoffset(), timedelta(0))

    def test_loopback_handshake_reports_only_durable_fields(self):
        with running_peer() as (setup, server_result, _):
            self.assertEqual(set(setup), {'address', 'port', 'code'})
            self.assertEqual(setup['address'], LOOPBACK)
            self.assertIsNotNone(re.fullmatch('[0-9a-f]{32}', setup['code']))
            self.assertGreater(setup['port'], 0)
            client = field_pair.check_peer(LOOPBACK, setup['port'], setup['code'],
                                           source=LOOPBACK, authorized=True)
            self.assert_result(client, 'handshake_verified', setup['port'])
            self.assert_result(server_result.get(timeout=1), 'handshake_verified', setup['port'])

    @unittest.skipUnless(socket.has_ipv6, 'IPv6 sockets unavailable')
    def test_ipv6_loopback_handshake(self):
        with socket.socket(socket.AF_INET6) as probe:
            try:
                probe.bind(('::1', 0))
            except OSError:
                self.skipTest('IPv6 loopback unavailable')
        with running_peer(address='::1', expected_peer='::1') as (setup, server_result, _):
            client = field_pair.check_peer('::1', setup['port'], setup['code'], source='::1', authorized=True)
            self.assert_result(client, 'handshake_verified', setup['port'])
            self.assert_result(server_result.get(timeout=1), 'handshake_verified', setup['port'])

    def test_wrong_code_does_not_end_listener(self):
        with running_peer(seconds=.8) as (setup, server_result, _):
            wrong_code = '00' * 16 if setup['code'] != '00' * 16 else '11' * 16
            client = field_pair.check_peer(LOOPBACK, setup['port'], wrong_code, authorized=True)
            self.assert_result(client, 'handshake_mismatch', setup['port'])
            self.assert_result(server_result.get(timeout=2), 'listener_timeout', setup['port'])

    def test_correct_code_from_unexpected_source_is_ignored(self):
        with running_peer(expected_peer='127.0.0.2', seconds=.8) as (setup, server_result, _):
            client = field_pair.check_peer(LOOPBACK, setup['port'], setup['code'],
                                           source=LOOPBACK, authorized=True)
            self.assert_result(client, 'handshake_mismatch', setup['port'])
            self.assert_result(server_result.get(timeout=2), 'listener_timeout', setup['port'])

    def test_echo_service_does_not_prove_the_peer_handshake(self):
        challenge = b'WSP1?' + b'a' * 16
        with other_service(challenge, lambda conn, request, _: conn.sendall(request)) as (port, received):
            client = field_pair.check_peer(LOOPBACK, port, CODE, authorized=True)
            self.assert_result(client, 'handshake_mismatch', port)
            request = received.get(timeout=1)
            self.assertNotIn(CODE.encode(), request)
            self.assertNotIn(bytes.fromhex(CODE), request)

    def test_incomplete_response_hits_handshake_timeout(self):
        def stall(conn, _, release):
            conn.sendall(b'W')
            release.wait(2)

        with other_service(b'WSP1?' + b'a' * 16, stall) as (port, _):
            client = field_pair.check_peer(LOOPBACK, port, CODE, authorized=True, timeout=.3)
            self.assert_result(client, 'handshake_timeout', port)

    def test_bound_port_without_listener_reports_refusal(self):
        with socket.socket() as unavailable:
            unavailable.bind((LOOPBACK, 0))
            port = unavailable.getsockname()[1]
            # Winsock's loopback refusal can arrive after the default two-second observation.
            client = field_pair.check_peer(LOOPBACK, port, CODE, authorized=True, timeout=4)
            self.assert_result(client, 'connection_refused', port)

    def test_client_cancels_during_handshake(self):
        cancel = threading.Event()

        def wait_for_release(conn, _, release):
            cancel.set()
            release.wait(2)

        with other_service(b'WSP1?' + b'a' * 16, wait_for_release) as (port, _):
            client = field_pair.check_peer(LOOPBACK, port, CODE, authorized=True, cancel=cancel)
            self.assert_result(client, 'cancelled', port)

    def test_listener_cancels_after_readiness(self):
        with running_peer() as (setup, server_result, cancel):
            cancel.set()
            self.assert_result(server_result.get(timeout=1), 'cancelled', setup['port'])

    def test_pre_cancelled_operations_do_not_open_a_socket(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(socket, 'socket', side_effect=AssertionError('unexpected socket')):
            self.assert_result(field_pair.serve_peer(LOOPBACK, LOOPBACK, authorized=True,
                                                     cancel=cancel), 'cancelled', 0)
            self.assert_result(field_pair.check_peer(LOOPBACK, 10000, CODE, authorized=True,
                                                     cancel=cancel), 'cancelled', 10000)

    def test_authorization_and_validation_precede_socket_operations(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('unexpected socket')):
            with self.assertRaises(ValueError):
                field_pair.serve_peer(LOOPBACK, LOOPBACK)
            with self.assertRaises(ValueError):
                field_pair.check_peer(LOOPBACK, 10000, CODE)
            for invalid in ('0.0.0.0', '::', '224.0.0.1', 'ff02::1', '255.255.255.255',
                            'localhost', '127.0.0.1/32', '::ffff:127.0.0.1'):
                with self.subTest(address=invalid):
                    with self.assertRaises(ValueError):
                        field_pair.serve_peer(invalid, LOOPBACK, authorized=True)
                    with self.assertRaises(ValueError):
                        field_pair.check_peer(invalid, 10000, CODE, authorized=True)
            for port, code, source, timeout in ((True, CODE, None, 2), (0, CODE, None, 2),
                                                 (65536, CODE, None, 2), (10000, 'bad', None, 2),
                                                 (10000, CODE, '::1', 2),
                                                 (10000, CODE, None, float('nan'))):
                with (self.subTest(port=port, source=source, timeout=timeout),
                      self.assertRaises(ValueError)):
                    field_pair.check_peer(LOOPBACK, port, code, source=source,
                                          timeout=timeout, authorized=True)
            with self.assertRaises(ValueError):
                field_pair.serve_peer(LOOPBACK, LOOPBACK, authorized=True, seconds=301)
