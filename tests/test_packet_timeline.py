import ipaddress
import json
import struct
import unittest

from test_packets import block, ethernet, ipv4, ipv6, pcap, pcapng
from wifiscope.case_validation import validate_report
from wifiscope.investigate import merge_reports
from wifiscope.packets import analyze_capture
from wifiscope.reports import prepare_export


CLIENT = '192.0.2.1'
SERVER = '192.0.2.2'


def timed_pcap(frames, starting_us=100000, step_us=10000):
    headers = []
    for index, frame in enumerate(frames):
        micros = starting_us + index * step_us
        headers.append(struct.pack('<IIII', 1700000000 + micros // 1000000,
                                   micros % 1000000, len(frame), len(frame)) + frame)
    return pcap([]) + b''.join(headers)


def udp(payload, sport, dport, src=CLIENT, dst=SERVER):
    return ethernet(ipv4(struct.pack('!4H', sport, dport, len(payload) + 8, 0) + payload, 17, src=src, dst=dst))


def tcp_segment(seq, ack, flags, payload=b'', reverse=False, port=443, fragment=0):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    sport, dport = (port, 12345) if reverse else (12345, port)
    head = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 80, flags, 8192, 0, 0)
    return ethernet(ipv4(head + payload, fragment=fragment, src=src, dst=dst))


def echo(kind, identification=7, *, reverse=False, v6=False, data=b'fixture'):
    payload = struct.pack('!BB3H', kind, 0, 0, identification, 42) + data
    if v6:
        packet = ipv6(payload, 58)
        if reverse:
            packet = packet[:8] + packet[24:40] + packet[8:24] + packet[40:]
        return ethernet(packet, 0x86dd)
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    return ethernet(ipv4(payload, 1, src=src, dst=dst))


def arp(request=True):
    smac = bytes.fromhex('001122334455' if request else '66778899aabb')
    tmac = b'\0' * 6 if request else bytes.fromhex('001122334455')
    src, dst = (CLIENT, SERVER) if request else (SERVER, CLIENT)
    packet = struct.pack('!HHBBH', 1, 0x800, 6, 4, 1 if request else 2)
    return ethernet(packet + smac + ipaddress.ip_address(src).packed + tmac + ipaddress.ip_address(dst).packed, 0x806)


def dns(flags, qtype=28, name=b'PRIVATE-DNS', transaction=0x1256):
    return (struct.pack('!6H', transaction, flags, 1, 0, 0, 0)
            + bytes([len(name)]) + name + b'\x07example\0' + struct.pack('!HH', qtype, 1))


def dhcp(message, xid=12, server=None, reported_ip=SERVER, address=None):
    reply = message in (2, 5, 6)
    body = bytearray(240)
    body[:8] = struct.pack('!BBBBI', 2 if reply else 1, 1, 6, 0, xid)
    if reply and address is not None:
        body[16:20] = ipaddress.ip_address(address).packed
    body[28:34] = bytes.fromhex('665544332211')
    body[236:240] = bytes.fromhex('63825363')
    options = bytes([53, 1, message, 12, 12]) + b'PRIVATE-DHCP'
    if server is not None:
        options += b'\x36\x04' + ipaddress.ip_address(server).packed
    if not reply and address is not None:
        options += b'\x32\x04' + ipaddress.ip_address(address).packed
    source, target = (67, 68) if reply else (68, 67)
    return udp(bytes(body) + options + b'\xff', source, target,
               reported_ip if reply else '0.0.0.0', '255.255.255.255')


def tls_record(kind, content):
    return struct.pack('!BHH', kind, 0x0303, len(content)) + content


def tls_hello(kind):
    common = bytes.fromhex('0303') + bytes(range(32)) + b'\x00'
    if kind == 1:
        name = b'private-sni.example'
        sni = struct.pack('!HBH', len(name) + 3, 0, len(name)) + name
        extension = struct.pack('!HH', 0, len(sni)) + sni
        hello = common + bytes.fromhex('000213010100') + struct.pack('!H', len(extension)) + extension
    else:
        hello = common + bytes.fromhex('130100')
    return tls_record(22, bytes([kind]) + len(hello).to_bytes(3, 'big') + hello)


def timeline(frames):
    return analyze_capture(timed_pcap(frames))['packet_analysis'].get('protocol_timeline', {})


class PacketTimelineTests(unittest.TestCase):
    def test_arp_and_echo_group_reverse_directions_with_visible_rtt(self):
        result = timeline([arp(), arp(False), echo(8), echo(0, reverse=True, data=b'other'),
                           echo(0, reverse=True), echo(128, v6=True), echo(129, reverse=True, v6=True)])
        events = result.get('events', [])
        self.assertEqual([event['event_type'] for event in events],
                         ['arp-request', 'arp-reply', 'echo-request', 'echo-reply',
                          'echo-reply', 'echo-request', 'echo-reply'])
        self.assertEqual([event['packet_number'] for event in events], list(range(1, 8)))
        self.assertEqual(events[0]['exchange_id'], events[1]['exchange_id'])
        self.assertIsNotNone(events[0]['exchange_id'])
        self.assertIsNone(events[3]['exchange_id'])
        self.assertIsNone(events[3].get('rtt_ms'))
        self.assertEqual(events[2]['exchange_id'], events[4]['exchange_id'])
        self.assertEqual(events[4]['rtt_ms'], 20.0)
        self.assertEqual(events[5]['exchange_id'], events[6]['exchange_id'])
        self.assertEqual(events[6]['rtt_ms'], 10.0)
        self.assertEqual({event['protocol'] for event in events}, {'arp', 'icmp', 'icmpv6'})

    def test_tcp_requires_all_three_sequence_valid_steps(self):
        result = timeline([tcp_segment(4294967295, 0, 2), tcp_segment(4294967295, 0, 2),
                           tcp_segment(40, 1, 18, reverse=True), tcp_segment(40, 0, 18, reverse=True),
                           tcp_segment(0, 42, 16), tcp_segment(0, 41, 16), tcp_segment(0, 41, 16),
                           tcp_segment(3, 0, 2), tcp_segment(3, 0, 2)])
        events = result.get('events', [])
        self.assertEqual([event['event_type'] for event in events],
                         ['tcp-syn', 'tcp-syn-retransmission', 'tcp-syn-ack', 'tcp-syn-ack',
                          'tcp-handshake-complete', 'tcp-syn', 'tcp-syn-retransmission'])
        self.assertIsNone(events[2]['exchange_id'])
        self.assertEqual(events[0]['exchange_id'], events[4]['exchange_id'])
        self.assertEqual(events[1]['exchange_id'], events[4]['exchange_id'])
        self.assertNotEqual(events[4]['exchange_id'], events[5]['exchange_id'])
        self.assertEqual(events[4]['packet_number'], 6)

    def test_dhcp_dora_uses_the_client_and_transaction(self):
        events = timeline([dhcp(1), dhcp(2), dhcp(3), dhcp(5, xid=13), dhcp(5)]).get('events', [])
        self.assertEqual([event['event_type'] for event in events],
                         ['dhcp-discover', 'dhcp-offer', 'dhcp-request', 'dhcp-ack', 'dhcp-ack'])
        self.assertEqual(len({events[i]['exchange_id'] for i in (0, 1, 2, 4)}), 1)
        self.assertIsNotNone(events[4]['exchange_id'])
        self.assertIsNone(events[3]['exchange_id'])
        self.assertNotIn('PRIVATE-DHCP', json.dumps(events))

    def test_dhcp_ack_from_a_different_server_does_not_complete_the_requested_offer(self):
        assigned = '192.0.2.12'
        wrong_server = '192.0.2.3'
        result = timeline([dhcp(1), dhcp(2, server=SERVER, address=assigned),
                           dhcp(3, server=SERVER, address=assigned),
                           dhcp(5, server=wrong_server, reported_ip=wrong_server, address=assigned),
                           dhcp(5, reported_ip=SERVER, address=assigned)])
        events = result['events']
        self.assertIsNone(events[3]['exchange_id'])
        self.assertEqual(events[0]['exchange_id'], events[4]['exchange_id'])

    def test_dns_matches_question_and_transaction_and_exports_only_allowed_fields(self):
        query = udp(dns(0x0100), 12345, 53)
        wrong_response = udp(dns(0x8183, name=b'DIFFERENT-DNS'), 53, 12345, SERVER, CLIENT)
        response = udp(dns(0x8383, name=b'private-dns'), 53, 12345, SERVER, CLIENT)
        raw = analyze_capture(timed_pcap([query, wrong_response, response]))
        report = merge_reports([raw, raw])
        prepared = prepare_export(report)
        events = prepared['packet_analysis'].get('protocol_timeline', {}).get('events', [])
        self.assertEqual([(e['event_type'], e['dns_type']) for e in events],
                         [('dns-query', 28), ('dns-response', 28), ('dns-response', 28)])
        self.assertEqual(events[2]['dns_rcode'], 3)
        self.assertTrue(events[2]['dns_truncated'])
        self.assertIsNone(events[1]['exchange_id'])
        self.assertEqual(events[0]['exchange_id'], events[2]['exchange_id'])
        self.assertTrue(events[0]['src_address'].startswith('id-'))
        self.assertEqual(events[0]['src_address'], events[2]['dst_address'])
        for value in ('PRIVATE-DNS', 'private-dns', 'DIFFERENT-DNS', CLIENT, SERVER):
            self.assertNotIn(value, json.dumps(prepared))
        self.assertEqual(len(prepared['packet_analysis_contexts']), 1)
        self.assertIn('dns-response', validate_report(prepared))

    def test_tcp_dns_observes_only_complete_length_framed_messages(self):
        def framed(body):
            return struct.pack('!H', len(body)) + body

        query = framed(dns(0x100, qtype=1, transaction=1)) + framed(dns(0x100, qtype=15, transaction=2))
        response = framed(dns(0x8000, qtype=1, transaction=1)) + framed(dns(0x8002, qtype=15, transaction=2))
        events = timeline([tcp_segment(11, 1, 24, query, port=53),
                           tcp_segment(22, 11 + len(query), 24, response[:-3], True, 53)])['events']
        self.assertEqual([event['dns_type'] for event in events], [1, 15, 1])
        self.assertEqual(events[0]['exchange_id'], events[2]['exchange_id'])
        self.assertEqual(events[2]['dns_rcode'], 0)

    def test_http_and_tls_indicators_retain_no_path_headers_sni_or_record_content(self):
        request = b'GET /PRIVATE-PATH?SECRET HTTP/1.1\r\nAuthorization: PRIVATE-TOKEN\r\n'
        response = b'HTTP/1.1 204 PRIVATE-STATUS\r\n'
        application = tls_record(23, b'PRIVATE-RECORD')
        result = timeline([tcp_segment(11, 1, 24, request, port=80),
                           tcp_segment(12, 11 + len(request), 24, response, True, 80),
                           tcp_segment(100, 1, 24, tls_hello(1)),
                           tcp_segment(200, 100 + len(tls_hello(1)), 24, tls_hello(2) + application, True)])
        events = result.get('events', [])
        self.assertEqual([e['event_type'] for e in events], ['http-request', 'http-response',
                         'tls-client-hello', 'tls-server-hello', 'tls-application-data'])
        self.assertEqual(events[0]['http_method'], 'GET')
        self.assertEqual(events[1]['status_code'], 204)
        self.assertEqual(events[0]['exchange_id'], events[1]['exchange_id'])
        self.assertEqual(events[2]['exchange_id'], events[4]['exchange_id'])
        for value in ('PRIVATE-PATH', 'SECRET', 'PRIVATE-TOKEN', 'PRIVATE-STATUS', 'private-sni', 'PRIVATE-RECORD'):
            self.assertNotIn(value, json.dumps(result))

    def test_http_pipeline_overflow_cannot_shift_later_response_pairing(self):
        first_seq = 11
        request = b'GET /a HTTP/1.1\r\n'
        response = b'HTTP/1.1 204\r\n'
        requests = [tcp_segment(first_seq + index * len(request), 1, 24, request, port=80)
                    for index in range(18)]
        events = timeline(requests + [
            tcp_segment(22, first_seq + 18 * len(request), 24, response, True, 80)])['events']
        self.assertEqual(events[-1]['event_type'], 'http-response')
        self.assertIsNone(events[-1]['exchange_id'])

    def test_separate_capture_interfaces_sections_and_vlans_do_not_pair(self):
        request, response = echo(8), echo(0, reverse=True)

        def enhanced(frame, interface=0):
            return block(6, struct.pack('<IIIII', interface, 0, 1000000, len(frame), len(frame)) + frame)

        separate_sections = pcapng([request]) + pcapng([response])
        different_interfaces = pcapng([]) + block(1, struct.pack('<HHI', 1, 0, 65535))
        different_interfaces += enhanced(request) + enhanced(response, 1)
        # The same tag on both packets would be one scope. Alter only the VID here.
        vlan_request = ethernet(request[14:], vlan=1)
        vlan_response = ethernet(response[14:], vlan=1)
        vlan_response = vlan_response[:14] + b'\x00\x02' + vlan_response[16:]
        for raw in (separate_sections, different_interfaces, timed_pcap([vlan_request, vlan_response])):
            with self.subTest(size=len(raw)):
                events = analyze_capture(raw)['packet_analysis'].get('protocol_timeline', {}).get('events', [])
                self.assertEqual(len(events), 2)
                self.assertIsNone(events[1]['exchange_id'])
                self.assertIsNone(events[1].get('rtt_ms'))

    def test_truncated_and_fragmented_protocol_units_do_not_create_false_evidence(self):
        request = b'GET /x HTTP/1.1\r\n'
        frames = [tcp_segment(100, 1, 24, request, fragment=0x2000),
                  tcp_segment(100, 1, 24, tls_hello(1)[:-6]),
                  tcp_segment(101, 2, 2)[:-6],
                  udp(dns(0x0000)[:-2], 12345, 53),
                  echo(8), echo(0, reverse=True)[:-1]]
        result = timeline(frames)
        self.assertTrue(result.get('partial'))
        self.assertEqual([e['event_type'] for e in result.get('events', [])], ['echo-request'])

    def test_undated_echoes_can_pair_without_rtt(self):
        raw = pcapng([echo(8), echo(0, reverse=True)], simple=True)
        events = analyze_capture(raw)['packet_analysis'].get('protocol_timeline', {}).get('events', [])
        self.assertEqual(len(events), 2)
        self.assertIsNotNone(events[1]['exchange_id'])
        self.assertIsNone(events[1]['observed_at'])
        self.assertIsNone(events[1].get('rtt_ms'))

    def test_event_limit_preserves_all_packet_counts(self):
        raw = analyze_capture(timed_pcap([echo(8, n) for n in range(1300)]))
        analysis = raw['packet_analysis']
        events = analysis.get('protocol_timeline', {})
        self.assertEqual(analysis['packets'], 1300)
        self.assertTrue(0 < len(events.get('events', [])) < 1300)
        self.assertEqual(events['dropped_events'], 1300 - len(events['events']))
        self.assertIn('packet-timeline-limit', raw['gaps'])
        self.assertTrue(events['partial'])
