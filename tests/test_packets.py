import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest

from wifiscope.packets import analyze_capture
from wifiscope.investigate import build_investigation, merge_reports
from wifiscope.reports import prepare_export, export_report
from wifiscope.demo import demo_report


def ethernet(payload, kind=0x0800, vlan=0):
    return bytes.fromhex('00112233445566778899aabb') + b'\x81\x00\x00\x01' * vlan + struct.pack('!H', kind) + payload


def tcp(payload=b'', port=80, flags=2, offset=5):
    return struct.pack('!HHIIBBHHH', 12345, port, 0, 0, offset << 4, flags, 8192, 0, 0) + payload


def ipv4(payload, proto=6, fragment=0, src='192.0.2.1', dst='192.0.2.2'):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, fragment, 64, proto, 0,
                       ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + payload


def ipv6(payload, proto=6):
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), proto, 64,
                       ipaddress.ip_address('2001:db8::1').packed, ipaddress.ip_address('2001:db8::2').packed) + payload


def udp_dns(flags=0, size=12):
    body = struct.pack('!6H', 1, flags, 1, 0, 0, 0)[:size]
    return struct.pack('!4H', 12345, 53, len(body) + 8, 0) + body


def arp(mac='66778899aabb'):
    return struct.pack('!HHBBH', 1, 0x800, 6, 4, 2) + bytes.fromhex(mac) + bytes([192, 0, 2, 1]) + b'\0' * 6 + bytes([192, 0, 2, 2])


def pcap(frames, endian='<', nano=False, link=1, snaplen=65535):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    data = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, snaplen, link)
    return data + b''.join(struct.pack(endian + 'IIII', 1700000000, 100, len(frame), len(frame)) + frame for frame in frames)


def block(kind, body, endian='<'):
    body += b'\0' * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def pcapng(frames, endian='<', simple=False, link=1):
    data = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
    data += block(1, struct.pack(endian + 'HHI', link, 0, 65535), endian)
    for frame in frames:
        body = struct.pack(endian + 'I', len(frame)) if simple else struct.pack(endian + 'IIIII', 0, 0, 1700000000, len(frame), len(frame))
        data += block(3 if simple else 6, body + frame, endian)
    return data


class PacketTests(unittest.TestCase):
    def test_single_capture_coverage_scope_remains_partial_and_demo_is_offline(self):
        report = build_investigation(analyze_capture(pcap([ethernet(ipv4(tcp()))])))
        coverage = next(row for row in report['investigation']['coverage'] if row['category'] == 'offline-packets')
        self.assertTrue(coverage['partial'])
        self.assertEqual(coverage['evaluated'], 1)
        self.assertIsNone(coverage['planned'])
        self.assertIn('packet-scope-unknown', report['gaps'])
        demo = demo_report()
        self.assertEqual(demo['packet_analysis']['plaintext_http_packets'], 1)
        self.assertTrue(next(source for source in demo['sources'] if source['type'] == 'pcap')['synthetic'])

    def test_packet_endpoints_become_candidate_assets_with_explicit_budget_error(self):
        report = build_investigation(analyze_capture(pcap([ethernet(ipv4(tcp()))])))
        self.assertEqual({asset['address'] for asset in report['investigation']['assets']}, {'192.0.2.1', '192.0.2.2'})
        self.assertTrue(all(asset['status'] == 'unknown' for asset in report['investigation']['assets']))
        frames = [ethernet(ipv4(tcp(), src=str(ipaddress.ip_address('10.0.0.1') + n))) for n in range(4096)]
        parsed = analyze_capture(pcap(frames))
        self.assertEqual(len(parsed['packet_analysis']['endpoints']), 4097)
        with self.assertRaisesRegex(ValueError, '4096 assets'):
            build_investigation(parsed)

    def test_pcapng_interface_clock_snaplen_and_multiple_interfaces(self):
        frame = ethernet(ipv4(tcp()))
        for endian in ('<', '>'):
            # Binary 2^-10 second resolution, plus a signed seconds offset.
            options = struct.pack(endian + 'HH', 9, 1) + b'\x8a\0\0\0' + struct.pack(endian + 'HHq', 14, 8, 2)
            raw = block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)
            raw += block(1, struct.pack(endian + 'HHI', 999, 0, 1), endian)
            raw += block(1, struct.pack(endian + 'HHI', 1, 0, 0) + options, endian)
            raw += block(6, struct.pack(endian + 'IIIII', 1, 0, 1024, len(frame), len(frame)) + frame, endian)
            report = analyze_capture(raw)
            self.assertEqual(report['sources'][0]['observed_at'], '1970-01-01T00:00:03+00:00')
            self.assertEqual(report['packet_analysis']['tcp_syn_packets'], 1)
        raw = bytearray(pcap([frame]))
        struct.pack_into('<I', raw, 20, 1 | (4 << 28) | (1 << 26))
        self.assertEqual(analyze_capture(bytes(raw))['packet_analysis']['tcp_syn_packets'], 1)

    def test_ng_bad_options_lengths_section_bounds_and_truncated_blocks(self):
        header = pcapng([])
        frame = ethernet(ipv4(tcp()))
        invalid = [header + block(6, struct.pack('<IIIII', 0, 0, 0, len(frame) + 100, len(frame) + 100) + frame),
                   header + block(1, struct.pack('<HHI', 1, 0, 1) + struct.pack('<HH', 9, 8)),
                   header + block(3, struct.pack('<I', 1) + b'x' * 8),
                   block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, 0)) + header[28:]]
        for raw in invalid:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                analyze_capture(raw)
        report = analyze_capture(pcapng([frame])[:-1])
        self.assertTrue(report['packet_analysis']['partial'])
        self.assertEqual(report['packet_analysis']['packets'], 0)
        self.assertIn('packet-truncated', report['gaps'])

    def test_ipv6_extension_byte_budget_and_ah_minimum_length(self):
        legal = b'\x06\xff' + b'\0' * 2046 + tcp()
        report = analyze_capture(pcap([ethernet(ipv6(legal, 0), 0x86dd)]))
        self.assertEqual(report['packet_analysis']['tcp_syn_packets'], 1)
        over = b'\x00\xff' + b'\0' * 2046 + b'\x06\x00' + b'\0' * 6 + tcp()
        report = analyze_capture(pcap([ethernet(ipv6(over, 0), 0x86dd)]))
        self.assertIn('packet-ipv6-extension-limit', report['gaps'])
        report = analyze_capture(pcap([ethernet(ipv6(b'\x06\x00' + b'\0' * 6 + tcp(), 51), 0x86dd)]))
        self.assertEqual(report['packet_analysis']['tcp_syn_packets'], 0)
        self.assertIn('packet-invalid-length', report['gaps'])

    def test_conversation_binding_and_observation_caps(self):
        frames = [ethernet(ipv4(struct.pack('!HHIIBBHHH', n, 80, 0, 0, 80, 2, 0, 0, 0))) for n in range(16385)]
        with self.assertRaisesRegex(ValueError, 'conversations'):
            analyze_capture(pcap(frames))
        frames = [ethernet(arp(f'{n:012x}'), 0x806) for n in range(8193)]
        with self.assertRaisesRegex(ValueError, 'arp_bindings'):
            analyze_capture(pcap(frames))
        frames = []
        for n in range(1025):
            for mac in ('66778899aabb', '66778899aabc'):
                payload = bytearray(arp(mac))
                payload[14:18] = ipaddress.ip_address(0x0a000001 + n).packed
                frames.append(ethernet(payload, 0x806))
        with self.assertRaisesRegex(ValueError, 'observations'):
            analyze_capture(pcap(frames))

    def test_classic_endians_timestamp_units_and_metadata_only(self):
        frame = ethernet(ipv4(tcp(b'GET /PRIVATE HTTP/1.1\r\nAuthorization: SECRET\r\n')))
        for endian in ('<', '>'):
            for nano in (False, True):
                raw = pcap([frame], endian, nano)
                report = analyze_capture(raw)
                summary = report['packet_analysis']
                self.assertEqual((summary['packets'], summary['captured_bytes'], summary['plaintext_http_packets']), (1, len(frame), 1))
                self.assertEqual(summary['tcp_syn_packets'], 1)
                self.assertEqual(summary['conversations'][0]['dst_port'], 80)
                self.assertEqual(report['sources'][0]['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertNotEqual(report['sources'][0]['observed_at'], report['sources'][0]['imported_at'])
                self.assertNotIn('PRIVATE', json.dumps(report))
                self.assertNotIn('SECRET', json.dumps(report))

    def test_pcapng_endians_sections_and_simple_packet_unknown_time(self):
        frame = ethernet(ipv4(tcp()))
        for endian in ('<', '>'):
            report = analyze_capture(pcapng([frame], endian) + pcapng([frame], '>' if endian == '<' else '<'))
            self.assertEqual(report['packet_analysis']['packets'], 2)
        report = analyze_capture(pcapng([frame], simple=True))
        self.assertIsNone(report['sources'][0]['observed_at'])

    def test_vlan_ipv6_extensions_and_arp_conflict(self):
        frames = [ethernet(ipv4(tcp(flags=4)), vlan=4), ethernet(ipv6(b'\x06\x00' + b'\0' * 6 + tcp()), 0x86dd),
                  ethernet(arp(), 0x806), ethernet(arp('66778899aabc'), 0x806)]
        summary = analyze_capture(pcap(frames))['packet_analysis']
        self.assertEqual(summary['tcp_reset_packets'], 1)
        self.assertEqual(len(summary['endpoints']), 4)
        self.assertEqual(len(summary['arp_bindings']), 2)
        self.assertEqual(summary['observations'][0]['code'], 'arp-conflict')
        self.assertIn('2001:db8::1', [e['address'] for e in summary['endpoints']])

    def test_http_requires_request_prefix_and_dns_valid_udp_header(self):
        frames = [ethernet(ipv4(tcp(b'not http', port=80))), ethernet(ipv4(tcp(b'GET /x HTTP/1.1\r\n', port=9999))),
                  ethernet(ipv4(udp_dns(), 17)), ethernet(ipv4(udp_dns(0x8003), 17)),
                  ethernet(ipv4(udp_dns(3), 17)), ethernet(ipv4(udp_dns(size=11), 17))]
        summary = analyze_capture(pcap(frames))['packet_analysis']
        self.assertEqual((summary['plaintext_http_packets'], summary['dns_queries'], summary['dns_nxdomain']), (1, 2, 1))

    def test_fragments_truncation_and_bad_lengths_are_honest(self):
        frames = [ethernet(ipv4(tcp(b'GET / HTTP/1.1\r\n'), fragment=1)),
                  ethernet(ipv6(struct.pack('!BBHI', 6, 0, 8, 1) + tcp(), 44), 0x86dd),
                  ethernet(ipv4(tcp(offset=4))), ethernet(ipv4(tcp())[:-5])]
        report = analyze_capture(pcap(frames))
        self.assertEqual(report['packet_analysis']['plaintext_http_packets'], 0)
        self.assertFalse(any(c['src_port'] for c in report['packet_analysis']['conversations']))
        self.assertTrue(report['packet_analysis']['partial'])
        self.assertIn('packet-fragment', report['gaps'])
        self.assertIn('packet-truncated', report['gaps'])
        report = analyze_capture(pcap([ethernet(ipv4(tcp()))])[:-3])
        self.assertTrue(report['packet_analysis']['partial'])

    def test_format_guards_unknown_link_and_walk_bounds(self):
        frame = ethernet(ipv4(tcp()))
        ng = pcapng([frame])
        for raw in [b'', b'nope', b'x' * (16 * 1024 * 1024 + 1), ng[:-4] + b'\0' * 4,
                    ng[:4] + b'\0' * 4 + ng[8:], pcap([frame], snaplen=1),
                    pcapng([frame])[:48] + block(6, struct.pack('<IIIII', 2, 0, 0, 0, 0))]:
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                analyze_capture(raw)
        report = analyze_capture(pcap([frame], link=999))
        self.assertEqual(report['packet_analysis']['protocol_counts'], {})
        self.assertIn('packet-linktype-unsupported', report['gaps'])
        report = analyze_capture(pcap([ethernet(ipv4(tcp()), vlan=5)]))
        self.assertIn('packet-vlan-limit', report['gaps'])
        report = analyze_capture(pcap([ethernet(ipv6((b'\x00\x00' + b'\0' * 6) * 17 + tcp(), 0), 0x86dd)]))
        self.assertIn('packet-ipv6-extension-limit', report['gaps'])

    def test_packet_and_aggregate_limits_reject_cleanly(self):
        with self.assertRaises(ValueError):
            analyze_capture(pcap([b''] * 100001))
        frames = [ethernet(ipv4(tcp(), src=str(ipaddress.ip_address('10.0.0.1') + n))) for n in range(8193)]
        with self.assertRaises(ValueError):
            analyze_capture(pcap(frames))

    def test_real_investigation_merge_privacy_and_rendering(self):
        raw = analyze_capture(pcap([ethernet(ipv4(tcp(b'GET /PRIVATE HTTP/1.1\r\n'))), ethernet(arp(), 0x806), ethernet(arp('66778899aabc'), 0x806)]))
        other = analyze_capture(pcapng([ethernet(ipv6(tcp()), 0x86dd)]))
        report = merge_reports([raw, other, raw])
        self.assertEqual(len(report['packet_analysis_contexts']), 2)
        self.assertEqual(sum(c['packets'] for c in report['packet_analysis_contexts']), 4)
        findings = report['investigation']['findings']
        self.assertEqual(next(f for f in findings if f['code'] == 'packet-http')['status'], 'observed')
        self.assertEqual(next(f for f in findings if f['code'] == 'arp-conflict')['status'], 'needs-review')
        coverage = next(c for c in report['investigation']['coverage'] if c['category'] == 'offline-packets')
        self.assertTrue(coverage['partial'])
        self.assertIsNone(coverage['planned'])
        prepared = prepare_export(report)
        text = json.dumps(prepared)
        for value in ('192.0.2.1', '192.0.2.2', '2001:db8::1', '66:77:88:99:aa:bb', 'PRIVATE'):
            self.assertNotIn(value, text)
        context = prepared['packet_analysis_contexts'][0]
        endpoint = next(e for e in context['endpoints'] if e['packets'] == 1)
        self.assertIn(endpoint['address'], [c['src_address'] for c in context['conversations']] + [c['dst_address'] for c in context['conversations']])
        self.assertEqual(context['plaintext_http_packets'], 1)
        with tempfile.TemporaryDirectory() as directory:
            files = export_report(report, Path(directory) / 'bundle')
            self.assertIn('Offline packet metadata', Path(files['html']).read_text(encoding='utf-8'))
        self.assertIn('packet_analysis', build_investigation(raw))
