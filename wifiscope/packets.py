"""Conservative Ethernet/IP metadata analysis; no payload retention or IO."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
import struct

from .capture_formats import records

CAPS = {'endpoints': 8192, 'conversations': 16384, 'arp_bindings': 8192, 'observations': 1024}
LIMITATIONS = {'packet-timing-limited', 'packet-offload-unknown', 'packet-checksums-unverified',
               'packet-retransmission-unknown', 'packet-scope-unknown'}
HTTP_REQUEST = re.compile(rb'^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [\x21-\x7e]{1,8192} HTTP/1\.[01]\r\n')


def analyze_capture(data: bytes) -> dict:
    """Analyze <=16 MiB/100000 packets, raising ValueError on invalid framing.

    Incomplete frames and unsupported protocols yield partial metadata and typed
    gaps. Packet timestamps are original evidence; import time is separate.
    """
    gaps = set()
    summary = dict(packets=0, captured_bytes=0, protocol_counts={}, endpoints=[], conversations=[],
        tcp_syn_packets=0, tcp_reset_packets=0, dns_queries=0, dns_nxdomain=0,
        plaintext_http_packets=0, arp_bindings=[], observations=[])
    protocols, endpoints, conversations, bindings, conflicts = Counter(), {}, {}, {}, set()
    first_time = None
    unknown_time = False

    def bounded(mapping, key, field, value):
        if key not in mapping:
            if len(mapping) >= CAPS[field]:
                raise ValueError('Capture exceeds ' + field + ' aggregate limit.')
            mapping[key] = value
        return mapping[key]

    def endpoint(address, size):
        row = bounded(endpoints, address, 'endpoints', dict(address=address, packets=0, bytes=0))
        row['packets'] += 1
        row['bytes'] += size

    def transport(payload, proto, src, dst, size, fragmented):
        protocol = {6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6'}.get(proto)
        if protocol is None:
            gaps.add('packet-transport-unsupported')
            return
        protocols[protocol] += 1
        sport = dport = None
        if proto == 6:
            if len(payload) < 20:
                gaps.add('packet-truncated')
            else:
                header = (payload[12] >> 4) * 4
                if header < 20:
                    gaps.add('packet-invalid-length')
                elif header > len(payload):
                    gaps.add('packet-truncated')
                else:
                    sport, dport = struct.unpack_from('!HH', payload)
                    summary['tcp_syn_packets'] += bool(payload[13] & 2)
                    summary['tcp_reset_packets'] += bool(payload[13] & 4)
                    if not fragmented and HTTP_REQUEST.match(payload[header:]):
                        summary['plaintext_http_packets'] += 1
        elif proto == 17:
            if len(payload) < 8:
                gaps.add('packet-truncated')
            else:
                length = struct.unpack_from('!H', payload, 4)[0]
                if length < 8:
                    gaps.add('packet-invalid-length')
                elif length > len(payload):
                    gaps.add('packet-truncated')
                else:
                    sport, dport = struct.unpack_from('!HH', payload)
                    if not fragmented and 53 in (sport, dport) and length >= 20:
                        flags = struct.unpack_from('!H', payload, 10)[0]
                        # Only standard opcode=0 messages; never retain names/answers.
                        if flags & 0x7800 == 0:
                            summary['dns_queries'] += not bool(flags & 0x8000)
                            summary['dns_nxdomain'] += bool(flags & 0x8000) and flags & 15 == 3
        key = (src, dst, sport, dport, protocol)
        row = bounded(conversations, key, 'conversations', dict(src_address=src, dst_address=dst,
            src_port=sport, dst_port=dport, protocol=protocol, packets=0, bytes=0))
        row['packets'] += 1
        row['bytes'] += size

    for link, frame, observed in records(data, gaps):
        summary['packets'] += 1
        summary['captured_bytes'] += len(frame)
        if observed is None:
            unknown_time = True
        elif first_time is None or observed < first_time:
            first_time = observed
        if link != 1:
            gaps.add('packet-linktype-unsupported')
            continue
        if len(frame) < 14:
            gaps.add('packet-truncated')
            continue
        kind = struct.unpack_from('!H', frame, 12)[0]
        start, vlans = 14, 0
        while kind in (0x8100, 0x88a8, 0x9100):
            vlans += 1
            if vlans > 4:
                gaps.add('packet-vlan-limit')
                break
            if len(frame) < start + 4:
                gaps.add('packet-truncated')
                break
            kind = struct.unpack_from('!H', frame, start + 2)[0]
            start += 4
        else:
            payload = frame[start:]
            if kind == 0x806:
                protocols['arp'] += 1
                if len(payload) < 28:
                    gaps.add('packet-truncated')
                    continue
                if struct.unpack_from('!HHBB', payload) != (1, 0x800, 6, 4) or struct.unpack_from('!H', payload, 6)[0] not in (1, 2):
                    gaps.add('packet-arp-unsupported')
                    continue
                address = str(ipaddress.ip_address(bytes(payload[14:18])))
                mac = ':'.join(f'{b:02x}' for b in payload[8:14])
                if address != '0.0.0.0':
                    bounded(bindings, (address, mac), 'arp_bindings', dict(address=address, mac=mac))
                    conflicts.add(address)
                continue
            if kind == 0x800:
                protocols['ipv4'] += 1
                if len(payload) < 20:
                    gaps.add('packet-truncated')
                    continue
                header = (payload[0] & 15) * 4
                total = struct.unpack_from('!H', payload, 2)[0]
                if payload[0] >> 4 != 4 or header < 20 or total < header:
                    gaps.add('packet-invalid-length')
                    continue
                if len(payload) < total:
                    gaps.add('packet-truncated')
                if len(payload) < header:
                    continue
                src, dst = [str(ipaddress.ip_address(bytes(payload[n:n + 4]))) for n in (12, 16)]
                proto, body = payload[9], payload[header:min(total, len(payload))]
                fragment = struct.unpack_from('!H', payload, 6)[0]
                fragmented, nonfirst = bool(fragment & 0x3fff), bool(fragment & 0x1fff)
            elif kind == 0x86dd:
                protocols['ipv6'] += 1
                if len(payload) < 40:
                    gaps.add('packet-truncated')
                    continue
                total = 40 + struct.unpack_from('!H', payload, 4)[0]
                if payload[0] >> 4 != 6 or total == 40:
                    gaps.add('packet-ipv6-unsupported')
                    continue
                if len(payload) < total:
                    gaps.add('packet-truncated')
                src, dst = [str(ipaddress.ip_address(bytes(payload[n:n + 16]))) for n in (8, 24)]
                proto, pos, walked, steps = payload[6], 40, 0, 0
                fragmented = nonfirst = False
                payload = payload[:total]
                while proto in (0, 43, 44, 51, 60):
                    steps += 1
                    if steps > 16 or walked >= 2048:
                        gaps.add('packet-ipv6-extension-limit')
                        break
                    if len(payload) < pos + 2:
                        gaps.add('packet-truncated')
                        break
                    length = 8 if proto == 44 else (payload[pos + 1] + 2) * 4 if proto == 51 else (payload[pos + 1] + 1) * 8
                    if proto == 51 and length < 12:
                        gaps.add('packet-invalid-length')
                        break
                    if walked + length > 2048:
                        gaps.add('packet-ipv6-extension-limit')
                        break
                    if len(payload) < pos + length:
                        gaps.add('packet-truncated')
                        break
                    if proto == 44:
                        fragmented = True
                        nonfirst = bool(struct.unpack_from('!H', payload, pos + 2)[0] & 0xfff8)
                    proto, pos, walked = payload[pos], pos + length, walked + length
                    if nonfirst:
                        break
                else:
                    pass
                if proto in (0, 43, 44, 51, 60) and not nonfirst:
                    continue
                body = payload[pos:]
            else:
                gaps.add('packet-network-unsupported')
                continue
            for address in (src, dst):
                endpoint(address, len(frame))
            if fragmented:
                gaps.add('packet-fragment')
            if not nonfirst:
                transport(body, proto, src, dst, len(frame), fragmented)
    by_address = Counter(address for address, _ in bindings)
    for address in sorted(conflicts):
        if by_address[address] > 1:
            if len(summary['observations']) >= CAPS['observations']:
                raise ValueError('Capture exceeds observations aggregate limit.')
            summary['observations'].append(dict(code='arp-conflict', address=address, status='needs-review'))
    if unknown_time:
        gaps.add('packet-time-unknown')
    summary.update(protocol_counts=dict(protocols), endpoints=list(endpoints.values()),
        conversations=list(conversations.values()), arp_bindings=list(bindings.values()), partial=bool(gaps))
    gaps.update(LIMITATIONS)
    source_hash = hashlib.sha256(data).hexdigest()
    summary.update(source_sha256=source_hash, observed_at=None if unknown_time else first_time, source='packets')
    summary['limits'] = dict(max_input_bytes=16 * 1024 * 1024, max_packets=100000, max_endpoints=8192,
        max_conversations=16384, max_arp_bindings=8192, max_observations=1024, max_vlan_tags=4,
        max_ipv6_extension_headers=16, max_ipv6_extension_bytes=2048)
    summary['input_bytes'] = len(data)
    return dict(schema_version=1, packet_analysis=summary, sources=[dict(type='pcapng' if data[:4] == b'\x0a\x0d\x0d\x0a' else 'pcap',
        sha256=source_hash, imported_at=datetime.now(timezone.utc).isoformat(), observed_at=summary['observed_at'],
        coverage=dict(planned=None, attempted=None, evaluated=summary['packets'], count_unit='packets', partial=True))], gaps=sorted(gaps))
