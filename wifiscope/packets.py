"""Conservative Ethernet/IP metadata analysis; no payload retention or IO."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import struct

from .capture_formats import records
from .packet_timeline import HTTP_REQUEST, MAX_EVENTS, MAX_TRACKED, MAX_AGE_SECONDS, MAX_PACKET_DISTANCE, PacketTimeline

CAPS = {'endpoints': 8192, 'conversations': 16384, 'arp_bindings': 8192, 'observations': 1024}
LIMITATIONS = {'packet-timing-limited', 'packet-offload-unknown', 'packet-checksums-unverified',
               'packet-retransmission-unknown', 'packet-scope-unknown'}


def analyze_capture(data: bytes) -> dict:
    """Analyze <=16 MiB/100000 packets, raising ValueError on invalid framing.

    Incomplete frames and unsupported protocols yield partial metadata and typed
    gaps. Packet timestamps are original evidence; import time is separate.
    """
    gaps = set()
    timeline = PacketTimeline(gaps)
    summary = dict(packets=0, captured_bytes=0, wire_bytes=0, protocol_counts={}, endpoints=[], conversations=[],
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

    def transport(payload, proto, src, dst, size, ip_version, fragmented, complete):
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
                    if complete:
                        timeline.tcp((src, dst, sport, dport), payload, header)
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
                    if complete:
                        timeline.udp(ip_version, (src, dst, sport, dport), payload[8:length])
        elif complete and (ip_version, proto) in ((4, 1), (6, 58)):
            timeline.echo(ip_version, src, dst, payload)
        key = (src, dst, sport, dport, protocol)
        row = bounded(conversations, key, 'conversations', dict(src_address=src, dst_address=dst,
            src_port=sport, dst_port=dport, protocol=protocol, packets=0, bytes=0))
        row['packets'] += 1
        row['bytes'] += size

    for link, frame, observed, original, scope in records(data, gaps, include_scope=True):
        summary['packets'] += 1
        summary['captured_bytes'] += len(frame)
        summary['wire_bytes'] += original
        if observed is None:
            unknown_time = True
        elif first_time is None or observed < first_time:
            first_time = observed
        if link not in (0, 1, 101, 113, 276):
            gaps.add('packet-linktype-unsupported')
            continue
        minimum = {0: 4, 1: 14, 101: 1, 113: 16, 276: 20}[link]
        if len(frame) < minimum:
            gaps.add('packet-truncated')
            continue
        if link == 1:
            kind, start = struct.unpack_from('!H', frame, 12)[0], 14
        elif link == 0:
            # DLT_NULL family is the capturing host's byte order. Accept both
            # byte orders and documented BSD/Linux IPv6 family values.
            families = (struct.unpack_from('<I', frame)[0], struct.unpack_from('>I', frame)[0])
            kind = 0x800 if 2 in families else 0x86dd if any(f in (10, 24, 28, 30) for f in families) else 0
            start = 4
        elif link == 101:
            kind, start = {4: 0x800, 6: 0x86dd}.get(frame[0] >> 4, 0), 0
        elif link == 113:
            kind, start = struct.unpack_from('!H', frame, 14)[0], 16
        else:
            kind, start = struct.unpack_from('!H', frame)[0], 20
        vlans = []
        while kind in (0x8100, 0x88a8, 0x9100):
            if len(vlans) >= 4:
                gaps.add('packet-vlan-limit')
                break
            if len(frame) < start + 4:
                gaps.add('packet-truncated')
                break
            tci, inner = struct.unpack_from('!HH', frame, start)
            vlans.append((kind, tci & 0xfff))
            kind = inner
            start += 4
        else:
            payload = frame[start:]
            timeline.begin_packet(scope, tuple(vlans), summary['packets'], observed)
            if kind == 0x806:
                protocols['arp'] += 1
                if len(payload) < 28:
                    gaps.add('packet-truncated')
                    continue
                hardware, network, mac_size, ip_size, operation = struct.unpack_from('!HHBBH', payload)
                if (hardware, network, mac_size, ip_size) != (1, 0x800, 6, 4) or operation not in (1, 2):
                    gaps.add('packet-arp-unsupported')
                    continue
                address = str(ipaddress.ip_address(bytes(payload[14:18])))
                mac = ':'.join(f'{b:02x}' for b in payload[8:14])
                if address != '0.0.0.0':
                    bounded(bindings, (address, mac), 'arp_bindings', dict(address=address, mac=mac))
                    conflicts.add(address)
                if len(frame) == original:
                    target = str(ipaddress.ip_address(bytes(payload[24:28])))
                    timeline.arp(operation, address, target, payload)
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
                ip_version = 4
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
                ip_version = 6
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
                complete = not fragmented and len(frame) == original and total <= len(payload)
                transport(body, proto, src, dst, len(frame), ip_version, fragmented, complete)
    by_address = Counter(address for address, _ in bindings)
    for address in sorted(conflicts):
        if by_address[address] > 1:
            if len(summary['observations']) >= CAPS['observations']:
                raise ValueError('Capture exceeds observations aggregate limit.')
            summary['observations'].append(dict(code='arp-conflict', address=address, status='needs-review'))
    if unknown_time:
        gaps.add('packet-time-unknown')
    summary.update(protocol_counts=dict(protocols), endpoints=list(endpoints.values()),
        conversations=list(conversations.values()), arp_bindings=list(bindings.values()), partial=bool(gaps),
        protocol_timeline=timeline.result())
    gaps.update(LIMITATIONS)
    source_hash = hashlib.sha256(data).hexdigest()
    summary.update(source_sha256=source_hash, observed_at=None if unknown_time else first_time, source='packets')
    summary['limits'] = dict(max_input_bytes=16 * 1024 * 1024, max_packets=100000, max_endpoints=8192,
        max_conversations=16384, max_arp_bindings=8192, max_observations=1024, max_vlan_tags=4,
        max_ipv6_extension_headers=16, max_ipv6_extension_bytes=2048, max_timeline_events=MAX_EVENTS,
        max_timeline_tracked=MAX_TRACKED, max_timeline_age_seconds=MAX_AGE_SECONDS,
        max_timeline_distance_packets=MAX_PACKET_DISTANCE)
    summary['input_bytes'] = len(data)
    return dict(schema_version=1, packet_analysis=summary, sources=[dict(type='pcapng' if data[:4] == b'\x0a\x0d\x0d\x0a' else 'pcap',
        sha256=source_hash, imported_at=datetime.now(timezone.utc).isoformat(), observed_at=summary['observed_at'],
        coverage=dict(planned=None, attempted=None, evaluated=summary['packets'], count_unit='packets', partial=True))], gaps=sorted(gaps))
