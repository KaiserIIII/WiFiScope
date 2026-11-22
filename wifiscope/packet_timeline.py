"""Bounded, packet-local protocol metadata and capture-local correlation."""
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
from ipaddress import IPv4Address
import re
import struct


MAX_EVENTS = 1024
MAX_TRACKED = 2048
MAX_AGE_SECONDS = 120
MAX_PACKET_DISTANCE = 8192
MAX_FLOW_STEPS = 16
HTTP_METHODS = frozenset(('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'))
HTTP_REQUEST = re.compile(rb'^(' + b'|'.join(name.encode('ascii') for name in sorted(HTTP_METHODS))
                          + rb') [\x21-\x7e]{1,8192} HTTP/1\.[01]\r\n')
HTTP_RESPONSE = re.compile(rb'^HTTP/1\.[01] ([1-5][0-9]{2})(?: [\t\x20-\x7e]{0,1024})?\r\n')
HTTP_PIPELINE_UNTRACKED = object()
DHCP_EVENTS = {1: 'dhcp-discover', 2: 'dhcp-offer', 3: 'dhcp-request', 5: 'dhcp-ack', 6: 'dhcp-nak'}
EVENT_PROTOCOLS = {
    'arp': frozenset(('arp-request', 'arp-reply')),
    'icmp': frozenset(('echo-request', 'echo-reply')),
    'icmpv6': frozenset(('echo-request', 'echo-reply')),
    'tcp': frozenset(('tcp-syn', 'tcp-syn-ack', 'tcp-syn-retransmission', 'tcp-handshake-complete')),
    'dhcp': frozenset(DHCP_EVENTS.values()),
    'dns': frozenset(('dns-query', 'dns-response')),
    'http': frozenset(('http-request', 'http-response')),
    'tls': frozenset(('tls-client-hello', 'tls-server-hello', 'tls-application-data')),
}


def _reverse(flow):
    src, dst, sport, dport = flow
    return (dst, src, dport, sport)


def _dns_question(message):
    # Standard messages have a single question. The first name has no prior
    # name to compress against. Retain only a case-insensitive digest locally.
    start = 12
    while start < min(len(message), 267):
        size = message[start]
        if not size:
            if start + 5 > len(message):
                break
            qtype, qclass = struct.unpack_from('!HH', message, start + 1)
            digest = hashlib.sha256(bytes(message[12:start + 1]).lower()).digest()
            return qtype, qclass, digest
        if size > 63:
            break
        start += size + 1
    return None


def _dhcp_message(message):
    if len(message) < 241 or message[1:3] != b'\x01\x06' or message[236:240] != b'\x63\x82\x53\x63':
        return None
    options = {}
    port = 240
    while port < len(message):
        code = message[port]
        port += 1
        if code == 0:
            continue
        if code == 255:
            kind = options.get(53)
            if kind is None or kind[0] not in DHCP_EVENTS:
                return None
            return (kind[0], bytes(message[4:8]), bytes(message[28:34]), bytes(message[16:20]),
                    options.get(54), options.get(50))
        if port == len(message):
            return None
        size = message[port]
        port += 1
        if port + size > len(message):
            return None
        if code in (50, 53, 54):
            if code in options or size != (1 if code == 53 else 4):
                return None
            options[code] = bytes(message[port:port + size])
        port += size
    return None


def _valid_tls_hello(body, kind):
    if len(body) < 38 or body[0] != 3 or body[1] > 3 or body[34] > 32:
        return False
    cursor = 35 + body[34]
    if cursor + 3 > len(body):
        return False
    if kind == 1:
        suites = struct.unpack_from('!H', body, cursor)[0]
        if suites < 2 or suites % 2 or cursor + 2 + suites >= len(body):
            return False
        cursor += 2 + suites
        if not body[cursor]:
            return False
        cursor += 1 + body[cursor]
    else:
        cursor += 3
    return cursor == len(body) or (cursor + 2 <= len(body)
        and cursor + 2 + struct.unpack_from('!H', body, cursor)[0] == len(body))


@dataclass
class _Handshake:
    exchange: int
    client_seq: int
    client_next: int
    server_next: int | None = None
    complete: bool = False


@dataclass
class _DhcpExchange:
    exchange: int
    offers: dict = field(default_factory=dict)
    requested: bool = False
    server: bytes | None = None
    address: bytes | None = None


class PacketTimeline:
    def __init__(self, gaps):
        self.gaps = gaps
        self.events = []
        self.dropped = 0
        self._pending = OrderedDict()
        self._next_exchange = 1
        self._observation_groups = {}

    def begin_packet(self, scope, vlans, number, observed_at):
        self.scope = (scope, vlans)
        self.number = number
        self.observed_at = observed_at
        self.time = datetime.fromisoformat(observed_at) if observed_at is not None else None

    def _lookup(self, protocol, key):
        slot = (self.scope, protocol, key)
        if slot in self._pending:
            number, when, value = self._pending[slot]
            age = (self.time - when).total_seconds() if self.time is not None and when is not None else 0
            if age < 0:
                return None
            if age <= MAX_AGE_SECONDS and self.number - number <= MAX_PACKET_DISTANCE:
                return value
            self._pending.pop(slot)
        return None

    def _store(self, protocol, key, value):
        slot = (self.scope, protocol, key)
        self._pending[slot] = (self.number, self.time, value)
        self._pending.move_to_end(slot)
        if len(self._pending) > MAX_TRACKED:
            self._pending.popitem(last=False)
            self.gaps.add('packet-timeline-state-limit')

    def _discard(self, protocol, key):
        self._pending.pop((self.scope, protocol, key), None)

    def _id(self):
        exchange = self._next_exchange
        self._next_exchange += 1
        return exchange

    def _emit(self, protocol, event_type, flow, exchange, **details):
        if len(self.events) >= MAX_EVENTS:
            self.dropped += 1
            self.gaps.add('packet-timeline-limit')
            return
        src, dst, sport, dport = flow
        group = self._observation_groups.setdefault(self.scope, len(self._observation_groups) + 1)
        event = dict(protocol=protocol, event_type=event_type, exchange_id=exchange,
                     packet_number=self.number, observed_at=self.observed_at,
                     src_address=src, dst_address=dst, observation_group=group)
        if sport is not None:
            event.update(src_port=sport, dst_port=dport)
        event.update(details)
        self.events.append(event)

    def result(self):
        return dict(events=self.events, dropped_events=self.dropped, partial=bool(self.gaps))

    def arp(self, operation, src, dst, message):
        flow = (src, dst, None, None)
        sender_mac = ":".join(f"{byte:02x}" for byte in message[8:14])
        if operation == 1:
            key = (src, dst, bytes(message[8:14]))
            exchange = self._lookup('arp', key) or self._id()
            self._store('arp', key, exchange)
            self._emit('arp', 'arp-request', flow, exchange, arp_sender_mac=sender_mac)
        else:
            key = (dst, src, bytes(message[18:24]))
            exchange = self._lookup('arp', key)
            if exchange is not None:
                self._discard('arp', key)
            self._emit('arp', 'arp-reply', flow, exchange, arp_sender_mac=sender_mac)

    def echo(self, ip_version, src, dst, message):
        request, reply = (8, 0) if ip_version == 4 else (128, 129)
        if len(message) < 8 or message[1] != 0 or message[0] not in (request, reply):
            return
        protocol = 'icmp' if ip_version == 4 else 'icmpv6'
        flow = (src, dst, None, None)
        is_request = message[0] == request
        key = (flow if is_request else _reverse(flow), bytes(message[4:8]), hashlib.sha256(message[8:]).digest())
        pending = self._lookup(protocol, key)
        if is_request:
            exchange = pending[0] if pending else self._id()
            # Multiple identical requests make the originating timestamp ambiguous.
            self._store(protocol, key, (exchange, None if pending else self.time))
            self._emit(protocol, 'echo-request', flow, exchange)
        else:
            exchange, sent_at = pending if pending else (None, None)
            rtt = (self.time - sent_at).total_seconds() * 1000 if sent_at is not None and self.time is not None else None
            if pending:
                self._discard(protocol, key)
            self._emit(protocol, 'echo-reply', flow, exchange, rtt_ms=round(rtt, 3) if rtt is not None else None)

    def udp(self, ip_version, flow, message):
        if 53 in flow[2:]:
            self._dns(flow, message, 'udp')
        elif ip_version == 4 and flow[2:] in ((68, 67), (67, 68), (67, 67)):
            self._dhcp(flow, message)

    def _dns(self, flow, message, transport):
        if len(message) < 12:
            return
        transaction, flags, count = struct.unpack_from('!HHH', message)
        if flags & 0x7800 or count > 1:
            return
        response = bool(flags & 0x8000)
        if flow[2 if response else 3] != 53 or (not response and count != 1):
            return
        question = _dns_question(message) if count else None
        if count and question is None:
            return
        key = (flow if not response else _reverse(flow), transport, transaction, question)
        exchange = self._lookup('dns', key) if question is not None else None
        if not response:
            exchange = exchange or self._id()
            self._store('dns', key, exchange)
        elif exchange is not None:
            self._discard('dns', key)
        self._emit('dns', 'dns-response' if response else 'dns-query', flow, exchange,
                   dns_type=question[0] if question is not None else None,
                   dns_rcode=flags & 0x0f if response else None, dns_truncated=bool(flags & 0x0200))

    def _dhcp(self, flow, message):
        parsed = _dhcp_message(message)
        if parsed is None:
            return
        kind, xid, client, offered_address, server, requested_address = parsed
        from_client = kind in (1, 3)
        ports = (68, 67) if from_client else (67, 68)
        if message[0] != (1 if from_client else 2) or flow[2:] not in (ports, (67, 67)):
            return
        key = (xid, client, bytes(message[24:28]))
        pending = self._lookup('dhcp', key)
        exchange = None
        server_key = server or (IPv4Address(flow[0]).packed if not from_client else None)
        if kind == 1:
            if pending is None or pending.requested:
                pending = _DhcpExchange(self._id())
            exchange = pending.exchange
            self._store('dhcp', key, pending)
        elif kind == 2 and pending and not pending.requested:
            exchange = pending.exchange
            if len(pending.offers) < MAX_FLOW_STEPS or server_key in pending.offers:
                pending.offers[server_key] = offered_address
                self._store('dhcp', key, pending)
            else:
                self.gaps.add('packet-timeline-state-limit')
        elif kind == 3:
            if pending and pending.requested and (pending.server, pending.address) != (server, requested_address):
                pending = None
            if pending and not pending.requested:
                selected = pending.offers.get(server)
                if not pending.offers or (server is None and len(pending.offers) > 1) or (
                        server is not None and (selected is None or requested_address not in (None, selected))):
                    pending = None
            pending = pending or _DhcpExchange(self._id())
            pending.requested, pending.server, pending.address = True, server, requested_address
            exchange = pending.exchange
            self._store('dhcp', key, pending)
        elif kind in (5, 6) and pending and pending.requested and (
                pending.server in (None, server_key) and (kind == 6 or pending.address in (None, offered_address))):
            exchange = pending.exchange
            self._discard('dhcp', key)
        self._emit('dhcp', DHCP_EVENTS[kind], flow, exchange)

    def tcp(self, flow, header, header_length):
        seq, ack = struct.unpack_from('!II', header, 4)
        flags = header[13]
        payload = header[header_length:]
        step = flags & 0x17  # ACK, RST, SYN, FIN
        reverse = _reverse(flow)
        if step == 2:
            pending = self._lookup('tcp', flow)
            same_syn = pending is not None and pending.client_seq == seq
            if not same_syn:
                pending = _Handshake(self._id(), seq, (seq + len(payload) + 1) & 0xffffffff)
                for protocol in ('http', 'http-response', 'tls'):
                    self._discard(protocol, flow)
                    self._discard(protocol, reverse)
                self._store('tcp', flow, pending)
            self._emit('tcp', 'tcp-syn-retransmission' if same_syn else 'tcp-syn', flow, pending.exchange)
        elif step == 18:
            pending = self._lookup('tcp', reverse)
            exchange = None
            server_next = (seq + len(payload) + 1) & 0xffffffff
            if pending and ack == pending.client_next and pending.server_next in (None, server_next):
                pending.server_next = server_next
                exchange = pending.exchange
                self._store('tcp', reverse, pending)
            self._emit('tcp', 'tcp-syn-ack', flow, exchange)
        elif step == 16:
            pending = self._lookup('tcp', flow)
            if pending and not pending.complete and (seq, ack) == (pending.client_next, pending.server_next):
                pending.complete = True
                self._store('tcp', flow, pending)
                self._emit('tcp', 'tcp-handshake-complete', flow, pending.exchange)
        if payload and not flags & 4:
            self._tcp_payload(flow, payload, (seq + bool(flags & 2)) & 0xffffffff, ack if flags & 16 else None)
        if flags & 5:
            for protocol in ('tcp', 'http', 'http-response', 'tls'):
                self._discard(protocol, flow)
                self._discard(protocol, reverse)

    def _tcp_payload(self, flow, payload, seq, ack):
        request = HTTP_REQUEST.match(payload)
        response = HTTP_RESPONSE.match(payload)
        if request or response:
            self._http(flow, request, response, seq, ack)
            return
        if 53 in flow[2:]:
            offset = 0
            for _ in range(MAX_FLOW_STEPS):
                if offset + 2 > len(payload):
                    break
                size = struct.unpack_from('!H', payload, offset)[0]
                if size < 12 or offset + 2 + size > len(payload):
                    break
                self._dns(flow, payload[offset + 2:offset + 2 + size], 'tcp')
                offset += size + 2
            else:
                if offset < len(payload):
                    self.gaps.add('packet-timeline-state-limit')
            return
        self._tls(flow, payload)

    def _http(self, flow, request, response, seq, ack):
        reverse = _reverse(flow)
        if request:
            pending = self._lookup('http', flow)
            exchange = None
            if pending is not HTTP_PIPELINE_UNTRACKED:
                queue = pending or []
                exchange = next((exchange for exchange, start, _ in queue if start == seq), None)
                if exchange is None and len(queue) < MAX_FLOW_STEPS:
                    exchange = self._id()
                    queue.append((exchange, seq, (seq + request.end()) & 0xffffffff))
                elif exchange is None:
                    # A missing pipeline entry could shift every later response pairing.
                    queue = HTTP_PIPELINE_UNTRACKED
                    self.gaps.add('packet-timeline-state-limit')
                pending = queue
            self._store('http', flow, pending)
            self._emit('http', 'http-request', flow, exchange, http_method=request[1].decode('ascii'))
            return
        status = int(response[1])
        recent = self._lookup('http-response', flow)
        exchange = None
        if recent and recent[0] == seq:
            exchange = recent[1]
        else:
            queue = self._lookup('http', reverse)
            if isinstance(queue, list) and queue and ack is not None and ((ack - queue[0][2]) & 0xffffffff) < 0x80000000:
                exchange = queue[0][0]
                if status == 101 or status >= 200:
                    queue.pop(0)
            self._store('http-response', flow, (seq, exchange))
        self._emit('http', 'http-response', flow, exchange, status_code=status)

    def _tls(self, flow, payload):
        offset = 0
        reverse = _reverse(flow)
        for _ in range(MAX_FLOW_STEPS):
            if offset + 5 > len(payload):
                return
            kind, version, size = struct.unpack_from('!BHH', payload, offset)
            end = offset + 5 + size
            if kind not in (20, 21, 22, 23, 24) or not 0x0301 <= version <= 0x0303 or size > 18432 or end > len(payload):
                return
            record = payload[offset + 5:end]
            offset = end
            if kind == 22 and len(record) >= 4:
                hello, length = record[0], int.from_bytes(record[1:4], 'big')
                if hello not in (1, 2) or length + 4 > len(record) or not _valid_tls_hello(record[4:4 + length], hello):
                    continue
                if hello == 1:
                    exchange = self._lookup('tls', flow) or self._id()
                    self._store('tls', flow, exchange)
                else:
                    exchange = self._lookup('tls', reverse)
                    if exchange is not None:
                        self._store('tls', reverse, exchange)
                self._emit('tls', 'tls-client-hello' if hello == 1 else 'tls-server-hello', flow, exchange)
            elif kind == 23 and size:
                exchange = self._lookup('tls', flow) or self._lookup('tls', reverse)
                if exchange is not None or 443 in flow[2:]:
                    self._emit('tls', 'tls-application-data', flow, exchange)
        if offset < len(payload):
            self.gaps.add('packet-timeline-state-limit')
