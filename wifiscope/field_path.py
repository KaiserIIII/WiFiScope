"""Opt-in observations of specific DNS, NTP and HTTPS paths."""
import errno
import http.client
import io
import re
import secrets
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import probe

_METHODS = {'dns': 'udp-dns', 'ntp': 'udp-ntp', 'doh': 'https-doh-post', 'download': 'https-download-get'}
_QUESTION = b'\x07example\x03com\x00\x00\x01\x00\x01'  # example.com. IN A
_DNS_MEDIA = 'application/dns-message'
_DOWNLOAD_LIMIT = 1024 * 1024
_DOH_LIMIT = 65535
_HTTP_OVERHEAD = 16 * 1024


class _ResponseLimit(Exception):
    pass


def _address(value):
    address = probe._literal(value) if isinstance(value, str) else None
    if address is None:
        raise ValueError('Use a numeric IP address.')
    return probe._literal(probe._host(value))


def _udp_endpoint(value, default_port):
    if isinstance(value, (tuple, list)) and len(value) == 2:
        host, port = value
    elif isinstance(value, str) and probe._literal(value) is not None:
        host, port = value, default_port
    else:
        match = re.fullmatch(r'(?:\[([^\[\]]+:[^\[\]]*)\]|([^:\[\]]+)):([0-9]{1,5})',
                             value) if isinstance(value, str) else None
        if not match:
            raise ValueError('Use a numeric IP, IPv4:port, or [IPv6]:port.')
        host, port = match[1] or match[2], int(match[3])
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Port must be an integer from 1 to 65535.')
    return _address(host), port


def _https_endpoint(value):
    normalized = urlsplit(probe._url(value))
    if normalized.scheme != 'https':
        raise ValueError('Use an HTTPS URL.')
    authority = urlsplit(value).netloc
    if (not re.fullmatch(r'(?:\[[^\[\]%]+\]|[^:\[\]%]+)(?::[0-9]{1,5})?', authority) or
            (authority.startswith('[') and not normalized.netloc.startswith('['))):
        raise ValueError('Use a hostname or unscoped IP literal with an optional HTTPS port.')
    return normalized


def validate_path_plan(*, dns=None, ntp=None, doh=None, download=None, source=None, timeout=2.0):
    """Validate every requested endpoint and source binding without network activity."""
    if type(timeout) not in (int, float) or not .2 <= timeout <= 5:
        raise ValueError('Timeout must be from 0.2 to 5 seconds.')
    binding = _address(source) if source is not None else None
    targets = {
        'dns': _udp_endpoint(dns, 53) if dns is not None else None,
        'ntp': _udp_endpoint(ntp, 123) if ntp is not None else None,
        'doh': _https_endpoint(doh) if doh is not None else None,
        'download': _https_endpoint(download) if download is not None else None,
    }
    for name, target in targets.items():
        if target is not None and binding is not None:
            literal = target[0] if name in ('dns', 'ntp') else probe._literal(target.hostname)
            if literal is not None and literal.version != binding.version:
                raise ValueError('Source and numeric destination must use the same IP family.')
    return targets, binding


def _send(sock, payload, deadline, cancel):
    remaining = memoryview(payload)
    while remaining:
        sent = probe._operation(sock, lambda data=remaining: sock.send(data), False, deadline, cancel)
        if not sent:
            raise probe._InvalidResponse
        remaining = remaining[sent:]


def _dns_query(transaction):
    return transaction + b'\x01\x00\x00\x01' + bytes(6) + _QUESTION


def _skip_dns_name(message, offset):
    wire_end = None
    length = 0
    visited = set()
    while offset < len(message):
        size = message[offset]
        if size == 0:
            return wire_end if wire_end is not None else offset + 1
        if size >= 192 and offset + 1 < len(message):
            pointer = ((size & 63) << 8) | message[offset + 1]
            if not 12 <= pointer < offset or pointer in visited or len(visited) >= 128:
                break
            visited.add(pointer)
            if wire_end is None:
                wire_end = offset + 2
            offset = pointer
        elif 0 < size <= 63:
            length += size + 1
            if length >= 255:
                break
            offset += size + 1
        else:
            break
    raise probe._InvalidResponse


def _dns_status(message, query, row):
    question_end = 12 + len(_QUESTION)
    if (len(message) < question_end or message[:2] != query[:2] or
            message[12:question_end].lower() != _QUESTION):
        raise probe._InvalidResponse
    flags, questions, answers, authority, additional = struct.unpack_from('!5H', message, 2)
    if flags & 0xF840 != 0x8000 or questions != 1:  # Response, standard opcode, reserved bit clear.
        raise probe._InvalidResponse
    if flags & 0x0200:
        return 'truncated'
    offset = question_end
    for _ in range(answers + authority + additional):
        offset = _skip_dns_name(message, offset)
        if offset + 10 > len(message):
            raise probe._InvalidResponse
        data_length = struct.unpack_from('!H', message, offset + 8)[0]
        offset += 10 + data_length
        if offset > len(message):
            raise probe._InvalidResponse
    if offset != len(message):
        raise probe._InvalidResponse
    row['dns_rcode'] = flags & 15
    return 'ok' if row['dns_rcode'] == 0 else 'dns_error'


def _ntp_status(message, query):
    if (len(message) < 48 or len(message) % 4 or message[0] & 7 != 4 or
            (message[0] >> 3) & 7 not in (3, 4) or message[24:32] != query[40:48]):
        raise probe._InvalidResponse
    if message[1] == 0:
        return 'kiss_of_death'
    if message[0] >> 6 == 3 or message[1] == 16:
        return 'unsynchronized'
    if message[1] > 16 or not any(message[32:40]) or not any(message[40:48]):
        raise probe._InvalidResponse
    return 'ok'


def _udp_check(name, target, source, deadline, cancel, row):
    if name == 'dns':
        query, maximum = _dns_query(secrets.token_bytes(2)), 512
    else:
        cookie = (secrets.randbelow((1 << 64) - 1) + 1).to_bytes(8, 'big')
        query, maximum = b'\x23' + bytes(39) + cookie, 1024
    address, port = target
    ipv4 = address.version == 4
    family = 'IPv4' if ipv4 else 'IPv6'
    with socket.socket(socket.AF_INET if ipv4 else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        if source is not None:
            sock.bind(probe._sockaddr(str(source), family, 0))
        sock.connect(probe._sockaddr(str(address), family, port))
        sent = probe._operation(sock, lambda: sock.send(query), False, deadline, cancel)
        if sent != len(query):
            raise probe._InvalidResponse
        try:
            reply = probe._operation(sock, lambda: sock.recv(maximum + 1), True, deadline, cancel)
        except OSError as error:
            if error.errno == errno.EMSGSIZE or getattr(error, 'winerror', None) == 10040:
                raise _ResponseLimit from None
            raise
    row['bytes'] = len(reply)
    if len(reply) > maximum:
        raise _ResponseLimit
    return _dns_status(reply, query, row) if name == 'dns' else _ntp_status(reply, query)


def _start_tls(sock, hostname, deadline, cancel):
    # An explicit context uses system trust and hostname verification without
    # honoring the SSLKEYLOGFILE environment variable.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    secured = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False)
    try:
        probe._operation(secured, secured.do_handshake, True, deadline, cancel)
        return secured
    except BaseException:
        secured.close()
        raise


class _HTTPInput(io.RawIOBase):
    """Give HTTPResponse a byte budget and cancellable, nonblocking reads."""

    def __init__(self, sock, deadline, cancel):
        self.sock = sock
        self.deadline = deadline
        self.cancel = cancel
        self.remaining = _HTTP_OVERHEAD

    def makefile(self, mode):
        return io.BufferedReader(self)

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.remaining <= 0:
            raise _ResponseLimit
        size = probe._operation(self.sock, lambda: self.sock.recv_into(buffer, min(len(buffer), self.remaining)),
                                True, self.deadline, self.cancel)
        self.remaining -= size
        return size


def _http_body(response, row, doh):
    lengths = response.headers.get_all('Content-Length', [])
    transfers = [v.strip().lower() for v in response.headers.get_all('Transfer-Encoding', [])]
    encodings = [v.strip().lower() for v in response.headers.get_all('Content-Encoding', [])]
    if ((lengths and (len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,19}', lengths[0].strip()))) or
            (transfers and (transfers != ['chunked'] or lengths)) or encodings not in ([], ['identity'])):
        raise probe._InvalidResponse
    if doh:
        media = response.headers.get_all('Content-Type', [])
        if len(media) != 1 or media[0].strip().lower() != _DNS_MEDIA:
            raise probe._InvalidResponse
        if response.length is not None and response.length > _DOH_LIMIT:
            raise _ResponseLimit
    limit = _DOH_LIMIT + 1 if doh else _DOWNLOAD_LIMIT
    body = bytearray() if doh else None
    row['bytes'] = 0
    while row['bytes'] < limit:
        piece = response.read1(min(16384, limit - row['bytes']))
        if not piece:
            if response.length:
                raise probe._InvalidResponse
            break
        row['bytes'] += len(piece)
        if body is not None:
            body.extend(piece)
    if doh and row['bytes'] > _DOH_LIMIT:
        raise _ResponseLimit
    if not doh and row['bytes'] == limit and response.length != 0:
        row['gaps'].append('download-sample-capped')
    return body


def _content_range(response):
    """A range response must start at byte zero and stay within the request."""
    values = response.headers.get_all('Content-Range', [])
    match = re.fullmatch(r'bytes 0-([0-9]{1,19})/([0-9]{1,19}|\*)', values[0], re.IGNORECASE) if len(values) == 1 else None
    if not match:
        raise probe._InvalidResponse
    length = int(match[1]) + 1
    total = int(match[2]) if match[2] != '*' else None
    if (length > _DOWNLOAD_LIMIT or (total is not None and total < length) or
            (response.length is not None and response.length != length)):
        raise probe._InvalidResponse
    return length, total


def _https_check(name, target, source, deadline, cancel, row):
    hostname = target.hostname
    address = probe._literal(hostname)
    if address is None:
        row['gaps'].append('system-resolver-used')
        status, answers = probe._resolve(hostname, probe._remaining(float('inf'), deadline), cancel)
        if status != 'ok':
            return status
        address = next((literal for answer in answers if (literal := probe._literal(answer['address']))
                        and (source is None or literal.version == source.version)), None)
        if address is None:
            return 'no_compatible_address'
    doh = name == 'doh'
    query = _dns_query(b'\0\0') if doh else b''  # RFC 8484 recommends ID zero on this transport.
    method = 'POST' if doh else 'GET'
    headers = (f'{method} {target.path} HTTP/1.1\r\nHost: {target.netloc}\r\n'
               'Connection: close\r\nAccept-Encoding: identity\r\n')
    if doh:
        headers += f'Accept: {_DNS_MEDIA}\r\nContent-Type: {_DNS_MEDIA}\r\nContent-Length: {len(query)}\r\n'
    else:
        headers += f'Range: bytes=0-{_DOWNLOAD_LIMIT - 1}\r\n'
    family = 'IPv4' if address.version == 4 else 'IPv6'
    remaining = probe._remaining(float('inf'), deadline)
    with (
        probe._connect(str(address), family, target.port or 443, remaining, cancel,
                       source=str(source) if source is not None else None) as sock,
        _start_tls(sock, hostname, deadline, cancel) as secured,
    ):
        _send(secured, (headers + '\r\n').encode('ascii') + query, deadline, cancel)
        stream = _HTTPInput(secured, deadline, cancel)
        with http.client.HTTPResponse(stream, method=method) as response:
            response.begin()
            if response.headers.defects or response.status < 200 or response.status > 599:
                raise probe._InvalidResponse
            row['http_status'] = response.status
            if 300 <= response.status < 400:
                return 'redirect'
            partial = not doh and response.status == 206
            if response.status != 200 and not partial:
                return 'http_error'
            length, total = _content_range(response) if partial else (None, None)
            stream.remaining += _DOH_LIMIT + 1 if doh else _DOWNLOAD_LIMIT
            body = _http_body(response, row, doh)
            if doh:
                return _dns_status(body, query, row)
            if partial:
                if row['bytes'] != length:
                    raise probe._InvalidResponse
                if (total is None or total > length) and 'download-sample-capped' not in row['gaps']:
                    row['gaps'].append('download-sample-capped')
            return 'ok' if row['bytes'] else 'empty_response'


def path_checks(*, dns=None, ntp=None, doh=None, download=None, authorized=False, source=None,
                timeout=2.0, cancel=None):
    """Observe at most one endpoint per method after authorization and preflight.

    The timeout applies independently to each method. Source binding applies
    to probe sockets. HTTPS hostname lookup uses the system resolver and tries
    one compatible answer. Bytes count received datagram or HTTP payload bytes.
    Download Mbps is an end-to-end sample including setup time. Results contain
    categorical observations and counts only, with no targets or response data.
    """
    targets, binding = validate_path_plan(dns=dns, ntp=ntp, doh=doh, download=download,
                                          source=source, timeout=timeout)
    if any(target is not None for target in targets.values()) and authorized is not True:
        raise ValueError('Explicit authorization is required for active path checks.')
    results = dict.fromkeys(_METHODS)
    for name, target in targets.items():
        if target is None:
            continue
        deadline = time.monotonic() + timeout
        started = time.perf_counter()
        row = {
            'method': _METHODS[name],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'bytes': None,
            'ms': None,
            'gaps': ['single-endpoint-observation'],
        }
        if name == 'ntp':
            row['gaps'].append('clock-synchronization-not-tested')
        if name in ('doh', 'download'):
            row['http_status'] = None
        if name in ('dns', 'doh'):
            row['dns_rcode'] = None
        if name == 'download':
            row['mbps'] = None
        try:
            probe._check_cancel(cancel)
            check = _udp_check if name in ('dns', 'ntp') else _https_check
            row['status'] = check(name, target, binding, deadline, cancel, row)
        except _ResponseLimit:
            row['status'] = 'response_limit'
        except http.client.HTTPException:
            row['status'] = 'invalid_response'
        except (OSError, probe._Cancelled, probe._InvalidResponse) as error:
            row['status'] = probe._status(error)
        row['ms'] = (time.perf_counter() - started) * 1000
        if name == 'download' and row['status'] == 'ok' and row['ms'] > 0:
            row['mbps'] = row['bytes'] * 8 / (row['ms'] * 1000)
        if row['status'] != 'ok':
            row['gaps'].append(name + '-' + row['status'].replace('_', '-'))
        results[name] = row
    return results
