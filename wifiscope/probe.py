"""Explicitly authorized, bounded DNS/TCP/TLS/HEAD observations.

Only the requested hosts and endpoints are probed. DNS answers are pinned once;
no redirects, proxy discovery, response bodies, or unverified TLS fallback exist.
Timing statistics describe connection setup, not throughput or packet loss.
"""
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
import json
import math
import re
import select
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit, urlunsplit


_MAX_HEADERS = 16384
_MAX_LINE = 4096
_SECURITY_FIELDS = ('hsts', 'hsts_positive_max_age', 'csp', 'frame_protection',
                    'nosniff', 'cookies_secure', 'cookies_httponly')
_DNS_PROGRAM = r'''
import json, socket, sys
answers = []
counts = {socket.AF_INET: 0, socket.AF_INET6: 0}
try:
    for family, kind, protocol, canonical, address in socket.getaddrinfo(
            sys.argv[1], None, socket.AF_UNSPEC, socket.SOCK_STREAM):
        if family not in counts or counts[family] >= 2:
            continue
        value = address[0]
        if family == socket.AF_INET6 and address[3] and '%' not in value:
            value += '%' + str(address[3])
        row = {'family': 'IPv4' if family == socket.AF_INET else 'IPv6', 'address': value}
        if row not in answers:
            answers.append(row)
            counts[family] += 1
    print(json.dumps(answers))
except OSError:
    sys.exit(1)
'''


class _Cancelled(Exception):
    def __init__(self, started=False):
        self.started = started


class _InvalidResponse(Exception):
    pass


class _Deadline(TimeoutError):
    """An operation was not started because the request deadline elapsed."""


def _remaining(timeout, deadline):
    if deadline is None:
        return timeout
    remaining = min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        raise _Deadline
    return remaining


def _check_cancel(cancel):
    if cancel is not None and (cancel.is_set() if hasattr(cancel, 'is_set') else cancel()):
        raise _Cancelled


def _literal(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError('Invalid target hostname.')
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or any(c in value for c in '/*\\@?#[]'):
        raise ValueError('Use a single hostname or IP literal.')
    value = value[:-1] if value.endswith('.') else value
    address = _literal(value)
    if address is not None:
        effective = address.ipv4_mapped if address.version == 6 and address.ipv4_mapped else address
        if effective.is_unspecified or effective.is_multicast or str(effective) == '255.255.255.255':
            raise ValueError('Unspecified, multicast and broadcast targets are forbidden.')
        if '%' in value:
            if address.version != 6 or not value.rsplit('%', 1)[1].isdigit():
                raise ValueError('Only numeric IPv6 zone identifiers are supported.')
            if int(value.rsplit('%', 1)[1]) > 4294967295:
                raise ValueError('Invalid IPv6 zone identifier.')
        return str(address)
    if ':' in value or '%' in value or re.fullmatch(r'[0-9.]+', value):
        raise ValueError('Invalid IP literal.')
    try:
        value = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Invalid target hostname.') from None
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                               for part in value.split('.')):
        raise ValueError('Invalid target hostname.')
    # Avoid platform-specific legacy numeric address parsing (e.g. 0x7f000001).
    if all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', part) for part in value.split('.')):
        raise ValueError('Use a canonical IP literal.')
    return value


def _url(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError('URLs must contain at most 2048 characters.')
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or any(c in value for c in '\\?#'):
        raise ValueError('URL controls, queries and fragments are forbidden.')
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = _host(parsed.hostname)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
        if not 1 <= port <= 65535 or parsed.netloc.endswith(':'):
            raise ValueError
        authority = '[' + host + ']' if ':' in host else host
        if parsed.port is not None:
            authority += ':' + str(port)
        path = quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~")
        result = urlunsplit((parsed.scheme, authority, path, '', ''))
        if len(result) > 2048:
            raise ValueError
        return result
    except (ValueError, UnicodeError):
        raise ValueError('Use an HTTP(S) URL with a valid host and port, without credentials.') from None


def validate_request(hosts: list[str], ports: list[int], attempts: int,
                     timeout: float, urls: list[str] = ()) -> tuple[list[str], list[int], list[str]]:
    """Validate the entire request before any resolver or socket side effect.

    Returned hosts include URL hosts; returned ports remain explicit ports.
    URL endpoints must not be cross-multiplied with unrelated hosts or ports.
    """
    if not isinstance(hosts, (list, tuple)) or not isinstance(ports, (list, tuple)) or not isinstance(urls, (list, tuple)):
        raise ValueError('Hosts, ports and URLs must be lists.')
    if len(hosts) > 4 or len(ports) > 8 or len(urls) > 4:
        raise ValueError('Request exceeds host, port or URL bounds.')
    if type(attempts) is not int or not 1 <= attempts <= 5:
        raise ValueError('Attempts must be an integer from 1 to 5.')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not .2 <= timeout <= 5:
        raise ValueError('Timeout must be from 0.2 to 5 seconds.')
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError('Ports must be integers from 1 to 65535.')
    normalized_hosts = list(dict.fromkeys(_host(host) for host in hosts))
    normalized_urls = list(dict.fromkeys(_url(url) for url in urls))
    for url in normalized_urls:
        host = _host(urlsplit(url).hostname)
        if host not in normalized_hosts:
            normalized_hosts.append(host)
    all_ports = set(ports) | {_url_port(url) for url in normalized_urls}
    if len(normalized_hosts) > 4 or len(all_ports) > 8:
        raise ValueError('Combined targets exceed host or port bounds.')
    if not normalized_hosts or (not ports and not normalized_urls):
        raise ValueError('Supply at least one explicit target endpoint.')
    return normalized_hosts, list(dict.fromkeys(ports)), normalized_urls


def _url_port(url):
    parsed = urlsplit(url)
    return parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)


def _resolve(host, timeout, cancel):
    _check_cancel(cancel)
    address = _literal(host)
    if address is not None:
        return 'ok', [dict(family='IPv4' if address.version == 4 else 'IPv6', address=host)]
    child = None
    try:
        deadline = time.monotonic() + timeout
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
        child = subprocess.Popen([sys.executable, '-I', '-c', _DNS_PROGRAM, host],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, **options)
        while True:
            _check_cancel(cancel)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 'timeout', []
            try:
                output, _ = child.communicate(timeout=min(.05, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        _check_cancel(cancel)
        if child.returncode != 0 or len(output) > 4096:
            return 'dns_error', []
        answers = _answers(json.loads(output))
        return ('ok' if answers else 'no_addresses'), answers
    except _Cancelled:
        return 'cancelled', []
    except (OSError, ValueError, TypeError):
        return 'dns_error', []
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            child.communicate()


def _answers(raw):
    """Defensively validate, deduplicate and cap each address family."""
    result = []
    counts = {'IPv4': 0, 'IPv6': 0}
    if not isinstance(raw, list):
        return result
    for row in raw[:128]:
        if not isinstance(row, dict) or row.get('family') not in counts:
            continue
        try:
            address = _host(row.get('address'))
        except ValueError:
            continue
        literal = _literal(address)
        family = row['family']
        if literal is None or (literal.version == 4) != (family == 'IPv4'):
            continue
        item = dict(family=family, address=address)
        if counts[family] < 2 and item not in result:
            counts[family] += 1
            result.append(item)
    return result


class _Limiter:
    def __init__(self, cancel, deadline=None):
        self.next_start = 0
        self.cancel = cancel
        self.deadline = deadline

    def wait(self):
        while True:
            _check_cancel(self.cancel)
            scope_remaining = _remaining(float('inf'), self.deadline)
            remaining = self.next_start - time.monotonic()
            if remaining <= 0:
                self.next_start = time.monotonic() + .25
                return
            time.sleep(min(.025, remaining, scope_remaining))


def _wait(sock, reading, deadline, cancel):
    while True:
        _check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        readable, writable, exceptional = select.select(
            [sock] if reading else [], [] if reading else [sock], [sock], min(.05, remaining))
        if readable or writable or exceptional:
            return


def _operation(sock, callback, reading, deadline, cancel):
    while True:
        _check_cancel(cancel)
        if time.monotonic() >= deadline:
            raise TimeoutError
        try:
            return callback()
        except ssl.SSLWantReadError:
            _wait(sock, True, deadline, cancel)
        except ssl.SSLWantWriteError:
            _wait(sock, False, deadline, cancel)
        except BlockingIOError:
            _wait(sock, reading, deadline, cancel)


def _connect(address, family, port, timeout, cancel):
    """Connect to a numeric sockaddr; never invoke a second DNS lookup."""
    _check_cancel(cancel)
    deadline = time.monotonic() + timeout
    af = socket.AF_INET if family == 'IPv4' else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_STREAM)
    started = False
    try:
        sock.setblocking(False)
        if af == socket.AF_INET6:
            plain, _, zone = address.partition('%')
            target = (plain, port, 0, int(zone) if zone else 0)
        else:
            target = (address, port)
        started = True
        error = sock.connect_ex(target)
        pending = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                   getattr(errno, 'WSAEWOULDBLOCK', 10035), getattr(errno, 'WSAEINPROGRESS', 10036)}
        if error in pending:
            _wait(sock, False, deadline, cancel)
            error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, 'Connection failed')
        return sock
    except BaseException as error:
        if isinstance(error, _Cancelled):
            error.started = started
        sock.close()
        raise


def _start_tls(sock, host, deadline, cancel):
    context = ssl.create_default_context()
    secured = context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
    try:
        secured.setblocking(False)
        _operation(secured, secured.do_handshake, True, deadline, cancel)
        return secured
    except BaseException:
        secured.close()
        raise


def _status(error):
    if isinstance(error, _Cancelled):
        return 'cancelled'
    if isinstance(error, (TimeoutError, socket.timeout)):
        return 'timeout'
    if isinstance(error, ssl.SSLCertVerificationError):
        return 'certificate_error'
    if isinstance(error, ssl.SSLError):
        return 'tls_error'
    if isinstance(error, _InvalidResponse):
        return 'invalid_response'
    if isinstance(error, ConnectionRefusedError) or getattr(error, 'errno', None) in (errno.ECONNREFUSED, 10061):
        return 'refused'
    return 'error'


def _gap(record, source, status):
    if status in ('ok', 'redirect', 'http_error'):
        return
    gap = source + ('-' + status if status in ('timeout', 'cancelled') else '-unavailable')
    if gap not in record['gaps']:
        record['gaps'].append(gap)


def _tcp(address, family, port, attempts, timeout, limiter, cancel):
    times, statuses = [], []
    expired = False
    for _ in range(attempts):
        try:
            limiter.wait()
            connection_timeout = _remaining(timeout, limiter.deadline)
        except _Cancelled:
            break
        except _Deadline:
            expired = True
            break
        start = time.monotonic()
        try:
            sock = _connect(address, family, port, connection_timeout, cancel)
            times.append((time.monotonic() - start) * 1000)
            sock.close()
            statuses.append('ok')
        except (OSError, _Cancelled) as error:
            if not isinstance(error, _Cancelled) or error.started:
                statuses.append(_status(error))
            if isinstance(error, _Cancelled):
                break
    try:
        _check_cancel(cancel)
        cancelled = False
    except _Cancelled:
        cancelled = True
    status = ('cancelled' if cancelled else 'partial' if expired and statuses else
              'not_run' if expired else 'ok' if len(times) == attempts else
              'partial' if times else statuses[-1] if statuses else 'not_run')
    return dict(address=address, family=family, port=port, status=status,
                attempts=len(statuses), successes=len(times),
                failure_percent=(100 * (len(statuses) - len(times)) / len(statuses)) if statuses else None,
                rtt_min_ms=min(times) if times else None,
                rtt_mean_ms=sum(times) / len(times) if times else None,
                rtt_max_ms=max(times) if times else None,
                jitter_ms=(sum(abs(b - a) for a, b in zip(times, times[1:])) / (len(times) - 1)) if len(times) > 1 else None)


def _tls_metadata(sock):
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(sock.getpeercert()['notAfter']), timezone.utc)
    return dict(status='ok', verified=True, version=sock.version(),
                certificate_sha256=hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest(),
                not_after=expiry.isoformat(),
                days_remaining=(expiry - datetime.now(timezone.utc)).total_seconds() / 86400,
                cipher=sock.cipher()[0])


def _tls_probe(host, answer, port, timeout, limiter, cancel):
    row = dict(address=answer['address'], family=answer['family'], port=port,
               status='error', verified=False, attempts=0)
    sock = None
    try:
        limiter.wait()
        connection_timeout = _remaining(timeout, limiter.deadline)
        deadline = time.monotonic() + connection_timeout
        row['attempts'] = 1
        sock = _connect(answer['address'], answer['family'], port, connection_timeout, cancel)
        sock = _start_tls(sock, host, deadline, cancel)
        row.update(_tls_metadata(sock))
    except (OSError, _Cancelled, ValueError, KeyError, TypeError) as error:
        if isinstance(error, _Cancelled) and not error.started and sock is None:
            row['attempts'] = 0
        row['status'] = 'not_run' if isinstance(error, _Deadline) else _status(error)
    finally:
        if sock is not None:
            sock.close()
    return row


def _headers(sock, deadline, cancel):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        piece = _operation(sock, lambda: sock.recv(min(1024, _MAX_HEADERS - len(data))),
                           True, deadline, cancel)
        if not piece:
            raise _InvalidResponse
        data.extend(piece)
        end = data.find(b'\r\n\r\n')
        head = data[:end] if end >= 0 else data
        if any(len(line) > _MAX_LINE for line in head.split(b'\r\n')):
            raise _InvalidResponse
        if len(data) >= _MAX_HEADERS and end < 0:
            raise _InvalidResponse
        if b'\n' in head.replace(b'\r\n', b''):
            raise _InvalidResponse
    lines = bytes(head).split(b'\r\n')
    match = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e\x80-\xff]*)?', lines[0])
    if not match or len(lines) > 101:
        raise _InvalidResponse
    code = int(match[1])
    if code < 200:
        raise _InvalidResponse
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise _InvalidResponse
        if any(c < 32 and c != 9 or c == 127 for c in value):
            raise _InvalidResponse
        headers.setdefault(name.decode('ascii').lower(), []).append(value.decode('iso-8859-1').strip())
    return code, headers


def _hsts_positive(values):
    """Validate the bounded RFC6797 directive field, not just max-age text."""
    if len(values) != 1:
        return False
    text, offset, directives = values[0], 0, {}
    token = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
    while offset < len(text):
        if text[offset] in ' \t;':
            offset += 1
            continue
        name = token.match(text, offset)
        if not name or name[0].lower() in directives:
            return False
        key, offset, value = name[0].lower(), name.end(), None
        while offset < len(text) and text[offset] in ' \t':
            offset += 1
        if offset < len(text) and text[offset] == '=':
            offset += 1
            while offset < len(text) and text[offset] in ' \t':
                offset += 1
            if offset < len(text) and text[offset] == '"':
                offset += 1
                decoded = []
                while offset < len(text) and text[offset] != '"':
                    character = text[offset]
                    if character == '\\':
                        offset += 1
                        if offset >= len(text) or ord(text[offset]) > 127:
                            return False
                        character = text[offset]
                    if ord(character) < 32 and character != '\t' or ord(character) == 127:
                        return False
                    decoded.append(character)
                    offset += 1
                if offset >= len(text):
                    return False
                value = ''.join(decoded)
                offset += 1
            else:
                match = token.match(text, offset)
                if not match:
                    return False
                value, offset = match[0], match.end()
            while offset < len(text) and text[offset] in ' \t':
                offset += 1
        if offset < len(text) and text[offset] != ';':
            return False
        directives[key] = value
    if directives.get('includesubdomains') is not None:
        return False
    age = directives.get('max-age')
    return bool(age and re.fullmatch(r'[0-9]+', age) and any(c != '0' for c in age))


def _restrictive_ancestor_source(source):
    """Support self and HTTP(S) host sources; other semantics stay unknown."""
    if source.lower() == "'self'":
        return True
    if not source.isascii() or any(c in source for c in '\\?#'):
        return False
    try:
        parsed = urlsplit(source if '://' in source else 'https://' + source)
        if parsed.scheme not in ('http', 'https') or parsed.username is not None or parsed.password is not None:
            return False
        host = parsed.hostname
        if host is None or ':' in host or parsed.netloc.endswith(':'):
            return False
        _host(host[2:] if host.startswith('*.') else host)
        if not parsed.netloc.endswith(':*') and parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        if not re.fullmatch(r"(?:/[A-Za-z0-9._~!$&'()*+=:@%/-]*)?", parsed.path):
            return False
        if re.search(r'%(?![0-9a-fA-F]{2})', parsed.path):
            return False
        return True
    except (ValueError, UnicodeError):
        return False


def _frame_protection(headers):
    """Conservative evidence, not a browser-equivalent CSP evaluator.

    First duplicate directives win within each policy; comma-separated policies
    and separate header fields are enforced together. Unsupported source forms
    remain null, and an enforced frame-ancestors directive takes priority over
    XFO. Scheme-wide sources, IPv6 hosts and mixed none lists are not evaluated.
    """
    observations = []
    for field in headers.get('content-security-policy', []):
        for policy in field.split(','):
            for directive in policy.split(';'):
                parts = re.split(r'[ \t]+', directive.strip(' \t'))
                if parts[0].lower() != 'frame-ancestors':
                    continue
                sources = parts[1:]
                if len(sources) == 1 and sources[0].lower() == "'none'":
                    observations.append(True)
                elif '*' in sources:
                    observations.append(False)
                elif sources and all(_restrictive_ancestor_source(source) for source in sources):
                    observations.append(True)
                else:
                    observations.append(None)
                break
    if observations:
        return True if True in observations else None if None in observations else False
    xfo = headers.get('x-frame-options', [])
    return len(xfo) == 1 and xfo[0].upper() in ('DENY', 'SAMEORIGIN')


def _security(headers, evaluated):
    result = dict.fromkeys(_SECURITY_FIELDS)
    if not evaluated:
        return result
    hsts = headers.get('strict-transport-security', [])
    policies = headers.get('content-security-policy', [])
    nosniff = headers.get('x-content-type-options', [])
    cookies = headers.get('set-cookie', [])
    cookie_attributes = [{attribute.strip().lower() for attribute in cookie.split(';')[1:]}
                         for cookie in cookies]
    result.update(hsts=bool(hsts), hsts_positive_max_age=_hsts_positive(hsts),
                  csp=any(policy.strip() for policy in policies), frame_protection=_frame_protection(headers),
                  nosniff=len(nosniff) == 1 and nosniff[0].lower() == 'nosniff',
                  cookies_secure=all('secure' in attributes for attributes in cookie_attributes) if cookies else None,
                  cookies_httponly=all('httponly' in attributes for attributes in cookie_attributes) if cookies else None)
    return result


def _http_probe(url, answer, timeout, limiter, cancel):
    parsed = urlsplit(url)
    row = dict(url=url, address=answer['address'], family=answer['family'], status='error',
               status_code=None, attempts=0, header_presence={}, content_kind='unknown',
               security_checks=dict.fromkeys(_SECURITY_FIELDS))
    sock = None
    try:
        limiter.wait()
        connection_timeout = _remaining(timeout, limiter.deadline)
        deadline = time.monotonic() + connection_timeout
        row['attempts'] = 1
        sock = _connect(answer['address'], answer['family'], _url_port(url), connection_timeout, cancel)
        if parsed.scheme == 'https':
            sock = _start_tls(sock, parsed.hostname, deadline, cancel)
        request = memoryview(('HEAD ' + (parsed.path or '/') + ' HTTP/1.1\r\nHost: ' +
                              parsed.netloc + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        while request:
            size = _operation(sock, lambda: sock.send(request), False, deadline, cancel)
            if not size:
                raise _InvalidResponse
            request = request[size:]
        code, headers = _headers(sock, deadline, cancel)
        row.update(status='ok' if code < 300 else 'redirect' if code < 400 else 'http_error',
                   status_code=code,
                   header_presence={key.replace('-', '_'): key in headers for key in (
                       'server', 'location', 'content-type', 'content-length', 'strict-transport-security')},
                   security_checks=_security(headers, 200 <= code < 300))
        media = headers.get('content-type', [''])[0].split(';')[0].strip().lower()
        row['content_kind'] = 'html' if media in ('text/html', 'application/xhtml+xml') else 'other' if media else 'unknown'
    except (OSError, _Cancelled, _InvalidResponse, ValueError) as error:
        if isinstance(error, _Cancelled) and not error.started and sock is None:
            row['attempts'] = 0
        row['status'] = 'not_run' if isinstance(error, _Deadline) else _status(error)
    finally:
        if sock is not None:
            sock.close()
    return row


def probe_hosts(hosts: list[str], ports: list[int], *, authorized: bool = False,
                attempts: int = 3, timeout: float = 2.0, urls: list[str] = (), cancel=None,
                deadline: float | None = None) -> list[dict]:
    """Probe only explicit endpoints after authorization and full validation.

    ``cancel`` may be a threading.Event or a no-argument Boolean callable.
    DNS subprocesses are killed/reaped on timeout or cancellation. Socket work
    uses total operation deadlines and polls cancellation at most every 50 ms.
    The limiter is shared by all TCP, TLS and HTTP connections within this call.
    ``deadline`` is an optional absolute monotonic request deadline; operations
    that cannot start before it are not_run and carry categorical timeout gaps.
    """
    if authorized is not True:
        raise ValueError('Explicit authorization is required for active probes.')
    original_hosts = hosts
    hosts, ports, urls = validate_request(hosts, ports, attempts, timeout, urls)
    if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
        raise ValueError('Deadline must be a finite monotonic timestamp.')
    explicit_hosts = {_host(host) for host in original_hosts}
    records, plans = [], {}
    for host in hosts:
        own_urls = [url for url in urls if _host(urlsplit(url).hostname) == host]
        endpoint_ports = list(dict.fromkeys((ports if host in explicit_hosts else []) +
                                           [_url_port(url) for url in own_urls]))
        if not endpoint_ports:
            raise ValueError('Each explicit host requires a port or a matching URL.')
        tls_ports = {port for port in endpoint_ports if port == 443}
        tls_ports.update(_url_port(url) for url in own_urls if urlsplit(url).scheme == 'https')
        plans[host] = endpoint_ports, own_urls, sorted(tls_ports)
    for host in hosts:
        try:
            _check_cancel(cancel)
            status, answers = _resolve(host, _remaining(timeout, deadline), cancel)
        except _Cancelled:
            status, answers = 'cancelled', []
        except _Deadline:
            status, answers = 'not_run', []
        answers = _answers(answers)
        record = dict(host=host, dns=dict(status=status, answers=answers),
                      tcp=[], tls=[], http=[], gaps=[])
        _gap(record, 'dns', status)
        _deadline_gap(record, 'dns', deadline)
        records.append(record)
    budget = sum(len(record['dns']['answers']) * (
                     len(plans[record['host']][0]) * attempts +
                     len(plans[record['host']][1]) + len(plans[record['host']][2]))
                 for record in records)
    if budget > 128:
        raise ValueError('Resolved request exceeds the 128 connection attempt budget.')
    limiter = _Limiter(cancel, deadline)
    for record in records:
        host = record['host']
        endpoint_ports, own_urls, tls_ports = plans[host]
        for answer in record['dns']['answers']:
            for port in endpoint_ports:
                row = _tcp(answer['address'], answer['family'], port, attempts, timeout, limiter, cancel)
                record['tcp'].append(row)
                _gap(record, 'tcp', row['status'])
                _deadline_gap(record, 'tcp', deadline)
            for port in tls_ports:
                row = _tls_probe(host, answer, port, timeout, limiter, cancel)
                record['tls'].append(row)
                _gap(record, 'tls', row['status'])
                _deadline_gap(record, 'tls', deadline)
            for url in own_urls:
                row = _http_probe(url, answer, timeout, limiter, cancel)
                record['http'].append(row)
                _gap(record, 'http', row['status'])
                _deadline_gap(record, 'http', deadline)
    return records


def _deadline_gap(record, source, deadline):
    if deadline is not None and time.monotonic() >= deadline:
        for gap in ('probe-timeout', source + '-timeout'):
            if gap not in record['gaps']:
                record['gaps'].append(gap)
