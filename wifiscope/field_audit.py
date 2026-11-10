"""Bounded campus evidence, with independent observations for each layer."""
import math
import re
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface
from urllib.parse import urlsplit

from . import probe
from .field_link import echo_probe, neighbor_comparison, read_link

_GATEWAY_PORTS = (22, 23, 830)
_PEER_PORTS = (445, 3389, 8080)
_SSH_LINE = re.compile(rb'^SSH-(1\.[0-9]{1,2}|2\.0)-([!-~]{1,100})(?:[ \t][^\r\n]*)?\r?\n')
_TELNET_NEGOTIATION = re.compile(rb'\xff[\xfb-\xfe][\x00-\xff]')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _ip(value):
    if value is None:
        return None
    host = probe._host(value)
    try:
        address = ip_address(host)
    except ValueError:
        raise ValueError('Field IP targets must be numeric addresses.') from None
    if address.version == 6 and address.ipv4_mapped:
        raise ValueError('Use native IPv4 for an IPv4-mapped address.')
    return str(address)


def _family(address):
    return 'IPv6' if ':' in address else 'IPv4'


def _ports(values):
    if not 1 <= len(values) <= 8 or any(type(p) is not int or not 1 <= p <= 65535 for p in values):
        raise ValueError('Specify 1 to 8 ports between 1 and 65535.')
    return tuple(dict.fromkeys(values))


def _stopped(cancel):
    try:
        probe._check_cancel(cancel)
    except probe._Cancelled:
        return True
    return False


def _pause(interval, cancel):
    until = time.monotonic() + interval
    while not _stopped(cancel):
        left = until - time.monotonic()
        if left <= 0:
            return True
        time.sleep(min(.05, left))
    return False


def _server_protocol(data):
    match = _SSH_LINE.match(data)
    if match:
        product = match[2].lower()
        known = next((label for prefix, label in (
            (b'rgos_ssh', 'RGOS SSH'), (b'openssh_', 'OpenSSH'), (b'dropbear_', 'Dropbear')
        ) if product.startswith(prefix)), None)
        return {'protocol': 'ssh', 'ssh_version': match[1].decode('ascii'), 'product_hint': known}
    if _TELNET_NEGOTIATION.search(data):
        lower = data.lower()
        prompt = any(marker in lower for marker in (b'user access verification', b'username:', b'login:'))
        return {'protocol': 'telnet', 'login_prompt': prompt}
    return {'protocol': 'unknown'}


def _tcp_row(address, port, timeout, limiter, cancel, source, *, identify=False):
    row = {'port': port, 'observed_at': _now(), 'status': 'not-run'}
    if identify:
        row['protocol'] = 'unknown'
    try:
        limiter.wait()
        started = time.monotonic()
        deadline = started + timeout
        with probe._connect(address, _family(address), port, timeout, cancel, source=source) as sock:
            row.update(status='reachable', ms=round((time.monotonic() - started) * 1000, 2))
            if identify:
                data = bytearray()
                while len(data) < 512:
                    try:
                        piece = probe._operation(sock, lambda: sock.recv(512 - len(data)),
                                                 True, deadline, cancel)
                    except (OSError, probe._Cancelled):
                        break
                    if not piece:
                        break
                    data.extend(piece)
                    evidence = _server_protocol(data)
                    if evidence['protocol'] == 'ssh' or evidence.get('login_prompt'):
                        break
                row.update(_server_protocol(data))
    except (OSError, probe._Cancelled) as error:
        row['status'] = probe._status(error)
    return row


def _portal_rows(urls, samples, interval, timeout, limiter, cancel, source):
    from .field_path import _start_tls

    resolved = {}
    rows = []
    for index in range(samples):
        if index and not _pause(interval, cancel):
            break
        for url in urls:
            if _stopped(cancel):
                return rows
            parsed = urlsplit(url)
            host = parsed.hostname
            if host not in resolved:
                try:
                    status, answers = probe._resolve(host, timeout, cancel)
                except probe._Cancelled:
                    return rows
                answers = [a for a in probe._answers(answers)
                           if source is None or a['family'] == _family(source)]
                if status == 'ok' and answers:
                    resolved[host] = status, answers
            else:
                status, answers = resolved[host]
            base = {'target': url, 'sample': index + 1, 'transport': parsed.scheme}
            if not answers:
                rows.append(dict(base, status=status if status != 'ok' else 'no-compatible-address',
                                 observed_at=_now(), family=None, http_status=None, has_location=None))
            for answer in answers:
                if _stopped(cancel):
                    return rows
                result = probe._http_probe(url, answer, timeout, limiter, cancel, source=source,
                                           tls_starter=_start_tls)
                rows.append(dict(base, observed_at=_now(), address=answer['address'],
                                 family=answer['family'], status=result['status'],
                                 http_status=result['status_code'],
                                 has_location=result['header_presence'].get('location')))
    return rows


def isolation_state(peers, neighbors):
    if not peers:
        return 'not-tested'
    classes = {r.get('target'): r.get('class') for r in neighbors}
    reachable = [peer for peer in peers if any(t['status'] == 'reachable' for t in peer['tcp'])]
    if reachable:
        shared = any(classes.get(peer.get('target')) == 'shared_gateway_mac' for peer in reachable)
        return 'tcp-reachable-with-shared-mac' if shared else 'tcp-reachable'
    if any(peer['icmp']['status'] == 'reply' for peer in peers):
        return 'icmp-only'
    return 'inconclusive'


def run_field(*, gateway=None, gateway_ports=_GATEWAY_PORTS, portals=(), peers=(),
              peer_ports=_PEER_PORTS, samples=3, interval=1, timeout=2, interface=None,
              source=None, dns=None, ntp=None, doh=None, download=None, authorized=False,
              cancel=None):
    """Collect local context, then run the exact explicitly authorized plan."""
    if len(portals) > 2 or len(peers) > 8:
        raise ValueError('Use at most two portal URLs and eight peer addresses.')
    if type(samples) is not int or not 1 <= samples <= 6:
        raise ValueError('Use 1 to 6 portal samples.')
    if type(interval) not in (int, float) or not math.isfinite(interval) or not .25 <= interval <= 10:
        raise ValueError('Portal interval must be 0.25 to 10 seconds.')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not .2 <= timeout <= 5:
        raise ValueError('Timeout must be 0.2 to 5 seconds.')
    if interface is not None and (not isinstance(interface, str) or not interface.strip()
                                 or len(interface) > 128 or any(ord(c) < 32 for c in interface)):
        raise ValueError('Invalid interface name.')
    active = bool(gateway or portals or peers or dns or ntp or doh or download)
    if active and authorized is not True:
        raise ValueError('Explicit authorization is required for field probes.')
    gateway, source = _ip(gateway), _ip(source)
    peers = tuple(dict.fromkeys(_ip(p) for p in peers))
    if any(peer is None for peer in peers):
        raise ValueError('Peer addresses cannot be empty.')
    if any('%' in value for value in (*peers, source) if value):
        raise ValueError('Scoped addresses are currently supported by the paired check only.')
    if source and any(_family(t) != _family(source) for t in (gateway, *peers) if t):
        raise ValueError('Source and numeric target address families must match.')
    portals = tuple(dict.fromkeys(probe._url(url) for url in portals))
    gateway_ports, peer_ports = _ports(gateway_ports), _ports(peer_ports)
    path = {'dns': dns, 'ntp': ntp, 'doh': doh, 'download': download, 'source': source, 'timeout': timeout}
    path_enabled = any(v is not None for v in (dns, ntp, doh, download))
    if path_enabled:
        from .field_path import validate_path_plan
        validate_path_plan(**path)
    if active and interface is not None and source is None:
        raise ValueError('Supply a source address for an explicitly selected interface.')
    at = _now()
    link = read_link(interface, cancel=cancel) if not _stopped(cancel) else {'gaps': ['local-not-run']}
    source_status = 'system-selected'
    if active and source and not _stopped(cancel):
        link_addresses = {str(ip_interface(item).ip) for item in link.get('addresses', [])}
        if (link_addresses or interface is not None) and source not in link_addresses:
            raise ValueError('The source address is unavailable on the selected local link.')
        source_status = 'bound-link-address' if source in link_addresses else 'bound-interface-unverified'
    limiter = probe._Limiter(cancel)
    report = {'schema_version': 1, 'kind': 'campus-field-audit', 'started_at': at, 'link': link,
                  'gateway': None, 'portal': [], 'peer_sample': [], 'neighbor': None,
                  'isolation': 'not-tested', 'path': None}
    if gateway and not _stopped(cancel):
        rows = []
        for port in gateway_ports:
            if _stopped(cancel):
                break
            rows.append(_tcp_row(gateway, port, timeout, limiter, cancel, source, identify=True))
        report['gateway'] = {'target': gateway, 'ports': rows, 'planned_ports': list(gateway_ports)}
    report['portal'] = _portal_rows(portals, samples, interval, timeout, limiter, cancel, source) if portals else []
    for target in peers:
        if _stopped(cancel):
            break
        icmp = echo_probe(target, timeout=timeout, cancel=cancel, source=source)
        rows = []
        for port in peer_ports:
            if _stopped(cancel):
                break
            rows.append(_tcp_row(target, port, timeout, limiter, cancel, source))
        report['peer_sample'].append({'target': target, 'observed_at': _now(), 'icmp': icmp, 'tcp': rows})
    if peers and not _stopped(cancel):
        report['neighbor'] = neighbor_comparison(link, peers, cancel=cancel)
    neighbors = (report['neighbor'] or {}).get('rows', [])
    report['isolation'] = isolation_state(report['peer_sample'], neighbors)
    if path_enabled and not _stopped(cancel):
        from .field_path import path_checks
        report['path'] = path_checks(**path, authorized=True, cancel=cancel)
    report['plan'] = {'gateway': gateway, 'gateway_ports': list(gateway_ports) if gateway else [],
                          'portals': len(portals), 'portal_targets': list(portals),
                          'portal_samples': samples if portals else 0,
                          'peers': len(peers), 'peer_targets': list(peers),
                          'peer_ports': list(peer_ports) if peers else [],
                          'path_targets': [{'method': name, 'target': str(path[name])}
                                        for name in ('dns', 'ntp', 'doh', 'download') if path[name] is not None],
                          'source': source, 'source_status': source_status, 'timeout_seconds': timeout}
    report.update(ended_at=_now(), status='cancelled' if _stopped(cancel) else 'complete')
    return report
