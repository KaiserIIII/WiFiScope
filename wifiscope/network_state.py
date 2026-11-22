"""Local network inventory and a bounded numeric hop observation."""

import math
import platform
import re
import time
from ipaddress import ip_network

from .field_link import (
    _cancelled,
    _cidr,
    _int,
    _invoke,
    _ip,
    _ips,
    _mac,
    _probe_address,
    _ps,
    _records,
    _structured,
    _text,
)

_WINDOWS_STATE = r"""
$e = [ordered]@{interfaces=$null; routes=$null; neighbors=$null; tcp=$null; udp=$null}
try {
    $e.interfaces = @(Get-NetIPConfiguration -All | ForEach-Object {
        [pscustomobject]@{
            interface=$_.InterfaceAlias; index=$_.InterfaceIndex; state=[string]$_.NetAdapter.Status
            addresses=@(@($_.IPv4Address)+@($_.IPv6Address) | Where-Object {$_ -and $_.IPAddress} |
                ForEach-Object {"$($_.IPAddress)/$($_.PrefixLength)"})
            dns=@($_.DNSServer | ForEach-Object {$_.ServerAddresses})
        }
    })
} catch {}
try {
    $e.routes = @(Get-NetRoute -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{interface=$_.InterfaceAlias; index=$_.InterfaceIndex; destination=$_.DestinationPrefix
            gateway=$_.NextHop; metric=$_.RouteMetric; protocol=[string]$_.Protocol}
    })
} catch {}
try {
    $e.neighbors = @(Get-NetNeighbor | ForEach-Object {
        [pscustomobject]@{interface=$_.InterfaceAlias; index=$_.InterfaceIndex
            ip=$_.IPAddress; mac=$_.LinkLayerAddress; state=[string]$_.State}
    })
} catch {}
try {
    $e.tcp = @(Get-NetTCPConnection -State Listen | ForEach-Object {
        [pscustomobject]@{address=$_.LocalAddress; port=$_.LocalPort; pid=$_.OwningProcess}
    })
} catch {}
try {
    $e.udp = @(Get-NetUDPEndpoint | ForEach-Object {
        [pscustomobject]@{address=$_.LocalAddress; port=$_.LocalPort; pid=$_.OwningProcess}
    })
} catch {}
ConvertTo-Json -InputObject $e -Depth 5 -Compress
"""
_TRACE_DEADLINE = 30.0
_HOP_LINE = re.compile(r'^\s*([0-9]{1,2})\s+(\S.*?)\s*$')
_HOP_RTT = re.compile(r'([<＜])?\s*([0-9]{1,9}(?:[.,][0-9]{1,5})?)\s*(?:ms\b|毫秒)', re.IGNORECASE)
_UNREACHABLE = re.compile(r'![A-Z0-9]+\b|\bunreachable\b|无法访问|無法連線|不可达|無法到達', re.IGNORECASE)


def _label(value):
    if isinstance(value, str) and value.strip() and len(value) <= 256 and value.isprintable():
        return value.strip()
    return None


def _index(value):
    return _int(value, 1, 2**32 - 1)


def _interface(row):
    name = _label(row.get('interface'))
    if name is None:
        return None
    addresses = row.get('addresses')
    if not isinstance(addresses, list):
        addresses = []
    return {'interface': name, 'index': _index(row.get('index')),
            'state': _label(row.get('state')),
            'addresses': list(dict.fromkeys(str(address) for value in addresses
                                           if (address := _cidr(value)) is not None)),
            'dns': _ips(row.get('dns'))}


def _linux_interface(row):
    addresses = [f"{item.get('local')}/{item.get('prefixlen')}" for item in _records(row.get('addr_info'))]
    return _interface({'interface': row.get('ifname'), 'index': row.get('ifindex'),
                       'state': row.get('operstate'), 'addresses': addresses})


def _gateway(row):
    via = row.get('via')
    gateway = row.get('gateway') or (via.get('host') if isinstance(via, dict) else None)
    address = _ip(gateway, local=True)
    return str(address) if address is not None and not address.is_unspecified else None


def _route(row, family=None):
    linux = family is not None
    raw = row.get('dst' if linux else 'destination')
    if raw == 'default' and linux:
        raw = '0.0.0.0/0' if family == 4 else '::/0'
    if not isinstance(raw, str) or len(raw) > 128:
        return None
    try:
        destination = ip_network(raw, strict=False)
    except ValueError:
        return None
    if linux and destination.version != family:
        return None
    table = row.get('table', 'main') if linux else 'active'
    nexthops = [{'gateway': _gateway(hop), 'interface': _label(hop.get('dev')),
                 'weight': _int(hop.get('weight'), 1, 2**32 - 1)}
                for hop in _records(row.get('nexthops'))]
    source = _ip(row.get('prefsrc'), local=True)
    return {'destination': str(destination), 'family': destination.version, 'gateway': _gateway(row),
            'interface': _label(row.get('dev' if linux else 'interface')), 'index': _index(row.get('index')),
            'metric': _int(row.get('metric'), 0, 2**32 - 1),
            'table': table if type(table) is int else _label(table), 'protocol': _label(row.get('protocol')),
            'type': _label(row.get('type')), 'preferred_source': str(source) if source is not None else None,
            'nexthops': nexthops}


def _neighbor(row, linux):
    address = _ip(row.get('dst' if linux else 'ip'), local=True)
    if address is None:
        return None
    state = row.get('state')
    labels = state if isinstance(state, list) else [state]
    states = list(dict.fromkeys(label.casefold() for value in labels if (label := _label(value))))
    return {'ip': str(address), 'interface': _label(row.get('dev' if linux else 'interface')),
            'index': _index(row.get('index')), 'mac': _mac(row.get('lladdr' if linux else 'mac')),
            'state': states}


def _listeners(records, protocol):
    rows = []
    for row in _records(records):
        raw = row.get('address')
        address = _ip(raw, local=True)
        port = _int(row.get('port'), 1, 65535)
        if port is None or (address is None and raw != '*'):
            continue
        if address is None or address.is_unspecified:
            bind = 'wildcard'
        else:
            bind = 'loopback' if address.is_loopback else 'specific'
        rows.append({'protocol': protocol, 'address': str(address) if address is not None else '*',
                     'port': port, 'bind': bind, 'pid': _int(row.get('pid'), 0, 2**32 - 1)})
    return rows


def _linux_sockets(output):
    if output is None:
        return {}
    protocols = {'tcp': [], 'udp': []}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0] in protocols:
            address, _, port = parts[4].rpartition(':')
            protocols[parts[0]].append({'address': address.strip('[]'), 'port': port})
    return protocols


def _local_windows(read, add):
    output = _structured(read(_ps(_WINDOWS_STATE), maximum=14), dict) or {}
    add('interfaces', 'interfaces', output.get('interfaces'), _interface)
    add('routes', 'routes', output.get('routes'), _route)
    add('neighbors', 'neighbors', output.get('neighbors'), lambda row: _neighbor(row, False))
    return output


def _local_linux(read, add):
    add('interfaces', 'interfaces', _structured(read(['ip', '-j', 'address', 'show']), list), _linux_interface)
    for family in (4, 6):
        routes = _structured(read(['ip', f'-{family}', '-j', 'route', 'show', 'table', 'all']), list)
        add('routes', f'ipv{family}-routes', routes, lambda row, version=family: _route(row, version))
    neighbors = _structured(read(['ip', '-j', 'neigh', 'show']), list)
    add('neighbors', 'neighbors', neighbors, lambda row: _neighbor(row, True))
    return _linux_sockets(read(['ss', '-H', '-lntu']))


def read_local_network(*, cancel=None):
    """Read local interfaces, active routes, cached neighbors and listening sockets."""
    system = platform.system()
    report = {'platform': system, 'status': 'unknown', 'interfaces': [], 'routes': [],
              'neighbors': [], 'listeners': [], 'gaps': []}
    available = []
    deadline = time.monotonic() + 14

    def read(argv, *, maximum=4):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or _cancelled(cancel):
            return None
        return _text(argv, timeout=min(remaining, maximum), cancel=cancel)

    def add(key, source, records, parse):
        if isinstance(records, list):
            available.append(source)
            rows = [value for row in _records(records) if (value := parse(row)) is not None]
            report[key].extend(rows)
            if len(rows) != len(records):
                report['gaps'].append(f'{source}-incomplete')
        else:
            report['gaps'].append(f'{source}-unavailable')

    if _cancelled(cancel):
        report.update(status='cancelled', gaps=['local-cancelled'])
        return report
    readers = {'Windows': _local_windows, 'Linux': _local_linux}
    if system not in readers:
        report['gaps'].append('platform-unsupported')
        return report
    sockets = readers[system](read, add)
    for protocol in ('tcp', 'udp'):
        records = sockets.get(protocol)
        if isinstance(records, list):
            available.append(f'{protocol}-listeners')
            listeners = _listeners(records, protocol)
            report['listeners'].extend(listeners)
            if len(listeners) != len(records):
                report['gaps'].append(f'{protocol}-listeners-incomplete')
        else:
            report['gaps'].append(f'{protocol}-listeners-unavailable')
    if _cancelled(cancel):
        report['status'] = 'cancelled'
    elif available:
        report['status'] = 'partial' if report['gaps'] else 'ok'
    return report


def _hops(output, max_hops):
    found = {}
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if not match or not 1 <= int(match[1]) <= max_hops:
            continue
        hop = int(match[1])
        body = match[2]
        timings = list(_HOP_RTT.finditer(body))
        addresses = list(dict.fromkeys(str(address) for word in body.split()
                                      if (address := _ip(word.strip('[](),'), local=True)) is not None))
        if not addresses and not timings and '*' not in body:
            continue
        status = 'unreachable' if _UNREACHABLE.search(body) else 'reply' if addresses else 'no_reply'
        found[hop] = {'hop': hop, 'status': status, 'addresses': addresses,
                      'rtt_ms': [float(timing[2].replace(',', '.')) for timing in timings],
                      'rtt_less_than': [bool(timing[1]) for timing in timings]}
    return [found[hop] for hop in sorted(found)]


def trace_path(target, *, timeout, max_hops, authorized=False, source=None, cancel=None):
    """Perform one authorized numeric trace with no reverse DNS and a hard deadline."""
    address = _probe_address(target)
    origin = _probe_address(source) if source is not None else None
    if authorized is not True:
        raise ValueError('Explicit authorization is required for active tracing.')
    if (address is None or (source is not None and (origin is None or address.version != origin.version))
            or type(timeout) not in (int, float) or not .2 <= timeout <= 5
            or type(max_hops) is not int or not 1 <= max_hops <= 30):
        raise ValueError('Invalid numeric trace target, source, timeout or hop limit.')
    result = {'target': str(address), 'method': 'icmp-trace', 'status': 'unknown',
              'observation': 'platform_unsupported', 'reached': None, 'hops': []}
    if _cancelled(cancel):
        return dict(result, status='cancelled', observation='cancelled')
    system = platform.system()
    if system == 'Windows':
        if origin is not None and address.version == 4:
            return dict(result, observation='source_binding_unavailable')
        argv = ['tracert.exe', '-d', f'-{address.version}', '-h', str(max_hops), '-w', str(math.ceil(timeout * 1000))]
        if origin is not None:
            argv.extend(['-S', str(origin)])
        probes_per_hop = 3
    elif system == 'Linux':
        argv = ['traceroute', f'-{address.version}', '-n', '-I', '-q', '1', '-m', str(max_hops), '-w', f'{timeout:.3f}']
        if origin is not None:
            argv.extend(['-s', str(origin)])
        probes_per_hop = 1
    else:
        return result
    argv.append(str(address))
    limit = min(_TRACE_DEADLINE, max_hops * probes_per_hop * timeout + 3)
    status, code, output = _invoke(argv, timeout=limit, cancel=cancel)
    if status == 'cancelled':
        return dict(result, status='cancelled', observation='cancelled')
    if status != 'complete':
        return dict(result, observation='process_deadline' if status == 'timeout' else 'trace_unavailable')
    hops = _hops(output, max_hops)
    reached = any(str(address) in hop['addresses'] and hop['status'] == 'reply' for hop in hops)
    if reached:
        return dict(result, hops=hops, reached=True, status='ok', observation='destination_reply')
    if not hops:
        return dict(result, observation='command_failed' if code else 'hop_output_unavailable')
    if all(hop['status'] == 'no_reply' for hop in hops):
        return dict(result, hops=hops, reached=False, status='failed', observation='no_hop_reply')
    return dict(result, hops=hops, reached=False, status='partial', observation='destination_unconfirmed')
