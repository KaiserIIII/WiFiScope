"""Read-only field evidence and one explicitly requested numeric ICMP probe."""

import ipaddress
import json
import math
import os
import platform
import re
import subprocess
import sys
import time

from .wifi import _security_value, decode_console

_COMMAND_TIMEOUT = 6
_WINDOWS_LINK_TIMEOUT = 14
_LINK_TIMEOUT = 20
_OUTPUT_LIMIT = 1 << 20
_PROXY_ENV = {'http_proxy', 'https_proxy', 'all_proxy'}
_DEFAULTS = {'0.0.0.0/0': 4, '::/0': 6}
_PS_PREFIX = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
              "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();")
_WINDOWS_LINK = r"""
$e = [ordered]@{interfaces=$null; routes=$null; dhcp=$null; tcp=$null; udp=$null; firewall=$null; wininet_proxy=$null}
try {
    $e.interfaces = @(Get-NetIPConfiguration | ForEach-Object {
        [pscustomobject]@{
            name=$_.InterfaceAlias; index=$_.InterfaceIndex
            addresses=@(@($_.IPv4Address)+@($_.IPv6Address) | Where-Object {$_ -and $_.IPAddress} |
                ForEach-Object {"$($_.IPAddress)/$($_.PrefixLength)"})
            dns=@($_.DNSServer | ForEach-Object {$_.ServerAddresses})
        }
    })
} catch {}
try {
    $e.routes = @(Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | ForEach-Object {
        [pscustomobject]@{index=$_.InterfaceIndex; destination=$_.DestinationPrefix; gateway=$_.NextHop; metric=$_.RouteMetric}
    })
} catch {}
try {
    $now = [datetime]::UtcNow
    $e.dhcp = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' | ForEach-Object {
        $seconds = $null
        $remaining = $null
        if ($_.DHCPEnabled -and $_.DHCPLeaseObtained -and $_.DHCPLeaseExpires) {
            $start = $_.DHCPLeaseObtained.ToUniversalTime()
            $end = $_.DHCPLeaseExpires.ToUniversalTime()
            $seconds = [long][math]::Floor(($end - $start).TotalSeconds)
            $remaining = [long][math]::Floor(($end - $now).TotalSeconds)
        }
        [pscustomobject]@{index=$_.InterfaceIndex; enabled=$_.DHCPEnabled; seconds=$seconds; remaining=$remaining}
    })
} catch {}
try {
    $e.tcp = @(Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | ForEach-Object {
        [pscustomobject]@{address=$_.LocalAddress; port=$_.LocalPort}
    })
} catch {}
try {
    $e.udp = @(Get-NetUDPEndpoint | ForEach-Object {
        [pscustomobject]@{address=$_.LocalAddress; port=$_.LocalPort}
    })
} catch {}
try {
    $e.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{name=$_.Name; enabled=$(switch ([string]$_.Enabled) {
            'True' {$true} 'False' {$false} default {$null}
        })}
    })
} catch {}
try {
    $settings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($settings.ProxyEnable -eq 1 -or $settings.AutoConfigURL) { $e.wininet_proxy = $true }
    else { $e.wininet_proxy = $false }
} catch {}
ConvertTo-Json -InputObject $e -Depth 5 -Compress
"""
_WINDOWS_NEIGHBORS = r"""
$entries = @(Get-NetNeighbor | ForEach-Object {
    [pscustomobject]@{interface=$_.InterfaceAlias; ip=$_.IPAddress; mac=$_.LinkLayerAddress; state=[string]$_.State}
})
ConvertTo-Json -InputObject $entries -Compress
"""


def _ps(script):
    return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', _PS_PREFIX + script]


def _cancelled(cancel):
    if cancel is None:
        return False
    return bool(cancel() if callable(cancel) else cancel.is_set())


def _invoke(argv, *, timeout: float = _COMMAND_TIMEOUT, cancel=None):
    """Return command status, return code, and bounded decoded output."""
    env = dict(os.environ, LC_ALL='C') if platform.system() == 'Linux' else None
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

    try:
        if cancel is None:
            process = subprocess.run(argv, capture_output=True, check=False, timeout=timeout,
                                     shell=False, env=env, creationflags=creationflags)
            code, raw = process.returncode, process.stdout
        else:
            if _cancelled(cancel):
                return 'cancelled', None, ''
            deadline = time.monotonic() + timeout
            with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  shell=False, env=env, creationflags=creationflags) as process:
                try:
                    while True:
                        if _cancelled(cancel):
                            return 'cancelled', None, ''
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return 'timeout', None, ''
                        try:
                            raw, _ = process.communicate(timeout=min(remaining, 0.1))
                            code = process.returncode
                            break
                        except subprocess.TimeoutExpired:
                            continue
                finally:
                    if process.poll() is None:
                        process.kill()
    except subprocess.TimeoutExpired:
        return 'timeout', None, ''
    except (OSError, subprocess.SubprocessError, ValueError):
        return 'unavailable', None, ''
    if len(raw) > _OUTPUT_LIMIT:
        return 'unavailable', None, ''
    return 'complete', code, decode_console(raw)


def _text(argv, *, timeout: float = _COMMAND_TIMEOUT, cancel=None):
    status, code, output = _invoke(argv, timeout=timeout, cancel=cancel)
    return output if status == 'complete' and code == 0 else None


def _structured(output, expected):
    if output is not None:
        try:
            value = json.loads(output)
        except (ValueError, RecursionError):
            return None
        if isinstance(value, expected):
            return value
    return None


def _records(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _ip(value, *, local=False):
    if isinstance(value, str):
        if local:
            value = value.partition('%')[0]
        elif '%' in value:
            return None
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None
    return None


def _cidr(value):
    if not isinstance(value, str) or '/' not in value:
        return None
    address, prefix = value.rsplit('/', 1)
    address = _ip(address, local=True)
    if address is None:
        return None
    try:
        return ipaddress.ip_interface(f'{address}/{prefix}')
    except ValueError:
        return None


def _ips(values):
    if not isinstance(values, list):
        return []
    return list(dict.fromkeys(str(ip) for value in values if (ip := _ip(value, local=True)) is not None))


def _mac(value):
    if not isinstance(value, str):
        return None
    value = value.lower().replace('-', ':')
    if (re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value)
            and value != '00:00:00:00:00:00' and int(value[:2], 16) & 1 == 0):
        return value
    return None


def _int(value, lower, upper):
    if isinstance(value, str) and re.fullmatch(r'-?[0-9]{1,12}', value):
        value = int(value)
    return value if type(value) is int and lower <= value <= upper else None


_WINDOWS_WLAN_LABELS = {
    'name': 'interface', '名称': 'interface', '名稱': 'interface',
    'state': 'state', '状态': 'state', '狀態': 'state',
    'ssid': 'ssid', 'bssid': 'bssid', 'ap bssid': 'bssid',
    'authentication': 'authentication', '身份验证': 'authentication', '驗證': 'authentication',
    '验证': 'authentication', '驗證方式': 'authentication',
    'cipher': 'cipher', 'encryption': 'cipher', '加密': 'cipher', '加密方式': 'cipher',
    '密码': 'cipher', '密碼': 'cipher',
    'channel': 'channel', '信道': 'channel', '频道': 'channel', '通道': 'channel',
    'signal': 'signal_percent', '信号': 'signal_percent', '訊號': 'signal_percent',
    'rssi': 'signal_dbm',
}


def _windows_associations(output):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([^:：]+?)\s*[:：] ?(.*)$', line)
        if not match:
            continue
        field = _WINDOWS_WLAN_LABELS.get(match[1].casefold())
        if field == 'interface':
            rows.append({})
        if field and rows:
            rows[-1][field] = match[2] if field == 'ssid' else match[2].strip()
    return [{
        'interface': row['interface'], 'ssid': row.get('ssid'), 'bssid': _mac(row.get('bssid')),
        'authentication': _security_value(row.get('authentication'), 'authentication'),
        'cipher': _security_value(row.get('cipher'), 'encryption'),
        'channel': _int(row.get('channel'), 1, 233),
        'signal_percent': _int(row.get('signal_percent', '').removesuffix('%').strip(), 0, 100),
        'signal_dbm': _int(row.get('signal_dbm', '').removesuffix('dBm').strip(), -127, -1),
    } for row in rows if row['interface'] and row.get('state', '').casefold() in
        ('connected', '已连接', '已連線', '已連接', '連線')]


def _linux_interface(value):
    return isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,14}', value) is not None


def _channel(frequency):
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 5005 <= frequency <= 5895 and frequency % 5 == 0:
        return (frequency - 5000) // 5
    if frequency == 5935:
        return 2
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    return None


def _linux_associations(interface, read):
    if interface is None:
        output = read(['iw', 'dev'])
        if output is None:
            return None
        names = re.findall(r'^\s+Interface (\S+)$', output, re.MULTILINE)[:8]
    else:
        names = [interface]
    rows = []
    failed = False
    for name in names:
        if not _linux_interface(name):
            continue
        output = read(['iw', 'dev', name, 'link'])
        if output is None:
            failed = True
            continue
        association = re.search(r'^Connected to (\S+)', output, re.MULTILINE)
        if not association:
            continue
        ssid = re.search(r'^\s*SSID: (.*)$', output, re.MULTILINE)
        frequency = re.search(r'^\s*freq: ([0-9]+)$', output, re.MULTILINE)
        signal = re.search(r'^\s*signal: (-?[0-9]+) dBm$', output, re.MULTILINE)
        mhz = _int(frequency[1], 0, 100000) if frequency else None
        rows.append({'interface': name, 'ssid': ssid[1] if ssid else None, 'bssid': _mac(association[1]),
                         'channel': _channel(mhz) if mhz is not None else None,
                         'signal_dbm': _int(signal[1], -127, -1) if signal else None})
    return None if failed and not rows else rows


def _routes(records):
    routes = []
    for row in records:
        family = _DEFAULTS.get(row.get('destination')) if isinstance(row.get('destination'), str) else None
        gateway = _ip(row.get('gateway'), local=True)
        if family is None or (gateway is not None and gateway.version != family):
            continue
        routes.append({'destination': row['destination'],
                           'gateway': str(gateway) if gateway and not gateway.is_unspecified else None,
                           'metric': _int(row.get('metric'), 0, 2**32 - 1)})
    return routes


def _listeners(by_protocol, addresses):
    selected = {address.ip for address in map(_cidr, addresses) if address is not None}
    result = set()
    for protocol, records in by_protocol.items():
        for row in _records(records):
            port = _int(row.get('port'), 1, 65535)
            raw = row.get('address')
            address = _ip(raw, local=True)
            if port is None or (address is None and raw != '*'):
                continue
            if address is None or address.is_unspecified:
                scope = 'wildcard'
            elif address.is_loopback:
                scope = 'loopback'
            elif address in selected:
                scope = 'interface'
            else:
                scope = 'other_address'
            result.add((protocol, port, scope))
    return [{'protocol': protocol, 'port': port, 'bind': scope} for protocol, port, scope in sorted(result)]


def _winhttp_proxy(output):
    if not output:
        return None
    if re.search(r'direct access \(no proxy server\)|直接访问\s*[（(]没有代理服务器|直接存取\s*[（(]沒有 Proxy 伺服器',
                 output, re.IGNORECASE):
        return False
    if re.search(r'^\s*(?:proxy server\(s\)|代理服务器|Proxy 伺服器)\s*[:：]\s*\S', output, re.IGNORECASE | re.MULTILINE):
        return True
    return None


def _apply_windows(link, requested, read):
    local = _structured(read(_ps(_WINDOWS_LINK), timeout=_WINDOWS_LINK_TIMEOUT), dict) or {}
    name = link['interface'] or requested
    interface = next((row for row in _records(local.get('interfaces')) if name and
                      isinstance(row.get('name'), str) and row['name'].casefold() == name.casefold()), {})
    if interface and link['interface'] is None:
        link['interface'] = interface['name']
    addresses = interface.get('addresses')
    link['addresses'] = list(dict.fromkeys(str(address) for value in addresses
                                          if (address := _cidr(value)) is not None)) if isinstance(addresses, list) else []
    link['dns'] = _ips(interface.get('dns'))
    index = _int(interface.get('index'), 1, 2**32 - 1)
    if index is not None:
        link['routes'] = _routes([row for row in _records(local.get('routes')) if row.get('index') == index])
        dhcp = next((row for row in _records(local.get('dhcp')) if row.get('index') == index), {})
        if type(dhcp.get('enabled')) is bool:
            link['dhcp_enabled'] = dhcp['enabled']
        if link['dhcp_enabled']:
            link['lease_seconds'] = _int(dhcp.get('seconds'), 1, 2**32 - 1)
            remaining = dhcp.get('remaining')
            if type(remaining) is int:
                link['lease_remaining_seconds'] = _int(max(0, remaining), 0, 2**32 - 1)
    link['listeners'] = _listeners({'tcp': local.get('tcp'), 'udp': local.get('udp')}, link['addresses'])
    for protocol in ('tcp', 'udp'):
        if not isinstance(local.get(protocol), list):
            link['gaps'].append(f'{protocol}-listeners-unavailable')
    link['firewall'] = {row['name']: row['enabled'] for row in _records(local.get('firewall'))
                        if row.get('name') in ('Public', 'Private', 'Domain') and type(row.get('enabled')) is bool}
    if type(local.get('wininet_proxy')) is bool:
        link['wininet_proxy_configured'] = local['wininet_proxy']
    link['winhttp_proxy_configured'] = _winhttp_proxy(read(['netsh.exe', 'winhttp', 'show', 'proxy']))
    proxy_values = (link['wininet_proxy_configured'], link['winhttp_proxy_configured'],
                    link['environment_proxy_configured'])
    link['proxy_configured'] = True if True in proxy_values else None if None in proxy_values else False
    if link['wininet_proxy_configured'] is None:
        link['gaps'].append('wininet-proxy-unavailable')
    if link['winhttp_proxy_configured'] is None:
        link['gaps'].append('winhttp-proxy-unavailable')


def _apply_linux(link, requested, read):
    name = link['interface'] or requested
    interface = {}
    if _linux_interface(name):
        interfaces = _records(_structured(read(['ip', '-j', 'address', 'show', 'dev', name]), list))
        interface = next((row for row in interfaces if row.get('ifname') == name), {})
        if interface:
            link['interface'] = name
    if link['interface'] is not None:
        for row in _records(interface.get('addr_info')):
            address = _cidr(f"{row.get('local')}/{row.get('prefixlen')}")
            if address is not None:
                link['addresses'].append(str(address))
        for family, destination in (('-4', '0.0.0.0/0'), ('-6', '::/0')):
            rows = _structured(read(['ip', family, '-j', 'route', 'show', 'default', 'dev', name]), list)
            if rows is None:
                link['gaps'].append('ipv4-routes-unavailable' if family == '-4' else 'ipv6-routes-unavailable')
            else:
                link['routes'].extend(_routes([dict(row, destination=destination)
                                              for row in _records(rows) if row.get('dev') == name]))
        output = read(['nmcli', '-t', '-e', 'no', '-f', 'IP4.DNS,IP6.DNS,DHCP4.OPTION', 'device', 'show', name])
        if output:
            link['dns'] = _ips(re.findall(r'^IP[46]\.DNS\[\d+\]:(\S+)$', output, re.MULTILINE))
            lease = re.search(r'^DHCP4\.OPTION\[\d+\]:dhcp_lease_time = ([0-9]+)$', output, re.MULTILINE)
            if lease:
                link['lease_seconds'] = _int(lease[1], 1, 2**32 - 1)
                if link['lease_seconds'] is not None:
                    link['dhcp_enabled'] = True
    output = read(['ss', '-H', '-lntu'])
    if output is None:
        link['gaps'].extend(['tcp-listeners-unavailable', 'udp-listeners-unavailable'])
    else:
        by_protocol = {'tcp': [], 'udp': []}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] not in by_protocol:
                continue
            address, _, port = fields[4].rpartition(':')
            by_protocol[fields[0]].append({'address': address.strip('[]'), 'port': port})
        link['listeners'] = _listeners(by_protocol, link['addresses'])
    if link['environment_proxy_configured']:
        link['proxy_configured'] = True


def read_link(interface=None, *, cancel=None) -> dict:
    """Observe current association and local host evidence with explicit gaps."""
    system = platform.system()
    if not isinstance(interface, str):
        interface = None
    link = {'interface': None, 'ssid': None, 'bssid': None, 'authentication': None, 'cipher': None,
                'channel': None, 'signal_dbm': None, 'signal_percent': None, 'addresses': [], 'gateways': [], 'dns': [],
                'routes': [], 'dhcp_enabled': None, 'lease_seconds': None, 'lease_remaining_seconds': None,
                'listeners': [], 'firewall': {}, 'proxy_configured': None, 'environment_proxy_configured': any(
                    bool(value) for key, value in os.environ.items() if key.casefold() in _PROXY_ENV),
                'wininet_proxy_configured': None, 'winhttp_proxy_configured': None, 'gaps': []}
    if _cancelled(cancel):
        link['gaps'].append('local-cancelled')
        return link
    deadline = time.monotonic() + _LINK_TIMEOUT

    def read(argv, *, timeout: float = _COMMAND_TIMEOUT):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        return _text(argv, timeout=min(timeout, remaining), cancel=cancel)

    if system == 'Windows':
        output = read(['netsh.exe', 'wlan', 'show', 'interfaces'])
        rows = _windows_associations(output) if output else None
        if isinstance(interface, str) and rows is not None:
            rows = [row for row in rows if row['interface'].casefold() == interface.casefold()]
    elif system == 'Linux':
        rows = _linux_associations(interface, read)
    else:
        link['gaps'].append('platform-unsupported')
        return link

    if rows and len(rows) == 1:
        link.update(rows[0])
    elif len(rows or []) > 1:
        link['gaps'].append('association-ambiguous')
    else:
        link['gaps'].append('association-unavailable')
    if not _cancelled(cancel):
        if system == 'Windows':
            _apply_windows(link, interface, read)
        else:
            _apply_linux(link, interface, read)
    if _cancelled(cancel):
        link['gaps'].append('local-cancelled')
    link['gateways'] = list(dict.fromkeys(row['gateway'] for row in link['routes'] if row['gateway']))

    for key in ('ssid', 'bssid', 'authentication', 'cipher', 'channel', 'signal_dbm', 'dhcp_enabled',
                'lease_seconds', 'lease_remaining_seconds', 'proxy_configured'):
        if link[key] is None:
            link['gaps'].append(key.replace('_', '-') + '-unavailable')
    for key in ('addresses', 'routes', 'dns', 'firewall'):
        if not link[key]:
            link['gaps'].append(key + '-unavailable')
    return link


def _cached_neighbors(interface, cancel):
    system = platform.system()
    if system == 'Windows':
        output = _structured(_text(_ps(_WINDOWS_NEIGHBORS), cancel=cancel), list)
    elif system == 'Linux' and _linux_interface(interface):
        output = _structured(_text(['ip', '-j', 'neigh', 'show', 'dev', interface], cancel=cancel), list)
    else:
        return None
    if output is None:
        return None
    entries = {}
    for row in _records(output):
        if system == 'Windows':
            alias = row.get('interface')
            if not isinstance(alias, str) or alias.casefold() != interface.casefold():
                continue
            address, mac, state = row.get('ip'), row.get('mac'), row.get('state')
        else:
            if row.get('dev', interface) != interface:
                continue
            address, mac, state = row.get('dst'), row.get('lladdr'), row.get('state')
        address = _ip(address, local=True)
        mac = _mac(mac)
        states = state if isinstance(state, list) else [state]
        states = {value.casefold() for value in states if isinstance(value, str)}
        if address is not None and mac and states.intersection(
                {'reachable', 'stale', 'delay', 'probe', 'permanent', 'noarp'}):
            entries.setdefault(address, set()).add(mac)
    return entries


def neighbor_comparison(link, targets, *, cancel=None) -> dict:
    """Classify existing same-interface entries without populating the cache."""
    name = link.get('interface')
    local = [address for value in link.get('addresses', []) if (address := _cidr(value)) is not None]
    gateways = [gateway for value in link.get('gateways', []) if (gateway := _ip(value, local=True)) is not None]
    rows, pending = [], []
    seen = set()
    for value in targets:
        target = _ip(value)
        if target is None or target in seen:
            continue
        seen.add(target)
        if not isinstance(name, str) or not name or not local:
            classification = 'link_unavailable'
        elif target in gateways:
            classification = 'gateway_target'
        elif any(target == address.ip for address in local):
            classification = 'local_target'
        elif not any(target in address.network for address in local):
            classification = 'not_on_link'
        else:
            classification = 'cache_unavailable'
            pending.append((len(rows), target))
        rows.append(dict(target=str(target), **{'class': classification}))
    if not pending:
        return {'status': 'unavailable' if any(row['class'] == 'link_unavailable' for row in rows)
                    else 'not_applicable', 'rows': rows}

    if _cancelled(cancel):
        return {'status': 'cancelled', 'rows': rows}
    cache = _cached_neighbors(name, cancel)
    if cache is None:
        return {'status': 'cancelled' if _cancelled(cancel) else 'unavailable', 'rows': rows}
    for index, target in pending:
        target_macs = cache.get(target, set())
        gateway_macs = {mac for gateway in gateways if gateway.version == target.version
                        for mac in cache.get(gateway, ())}
        if not target_macs:
            classification = 'no_target_entry'
        elif not gateway_macs:
            classification = 'no_gateway_entry'
        elif len(target_macs) > 1:
            classification = 'ambiguous_target_entry'
        elif len(gateway_macs) > 1:
            classification = 'ambiguous_gateway_entry'
        elif target_macs == gateway_macs:
            classification = 'shared_gateway_mac'
        else:
            classification = 'different_gateway_mac'
        rows[index]['class'] = classification
    return {'status': 'observed', 'rows': rows}


_WINDOWS_PING = """
$sender = [System.Net.NetworkInformation.Ping]::new()
try {
    $reply = $sender.Send([System.Net.IPAddress]::Parse('%s'), %d)
    ConvertTo-Json -Compress -InputObject @{status=[string]$reply.Status; address=[string]$reply.Address; ms=$reply.RoundtripTime}
} finally { $sender.Dispose() }
"""
# Windows ping.exe can select a source only for IPv6. Use the IP Helper API
# for a bound IPv4 request. Its fixed reply prefix is address, status, and RTT.
_BOUND_V4 = """
import ctypes
import ipaddress
import json
import struct
import sys

target, source, timeout = sys.argv[1:]
destination = int.from_bytes(ipaddress.IPv4Address(target).packed, sys.byteorder)
origin = int.from_bytes(ipaddress.IPv4Address(source).packed, sys.byteorder)
iphlp = ctypes.WinDLL('iphlpapi.dll', use_last_error=True)
u32, ptr = ctypes.c_uint32, ctypes.c_void_p
iphlp.IcmpCreateFile.restype = ptr
iphlp.IcmpCloseHandle.argtypes = [ptr]
iphlp.IcmpSendEcho2Ex.argtypes = [ptr, ptr, ptr, ptr, u32, u32, ptr, ctypes.c_uint16, ptr, ptr, u32, u32]
iphlp.IcmpSendEcho2Ex.restype = u32
handle = iphlp.IcmpCreateFile()
if handle in (None, ptr(-1).value):
    raise SystemExit(1)
try:
    data = ctypes.create_string_buffer(b'WiFiScope')
    reply = ctypes.create_string_buffer(512)
    count = iphlp.IcmpSendEcho2Ex(handle, None, None, None, origin, destination,
                                 data, len(data) - 1, None, reply, len(reply), int(timeout))
    if count:
        status, ms = struct.unpack_from('=II', reply, 4)
        print(json.dumps(dict(status=status, address=str(ipaddress.IPv4Address(reply.raw[:4])), ms=ms)))
    else:
        print(json.dumps(dict(status=ctypes.get_last_error())))
finally:
    iphlp.IcmpCloseHandle(handle)
"""
_UNREACHABLE_IP_STATUS = {
    'DestinationNetworkUnreachable', 'DestinationHostUnreachable', 'DestinationProtocolUnreachable',
    'DestinationPortUnreachable', 'DestinationProhibited', 'DestinationUnreachable',
    'DestinationScopeMismatch', 'BadRoute', 'TtlExpired', 'TtlReassemblyTimeExceeded',
    'TimeExceeded', 11002, 11003, 11004, 11005, 11012, 11013, 11014, 11040, 11041, 11045,
}


def _windows_echo(output, target):
    reply = _structured(output, dict)
    if not reply:
        return {'status': 'unavailable'}
    status = reply.get('status')
    if ((status == 'Success' or type(status) is int and status == 0)
            and _ip(reply.get('address'), local=True) == target):
        ms = _int(reply.get('ms'), 0, 2**32 - 1)
        return {'status': 'reply', 'ms': ms} if ms is not None else {'status': 'reply'}
    if status in ('TimedOut', 11010):
        return {'status': 'timeout'}
    if isinstance(status, (str, int)) and status in _UNREACHABLE_IP_STATUS:
        return {'status': 'unreachable'}
    return {'status': 'unavailable'}


def _linux_echo(output, target, code):
    if code == 0:
        for line in output.splitlines():
            match = re.fullmatch(r'[0-9]+ bytes from (\S+): icmp_seq=1\s+.*?time[=<]([0-9]+(?:\.[0-9]+)?) ms.*', line)
            if match and _ip(match[1], local=True) == target:
                return {'status': 'reply', 'ms': float(match[2])}
    if re.search(r'^From .*icmp_seq=1\s+.*(?:unreachable|time exceeded|prohibited)', output, re.IGNORECASE | re.MULTILINE):
        return {'status': 'unreachable'}
    if code == 1 and re.search(r'^1 packets transmitted, 0 (?:packets )?received\b', output, re.MULTILINE):
        return {'status': 'timeout'}
    return {'status': 'unavailable'}


def _windows_v6_echo(output, target, code):
    if code == 0:
        for line in output.splitlines():
            match = re.fullmatch(r'(?:Reply from|来自|來自)\s*(\S+?)\s*(?:的回复|的回覆)?[:：]\s*'
                                 r'(?:time|时间|時間)\s*[=<＜]\s*([0-9]+)\s*ms\s*', line, re.IGNORECASE)
            if match and _ip(match[1], local=True) == target:
                return {'status': 'reply', 'ms': int(match[2])}
    if re.search(r'request timed out|请求超时|要求等候逾時', output, re.IGNORECASE):
        return {'status': 'timeout'}
    if re.search(r'destination (?:host|network) unreachable|无法访问目标主机|無法連線到目的地主機', output, re.IGNORECASE):
        return {'status': 'unreachable'}
    return {'status': 'unavailable'}


def _probe_address(value):
    address = _ip(value)
    if (address is None or address.is_multicast or address.is_unspecified
            or address == ipaddress.IPv4Address('255.255.255.255')
            or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None):
        return None
    return address


def echo_probe(target, *, timeout=1.0, cancel=None, source=None) -> dict:
    """Send one echo to a validated numeric destination, optionally bound."""
    target = _probe_address(target)
    origin = _probe_address(source) if source is not None else None
    if target is None or (source is not None and (origin is None or target.version != origin.version)):
        return {'status': 'invalid_target'}
    if _cancelled(cancel):
        return {'status': 'cancelled'}
    if type(timeout) not in (int, float) or not 0 < timeout <= 10:
        return {'status': 'unavailable'}
    system = platform.system()
    milliseconds = math.ceil(timeout * 1000)
    if system == 'Windows' and origin is None:
        argv = _ps(_WINDOWS_PING % (target, milliseconds))
    elif system == 'Windows' and target.version == 4:
        argv = [sys.executable, '-I', '-c', _BOUND_V4, str(target), str(origin), str(milliseconds)]
    elif system == 'Windows':
        argv = ['ping.exe', '-6', '-n', '1', '-w', str(milliseconds), '-S', str(origin), str(target)]
    elif system == 'Linux':
        argv = ['ping', f'-{target.version}', '-n', '-c', '1', '-W', str(milliseconds / 1000)]
        if origin is not None:
            argv.extend(['-I', str(origin)])
        argv.append(str(target))
    else:
        return {'status': 'unavailable'}

    status, code, output = _invoke(argv, timeout=timeout + (3 if system == 'Windows' else 1), cancel=cancel)
    if status != 'complete':
        # Process deadline gives no evidence that a request was sent.
        return {'status': 'unavailable' if status == 'timeout' else status}
    if system == 'Linux':
        return _linux_echo(output, target, code)
    if origin is not None and target.version == 6:
        return _windows_v6_echo(output, target, code)
    return _windows_echo(output, target) if code == 0 else {'status': 'unavailable'}
