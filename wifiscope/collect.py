"""Read-only local evidence collection."""
from datetime import datetime, timezone
import ipaddress
import json
import os
import platform
import subprocess

from .audit import assess
from .wifi import decode_console, parse_netsh, parse_nmcli


def _list(value):
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def _addresses(value):
    result = []
    for item in value if isinstance(value, list) else [value]:
        if not isinstance(item, str):
            continue
        try:
            ipaddress.ip_address(item)
        except ValueError:
            continue
        result.append(item)
    return result


def collect_local() -> dict:
    system = platform.system()
    report = dict(schema_version=1, collected_at=datetime.now(timezone.utc).isoformat(),
                  platform=system, wifi=[], interfaces=[], routes=[], firewall=[],
                  environment={'proxy_configured': any(value for key, value in os.environ.items() if key.casefold() in ('http_proxy', 'https_proxy', 'all_proxy'))},
                  connectivity=[], findings=[], gaps=[])

    def gap(code):
        if code not in report['gaps']:
            report['gaps'].append(code)

    def run(command, source, as_json=False):
        try:
            result = subprocess.run(command, capture_output=True, timeout=8, check=False, shell=False)
            if result.returncode:
                gap(source + '-unavailable')
                return [] if as_json else ''
            text = decode_console(result.stdout)
            if as_json:
                parsed = json.loads(text)
                if parsed is not None and not isinstance(parsed, (list, dict)):
                    raise ValueError('invalid structured result')
                return _list(parsed)
            return text
        except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
            gap(source + '-unavailable')
            return [] if as_json else ''

    def powershell(script, source):
        # Fixed read-only queries. No caller-controlled shell text or saved keys.
        prefix = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();"
        return run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', prefix + script], source, True)

    if system == 'Windows':
        report['wifi'] = parse_netsh(run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 'wifi'))
        interfaces = powershell("Get-NetIPConfiguration | ForEach-Object { [pscustomobject]@{name=$_.InterfaceAlias;mac=$_.NetAdapter.MacAddress;addresses=@($_.IPv4Address.IPAddress)+@($_.IPv6Address.IPAddress);dns=@($_.DNSServer.ServerAddresses)} } | ConvertTo-Json -Depth 5 -Compress", 'interfaces')
        routes = powershell("Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | ForEach-Object {[pscustomobject]@{destination=$_.DestinationPrefix;gateway=$_.NextHop;interface=$_.InterfaceAlias;metric=$_.RouteMetric}} | ConvertTo-Json -Compress", 'routes')
        firewall = powershell("Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {[pscustomobject]@{name=$_.Name;enabled=$(switch ([string]$_.Enabled) {'True' {$true} 'False' {$false} default {$null}})}} | ConvertTo-Json -Compress", 'firewall')
        for row in interfaces:
            if isinstance(row, dict):
                report['interfaces'].append(dict(name=row.get('name') if isinstance(row.get('name'), str) else None,
                    mac=row.get('mac') if isinstance(row.get('mac'), str) else None,
                    addresses=_addresses(row.get('addresses')), dns=_addresses(row.get('dns'))))
        for row in routes:
            if isinstance(row, dict) and row.get('destination') in ('0.0.0.0/0', '::/0'):
                gateways = _addresses(row.get('gateway'))
                report['routes'].append(dict(destination=row['destination'], gateway=gateways[0] if gateways else None,
                    interface=row.get('interface') if isinstance(row.get('interface'), str) else None,
                    metric=row.get('metric') if type(row.get('metric')) is int else None))
        for row in firewall:
            if isinstance(row, dict) and row.get('name') in ('Public', 'Private', 'Domain'):
                report['firewall'].append(dict(name=row['name'], enabled=row.get('enabled') if type(row.get('enabled')) is bool else None))
    elif system == 'Linux':
        report['wifi'] = parse_nmcli(run(['nmcli', '-t', '--escape', 'yes', '-f', 'SSID,BSSID,SECURITY,SIGNAL,CHAN', 'device', 'wifi', 'list', '--rescan', 'no'], 'wifi'))
        for row in run(['ip', '-j', 'address', 'show'], 'interfaces', True):
            if isinstance(row, dict):
                address_info = row.get('addr_info')
                if not isinstance(address_info, list):
                    address_info = []
                    gap('interface-addresses-unavailable')
                report['interfaces'].append(dict(name=row.get('ifname') if isinstance(row.get('ifname'), str) else None,
                    mac=row.get('address') if isinstance(row.get('address'), str) else None,
                    addresses=_addresses([a.get('local') for a in address_info if isinstance(a, dict)]), dns=[]))
        # Query both families: ip's default route command otherwise returns IPv4 only.
        for family in ('-4', '-6'):
            for row in run(['ip', family, '-j', 'route', 'show', 'default'], 'routes', True):
                if isinstance(row, dict):
                    gateways = _addresses(row.get('gateway'))
                    report['routes'].append(dict(destination='0.0.0.0/0' if family == '-4' else '::/0',
                        gateway=gateways[0] if gateways else None,
                        interface=row.get('dev') if isinstance(row.get('dev'), str) else None,
                        metric=row.get('metric') if type(row.get('metric')) is int else None))
        gap('dns-unavailable')
        gap('firewall-unavailable')
    else:
        gap('platform-unsupported')
    for source in ('wifi', 'interfaces', 'routes', 'firewall'):
        if not report[source]:
            gap(source + '-unavailable')
    report['findings'] = assess(report)
    return report
