"""Parse bounded, local Cisco IOS evidence without executing commands."""

import ctypes
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .network_device_config import ConfigBanner, config_preview, project_config
from .network_device_values import (
    area_id,
    interface_address,
    interface_name,
    ip_network,
    ipv4,
    vlan_id,
    vlan_name,
)

MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_LINES = 30_000
MAX_EVIDENCE_LINE_LENGTH = 8192

_COMMANDS = {
    'vlans': 'show vlan brief',
    'trunks': 'show interfaces trunk',
    'routes': 'show ip route',
    'ospf_neighbors': 'show ip ospf neighbor',
    'ospf_interfaces': 'show ip ospf interface',
    'ospf_lsdb': 'show ip ospf database',
    'lldp_neighbors': 'show lldp neighbors',
    'config': 'show running-config',
}

_COMMAND_PATTERNS = {
    'vlans': r'vlan(?:\s+brief)?',
    'trunks': r'int(?:erfaces?)?\s+trunk',
    'routes': r'ip\s+route(?:\s+vrf\s+\S+)?',
    'ospf_neighbors': r'ip\s+ospf\s+neighbors?',
    'ospf_interfaces': r'ip\s+ospf\s+int(?:erfaces?)?(?:\s+brief)?',
    'ospf_lsdb': r'ip\s+ospf\s+database',
    'lldp_neighbors': r'lldp\s+neighbors?',
    'config': r'(?:running-config|run|startup-config|start)',
}

_PROMPT = re.compile(r'^(?P<host>[a-z0-9][a-z0-9_.-]{0,62})(?:\([a-z0-9_.-]{1,40}\))?[#>]\s*(?P<body>.*)$', re.IGNORECASE)
_SHOW = re.compile(r'^(?:show|sh)\s+(.*)$', re.IGNORECASE)
_VLAN_HEADER = re.compile(r'^VLAN\s+Name\s+Status\s+Ports(?:\s|$)', re.IGNORECASE)
_VLAN_ROW = re.compile(r'^(\d{1,4})\s+(.+?)\s+(active|act/\S+|sus(?:pend(?:ed)?)?|shutdown|inactive)\b\s*(.*)$', re.IGNORECASE)
_TRUNK_HEADER = re.compile(r'^Port\s+(Mode\s+Encapsulation|Vlans\s+).+', re.IGNORECASE)
_ROUTE_HEADER = re.compile(r'^(?:Codes:|Gateway of last resort\b|Routing Table:)', re.IGNORECASE)
_IP = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
_ROUTE_ROW = re.compile(r'^([A-Z][A-Z0-9]*|i)(?:[*+%&]*\s*(IA|E[12]|N[12]|L[12]|EX|i[12]|su|ia))?'
                        r'[*+%&]*\s+(' + _IP + r'(?:/[0-9]{1,2})?)\s+(.+)$')
_SUBNET_HEADING = re.compile(r'^(' + _IP + r'/[0-9]{1,2})\s+is\s+(variably\s+)?subnetted,\s+\d+\s+subnet', re.IGNORECASE)
_NEIGHBOR_HEADER = re.compile(r'^(?:Neighbor\s+)?ID\s+Pri\s+State\s+Dead\s+Time\s+Address\s+Interface\b', re.IGNORECASE)
_NEIGHBOR_ROW = re.compile(r'^(' + _IP + r')\s+(\d{1,3})\s+([A-Z0-9-]+)(?:/\s*([A-Z-]+))?\s+'
                           r'(?:[0-9:]+|-)\s+(' + _IP + r')\s+(\S+)$', re.IGNORECASE)
_OSPF_IF_HEADER = re.compile(r'^Interface\s+PID\s+Area\s+IP\s+Address/Mask\s+Cost\s+State\b', re.IGNORECASE)
_OSPF_IF_ROW = re.compile(r'^(\S+)\s+is\s+[\w -]+,\s+line protocol is\s+[\w -]+', re.IGNORECASE)
_LSDB_HEADER = re.compile(r'^OSPF Router with ID\s+\((' + _IP + r')\)\s+\(Process ID\s+(\d{1,5})\)', re.IGNORECASE)
_LSDB_TYPE = re.compile(r'^(.+?) Link States(?:\s+\(Area\s+([0-9.]+)\))?$', re.IGNORECASE)
_LSDB_TYPES = {
    'router': 'router', 'net': 'network', 'network': 'network', 'summary net': 'summary_network',
    'summary asb': 'summary_asbr', 'type-5 as external': 'as_external', 'type-5 external': 'as_external',
    'type-7 as external': 'nssa_external', 'type-7 nssa external': 'nssa_external', 'type-7 nssa': 'nssa_external',
    'opaque link': 'opaque_link', 'opaque area': 'opaque_area', 'opaque as': 'opaque_as',
}
_LLDP_HEADER = re.compile(r'^Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID', re.IGNORECASE)
_CONFIG_START = re.compile(r'^(?:building configuration|current configuration|version\s+\d|vlan\s+\d|banner\s+\S'
                           r'|interface\s+\S|router\s+ospf\s+\d)', re.IGNORECASE)
_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_SEPARATOR = re.compile(r'[-= ]{3,}')
_SAFE_TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}')


@dataclass
class _Block:
    section: str
    device: str = ''
    filtered: bool = False
    vrf: str = ''
    lines: list = field(default_factory=list)


@dataclass
class _Rows:
    block: _Block
    rows: list = field(default_factory=list)
    unknown: int = 0
    recognized: bool = False

    def append(self, number, **row):
        row.update(source_line=number, source_device=self.block.device)
        self.rows.append(row)
        self.recognized = True
        return row

    def lines(self):
        for number, raw in self.block.lines:
            line = raw.strip()
            if not line or _SEPARATOR.fullmatch(line):
                continue
            interrupted = line.startswith(('--More--', '%')) or '\b' in line
            if interrupted and not re.fullmatch(r'%\s*No OSPF process is running', line, re.IGNORECASE):
                self.unknown += 1
                continue
            yield number, line


def _guess_section(line):
    if _VLAN_HEADER.match(line):
        return 'vlans'
    if _TRUNK_HEADER.match(line):
        return 'trunks'
    if _ROUTE_HEADER.match(line) or _ROUTE_ROW.match(line):
        return 'routes'
    if _NEIGHBOR_HEADER.match(line):
        return 'ospf_neighbors'
    if _OSPF_IF_HEADER.match(line) or _OSPF_IF_ROW.match(line):
        return 'ospf_interfaces'
    if _LSDB_HEADER.match(line) or _LSDB_TYPE.match(line):
        return 'ospf_lsdb'
    if _LLDP_HEADER.match(line):
        return 'lldp_neighbors'
    if _CONFIG_START.match(line):
        return 'config'
    return ''


def _start_command(command, device):
    body = _SHOW.match(command)
    if body is None:
        return _Block('', device)
    base, pipe, _query = body[1].partition('|')
    base = ' '.join(base.split())
    for section, pattern in _COMMAND_PATTERNS.items():
        if re.fullmatch(pattern, base, re.IGNORECASE):
            vrf = base.split()[-1] if section == 'routes' and ' vrf ' in base.casefold() else ''
            vrf = vrf if _SAFE_TOKEN.fullmatch(vrf) else ''
            return _Block(section, device, bool(vrf or pipe), vrf)
    scoped = re.fullmatch(r'ip\s+ospf\s+int(?:erfaces?)?\s+(.+)', base, re.IGNORECASE)
    if scoped and interface_name(scoped[1]):
        return _Block('ospf_interfaces', device, filtered=True)
    return _Block('', device)


def _blocks(lines):
    device, active = '', None
    devices, blocks = {}, []
    unknown = 0
    banner = ConfigBanner()
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if active is None and (section := _guess_section(line)):
            active = _Block(section)
            blocks.append(active)
        if active is not None and active.section == 'config' and banner.accepts(line):
            active.lines.append((number, raw))
            continue
        prompt = _PROMPT.fullmatch(line)
        if prompt is not None:
            device = prompt['host']
            devices.setdefault(device, None)
            active = _start_command(prompt['body'], device)
            if active.section:
                blocks.append(active)
            continue
        if _SHOW.match(line):
            active = _start_command(line, device)
            if active.section:
                blocks.append(active)
            continue
        if active is not None and active.section:
            active.lines.append((number, raw))
        elif line:
            unknown += 1
    return blocks, list(devices), unknown


def _parse_vlans(block):
    parsed = _Rows(block)
    current = None
    for number, line in parsed.lines():
        if _VLAN_HEADER.match(line):
            parsed.recognized = True
            continue
        match = _VLAN_ROW.match(line)
        if match:
            identifier, name = vlan_id(match[1]), vlan_name(match[2].strip())
            if identifier is None or name is None:
                parsed.unknown += 1
                current = None
                continue
            current = parsed.append(number, vlan_id=identifier, name=name, status=match[3].lower(), ports=[],
                                    _port_lines={})
            line = match[4]
        elif current is None:
            parsed.unknown += 1
            continue
        if not line:
            continue
        for value in line.split(','):
            if not value.strip():
                continue
            port = interface_name(value)
            if port is None:
                parsed.unknown += 1
            elif port not in current['_port_lines']:
                current['ports'].append(port)
                current['_port_lines'][port] = number
    return parsed


def _allowed_vlans(value):
    if value.lower() == 'none':
        return 'none'
    if value.lower() == 'all':
        return '1-4094'
    ranges = []
    for segment in value.split(','):
        start, dash, end = segment.strip().partition('-')
        low = vlan_id(start)
        high = vlan_id(end) if dash else low
        if low is None or high is None or low > high:
            return None
        ranges.append((low, high))
    merged = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return ','.join(str(low) if low == high else f'{low}-{high}' for low, high in merged)


def _parse_trunks(block):
    parsed = _Rows(block)
    table, ports = None, {}
    for number, line in parsed.lines():
        if _TRUNK_HEADER.match(line):
            header = ' '.join(line.casefold().split())
            if header.startswith('port mode'):
                table = 'main'
            elif header == 'port vlans allowed on trunk':
                table = 'allowed_vlans'
            elif header.startswith('port vlans allowed and active'):
                table = 'active_vlans'
            elif header.startswith('port vlans in spanning tree'):
                table = 'forwarding_vlans'
            else:
                parsed.unknown += 1
                table = None
            parsed.recognized = table is not None
            continue
        if line.casefold() in ('no interfaces are trunking', 'no trunk ports found'):
            parsed.recognized = True
            continue
        parts = line.split()
        port = interface_name(parts[0])
        if not table or not port or len(parts) < 2:
            parsed.unknown += 1
            continue
        if table == 'main':
            native = vlan_id(parts[-1])
            if len(parts) != 5 or native is None or not all(_SAFE_TOKEN.fullmatch(part) for part in parts[1:4]):
                parsed.unknown += 1
                continue
            values = {'mode': parts[1], 'encapsulation': parts[2], 'status': parts[3], 'native_vlan': native}
        else:
            allowed = _allowed_vlans(''.join(parts[1:]))
            if allowed is None:
                parsed.unknown += 1
                continue
            values = {table: allowed}
        if port not in ports:
            ports[port] = parsed.append(number, interface=port, mode=None, encapsulation=None, status=None,
                                        native_vlan=None, allowed_vlans=None, active_vlans=None,
                                        forwarding_vlans=None)
        ports[port].update(values)
    return parsed


def _route_path(tail):
    distance, metric = None, None
    indicators = re.match(r'^\[(\d{1,3})/(\d{1,10})\]\s*', tail)
    if indicators:
        distance, metric = int(indicators[1]), int(indicators[2])
        tail = tail[indicators.end():]
    first, *rest = [value.strip() for value in tail.split(',')]
    if first.casefold() in ('is directly connected', 'is a summary'):
        port = next((name for value in rest if (name := interface_name(value))), None)
        return (distance, metric, None, port) if port is not None else None
    if not first.lower().startswith('via '):
        return None
    gateway = first[4:].strip()
    # Some platforms append a prior-route VRF name to the address.
    hop = ipv4(gateway) or (ipv4(gateway.split('%', 1)[0]) if '%' in gateway else None)
    port = interface_name(gateway) or next((name for value in rest if (name := interface_name(value))), None)
    return (distance, metric, hop, port) if hop or port else None


def _parse_routes(block):
    parsed = _Rows(block)
    vrf, subnet, previous = block.vrf, None, None
    for number, line in parsed.lines():
        if _ROUTE_HEADER.match(line) or (' - ' in line and re.match(r'^[A-Za-z0-9]{1,8}\s+-', line)):
            parsed.recognized = True
            if line.casefold().startswith('routing table:'):
                found = line.partition(':')[2].strip()
                if _SAFE_TOKEN.fullmatch(found):
                    vrf = found
                else:
                    parsed.unknown += 1
                previous, subnet = None, None
            continue
        if re.fullmatch(r'(?:IP routing not enabled|No matching routes|No routes found)', line, re.IGNORECASE):
            parsed.recognized = True
            continue
        heading = _SUBNET_HEADING.match(line)
        if heading:
            subnet = None if heading[2] else ip_network(heading[1])
            previous = None
            continue
        match = _ROUTE_ROW.match(line)
        if match:
            protocol, subtype, destination, tail = match.groups()
            if subtype:
                protocol += ' ' + subtype
            if '/' in destination:
                prefix = ip_network(destination)
            elif subnet and ip_network(destination + '/' + subnet.split('/')[-1]) == subnet:
                prefix = subnet
            else:
                prefix = ipv4(destination)
            previous = (protocol, prefix) if prefix is not None else None
        else:
            tail = line
            if not line.startswith(('via ', '[')):
                previous = None
        path = _route_path(tail) if previous is not None else None
        if path is None:
            parsed.unknown += 1
            continue
        protocol, prefix = previous
        distance, metric, hop, port = path
        parsed.append(number, prefix=prefix, protocol=protocol, distance=distance, metric=metric,
                      next_hop=hop, interface=port, vrf=vrf)
    return parsed


def _parse_ospf_neighbors(block):
    parsed = _Rows(block)
    for number, line in parsed.lines():
        if (_NEIGHBOR_HEADER.match(line) or
                re.fullmatch(r'%?\s*(?:No (?:OSPF )?neighbors(?: found)?|No OSPF process is running)', line, re.IGNORECASE)):
            parsed.recognized = True
            continue
        match = _NEIGHBOR_ROW.fullmatch(line)
        if not match:
            parsed.unknown += 1
            continue
        neighbor, priority, state, role, address, port = match.groups()
        neighbor, address, port = ipv4(neighbor), ipv4(address), interface_name(port)
        if not neighbor or not address or not port or int(priority) > 255:
            parsed.unknown += 1
            continue
        parsed.append(number, neighbor_id=neighbor, priority=int(priority), state=state.upper(), role=role,
                      address=address, interface=port)
    return parsed


def _parse_ospf_interfaces(block):
    parsed = _Rows(block)
    current = None
    for number, line in parsed.lines():
        if (_OSPF_IF_HEADER.match(line) or
                re.fullmatch(r'%?\s*(?:No OSPF interfaces(?: found)?|No OSPF process is running)', line, re.IGNORECASE)):
            parsed.recognized = True
            continue
        match = _OSPF_IF_ROW.match(line)
        if match and (port := interface_name(match[1])):
            current = parsed.append(number, interface=port, process_id=None, area=None, address=None,
                                    cost=None, state=None, router_id=None)
            continue
        fields = line.split()
        if (len(fields) >= 6 and (port := interface_name(fields[0])) and
                fields[1].isascii() and fields[1].isdigit() and len(fields[1]) <= 5):
            area, address, cost = area_id(fields[2]), interface_address(fields[3]), fields[4]
            if area is not None and address and re.fullmatch(r'[0-9]{1,5}', cost):
                parsed.append(number, interface=port, process_id=int(fields[1]), area=area,
                              address=address, cost=int(cost), state=fields[5], router_id=None)
                continue
        if current is None:
            parsed.unknown += 1
            continue
        for key, expression, converter in (
            ('address', r'\bInternet address\s+(?:is\s+)?([0-9./]+)', interface_address),
            ('area', r'\bArea\s+([0-9.]+)', area_id),
            ('process_id', r'\bProcess ID\s+([0-9]{1,5})\b', int),
            ('router_id', r'\bRouter ID\s+(' + _IP + r')\b', ipv4),
            ('cost', r'\bCost:\s*([0-9]{1,5})\b', int),
            ('state', r'\bState\s+([A-Z][A-Z0-9_-]+)\b', str),
        ):
            evidence = re.search(expression, line, re.IGNORECASE)
            if evidence:
                current[key] = converter(evidence[1])
    return parsed


def _parse_lsdb(block):
    parsed = _Rows(block)
    router_id, process_id, lsa_type, area = None, None, None, None
    for number, line in parsed.lines():
        header = _LSDB_HEADER.match(line)
        if header:
            parsed.recognized = True
            router_id, process_id = ipv4(header[1]), int(header[2])
            lsa_type, area = None, None
            continue
        if (title := _LSDB_TYPE.fullmatch(line)):
            lsa_type = _LSDB_TYPES.get(title[1].lower())
            area = area_id(title[2]) if title[2] else None
            if lsa_type:
                parsed.recognized = True
            else:
                parsed.unknown += 1
            continue
        if re.match(r'^Link ID\s+ADV Router\b', line, re.IGNORECASE):
            continue
        if re.fullmatch(r'%?\s*No OSPF process is running', line, re.IGNORECASE):
            parsed.recognized = True
            continue
        tokens = line.split()
        if lsa_type and len(tokens) >= 5 and (link_id := ipv4(tokens[0])) and (router := ipv4(tokens[1])):
            parsed.append(number, lsa_type=lsa_type, link_id=link_id, advertising_router=router,
                          area=area, process_id=process_id, router_id=router_id)
        else:
            parsed.unknown += 1
    return parsed


def _parse_lldp(block):
    parsed = _Rows(block)
    for number, line in parsed.lines():
        lower = line.lower()
        if _LLDP_HEADER.match(line) or re.fullmatch(r'Total entries displayed:\s*[0-9]+', line, re.IGNORECASE):
            parsed.recognized = True
            continue
        if lower.startswith('capability codes:') or re.match(r'^\([A-Z]\)\s', line):
            continue
        parts = line.split()
        if len(parts) < 4 or not _SAFE_TOKEN.fullmatch(parts[0]):
            parsed.unknown += 1
            continue
        local = interface_name(parts[1])
        remote = interface_name(parts[-1]) or parts[-1]
        if not local or not re.fullmatch(r'[0-9]{1,5}', parts[2]) or not _SAFE_TOKEN.fullmatch(remote):
            parsed.unknown += 1
            continue
        capabilities = ''.join(parts[3:-1]).replace(',', '')
        if capabilities and not re.fullmatch(r'[A-Z]{1,12}', capabilities):
            parsed.unknown += 1
            continue
        parsed.append(number, device=parts[0], local_interface=local, remote_interface=remote,
                      capabilities=''.join(sorted(set(capabilities))))
    return parsed


_PARSERS = {
    'vlans': _parse_vlans,
    'trunks': _parse_trunks,
    'routes': _parse_routes,
    'ospf_neighbors': _parse_ospf_neighbors,
    'ospf_interfaces': _parse_ospf_interfaces,
    'ospf_lsdb': _parse_lsdb,
    'lldp_neighbors': _parse_lldp,
}


def _safe_label(label):
    if not isinstance(label, str):
        raise TypeError('Evidence label must be text.')
    return ''.join(char if char.isalnum() or char in ' ._-()[]' else '_' for char in label[:160]).strip()


def _evidence_lines(text):
    if not isinstance(text, str):
        raise TypeError('Device evidence must be text.')
    if len(text) > MAX_EVIDENCE_BYTES:
        raise ValueError('Device evidence exceeds the 2 MiB input limit.')
    text = _ANSI.sub('', text.removeprefix('\ufeff'))
    if re.search(r'[\x00-\x02\x04-\x07\x0b\x0c\x0e-\x1f\x7f]', text):
        raise ValueError('Device evidence must be a text capture.')
    lines = text.splitlines()
    if len(lines) > MAX_EVIDENCE_LINES or any(len(line) > MAX_EVIDENCE_LINE_LENGTH for line in lines):
        raise ValueError('Device evidence exceeds the line count or length limit.')
    return lines


def _coverage(section, command, details, count):
    states = {row['status'] for row in details.values()}
    if not states:
        status = 'missing'
    else:
        status = 'observed' if states == {'observed'} else 'partial'
    return {'section': section, 'command': command, 'status': status, 'rows': count,
            'unknown_lines': sum(row['unknown_lines'] for row in details.values()), 'by_device': details}


def parse_device_evidence(text, label=''):
    """Normalize a Cisco transcript or a standalone command capture into JSON-ready evidence."""
    blocks, devices, unclassified_lines = _blocks(_evidence_lines(text))
    rows = {key: [] for key in _PARSERS}
    rows['ports'] = []
    config = {key: [] for key in ('vlans', 'interfaces', 'ospf')}
    details = {name: {} for name in _COMMANDS}
    for block in blocks:
        if block.section == 'config':
            projected, unknown, recognized = project_config(block.lines, block.device)
            for category, entries in projected.items():
                config[category].extend(entries)
        else:
            parsed = _PARSERS[block.section](block)
            rows[block.section].extend(parsed.rows)
            unknown, recognized = parsed.unknown, parsed.recognized
        result = details[block.section].setdefault(block.device, {'status': 'observed', 'unknown_lines': 0})
        result['unknown_lines'] += unknown
        if block.filtered or unknown or not recognized:
            result['status'] = 'partial'
    for vlan in rows['vlans']:
        for port, number in vlan.pop('_port_lines').items():
            rows['ports'].append({'interface': port, 'vlan_id': vlan['vlan_id'], 'source_line': number,
                                  'source_device': vlan['source_device']})

    count_config = sum(len(entries) for entries in config.values())
    config['preview_lines'] = config_preview(config)
    coverage = [_coverage(section, command, details[section],
                          count_config if section == 'config' else len(rows[section]))
                for section, command in _COMMANDS.items()]
    warnings = []
    if unclassified_lines:
        warnings.append(f'{unclassified_lines} line(s) outside supported command output.')
    for item in coverage:
        if item['status'] == 'partial':
            warnings.append(f"{item['command']}: incomplete, filtered, or unrecognized output.")
    return {'schema_version': 1, 'source': {'label': _safe_label(label), 'encoding': 'unicode',
                                             'devices': devices, 'unclassified_lines': unclassified_lines},
            'coverage': coverage, 'warnings': warnings, **rows, 'config': config}


def local_evidence_path(path):
    name = os.fspath(path)
    if not isinstance(name, str) or not name or name.startswith(('\\\\', '//', '\\/', '/\\')):
        raise ValueError('Choose a local evidence file.')
    if '://' in name or '\x00' in name:
        raise ValueError('Choose a local evidence file.')
    path = Path(name)
    if os.name == 'nt':
        # Check the drive before a metadata or open operation. This also rejects mapped network drives.
        drive = Path(os.path.abspath(path)).drive
        if (not drive or drive.startswith(('\\\\', '//')) or ':' in name[len(path.drive):]
                or ctypes.windll.kernel32.GetDriveTypeW(drive + '\\') == 4):
            raise ValueError('Choose a local evidence file.')
    return path


def read_device_evidence(path):
    """Read a bounded regular local file as UTF-8 or GBK and normalize it."""
    path = local_evidence_path(path)
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('Choose a regular device evidence text file.')
        with path.open('rb') as stream:
            raw = stream.read(MAX_EVIDENCE_BYTES + 1)
    except OSError:
        raise ValueError('Unable to read the local device evidence file.') from None
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError('Device evidence exceeds the 2 MiB input limit.')
    encoding = 'utf-8-sig' if raw.startswith(b'\xef\xbb\xbf') else 'utf-8'
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        encoding = 'gbk'
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            raise ValueError('Device evidence must be encoded as UTF-8 or GBK.') from None
    parsed = parse_device_evidence(text, path.name)
    parsed['source']['encoding'] = encoding
    return parsed


_IDENTITIES = {
    'vlans': ('vlan_id',),
    'ports': ('interface',),
    'trunks': ('interface',),
    'routes': ('vrf', 'prefix'),
    'ospf_neighbors': ('neighbor_id', 'interface'),
    'ospf_interfaces': ('interface',),
    'ospf_lsdb': ('process_id', 'area', 'lsa_type', 'link_id', 'advertising_router'),
    'lldp_neighbors': ('local_interface', 'device', 'remote_interface'),
}
_CONFIG_IDENTITIES = {'vlans': ('vlan_id',), 'interfaces': ('interface',), 'ospf': ('vrf', 'process_id')}
_SCOPE = {'ports': 'vlans'}


def _row_groups(capture, section, separate_devices):
    groups = {}
    if section == 'config':
        sections = ((category, capture['config'][category], keys) for category, keys in _CONFIG_IDENTITIES.items())
    else:
        sections = ((section, capture[section], _IDENTITIES[section]),)
    for category, rows, keys in sections:
        for row in rows:
            device = row.get('source_device', '') if separate_devices else ''
            identifier = (device, category, *(row.get(key) for key in keys))
            groups.setdefault(identifier, []).append(row)
    return groups


def _order(value):
    return value is not None, str(value)


def _flatten_group(section, rows):
    if not rows:
        return None
    result = dict(rows[0])
    if section == 'vlans':
        result.pop('ports', None)
    if section in ('routes', 'ports'):
        for key in (('next_hop', 'interface', 'protocol', 'distance', 'metric') if section == 'routes' else ('vlan_id',)):
            values = sorted({row[key] for row in rows}, key=_order)
            result[key] = values[0] if len(values) == 1 else values
    if section == 'routes' and len(rows) > 1:
        path_fields = ('next_hop', 'interface', 'protocol', 'distance', 'metric')
        paths = {tuple(row[field] for field in path_fields) for row in rows}
        result['paths'] = [dict(zip(path_fields, path, strict=True))
                           for path in sorted(paths, key=lambda path: tuple(map(_order, path)))]
    return result


def _coverage_lookup(snapshot):
    return {item['section']: item for item in snapshot['coverage']}


def _section_status(coverage, device, separate_devices):
    if separate_devices:
        return coverage['by_device'].get(device, {}).get('status', 'missing')
    return coverage['status']


def _route_path_identity(row):
    return row['next_hop'], row['interface']


def _changed_fields(before, after, complete):
    return [field for field in sorted(before.keys() | after.keys())
            if field != 'paths' and not field.startswith('source_') and before.get(field) != after.get(field)
            and (complete or (before.get(field) is not None and after.get(field) is not None))]


def _route_path_changes(old_rows, new_rows, fields, complete):
    """Check attribute assignments on matching paths even when aggregate values are identical."""
    old_paths = {_route_path_identity(row): row for row in old_rows}
    new_paths = {_route_path_identity(row): row for row in new_rows}
    for key in old_paths.keys() & new_paths.keys():
        fields.extend(_changed_fields(old_paths[key], new_paths[key], complete))
    return sorted(set(fields))


def compare_device_evidence(before, after):
    """Compare two normalized captures, preserving uncertainty about missing observations."""
    before_details, after_details = _coverage_lookup(before), _coverage_lookup(after)
    before_devices, after_devices = set(before['source']['devices']), set(after['source']['devices'])
    separate_devices = len(before_devices | after_devices) > 1
    changes, coverage = [], []
    for section in (*_IDENTITIES, 'config'):
        canonical = _SCOPE.get(section, section)
        earlier, later = before_details[canonical], after_details[canonical]
        coverage.append({'section': section, 'before': earlier['status'], 'after': later['status'],
                         'comparable': earlier['status'] == later['status'] == 'observed'
                         and (not separate_devices or set(earlier['by_device']) == set(later['by_device']))})
        old_rows = _row_groups(before, section, separate_devices)
        new_rows = _row_groups(after, section, separate_devices)
        for key in sorted(old_rows.keys() | new_rows.keys(), key=lambda item: tuple(map(_order, item))):
            device, category, *identity = key
            complete = (_section_status(earlier, device, separate_devices) ==
                        _section_status(later, device, separate_devices) == 'observed')
            old_group, new_group = old_rows.get(key, []), new_rows.get(key, [])
            if not complete and not (old_group and new_group):
                continue
            if section == 'routes' and not complete:
                matching = set(map(_route_path_identity, old_group)) & set(map(_route_path_identity, new_group))
                old_group = [row for row in old_group if _route_path_identity(row) in matching]
                new_group = [row for row in new_group if _route_path_identity(row) in matching]
                if not old_group:
                    continue
            old, new = _flatten_group(section, old_group), _flatten_group(section, new_group)
            fields = _changed_fields(old, new, complete) if old is not None and new is not None else []
            if section == 'routes' and old is not None and new is not None:
                fields = _route_path_changes(old_group, new_group, fields, complete)
            if old is not None and new is not None and not fields:
                continue
            change = 'added' if old is None else 'removed' if new is None else 'changed'
            tag = [device, category if section == 'config' else '', *identity]
            description = ' / '.join(str(value) for value in tag if value is not None and value != '')
            changes.append({'section': section, 'identity': description, 'change': change,
                            'before': old, 'after': new, 'fields': fields})
    return {'schema_version': 1, 'coverage': coverage, 'changes': changes, 'count': len(changes)}
