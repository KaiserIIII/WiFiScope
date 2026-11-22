"""An allowlisted projection of IOS configuration for offline review."""

import re

from .network_device_values import (
    area_id,
    interface_address,
    interface_name,
    ipv4,
    vlan_id,
    vlan_name,
)

_BANNER = re.compile(r'banner\s+\S+\s+(\^.|.)', re.IGNORECASE)
_METADATA = ('building configuration', 'current configuration', 'using ', 'version ')


def _positive(value, maximum):
    return int(value) if value.isascii() and value.isdecimal() and len(value) <= 5 and 0 < int(value) <= maximum else None


def _contains_terminal_delimiter(remainder, delimiter):
    return delimiter in remainder or (delimiter.startswith('^') and len(delimiter) == 2
                                      and chr(ord(delimiter[1]) & 31) in remainder)


class ConfigBanner:
    """Track multiline banner bodies so transcript commands cannot start inside them."""

    def __init__(self):
        self.delimiter = None

    def accepts(self, line):
        if self.delimiter:
            if _contains_terminal_delimiter(line, self.delimiter):
                self.delimiter = None
            return True
        opening = _BANNER.match(line)
        if opening:
            if not _contains_terminal_delimiter(line[opening.end():], opening[1]):
                self.delimiter = opening[1]
            return True
        return False


def _new_group(line):
    prefix, _, value = line.partition(' ')
    prefix, value = prefix.lower(), value.strip()
    if prefix == 'vlan' and (identifier := vlan_id(value)) is not None:
        return 'vlans', identifier, {'vlan_id': identifier}
    if prefix == 'interface' and (identifier := interface_name(value)) is not None:
        return 'interfaces', identifier, {'interface': identifier}
    ospf = re.fullmatch(r'router\s+ospf\s+(\d{1,5})(?:\s+vrf\s+([A-Za-z0-9_.-]{1,64}))?', line, re.IGNORECASE)
    if ospf and (identifier := _positive(ospf[1], 65535)) is not None:
        vrf = ospf[2] or ''
        return 'ospf', (vrf, identifier), {'process_id': identifier, 'vrf': vrf}
    return None


def _set_config_value(category, target, line):
    """Store recognized values. Signal skipped feature declarations without retaining their text."""
    command = line.casefold()
    tokens = line.split()
    if category == 'vlans':
        if command.startswith('name '):
            value = vlan_name(line[5:].strip())
            if value is None:
                return False
            target['name'] = value
        elif command == 'shutdown' or command == 'no shutdown':
            target['shutdown'] = command == 'shutdown'
    elif category == 'interfaces':
        if command.startswith('switchport mode ') and len(tokens) == 3:
            if tokens[-1].casefold() not in ('access', 'trunk', 'dynamic'):
                return False
            target['mode'] = tokens[-1].casefold()
        elif command == 'switchport' or command == 'no switchport':
            target['switchport'] = command == 'switchport'
        elif command.startswith('switchport access vlan '):
            identifier = vlan_id(tokens[-1])
            if len(tokens) != 4 or identifier is None:
                return False
            target['access_vlan'] = identifier
        elif command.startswith('ip address '):
            if tokens[2].casefold() == 'dhcp' and len(tokens) == 3:
                target['address_method'] = 'dhcp'
            elif len(tokens) in (4, 5) and (len(tokens) == 4 or tokens[4].casefold() == 'secondary'):
                address = interface_address(tokens[2] + '/' + tokens[3])
                if address is None:
                    return False
                target.setdefault('addresses', set()).add(address)
                if len(tokens) == 5:
                    target.setdefault('secondary_addresses', set()).add(address)
            else:
                return False
        elif command.startswith('ip ospf cost '):
            cost = _positive(tokens[-1], 65535)
            if len(tokens) != 4 or cost is None:
                return False
            target['ospf_cost'] = cost
        elif re.match(r'ip ospf\s+\d', command):
            process = _positive(tokens[2], 65535)
            area = area_id(tokens[-1])
            if len(tokens) != 5 or tokens[3].casefold() != 'area' or process is None or area is None:
                return False
            target.update(ospf_process_id=process, ospf_area=area)
        elif command == 'shutdown' or command == 'no shutdown':
            target['shutdown'] = command == 'shutdown'
    elif category == 'ospf':
        if command.startswith('router-id '):
            address = ipv4(tokens[-1])
            if len(tokens) != 2 or address is None:
                return False
            target['router_id'] = address
        elif command.startswith('network '):
            if len(tokens) != 5 or tokens[3].casefold() != 'area':
                return False
            network, wildcard, area = ipv4(tokens[1]), ipv4(tokens[2]), area_id(tokens[-1])
            if network is None or wildcard is None or area is None:
                return False
            target.setdefault('_networks', set()).add((network, wildcard, area))
        elif command.startswith(('passive-interface ', 'no passive-interface ')):
            selection = tokens[-1].casefold() == 'default'
            field = 'active_interfaces' if command.startswith('no ') else 'passive_interfaces'
            if selection:
                target['passive_default'] = field == 'passive_interfaces'
            elif (name := interface_name(tokens[-1])) is not None:
                target.setdefault(field, set()).add(name)
            else:
                return False
    return True


def project_config(lines, source_device):
    groups = {name: {} for name in ('vlans', 'interfaces', 'ospf')}
    category, target = None, None
    unknown, recognized = 0, False
    banner = ConfigBanner()
    for number, raw in lines:
        line = raw.strip()
        lower = line.casefold()
        if banner.accepts(line):
            category, target = None, None
            continue
        if not line:
            continue
        if raw == '--More--' or raw.startswith('%'):
            unknown += 1
        elif line == '!' or lower in ('exit', 'end'):
            category, target = None, None
        elif lower.startswith(_METADATA):
            recognized = True
        elif raw[0].isspace():
            if target is not None and not _set_config_value(category, target, line):
                unknown += 1
        else:
            category, target = None, None
            group = _new_group(line)
            if group is None:
                if lower.startswith(('vlan ', 'interface ', 'router ospf ')):
                    unknown += 1
                continue
            category, identity, row = group
            target = groups[category].setdefault(identity, {
                **row, 'source_line': number, 'source_device': source_device,
            })
            recognized = True
    rows = {name: list(group.values()) for name, group in groups.items()}
    for row in rows['interfaces'] + rows['ospf']:
        if '_networks' in row:
            row['networks'] = [
                {'network': network, 'wildcard': wildcard, 'area': area}
                for network, wildcard, area in sorted(row.pop('_networks'))
            ]
        for key in ('addresses', 'secondary_addresses', 'active_interfaces', 'passive_interfaces'):
            if key in row:
                row[key] = sorted(row[key])
    return rows, unknown + int(banner.delimiter is not None), recognized


def config_preview(config):
    lines = []
    for category, fields in (('vlans', ('vlan_id',)), ('interfaces', ('interface',)),
                             ('ospf', ('process_id', 'vrf'))):
        title = {'vlans': 'VLAN', 'interfaces': 'Interface', 'ospf': 'OSPF process'}[category]
        for row in config[category]:
            device = row.get('source_device')
            identity = ' / '.join(str(row[field]) for field in fields if row[field])
            lines.append(f'{device + " / " if device else ""}{title} {identity}')
            for field, value in row.items():
                if field in fields or field.startswith('source_'):
                    continue
                if field == 'networks':
                    value = ', '.join(f"{item['network']} wildcard {item['wildcard']} area {item['area']}"
                                      for item in value)
                if isinstance(value, list):
                    value = ', '.join(value)
                lines.append(f'  {field.replace("_", " ")} = {value}')
    return lines
