"""Value validation shared by offline IOS evidence readers."""

import ipaddress
import re
import unicodedata

_INTERFACE_TYPES = {
    'e': 'Ethernet', 'et': 'Ethernet', 'eth': 'Ethernet', 'ethernet': 'Ethernet',
    'fa': 'FastEthernet', 'fastethernet': 'FastEthernet',
    'gi': 'GigabitEthernet', 'gig': 'GigabitEthernet', 'gigabitethernet': 'GigabitEthernet',
    'te': 'TenGigabitEthernet', 'tengigabitethernet': 'TenGigabitEthernet',
    'twe': 'TwentyFiveGigE', 'twentyfivegige': 'TwentyFiveGigE',
    'fo': 'FortyGigabitEthernet', 'fortygigabitethernet': 'FortyGigabitEthernet',
    'hu': 'HundredGigE', 'hundredgige': 'HundredGigE',
    'po': 'Port-channel', 'port-channel': 'Port-channel',
    'lo': 'Loopback', 'loopback': 'Loopback', 'vl': 'Vlan', 'vlan': 'Vlan',
    'se': 'Serial', 'ser': 'Serial', 'serial': 'Serial',
    'tu': 'Tunnel', 'tunnel': 'Tunnel', 'nu': 'Null', 'null': 'Null',
    'mg': 'Mgmt', 'mgmt': 'Mgmt', 'management': 'Management',
    'fddi': 'Fddi', 'di': 'Dialer', 'dialer': 'Dialer',
    'virtual-access': 'Virtual-Access', 'virtual-template': 'Virtual-Template',
    'bd': 'BDI', 'bdi': 'BDI', 'nve': 'nve',
}
_INTERFACE = re.compile(r'([A-Za-z][A-Za-z-]{0,25})\s*(\d{1,6}(?:[/.:]\d{1,6}){0,6})', re.ASCII)


def interface_name(value):
    match = _INTERFACE.fullmatch(value.strip())
    if match and (kind := _INTERFACE_TYPES.get(match[1].lower())):
        return kind + match[2]
    return None


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def ip_network(value):
    try:
        return str(ipaddress.IPv4Network(value, strict=False))
    except ValueError:
        return None


def interface_address(value):
    try:
        return str(ipaddress.IPv4Interface(value))
    except ValueError:
        return None


def area_id(value):
    if value.isascii() and value.isdecimal() and len(value) <= 10 and int(value) < 2**32:
        return str(int(value))
    if (address := ipv4(value)) is not None:
        return str(int(ipaddress.IPv4Address(address)))
    return None


def vlan_id(value):
    if re.fullmatch(r'\d{1,4}', value, re.ASCII) and 1 <= int(value) <= 4094:
        return int(value)
    return None


def vlan_name(value):
    allowed = ' ._-'
    if 0 < len(value) <= 64 and all(
        char in allowed or unicodedata.category(char)[0] in 'LN' for char in value
    ):
        return value
    return None
