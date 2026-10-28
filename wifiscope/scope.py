"""Pure explicit IP scope planning; this module never performs network IO."""
import ipaddress

QUICK_PORTS = [22, 80, 443, 445, 3389, 5900, 8080, 8443]


def expand_scope(entries: list[str], max_hosts: int = 64) -> list[str]:
    if not isinstance(entries, list) or type(max_hosts) is not int or not 1 <= max_hosts <= 64:
        raise ValueError('Use a list of explicit IP targets and a host limit from 1 to 64.')
    if len(entries) > 4096:
        raise ValueError('Too many scope entries.')
    plans = []
    for entry in entries:
        try:
            if not isinstance(entry, str) or '%' in entry:
                raise ValueError
            network = ipaddress.ip_network(entry, strict=False) if '/' in entry else None
            if network is not None:
                count = network.num_addresses
                if network.version == 4 and network.prefixlen < 31:
                    count -= 2
                elif network.version == 6 and network.prefixlen < 127:
                    count -= 1
                if count > max_hosts:
                    raise ValueError
                start = int(network.network_address)
                end = int(network.broadcast_address)
                if network.version == 4 and network.prefixlen < 31:
                    start, end = start + 1, end - 1
                elif network.version == 6 and network.prefixlen < 127:
                    start += 1
                plans.append((network.version, start, end))
            else:
                address = ipaddress.ip_address(entry)
                plans.append((address.version, int(address), int(address)))
        except (ValueError, TypeError):
            raise ValueError('Scope must contain bounded IP literals/CIDRs (maximum 64 hosts).') from None
    # Count the union using integer intervals before enumerating any host.
    merged = []
    for family, start, end in sorted(plans):
        if merged and merged[-1][0] == family and start <= merged[-1][2] + 1:
            merged[-1] = (family, merged[-1][1], max(end, merged[-1][2]))
        else:
            merged.append((family, start, end))
    if sum(end - start + 1 for _, start, end in merged) > max_hosts:
        raise ValueError('Aggregate scope exceeds the host budget (maximum 64).')
    result = []
    for family, start, end in plans:
        for number in range(start, end + 1):
            address = ipaddress.IPv4Address(number) if family == 4 else ipaddress.IPv6Address(number)
            try:
                effective = address.ipv4_mapped if address.version == 6 and address.ipv4_mapped else address
                if effective.is_unspecified or effective.is_multicast or str(effective) == '255.255.255.255':
                    raise ValueError
                value = str(address)
                if value not in result:
                    result.append(value)
            except ValueError:
                raise ValueError('Unspecified, multicast and broadcast targets are forbidden.') from None
    return result
