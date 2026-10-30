"""Bounded offline Nmap CPE assertions, never scanner execution or discovery.

Only direct service/osclass CPE children identify components. Source hypotheses,
source times and source count units survive without banners, aliases or scripts.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import re

from . import inventory
from .catalog_store import _safe_path
from .cpe_names import parse_cpe
from .cpe_uri import uri_to_formatted
from .importers import _xml, MAX_BYTES, MAX_ROWS
from .inventory import _cancel, _measure_json, scanner_presence, validate_inventory


def _refuse():
    raise ValueError('Inventory retention limit exceeded; import refused without truncation.')


class _Retention:
    """Exact additive default JSON accounting, before retaining each list member.

    Asset and component containers are measured independently; each append then
    charges its exact comma overhead. Only the constant-size source context is
    remeasured as counters/gaps change; no whole-model traversal per source row.
    """
    def __init__(self, envelope):
        self.nodes, self.size = _measure_json(envelope)
        self.context_nodes, self.context_size = _measure_json(envelope['import_context'])

    def context(self, context, gaps):
        context['gaps'] = sorted(gaps)
        summary = context['scanner_summary']
        summary['unmapped_hosts'] = summary['input_hosts'] - summary['retained_hosts']
        nodes, size = _measure_json(context)
        updated_nodes = self.nodes + nodes - self.context_nodes
        updated_size = self.size + size - self.context_size
        if updated_nodes > 250000 or updated_size > inventory.MAX_BYTES:
            _refuse()
        self.nodes, self.size = updated_nodes, updated_size
        self.context_nodes, self.context_size = nodes, size

    def append(self, value, nonempty):
        nodes, size = _measure_json(value)
        if self.nodes + nodes > 250000 or self.size + size + 2 * bool(nonempty) > inventory.MAX_BYTES:
            _refuse()
        self.nodes += nodes
        self.size += size + 2 * bool(nonempty)


def _source(path, cancel):
    _cancel(cancel)
    local = _safe_path(path)
    data, digest = bytearray(), hashlib.sha256()
    with open(local, 'rb') as stream:
        while True:
            _cancel(cancel)
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(data) + len(chunk) > MAX_BYTES:
                raise ValueError('Inventory source exceeds 16 MiB.')
            digest.update(chunk)
            data.extend(chunk)
    _cancel(cancel)
    return bytes(data), digest.hexdigest()


def _epoch(value):
    if value is None:
        return None, True
    # Source integer epoch seconds only; no NaN, timezone guessing or now().
    if not re.fullmatch('[0-9]{1,12}', value):
        return None, False
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat(), True
    except (ValueError, OSError, OverflowError):
        return None, False


def _host_time(host, document_time, document_valid):
    start, start_valid = _epoch(host.get('starttime'))
    end, end_valid = _epoch(host.get('endtime'))
    if not start_valid or not end_valid or start is not None and end is not None and end < start:
        return None, 'unknown', False
    if end is not None:
        return end, 'host-end', True
    if start is not None:
        return start, 'host-start', True
    return document_time, 'document-start' if document_time is not None else 'unknown', document_valid


def _enum(value, allowed, default='unknown'):
    if value is None:
        return default, True
    return (value, True) if value in allowed else (default, False)


def _integer(value, low, high):
    if value is None:
        return None, True
    if re.fullmatch('[0-9]{1,6}', value) and low <= int(value) <= high:
        return int(value), True
    return None, False


def _addresses(host, cancel):
    values, valid = [], True
    for item in host:
        _cancel(cancel)
        if item.tag != 'address' or item.get('addrtype') not in ('ipv4', 'ipv6'):
            continue
        raw = item.get('addr', '')
        try:
            address = ipaddress.ip_address(raw)
            if '%' in raw or address.version != (4 if item.get('addrtype') == 'ipv4' else 6):
                raise ValueError
        except ValueError:
            valid = False
            continue
        value = str(address)
        if value not in values:
            if len(values) >= 16:
                _refuse()
            values.append(value)
    return values, valid


def _port_state(port, cancel):
    # First direct state wins, including missing/invalid values. Charge each
    # sibling visit to cancellation once, rather than searching per service.
    for child in port:
        _cancel(cancel)
        if child.tag == 'state':
            return _enum(child.get('state'), inventory.PORT_STATES)
    return 'unknown', True


def _entries(host, cancel):
    # Walk only these explicit paths, in source order; no descendant/script walk.
    for container in host:
        _cancel(cancel)
        if container.tag == 'ports':
            for port in container:
                _cancel(cancel)
                if port.tag == 'port':
                    state = _port_state(port, cancel)
                    for child in port:
                        _cancel(cancel)
                        if child.tag == 'service':
                            yield 'service', child, port, state
        elif container.tag == 'os':
            for item in container:
                _cancel(cancel)
                if item.tag == 'osclass':
                    yield 'osclass', item, None, ('unknown', True)
                elif item.tag == 'osmatch':
                    for child in item:
                        _cancel(cancel)
                        if child.tag == 'osclass':
                            yield 'osclass', child, None, ('unknown', True)


def _metadata(origin, entry, port, port_state, status, host_ordinal, entry_ordinal, source_time, source_valid):
    valid = source_time[2] and source_valid
    host_status, ok = _enum(status, ('up', 'down', 'unknown'))
    valid &= ok
    method, ok = _enum(entry.get('method') if origin == 'service' else None, ('probed', 'table', 'unknown'))
    valid &= ok
    confidence, ok = _integer(entry.get('conf') if origin == 'service' else None, 0, 10)
    valid &= ok
    accuracy, ok = _integer(entry.get('accuracy') if origin == 'osclass' else None, 0, 100)
    valid &= ok
    protocol, ok = _enum(port.get('protocol') if port is not None else None, ('tcp', 'udp', 'sctp', 'unknown'))
    valid &= ok
    number, ok = _integer(port.get('portid') if port is not None else None, 1, 65535)
    valid &= ok
    state, ok = port_state
    valid &= ok
    return dict(origin=origin, method=method, confidence=confidence, accuracy=accuracy,
        protocol=protocol, port=number, state=state, host_status=host_status,
        host_ordinal=host_ordinal, entry_ordinal=entry_ordinal, cpe_ordinal=0,
        binding='formatted', timestamp_origin=source_time[1], metadata_valid=bool(valid), presence='possible')


def _identity(element):
    if len(element) or element.text is None:
        raise ValueError
    identifier = element.text
    if identifier[:5].lower() == 'cpe:/':
        formatted, binding = uri_to_formatted(identifier), 'uri'
    else:
        formatted, binding = identifier, 'formatted'
    name = parse_cpe(formatted)
    if (any(name.field(k).kind != 'literal' for k in ('part', 'vendor', 'product'))
            or any(len(name.field(k).text) > 256 for k in ('vendor', 'product'))
            or any(a.kind == 'unsupported' for a in name.attributes)):
        raise ValueError
    # Typed folded tokens identify equivalent assertions; version spelling is
    # independent evidence for separately declared, case-sensitive ordering.
    key = tuple((a.kind, tuple((c, q if c in '*?' else False) for c, q in a.tokens)
                 if a.kind == 'pattern' else a.text) for a in name.attributes), name.field('version').original_text
    return formatted, name, binding, key


def import_nmap_inventory(path, *, cancel=None):
    """Return independent schema1 inventory from an explicit safe local XML file."""
    data, digest = _source(path, cancel)
    root = _xml(data, cancel=cancel)
    if root.tag != 'nmaprun':
        raise ValueError('Expected Nmap nmaprun XML.')
    document_time, document_valid = _epoch(root.get('start'))
    finished = root.find('./runstats/finished')
    scan_status = finished.get('exit') if finished is not None else 'unknown'
    scan_status = scan_status if scan_status in ('success', 'error') else 'unknown'
    summary = dict.fromkeys(inventory.SCANNER_COUNTERS, 0)
    summary['scan_status'] = scan_status
    context = dict(format='nmap', source_sha256=digest, document_observed_at=document_time,
        **dict.fromkeys(inventory.CONTEXT_COUNTERS, 0), partial=scan_status != 'success', gaps=[], scanner_summary=summary)
    result = dict(schema_version=1, assets=[], import_context=context)
    retention = _Retention(result)
    gaps = {'nmap-import-unverified', 'nmap-scope-unknown', 'runtime-state-unverified'}
    if not document_valid:
        gaps.add('nmap-evidence-unknown')
    if document_time is None:
        gaps.add('source-time-unknown')
    if context['partial']:
        gaps.add('input-partial')
        gaps.add('nmap-evidence-unknown')
    for host in root:
        _cancel(cancel)
        if host.tag != 'host':
            continue
        host_ordinal = summary['input_hosts']
        summary['input_hosts'] += 1
        addresses, addresses_valid = _addresses(host, cancel)
        status = host.find('status')
        status = status.get('state') if status is not None else None
        source_time = _host_time(host, document_time, document_valid)
        if not addresses:
            gaps.add('nmap-address-unknown')
        if not addresses_valid or not source_time[2]:
            gaps.add('nmap-evidence-unknown')
        if source_time[0] is None:
            gaps.add('source-time-unknown')
        asset = dict(id='nmap-host-'+hashlib.sha256(repr((digest, host_ordinal)).encode()).hexdigest(),
            components=[], complete_parts=[])
        if addresses:
            asset.update(address=addresses[0], addresses=addresses)
        charged = False
        for origin, entry, port, state in _entries(host, cancel):
            _cancel(cancel)
            ordinal = context['input_entries']
            if ordinal >= MAX_ROWS:
                raise ValueError('Scanner source entry budget exceeded.')
            context['input_entries'] += 1
            summary['service_entries' if origin == 'service' else 'osclass_entries'] += 1
            metadata = _metadata(origin, entry, port, state, status, host_ordinal, ordinal, source_time,
                                 addresses_valid and document_valid)
            if not metadata['metadata_valid']:
                gaps.add('nmap-evidence-unknown')
            seen, kept, cpe_ordinal = set(), 0, 0
            for element in entry:
                _cancel(cancel)
                if element.tag != 'cpe':
                    continue
                current = cpe_ordinal
                cpe_ordinal += 1
                context['input_cpe_identifiers'] += 1
                try:
                    formatted, name, binding, key = _identity(element)
                except ValueError:
                    context['unsupported_identifiers'] += 1
                    gaps.add('unsupported-cpe')
                    continue
                if key in seen:
                    context['duplicate_identifiers'] += 1
                    gaps.add('duplicate-identifier')
                    continue
                scanner = dict(metadata, cpe_ordinal=current, binding=binding)
                scanner['presence'] = scanner_presence(scanner, name, bool(addresses))
                if scanner['presence'] == 'possible':
                    gaps.add('nmap-hypothesis')
                if name.field('version').kind != 'literal':
                    gaps.add('nmap-version-unknown')
                component = dict(id='nmap-component-'+hashlib.sha256(
                    repr((digest, host_ordinal, ordinal, current, key)).encode()).hexdigest(),
                    cpe=formatted, source='nmap', identification='probed' if scanner['method'] == 'probed' else 'imported',
                    observed_at=source_time[0], source_sha256=digest, version_scheme='unknown', scanner=scanner)
                _cancel(cancel)
                if context['retained_components'] >= 8192:
                    _refuse()
                context['retained_components'] += 1
                if not charged:
                    if len(result['assets']) >= 1024:
                        _refuse()
                    summary['retained_hosts'] += 1
                retention.context(context, gaps)
                if not charged:
                    retention.append(asset, bool(result['assets']))
                    charged = True
                retention.append(component, bool(asset['components']))
                # All bounds have been charged before retaining this assertion.
                seen.add(key)
                asset['components'].append(component)
                kept += 1
            if not kept:
                context['unmapped_entries'] += 1
                gaps.add('unmapped-identifier')
        if asset['components']:
            result['assets'].append(asset)
    if not result['assets']:
        raise ValueError('No usable explicit Nmap CPE identity; import refused.')
    retention.context(context, gaps)
    _cancel(cancel)
    _measure_json(result)
    _cancel(cancel)
    normalized = validate_inventory(result)
    _cancel(cancel)
    return normalized
