"""Bounded offline Nmap and Greenbone XML, with no script or raw prose retention."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import math
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat

MAX_BYTES = 16 * 1024 * 1024
MAX_ASSETS = 4096
MAX_ROWS = 65536
MAX_MODEL_ITEMS = 200000


def _xml(data, cancel=None):
    from .inventory import _cancel
    _cancel(cancel)
    if not isinstance(data, bytes) or len(data) > MAX_BYTES or b'\x00' in data:
        raise ValueError('XML must be UTF-8 bytes, at most 16 MiB, without NULs.')
    try:
        text = data.decode('utf-8-sig', errors='strict')
    except UnicodeError:
        raise ValueError('Only UTF-8 XML is supported.') from None
    encoding = re.search(r'<\?xml\b[^?]*\bencoding\s*=\s*[\'"]([^\'"]+)', text, re.I)
    if encoding and encoding[1].lower() not in ('utf-8', 'utf8'):
        raise ValueError('Only UTF-8 XML is supported.')
    declarations = re.findall(r'<!DOCTYPE[^>]*>', text, re.I)
    if '<!ENTITY' in text.upper() or any(not re.fullmatch(r'<!DOCTYPE\s+nmaprun\s*>', d) for d in declarations):
        raise ValueError('Entities, external DTDs and internal subsets are forbidden.')
    if len(declarations) > 1:
        raise ValueError('Multiple document declarations are forbidden.')
    # This first pass has no tree: callbacks reject budgets before allocation of
    # a full ElementTree. Text chunks are accumulated per node, not per callback.
    parser = expat.ParserCreate()
    stack = []
    counts = dict(elements=0, assets=0, rows=0)

    def start(name, attrs):
        _cancel(cancel)
        counts['elements'] += 1
        counts['assets'] += bool(name == 'host' and stack and stack[-1][0] == 'nmaprun')
        counts['rows'] += name == 'result' or bool(name == 'port' and stack and stack[-1][0] == 'ports')
        if len(stack) >= 64 or counts['elements'] > 200000 or counts['assets'] > MAX_ASSETS or counts['rows'] > MAX_ROWS:
            raise ValueError('XML nesting, element, asset or result budget exceeded.')
        if any(len(k) > 4096 or len(v) > 4096 for k, v in attrs.items()):
            raise ValueError('XML attribute exceeds 4096 characters.')
        stack.append([name, 0])

    def chars(value):
        _cancel(cancel)
        if stack:
            stack[-1][1] += len(value)
            if stack[-1][1] > 65536:
                raise ValueError('XML text node exceeds 65536 characters.')

    parser.StartElementHandler = start
    def end(name):
        _cancel(cancel)
        stack.pop()
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.ExternalEntityRefHandler = lambda *args: 0
    parser.EntityDeclHandler = lambda *args: (_ for _ in ()).throw(ValueError('Entities are forbidden.'))
    try:
        for offset in range(0, len(text), 65536):
            _cancel(cancel)
            parser.Parse(text[offset:offset+65536], False)
        parser.Parse('', True)
        _cancel(cancel)
        result = ET.fromstring(text)
        _cancel(cancel)
        return result
    except (expat.ExpatError, ET.ParseError):
        raise ValueError('Malformed or unsupported XML.') from None


def _address(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError:
        raise ValueError('Scanner host requires an explicit valid IP address.') from None


def _number(value, minimum, maximum, integer=False, optional=False):
    if optional and value in (None, ''):
        return None
    try:
        parsed = int(value) if integer else float(value)
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise ValueError
        return parsed
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Scanner numeric field is invalid or out of range.') from None


def _time(value, epoch=False):
    try:
        parsed = datetime.fromtimestamp(float(value), timezone.utc) if epoch else datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.isoformat()
    except (ValueError, TypeError, OverflowError, OSError, AttributeError):
        return None


def _source(kind, data, observed_at, **coverage):
    return dict(type=kind, sha256=hashlib.sha256(data).hexdigest(),
                imported_at=datetime.now(timezone.utc).isoformat(), observed_at=observed_at,
                coverage=dict(planned=None, attempted=None, evaluated=None, unattempted=None, partial=False, **coverage))


def _asset(address):
    return dict(address=address, family='IPv4' if ipaddress.ip_address(address).version == 4 else 'IPv6',
                hostnames=[], mac=None, status='unknown', services=[])


def _retained_weight(value):
    """Conservative model traversal cost, including replicated keys and strings."""
    count, size = 0, 0
    pending = [value]
    while pending:
        item = pending.pop()
        count += 1
        size += 8
        if isinstance(item, str):
            size += len(item.encode('utf-8'))
        elif isinstance(item, dict):
            pending.extend(child for pair in item.items() for child in pair)
        elif isinstance(item, list):
            pending.extend(item)
    return count, size


def import_nmap(data: bytes) -> dict:
    root = _xml(data)
    if root.tag != 'nmaprun':
        raise ValueError('Expected Nmap nmaprun XML.')
    assets = []
    expanded_rows = 0
    # Reserve the bounded result envelope as well as each expanded asset. This
    # is a retained-model bound, independent of the input XML byte/node limits.
    source = _source('nmap', data, _time(root.get('start'), True))
    model_items, model_bytes = _retained_weight(dict(schema_version=1, assets=[], imported_findings=[],
        sources=[dict(source, coverage=dict(planned=None, attempted=None, evaluated=0,
            unattempted=None, partial=True, count_unit='hosts'))], gaps=['scanner-scope-unknown']))
    for host in root.findall('host'):
        addresses = [r for r in host.findall('address') if r.get('addrtype') in ('ipv4', 'ipv6')]
        # An address-less host contributes to evaluated scope but cannot be
        # correlated to a device; do not invent an identity.
        if not addresses:
            continue
        ports = host.findall('./ports/port')
        if len(assets) + len(addresses) > MAX_ASSETS or expanded_rows + len(addresses) * len(ports) > MAX_ROWS:
            raise ValueError('Scanner asset/service budget exceeded.')
        services = []
        for item in ports:
            protocol = item.get('protocol')
            if protocol not in ('tcp', 'udp', 'sctp'):
                raise ValueError('Unsupported Nmap port protocol.')
            service = item.find('service')
            state = item.find('state')
            method = service.get('method') if service is not None else 'unknown'
            conf = _number(service.get('conf'), 0, 10, integer=True, optional=True) if service is not None else None
            services.append(dict(port=_number(item.get('portid'), 1, 65535, integer=True), protocol=protocol,
                state=state.get('state') if state is not None and state.get('state') in ('open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered') else 'unknown',
                service=service.get('name') if service is not None else None,
                product=service.get('product') if service is not None else None,
                version=service.get('version') if service is not None else None,
                identification=method if method in ('table', 'probed') else 'unknown',
                confidence=conf / 10 if conf is not None else None, source='nmap',
                observed_at=source['observed_at'], source_sha256=source['sha256']))
        hostnames = [h.get('name') for h in host.findall('./hostnames/hostname') if h.get('name')]
        mac = next((r.get('addr') for r in host.findall('address') if r.get('addrtype') == 'mac'), None)
        mac = mac if mac and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac) else None
        status = host.find('status')
        status = status.get('state') if status is not None and status.get('state') in ('up', 'down', 'unknown') else 'unknown'
        # Include actual canonical identity lengths: scoped IPv6 suffixes are
        # not bounded by the ordinary IPv6 textual length. No asset copies yet.
        canonical_addresses = [_address(entry.get('addr')) for entry in addresses]
        items, size = _retained_weight(dict(address='', family='IPv6', hostnames=hostnames,
            mac=mac, status=status, services=services, source='nmap', observed_at=source['observed_at'],
            source_sha256=source['sha256']))
        model_items += len(addresses) * items
        model_bytes += len(addresses) * size + sum(len(address.encode('utf-8')) for address in canonical_addresses)
        if model_items > MAX_MODEL_ITEMS or model_bytes > MAX_BYTES:
            raise ValueError('Scanner retained model budget exceeded.')
        expanded_rows += len(addresses) * len(ports)
        for address in canonical_addresses:
            asset = _asset(address)
            asset['hostnames'] = list(hostnames)
            asset['mac'] = mac
            asset['status'] = status
            asset['services'] = [dict(s) for s in services]
            assets.append(asset)
    finished, hosts = root.find('./runstats/finished'), root.find('./runstats/hosts')
    planned = _number(hosts.get('total'), 0, 2**64, integer=True, optional=True) if hosts is not None else None
    partial = finished is None or finished.get('exit') != 'success'
    source['coverage'].update(planned=planned, evaluated=len(root.findall('host')), partial=partial, count_unit='hosts')
    for asset in assets:
        asset['source'] = 'nmap'
        asset['observed_at'] = source['observed_at']
        asset['source_sha256'] = source['sha256']
        for service in asset['services']:
            service['source_sha256'] = source['sha256']
    return dict(schema_version=1, assets=assets, imported_findings=[], sources=[source],
                gaps=['scanner-partial' if partial else 'scanner-scope-unknown'] if partial or planned is None else [])


def import_greenbone(data: bytes) -> dict:
    root = _xml(data)
    if root.tag == 'get_reports_response':
        if root.get('status') not in ('200', '201'):
            raise ValueError('Greenbone response did not report success.')
        root = root.find('report')
    if root is None or root.tag != 'report':
        raise ValueError('Expected Greenbone report XML.')
    outer = root
    for container in (outer, outer.find('report')):
        if container is not None and (container.get('content_type') not in (None, 'application/xml', 'text/xml')
            or (container.text or '').strip() or any((child.tail or '').strip() for child in container)):
            raise ValueError('Unsupported Greenbone report payload; use GMP XML, not encoded/text exports.')
    if root.find('report') is not None:
        root = root.find('report')
    results = root.find('results')
    if results is None or (results.text or '').strip() or any(child.tag != 'result' or (child.tail or '').strip() for child in results):
        raise ValueError('Unsupported Greenbone report shape; expected GMP results/result XML (empty results is supported).')
    rows = root.findall('./results/result')
    allowed_results = set(rows)
    if any(row not in allowed_results for row in outer.iter('result')):
        raise ValueError('Unsupported Greenbone result placement; expected GMP results/result XML.')
    assets, findings = {}, []
    observed = _time(root.findtext('scan_start'))
    for row in rows:
        if row.get('host') is not None or row.find('host') is None:
            raise ValueError('Unsupported Greenbone result dialect; use GMP XML results.')
        address = _address(row.find('host').text)
        asset = assets.setdefault(address, _asset(address))
        hostname = row.findtext('./host/hostname')
        if hostname and hostname not in asset['hostnames']:
            asset['hostnames'].append(hostname)
        port_text = (row.findtext('port') or '').strip().lower()
        match = re.fullmatch(r'(?:(\d+)|(general))/(tcp|udp)', port_text)
        if port_text and not match:
            raise ValueError('Unsupported Greenbone port syntax.')
        port = _number(match[1], 1, 65535, integer=True) if match and match[1] else None
        protocol = match[3] if match else 'unknown'
        nvt = row.find('nvt')
        issue = nvt.get('oid') if nvt is not None else None
        cves = []
        if nvt is not None:
            for ref in nvt.findall('./refs/ref'):
                value = (ref.get('id') or '').upper()
                if ref.get('type', '').lower() == 'cve' and re.fullmatch(r'CVE-\d{4}-\d{4,10}', value):
                    cves.append(value)
            for value in re.findall(r'CVE-\d{4}-\d{4,10}', nvt.findtext('cve') or ''):
                cves.append(value)
        # Hash scanner identifiers to avoid keeping arbitrary result IDs/prose.
        issue_id = issue if issue and re.fullmatch(r'\d+(?:\.\d+){1,40}', issue) else hashlib.sha256((row.get('id') or ET.tostring(row, encoding='unicode')).encode()).hexdigest()
        findings.append(dict(address=address, port=port, protocol=protocol, source='greenbone',
            status='imported-unverified', title='Imported scanner finding', issue_id=issue_id,
            score=_number(row.findtext('severity'), 0, 10, optional=True),
            qod=_number(row.findtext('./qod/value'), 0, 100, integer=True, optional=True),
            cves=sorted(set(cves)), observed_at=observed))
    if len(assets) > MAX_ASSETS or len(findings) > MAX_ROWS:
        raise ValueError('Scanner asset/result budget exceeded.')
    status = root.findtext('scan_run_status')
    has_errors = bool(root.findall('.//error'))
    pagination = root.find('results')
    count = root.findtext('./result_count/full')
    expected = _number(count, 0, 2**64, integer=True, optional=True)
    filtered = root.find('filters') is not None or root.find('filter') is not None
    paginated = pagination is not None and any(pagination.get(k) not in (None, '', '1', '0', '-1') for k in ('start', 'max'))
    partial = status != 'Done' or has_errors or filtered or paginated or (expected is not None and expected > len(rows))
    source = _source('greenbone', data, observed)
    source['coverage'].update(evaluated=len(rows), partial=partial, count_unit='results')
    source.update(scan_status='complete' if status == 'Done' else 'unknown' if status is None else 'partial',
                  has_errors=has_errors, filtered=filtered, paginated=paginated)
    for finding in findings:
        finding['source_sha256'] = source['sha256']
    for asset in assets.values():
        asset.update(source='greenbone', source_sha256=source['sha256'], observed_at=observed)
    return dict(schema_version=1, assets=list(assets.values()), imported_findings=findings, sources=[source],
                gaps=['scanner-partial'] if partial else ['scanner-scope-unknown'])
