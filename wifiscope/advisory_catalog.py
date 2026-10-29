"""Bounded data-only advisory packs and conservative explicit version predicates.

No IO, code loading, CPE guessing, regex from data, or imported finding prose.
"""
import copy
from datetime import date
import hashlib
import json
import math
import re
from urllib.parse import urlsplit

MAX_BYTES = 16 * 1024 * 1024
MAX_RULES = 5000
SCHEMES = ('numeric', 'openssh-portable')
PRIORITIES = ('high', 'medium', 'low', 'info')
SOURCES = ('builtin-reviewed-subset', 'user-supplied-unverified', 'user-supplied-sha256-checked')
CVE = re.compile(r'CVE-\d{4}-\d{4,10}\Z', re.ASCII)
GAP_CODES = frozenset(('nvd-applicability-unverified', 'nvd-cpe-unsupported',
    'nvd-predicate-unsupported', 'nvd-product-unsupported', 'nvd-no-supported-predicate'))
PRODUCTS = [dict(id='httpd', aliases=['Apache httpd', 'httpd', 'Apache HTTP Server'], scheme='numeric'),
            dict(id='nginx', aliases=['nginx'], scheme='numeric'),
            dict(id='openssh', aliases=['OpenSSH', 'OpenSSH portable'], scheme='openssh-portable')]
CPE_PRODUCTS = {('apache', 'http_server'): 'httpd', ('f5', 'nginx'): 'nginx',
                ('nginx', 'nginx'): 'nginx', ('openbsd', 'openssh'): 'openssh'}


def _invalid():
    raise ValueError('Invalid advisory catalog; use the bounded native v1 or supported NVD2 schema.')


def scalar(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
        _invalid()
    return value


def review_date(value):
    scalar(value)
    try:
        if date.fromisoformat(value).isoformat() != value:
            _invalid()
    except ValueError:
        _invalid()
    return value


def public_reference(value):
    """Only reviewed public vendor pages and an exact NVD CVE detail path."""
    if not isinstance(value, str) or len(value) > 256:
        return None
    try:
        url = urlsplit(value)
    except ValueError:
        return None
    if url.scheme != 'https' or url.username or url.password or url.query:
        return None
    paths = {'httpd.apache.org': ('/security/vulnerabilities_24.html',),
             'www.openssh.org': ('/txt/release-9.8',),
             'nginx.org': ('/en/security_advisories.html',)}
    allowed = url.netloc in paths and url.path in paths[url.netloc]
    if url.netloc == 'nvd.nist.gov':
        allowed = bool(re.fullmatch(r'/vuln/detail/CVE-\d{4}-\d{4,10}', url.path, re.ASCII))
    if not allowed or url.fragment and not CVE.fullmatch(url.fragment):
        return None
    return value


def parse_version(value, scheme):
    """Up to eight bounded numeric components; portable p suffix is numeric."""
    if not isinstance(value, str) or len(value) > 96 or scheme not in SCHEMES:
        return None
    pattern = r'([0-9]{1,9}(?:\.[0-9]{1,9}){0,7})' + (r'p([0-9]{1,9})' if scheme == 'openssh-portable' else '')
    match = re.fullmatch(pattern, value, re.ASCII)
    if not match:
        return None
    parts = tuple(int(p) for p in match[1].split('.'))
    return parts + (0,) * (8 - len(parts)) + ((int(match[2]),) if scheme == 'openssh-portable' else ())


def validate_range(value, scheme):
    if not isinstance(value, dict) or not value or set(value) - {'start', 'end', 'start_inclusive', 'end_inclusive'}:
        _invalid()
    if not ('start' in value or 'end' in value):
        _invalid()
    for key in ('start', 'end'):
        if key in value:
            if parse_version(value[key], scheme) is None or type(value.get(key + '_inclusive')) is not bool:
                _invalid()
        elif key + '_inclusive' in value:
            _invalid()
    if 'start' in value and 'end' in value:
        start, end = parse_version(value['start'], scheme), parse_version(value['end'], scheme)
        if start > end or start == end and not (value['start_inclusive'] and value['end_inclusive']):
            _invalid()
    return copy.deepcopy(value)


def matches_version(version, scheme, rule):
    parsed = parse_version(version, scheme)
    if parsed is None:
        return False
    if any(parsed == parse_version(v, scheme) for v in rule.get('exact', [])):
        return True
    for bounds in rule.get('ranges', []):
        start, end = (parse_version(bounds.get(key), scheme) for key in ('start', 'end'))
        if start is not None and (parsed < start or parsed == start and not bounds['start_inclusive']):
            continue
        if end is not None and (parsed > end or parsed == end and not bounds['end_inclusive']):
            continue
        return True
    return False


def _bounded(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 16 or count > 250000:
            _invalid()
        if isinstance(item, dict):
            if len(item) > 10000:
                _invalid()
            pending.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif isinstance(item, list):
            if len(item) > 10000:
                _invalid()
            pending.extend((v, depth + 1) for v in item)
        elif type(item) in (int, float):
            if not math.isfinite(item) or abs(item) > 10**15:
                _invalid()
        elif item is not None and type(item) not in (str, bool):
            _invalid()


def _native(value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'catalog_version', 'reviewed_at', 'products', 'rules'}
            or type(value.get('schema_version')) is not int or value['schema_version'] != 1):
        _invalid()
    scalar(value['catalog_version'])
    review_date(value['reviewed_at'])
    products, rules = value['products'], value['rules']
    if not isinstance(products, list) or not 1 <= len(products) <= 128 or not isinstance(rules, list) or len(rules) > MAX_RULES:
        _invalid()
    schemes, aliases = {}, set()
    for product in products:
        if not isinstance(product, dict) or set(product) != {'id', 'aliases', 'scheme'}:
            _invalid()
        identifier = scalar(product['id'])
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', identifier, re.ASCII) or identifier in schemes or product['scheme'] not in SCHEMES:
            _invalid()
        if not isinstance(product['aliases'], list) or not 1 <= len(product['aliases']) <= 32:
            _invalid()
        schemes[identifier] = product['scheme']
        for alias in product['aliases']:
            normalized = scalar(alias).casefold()
            if normalized in aliases or alias != alias.strip():
                _invalid()
            aliases.add(normalized)
    normalized_rules, seen = [], set()
    for rule in rules:
        required = {'id', 'product', 'exact', 'ranges', 'priority', 'reviewed_at', 'references'}
        if not isinstance(rule, dict) or not required <= rule.keys() or rule.keys() - required - {'score'}:
            _invalid()
        if not isinstance(rule['id'], str) or not CVE.fullmatch(rule['id']) or rule['id'] in seen:
            _invalid()
        seen.add(rule['id'])
        if rule['product'] not in schemes or rule['priority'] not in PRIORITIES:
            _invalid()
        review_date(rule['reviewed_at'])
        scheme = schemes[rule['product']]
        if not isinstance(rule['exact'], list) or len(rule['exact']) > 32 or not isinstance(rule['ranges'], list) or len(rule['ranges']) > 32:
            _invalid()
        if not rule['exact'] and not rule['ranges']:
            _invalid()
        if any(parse_version(v, scheme) is None for v in rule['exact']) or len(set(rule['exact'])) != len(rule['exact']):
            _invalid()
        for bounds in rule['ranges']:
            validate_range(bounds, scheme)
        score = rule.get('score')
        if 'score' in rule and (type(score) not in (float, int) or not math.isfinite(score) or not 0 <= score <= 10):
            _invalid()
        if not isinstance(rule['references'], list) or len(rule['references']) > 16:
            _invalid()
        for reference in rule['references']:
            scalar(reference)
        normalized = copy.deepcopy(rule)
        normalized['references'] = list(dict.fromkeys(r for r in rule['references'] if public_reference(r)))
        normalized['gaps'] = []
        normalized_rules.append(normalized)
    return dict(schema_version=1, catalog_version=value['catalog_version'], reviewed_at=value['reviewed_at'],
                products=copy.deepcopy(products), rules=normalized_rules, import_gaps={})


def _nvd2(value):
    if not isinstance(value, dict) or not isinstance(value.get('vulnerabilities'), list) or len(value['vulnerabilities']) > MAX_RULES:
        _invalid()
    rules, seen, gaps = [], set(), {}

    def gap(code):
        gaps[code] = gaps.get(code, 0) + 1

    for item in value['vulnerabilities']:
        cve = item.get('cve') if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get('id'), str) or not CVE.fullmatch(cve['id']) or cve['id'] in seen:
            _invalid()
        seen.add(cve['id'])
        score = None
        metrics = cve.get('metrics', {})
        if not isinstance(metrics, dict):
            _invalid()
        for metric in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2', 'cvssMetricV40'):
            rows = metrics.get(metric, [])
            if not isinstance(rows, list) or len(rows) > 32:
                _invalid()
            for row in rows:
                data = row.get('cvssData') if isinstance(row, dict) else None
                candidate = data.get('baseScore') if isinstance(data, dict) else None
                if candidate is not None:
                    if type(candidate) not in (int, float) or not math.isfinite(candidate) or not 0 <= candidate <= 10:
                        _invalid()
                    if score is None:
                        score = candidate
        grouped = {}
        configs = cve.get('configurations', [])
        if not isinstance(configs, list) or len(configs) > 128:
            _invalid()
        pending = list(configs)
        while pending:
            node = pending.pop()
            if not isinstance(node, dict):
                _invalid()
            if node.get('negate') is True:
                gap('nvd-applicability-unverified')
                continue
            if node.get('operator', 'OR') != 'OR' or node.get('nodes') or node.get('children'):
                gap('nvd-applicability-unverified')
            for field in ('nodes', 'children'):
                children = node.get(field, [])
                if not isinstance(children, list) or len(children) > 128:
                    _invalid()
                pending.extend(children)
            matches = node.get('cpeMatch', [])
            if not isinstance(matches, list) or len(matches) > 5000:
                _invalid()
            for match in matches:
                if not isinstance(match, dict):
                    _invalid()
                if match.get('vulnerable') is not True:
                    gap('nvd-applicability-unverified')
                    continue
                criteria = match.get('criteria')
                if not isinstance(criteria, str) or len(criteria) > 256 or '\\' in criteria:
                    gap('nvd-cpe-unsupported')
                    continue
                parts = criteria.split(':')
                if (len(parts) != 13 or parts[:3] != ['cpe', '2.3', 'a'] or any(v != '*' for v in parts[6:])):
                    gap('nvd-cpe-unsupported')
                    continue
                product = CPE_PRODUCTS.get(tuple(parts[3:5]))
                if product is None:
                    gap('nvd-product-unsupported')
                    continue
                scheme = next(p['scheme'] for p in PRODUCTS if p['id'] == product)
                bounds = {}
                for bound in ('Start', 'End'):
                    keys = [key for key in ('version' + bound + 'Including', 'version' + bound + 'Excluding') if key in match]
                    if len(keys) > 1:
                        _invalid()
                    if keys:
                        key = keys[0]
                        bounds[bound.lower()] = match[key]
                        bounds[bound.lower() + '_inclusive'] = key.endswith('Including')
                exact = parts[5]
                if bounds:
                    if exact != '*':
                        gap('nvd-predicate-unsupported')
                        continue
                    if any(parse_version(bounds[key], scheme) is None for key in ('start', 'end') if key in bounds):
                        gap('nvd-predicate-unsupported')
                        continue
                    validate_range(bounds, scheme)
                elif parse_version(exact, scheme) is None:
                    gap('nvd-predicate-unsupported')
                    continue
                predicates = grouped.setdefault(product, dict(exact=[], ranges=[]))
                field, predicate = ('ranges', bounds) if bounds else ('exact', exact)
                if predicate not in predicates[field]:
                    if len(predicates[field]) >= 32:
                        _invalid()
                    predicates[field].append(predicate)
        if not grouped:
            gap('nvd-no-supported-predicate')
        for product, predicates in grouped.items():
            if len(rules) >= MAX_RULES:
                _invalid()
            priority = 'high' if score is not None and score >= 7 else 'medium' if score is not None and score >= 4 else 'low' if score else 'info'
            rules.append(dict(id=cve['id'], product=product, **predicates, priority=priority, score=score,
                reviewed_at=None, references=['https://nvd.nist.gov/vuln/detail/' + cve['id']],
                gaps=['nvd-applicability-unverified']))
    return dict(schema_version=1, catalog_version='nvd2-local-import', reviewed_at=None,
                products=copy.deepcopy(PRODUCTS), rules=rules, import_gaps=gaps)


def load_catalog(data: bytes, format='native', expected_sha256=None) -> dict:
    """Parse bytes only. A byte hash pin provides integrity, not authority."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES or format not in ('native', 'nvd2'):
        _invalid()
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256) or digest != expected_sha256.lower():
            raise ValueError('Advisory SHA256 pin is invalid or does not match the catalog bytes.')

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                _invalid()
            result[key] = item
        return result

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: _invalid())
        _bounded(value)
        result = (_native if format == 'native' else _nvd2)(value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        _invalid()
    result.update(sha256=digest, format=format,
        source='user-supplied-sha256-checked' if expected_sha256 is not None else 'user-supplied-unverified')
    return result


def builtin_catalog() -> dict:
    """New factual subset, vendor Affects rows reviewed on 2026-10-28."""
    apache = 'https://httpd.apache.org/security/vulnerabilities_24.html#'
    rows = [('CVE-2021-41773', 'httpd', ['2.4.49'], [], apache),
            ('CVE-2021-42013', 'httpd', ['2.4.49', '2.4.50'], [], apache),
            ('CVE-2024-38475', 'httpd', [], [('2.4.0', '2.4.59')], apache),
            ('CVE-2024-27316', 'httpd', [], [('2.4.17', '2.4.58')], apache),
            ('CVE-2024-6387', 'openssh', [], [('8.5p1', '9.7p1')], 'https://www.openssh.org/txt/release-9.8'),
            ('CVE-2021-23017', 'nginx', [], [('0.6.18', '1.20.0')], 'https://nginx.org/en/security_advisories.html')]
    rules = [dict(id=cve, product=product, exact=exact,
        ranges=[dict(start=start, end=end, start_inclusive=True, end_inclusive=True) for start, end in ranges],
        priority='high', reviewed_at='2026-10-28', references=[reference + cve if reference == apache else reference])
        for cve, product, exact, ranges, reference in rows]
    value = dict(schema_version=1, catalog_version='reviewed-subset-2026-10-28.1', reviewed_at='2026-10-28',
                 products=PRODUCTS, rules=rules)
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    result = load_catalog(data)
    result['source'] = 'builtin-reviewed-subset'
    return result


def _validate_catalog(value):
    """Check even in-memory normalized packs before matching or multiplication."""
    if not isinstance(value, dict):
        _invalid()
    _bounded(value)
    if value.get('source') == 'builtin-reviewed-subset':
        if value != builtin_catalog():
            _invalid()
        return
    if (value.get('source') not in SOURCES or value.get('format') not in ('native', 'nvd2')
            or not isinstance(value.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])):
        _invalid()
    rules = value.get('rules')
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        _invalid()
    # NVD may associate one CVE with multiple explicit products; each pair is unique.
    seen, groups = set(), {}
    if value['format'] == 'nvd2' and value.get('products') != PRODUCTS:
        _invalid()
    for rule in rules:
        key = (rule.get('id'), rule.get('product')) if isinstance(rule, dict) else None
        if not isinstance(rule, dict) or key in seen:
            _invalid()
        seen.add(key)
        review = rule.get('reviewed_at') or '1970-01-01'
        native_rule = {k: v for k, v in rule.items() if k != 'gaps' and not (k == 'score' and v is None)}
        native_rule['reviewed_at'] = review
        groups.setdefault(rule['product'] if value['format'] == 'nvd2' else 'native', []).append(native_rule)
        if (not isinstance(rule.get('gaps'), list) or any(g not in GAP_CODES for g in rule['gaps'])):
            _invalid()
    # Validate product declarations even for an empty NVD result.
    _native(dict(schema_version=1, catalog_version=value.get('catalog_version'),
        reviewed_at=value.get('reviewed_at') or '1970-01-01', products=value.get('products'), rules=[]))
    for group in groups.values():
        _native(dict(schema_version=1, catalog_version=value.get('catalog_version'),
            reviewed_at=value.get('reviewed_at') or '1970-01-01', products=value.get('products'), rules=group))
    gaps = value.get('import_gaps')
    if not isinstance(gaps, dict) or any(k not in GAP_CODES or type(v) is not int or not 0 <= v <= 250000 for k, v in gaps.items()):
        _invalid()


def validate_catalog(value):
    try:
        _validate_catalog(value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        _invalid()
