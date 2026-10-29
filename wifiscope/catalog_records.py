"""Typed public catalog facts and conservative applicability indexing (no matcher)."""
import datetime
import json
import re

from .catalog_stream import CatalogError

CVE_RE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}\Z')
STATUSES = frozenset(('Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Analyzed',
                      'Modified', 'Deferred', 'Rejected'))
MAX_CPE_LEAVES = 8192
MAX_AFFECTED_ROWS = 4096
CPE_FIELDS = ('part', 'vendor', 'product', 'version', 'update', 'edition', 'language',
              'sw_edition', 'target_sw', 'target_hw', 'other')
GAPS = frozenset(('status_unknown', 'timestamp_unknown', 'cvss_unknown', 'configuration_unknown_field',
                  'configuration_shape_unknown', 'cpe_unknown', 'cpe_pattern_unknown',
                  'affected_shape_unknown', 'affected_unknown_field', 'cna_identity_unknown',
                  'cna_context_unknown', 'cna_version_unknown'))


def text(value, maximum=256):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and not any(ord(c) < 32 or 0xd800 <= ord(c) <= 0xdfff for c in value))


def cve_id(value):
    if not isinstance(value, str) or not CVE_RE.fullmatch(value):
        raise CatalogError('Invalid CVE identifier.')
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))


def parse_cpe23(value):
    """Lex CPE 2.3 formatted strings; escaped separators/wildcards remain literal.

    Returns all eleven unescaped fields plus ``wildcard_fields`` (unescaped * or
    ?), or None for malformed syntax. This helper does not implement CPE matching.
    """
    if not text(value, 2048) or not value.startswith('cpe:2.3:'):
        return None
    fields, patterns, chars = [], [], []
    escaped, pattern = False, False
    for char in value[8:]:
        if escaped:
            chars.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(chars))
            patterns.append(pattern)
            chars, pattern = [], False
        else:
            chars.append(char)
            pattern |= char in '*?'
    if escaped:
        return None
    fields.append(''.join(chars))
    patterns.append(pattern)
    if len(fields) != 11 or fields[0] not in ('a', 'o', 'h') or any(not field for field in fields):
        return None
    result = dict(zip(CPE_FIELDS, fields))
    result['wildcard_fields'] = [name for name, pattern in zip(CPE_FIELDS, patterns) if pattern]
    return result


def modified_time(value):
    """Return comparable (zone-class, ISO datetime) or None, without inventing UTC."""
    if not text(value, 128):
        return None
    try:
        date = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return ('naive' if date.tzinfo is None else 'aware', date)
    except ValueError:
        return None


def normalize(raw):
    """Return (normalized record, sorted retrieval-key tuples).

    Unknown applicability is preserved as controlled gaps and broad buckets;
    imported descriptions, references and command-like prose are never copied.
    """
    if not isinstance(raw, dict):
        raise CatalogError('Invalid CVE object.')
    identifier = cve_id(raw.get('id'))
    gaps, keys = set(), set()
    status = raw.get('vulnStatus')
    if not isinstance(status, str) or status not in STATUSES:
        status = 'Unknown'
        gaps.add('status_unknown')
    record = {'cve': identifier, 'status': status, 'published': None, 'modified': None, 'cvss': [],
                  'configurations': [], 'affected': [], 'gaps': []}
    for source, target in (('published', 'published'), ('lastModified', 'modified')):
        value = raw.get(source)
        if value is not None:
            if text(value, 128) and modified_time(value) is not None:
                record[target] = value
            else:
                gaps.add('timestamp_unknown')

    metrics = raw.get('metrics', {})
    if isinstance(metrics, dict):
        for name, values in metrics.items():
            if name not in ('cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31', 'cvssMetricV40') or not isinstance(values, list):
                gaps.add('cvss_unknown')
                continue
            for metric in values:
                data = metric.get('cvssData', {}) if isinstance(metric, dict) else {}
                if not isinstance(data, dict):
                    gaps.add('cvss_unknown')
                    continue
                score, version = data.get('baseScore'), data.get('version')
                source = metric.get('source') if isinstance(metric, dict) else None
                if (type(score) not in (int, float) or not 0 <= score <= 10
                        or version not in ('2.0', '3.0', '3.1', '4.0') or not text(source)):
                    gaps.add('cvss_unknown')
                    continue
                record['cvss'].append({'score': score, 'version': version, 'source': source})
    else:
        gaps.add('cvss_unknown')

    leaves = 0
    def cpe_key(criteria):
        parsed = parse_cpe23(criteria)
        if parsed is None:
            gaps.add('cpe_unknown')
            keys.add(('broad', '*', '', ''))
        elif any(field in parsed['wildcard_fields'] for field in ('vendor', 'product')):
            gaps.add('cpe_pattern_unknown')
            keys.add(('broad', parsed['part'], '', ''))
        elif len(parsed['vendor']) > 256 or len(parsed['product']) > 256:
            gaps.add('cpe_unknown')
            keys.add(('broad', parsed['part'], '', ''))
        else:
            keys.add(('cpe', parsed['part'], parsed['vendor'].casefold(), parsed['product'].casefold()))

    def node(value):
        nonlocal leaves
        result = {'operator': 'OR', 'negate': False, 'nodes': [], 'cpeMatch': [], 'unsupported': False}
        if not isinstance(value, dict):
            gaps.add('configuration_shape_unknown')
            result['unsupported'] = True
            keys.add(('broad', '*', '', ''))
            return result
        if set(value) - {'operator', 'negate', 'nodes', 'cpeMatch'}:
            gaps.add('configuration_unknown_field')
            result['unsupported'] = True
        if 'operator' in value:
            if value['operator'] in ('AND', 'OR'):
                result['operator'] = value['operator']
            else:
                result['unsupported'] = True
        if 'negate' in value:
            if type(value['negate']) is bool:
                result['negate'] = value['negate']
            else:
                result['unsupported'] = True
        for field in ('nodes', 'cpeMatch'):
            if field in value and not isinstance(value[field], list):
                result['unsupported'] = True
        if result['unsupported']:
            gaps.add('configuration_shape_unknown')
            keys.add(('broad', '*', '', ''))
        for child in value.get('nodes', []) if isinstance(value.get('nodes', []), list) else []:
            result['nodes'].append(node(child))
        for match in value.get('cpeMatch', []) if isinstance(value.get('cpeMatch', []), list) else []:
            leaves += 1
            if leaves > MAX_CPE_LEAVES:
                raise CatalogError('CPE leaf budget exceeded.')
            if not isinstance(match, dict):
                result['unsupported'] = True
                gaps.add('configuration_shape_unknown')
                keys.add(('broad', '*', '', ''))
                continue
            fields = {'vulnerable', 'criteria', 'matchCriteriaId', 'versionStartIncluding',
                      'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'}
            item = {'unsupported': False}
            if set(match) - fields:
                gaps.add('configuration_unknown_field')
                item['unsupported'] = True
            for field in fields:
                if field in match:
                    valid = type(match[field]) is bool if field == 'vulnerable' else text(match[field], 2048 if field == 'criteria' else 1024)
                    if valid:
                        item[field] = match[field]
                    else:
                        item['unsupported'] = True
            if 'criteria' not in item or 'vulnerable' not in item:
                item['unsupported'] = True
            if item['unsupported']:
                gaps.add('configuration_shape_unknown')
                keys.add(('broad', '*', '', ''))
            cpe_key(item.get('criteria'))
            result['cpeMatch'].append(item)
        if not result['nodes'] and not result['cpeMatch']:
            result['unsupported'] = True
            gaps.add('configuration_shape_unknown')
            keys.add(('broad', '*', '', ''))
        return result

    configs = raw.get('configurations')
    config_state = 'missing'
    if configs is not None and configs != []:
        config_state = 'present'
        if isinstance(configs, list):
            record['configurations'] = [node(value) for value in configs]
        else:
            gaps.add('configuration_shape_unknown')
            keys.add(('broad', '*', '', ''))
        if any(g.startswith(('configuration_', 'cpe_')) for g in gaps):
            config_state = 'unsupported'

    affected = raw.get('affected')
    affected_state = 'missing'
    rows = 0
    if affected is not None and affected != []:
        affected_state = 'present'
        if not isinstance(affected, list):
            affected = []
            gaps.add('affected_shape_unknown')
            keys.add(('broad', '*', '', ''))
        for source in affected:
            if not isinstance(source, dict) or not isinstance(source.get('affectedData'), list):
                gaps.add('affected_shape_unknown')
                keys.add(('broad', '*', '', ''))
                continue
            entry = {'source': source.get('source') if text(source.get('source')) else None, 'affectedData': []}
            if set(source) - {'source', 'affectedData'}:
                gaps.add('affected_unknown_field')
            if entry['source'] is None:
                gaps.add('affected_shape_unknown')
            for affected_row in source['affectedData']:
                rows += 1
                if rows > MAX_AFFECTED_ROWS:
                    raise CatalogError('CNA affected-row budget exceeded.')
                if not isinstance(affected_row, dict):
                    gaps.add('affected_shape_unknown')
                    keys.add(('broad', '*', '', ''))
                    continue
                item = {'vendor': None, 'product': None, 'defaultStatus': None, 'versions': [],
                        'context': {}, 'cpes': [], 'unsupported': False}
                allowed = {'vendor', 'product', 'defaultStatus', 'versions', 'platforms', 'modules', 'programFiles',
                           'programRoutines', 'routines', 'cpes', 'collectionURL', 'packageURL', 'packageName', 'repo',
                           'descriptions', 'references'}
                if set(affected_row) - allowed:
                    gaps.add('affected_unknown_field')
                    item['unsupported'] = True
                for field in ('vendor', 'product'):
                    if text(affected_row.get(field)):
                        item[field] = affected_row[field]
                if item['vendor'] is None or item['product'] is None:
                    gaps.add('cna_identity_unknown')
                    item['unsupported'] = True
                    keys.add(('broad', '*', '', ''))
                else:
                    keys.add(('cna', '', item['vendor'].casefold(), item['product'].casefold()))
                for field in ('platforms', 'modules', 'programFiles', 'programRoutines', 'routines', 'collectionURL', 'packageURL', 'packageName', 'repo'):
                    if field in affected_row:
                        item['context'][field] = affected_row[field]
                        gaps.add('cna_context_unknown')
                if 'cpes' in affected_row:
                    cpes = affected_row['cpes']
                    if isinstance(cpes, list) and all(text(v, 2048) for v in cpes):
                        item['cpes'] = cpes
                        for criteria in cpes:
                            cpe_key(criteria)
                    else:
                        gaps.add('affected_shape_unknown')
                        item['unsupported'] = True
                        keys.add(('broad', '*', '', ''))
                if 'defaultStatus' in affected_row:
                    if affected_row['defaultStatus'] in ('affected', 'unaffected', 'unknown'):
                        item['defaultStatus'] = affected_row['defaultStatus']
                    else:
                        gaps.add('cna_version_unknown')
                        item['unsupported'] = True
                versions = affected_row.get('versions', [])
                if not isinstance(versions, list):
                    versions = []
                    gaps.add('cna_version_unknown')
                    item['unsupported'] = True
                for version in versions:
                    normalized = {'unsupported': False, 'changes': []}
                    fields = {'version', 'lessThan', 'lessThanOrEqual', 'versionType', 'status', 'changes'}
                    if not isinstance(version, dict):
                        version = {}
                    if set(version) - fields or {'lessThan', 'lessThanOrEqual'} <= set(version):
                        normalized['unsupported'] = True
                    for field in fields - {'changes'}:
                        if field in version:
                            if text(version[field], 1024) and (field != 'status' or version[field] in ('affected', 'unaffected', 'unknown')):
                                normalized[field] = version[field]
                            else:
                                normalized['unsupported'] = True
                    if 'version' not in normalized or 'status' not in normalized:
                        normalized['unsupported'] = True
                    changes = version.get('changes', [])
                    if not isinstance(changes, list):
                        changes = []
                        normalized['unsupported'] = True
                    for change in changes:
                        if (isinstance(change, dict) and set(change) == {'at', 'status'} and text(change['at'], 1024)
                                and change['status'] in ('affected', 'unaffected', 'unknown')):
                            normalized['changes'].append(dict(change))
                        else:
                            normalized['unsupported'] = True
                    if normalized['unsupported']:
                        gaps.add('cna_version_unknown')
                        item['unsupported'] = True
                    item['versions'].append(normalized)
                if not versions and item['defaultStatus'] is None:
                    gaps.add('cna_version_unknown')
                    item['unsupported'] = True
                entry['affectedData'].append(item)
            record['affected'].append(entry)
        if any(g.startswith(('affected_', 'cna_')) for g in gaps):
            affected_state = 'unsupported'
    record['applicability'] = {'configurations': config_state, 'affected': affected_state}
    record['gaps'] = sorted(gaps)
    return record, sorted(keys)
