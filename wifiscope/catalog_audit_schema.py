"""Strict typed catalog audit snapshot and shared-export-closure projection."""
import copy
from datetime import datetime, timedelta
import re
from .inventory import (validate_inventory, validate_import_context, bounded_json, timestamp,
                        text, SOURCES, IDENTIFICATIONS, SCHEMES, validate_addresses, validate_scanner)

GAPS = frozenset(('no-match-not-clearance', 'configuration/backport-unverified', 'audit-cancelled',
                  'audit-work-limit', 'catalog-input-partial', 'inventory-input-partial'))
REASONS = frozenset(('positive-witness-missing', 'model-conflict', 'applicability-unknown'))
SUMMARY = frozenset(('assets', 'components', 'relevant_records', 'evaluated_pairs', 'true_pairs',
    'unknown_pairs', 'not_matched_pairs', 'retained_results', 'unexamined_pairs', 'partial',
    'predicates', 'identity_queries', 'index_hits'))
FEED = frozenset(('feed_index', 'source_sha256', 'expanded_sha256', 'source_bytes', 'expanded_bytes',
                 'records', 'total_results', 'start_index', 'results_per_page', 'timestamp', 'partial', 'pin_verified'))
ROW = frozenset(('id', 'asset_id', 'component_ids', 'cve', 'applicability', 'severity', 'score', 'status',
    'reasons', 'gaps', 'model', 'observed_at', 'sources', 'published', 'modified', 'reference',
    'feed_membership', 'source_sha256'))
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')


def _bad():
    raise ValueError('Invalid typed catalog audit schema_version=1.')


def _keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        _bad()


def _count(value, maximum=10**12, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not int or not 0 <= value <= maximum:
        _bad()


def _codes(value, allowed):
    if not isinstance(value, list) or len(value) > len(allowed) or any(not isinstance(x, str) or x not in allowed for x in value) or len(set(value)) != len(value):
        _bad()


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        _bad()


def _source_time(value):
    if value is not None:
        text(value, 128)
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            _bad()


def _inventory(value, projected):
    # Projected CPE strings are opaque pseudonyms. Check the exact same typed
    # structure without trying to parse a pseudonym as a CPE or IP address.
    _keys(value, {'schema_version', 'assets'} | ({'import_context'} if isinstance(value, dict) and 'import_context' in value else set()))
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        _bad()
    if not isinstance(value['assets'], list) or not 1 <= len(value['assets']) <= 1024:
        _bad()
    assets, components, count = {}, set(), 0
    def identity(value, limit=256):
        text(value, limit)
        if projected and not re.fullmatch('id-[0-9a-f]{24}', value):
            _bad()
    for asset in value['assets']:
        if not isinstance(asset, dict):
            _bad()
        _keys(asset, {'id', 'components', 'complete_parts'} | ({'address', 'addresses'} & set(asset)))
        identifier = text(asset['id'])
        identity(identifier)
        if identifier in assets:
            _bad()
        assets[identifier] = set()
        _codes(asset['complete_parts'], {'a', 'o', 'h'})
        if asset.get('address') is not None:
            identity(asset['address'])
        validate_addresses(asset, projected=projected)
        if not isinstance(asset['components'], list) or not asset['components']:
            _bad()
        for component in asset['components']:
            count += 1
            if not isinstance(component, dict) or count > 8192:
                _bad()
            shape = {'cpe'} if 'cpe' in component else {'vendor', 'product', 'version'}
            _keys(component, shape | {'id', 'source', 'identification', 'observed_at', 'source_sha256', 'version_scheme'}
                  | ({'scanner'} if 'scanner' in component else set()))
            cid = text(component['id'])
            identity(cid)
            if cid in components:
                _bad()
            components.add(cid)
            assets[identifier].add(cid)
            for key in shape:
                if component[key] is not None or key != 'version':
                    identity(component[key], 4096 if key == 'cpe' else 1024 if key == 'version' else 256)
            if (component['source'] not in SOURCES or component['identification'] not in IDENTIFICATIONS
                    or component['version_scheme'] not in SCHEMES):
                _bad()
            timestamp(component['observed_at'])
            validate_scanner(component, asset, projected=projected)
            digest = component['source_sha256']
            if digest is not None and not re.fullmatch(r'(?:[0-9a-f]{64}|id-[0-9a-f]{24})', text(digest)):
                _bad()
            if projected and digest is not None:
                identity(digest)
    if 'import_context' in value:
        validate_import_context(value['import_context'], count, projected=projected, asset_count=len(assets))
        if projected and value['import_context']['source_sha256'] is not None:
            identity(value['import_context']['source_sha256'])
    if not projected:
        validate_inventory(value)
    return assets, count


def validate_catalog_audit(value):
    # Dedicated traversal permits scores while bounding before deepcopy.
    bounded_json(value, allow_numbers=True)
    from .investigate import _check_budget
    _check_budget(value)
    _keys(value, {'schema_version', 'engine_version', 'identity_mode', 'catalog', 'evaluated_at', 'status', 'inventory', 'summary', 'results', 'gaps'})
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['engine_version'] != '1' or value['status'] not in ('complete', 'partial', 'cancelled'):
        _bad()
    timestamp(value['evaluated_at'])
    if value['evaluated_at'] is None or value['identity_mode'] not in ('raw', 'projected'):
        _bad()
    if datetime.fromisoformat(value['evaluated_at'].replace('Z', '+00:00')).utcoffset() != timedelta(0):
        _bad()
    _codes(value['gaps'], GAPS)
    if not {'no-match-not-clearance', 'configuration/backport-unverified'} <= set(value['gaps']):
        _bad()
    cat = value['catalog']
    _keys(cat, {'schema_version', 'catalog_id', 'records', 'input_records', 'duplicate_records', 'rejected_records', 'without_applicability', 'unsupported_records', 'feeds'})
    _hash(cat['catalog_id'])
    if type(cat['schema_version']) is not int or cat['schema_version'] != 1:
        _bad()
    for key in ('records', 'input_records', 'duplicate_records', 'rejected_records', 'without_applicability', 'unsupported_records'):
        _count(cat[key])
    if cat['input_records'] != cat['records'] + cat['duplicate_records'] or any(cat[k] > cat['records'] for k in ('rejected_records', 'without_applicability', 'unsupported_records')):
        _bad()
    if not isinstance(cat['feeds'], list) or not 1 <= len(cat['feeds']) <= 64:
        _bad()
    for number, feed in enumerate(cat['feeds']):
        _keys(feed, FEED)
        for key in ('source_sha256', 'expanded_sha256'):
            _hash(feed[key])
        _source_time(feed['timestamp'])
        for key in FEED - {'source_sha256', 'expanded_sha256', 'timestamp', 'partial', 'pin_verified'}:
            _count(feed[key], nullable=key in ('total_results', 'start_index', 'results_per_page'))
        if type(feed['partial']) is not bool or type(feed['pin_verified']) is not bool:
            _bad()
        if feed['feed_index'] != number:
            _bad()
    if sum(feed['records'] for feed in cat['feeds']) != cat['input_records']:
        _bad()
    assets, count = _inventory(value['inventory'], value['identity_mode'] == 'projected')
    summary = value['summary']
    _keys(summary, SUMMARY)
    for key in SUMMARY - {'partial'}:
        _count(summary[key], nullable=key == 'unexamined_pairs')
    if (type(summary['partial']) is not bool or summary['partial'] != (value['status'] != 'complete')
            or summary['assets'] != len(assets) or summary['components'] != count
            or summary['evaluated_pairs'] != sum(summary[k] for k in ('true_pairs', 'unknown_pairs', 'not_matched_pairs'))
            or summary['evaluated_pairs'] > 50000 or summary['predicates'] > 500000
            or summary['relevant_records'] > 50000 or summary['relevant_records'] > cat['records']
            or value['status'] == 'complete' and summary['unexamined_pairs'] != 0
            or value['status'] != 'complete' and summary['unexamined_pairs'] is not None):
        _bad()
    rows = value['results']
    if not isinstance(rows, list) or len(rows) > 4096 or summary['retained_results'] != len(rows) or len(rows) != summary['true_pairs'] + summary['unknown_pairs']:
        _bad()
    seen = set()
    for row in rows:
        _keys(row, ROW)
        rid = text(row['id'])
        if rid in seen or not isinstance(row['asset_id'], str) or row['asset_id'] not in assets:
            _bad()
        if value['identity_mode'] == 'projected' and not re.fullmatch('id-[0-9a-f]{24}', rid):
            _bad()
        seen.add(rid)
        if not isinstance(row['component_ids'], list) or len(row['component_ids']) > 8192 or any(not isinstance(c, str) or c not in assets[row['asset_id']] for c in row['component_ids']) or len(set(row['component_ids'])) != len(row['component_ids']):
            _bad()
        if (not isinstance(row['cve'], str) or not CVE.fullmatch(row['cve']) or row['reference'] != 'https://nvd.nist.gov/vuln/detail/'+row['cve']
                or row['applicability'] not in ('true', 'unknown') or row['severity'] not in ('high', 'medium', 'low', 'info')
                or row['status'] not in ('needs-review', 'imported-unverified') or row['model'] not in ('cpe', 'cna', 'mixed', 'unknown')):
            _bad()
        if row['score'] is not None and (type(row['score']) not in (int, float) or not 0 <= row['score'] <= 10):
            _bad()
        _codes(row['gaps'], GAPS)
        _codes(row['reasons'], REASONS)
        _codes(row['sources'], set(SOURCES))
        for key in ('published', 'modified'):
            _source_time(row[key])
        if not isinstance(row['observed_at'], list) or len(row['observed_at']) > 8192:
            _bad()
        for at in row['observed_at']:
            timestamp(at)
            if at is None:
                _bad()
        for key in ('feed_membership', 'source_sha256'):
            if not isinstance(row[key], list) or len(row[key]) > 64:
                _bad()
            for item in row[key]:
                _hash(item) if key == 'source_sha256' else _count(item, len(cat['feeds'])-1)
    if summary['true_pairs'] != sum(r['applicability'] == 'true' for r in rows):
        _bad()


def project_catalog_audit(value, identity):
    validate_catalog_audit(value)
    result = copy.deepcopy(value)
    first = value['inventory']['assets'][0]['id']
    result['identity_mode'] = 'projected' if value['identity_mode'] == 'projected' or identity(first) != first else 'raw'
    for asset in result['inventory']['assets']:
        for key in ('id', 'address'):
            if key in asset:
                asset[key] = identity(asset[key])
        if 'addresses' in asset:
            asset['addresses'] = [identity(address) for address in asset['addresses']]
        for component in asset['components']:
            for key in ('id', 'cpe', 'vendor', 'product', 'version', 'source_sha256'):
                if key in component:
                    component[key] = identity(component[key])
    if 'import_context' in result['inventory']:
        context = result['inventory']['import_context']
        context['source_sha256'] = identity(context['source_sha256'])
    for row in result['results']:
        for key in ('id', 'asset_id', 'component_ids'):
            row[key] = identity(row[key])
    return result
