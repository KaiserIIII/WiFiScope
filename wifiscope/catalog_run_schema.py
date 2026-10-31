"""Typed frozen inputs, checkpoints and report pages for local audit runs."""
import copy
import hashlib
import json
import re

from .catalog_records import canonical
from .catalog_audit_schema import GAPS, _keys, _count, _codes
from .case_validation import validate_report
from .catalog_chunks import _cursor
from .inventory import bounded_json, validate_inventory, timestamp
from .investigate import _check_budget, build_investigation

COUNTS = frozenset(('evaluated_pairs', 'true_pairs', 'unknown_pairs', 'not_matched_pairs',
                    'retained_results', 'predicates', 'identity_queries', 'index_hits'))
TOTALS = COUNTS | {'relevant_records'}
REASONS = {
    'ready': {'ready'},
    'paused': {'page-limit', 'work-limit', 'pair-limit', 'cancelled'},
    'complete': {'exhausted'},
    'blocked': {'blocked-index', 'blocked-output', 'blocked-predicate'},
    'limited': {'run-page-limit', 'run-pair-limit', 'run-byte-limit'},
}
PAGE_KEYS = {'scope', 'run_id', 'page_number', 'total_pages', 'run_state', 'stop_reason',
             'computation_complete', 'source_partial', 'cumulative'}
STATUS_KEYS = {'run_id', 'state', 'stop_reason', 'page_count', 'computation_complete',
               'source_partial', 'cumulative', 'unexamined_pairs', 'gaps'}
MAX_PAYLOAD = 16 * 1024**2


def bad():
    raise ValueError('Invalid local catalog audit run.')


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf8')).hexdigest()


def decode(value):
    if not isinstance(value, str) or len(value) > MAX_PAYLOAD or len(value.encode('utf8')) > MAX_PAYLOAD:
        bad()
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                bad()
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs, parse_constant=lambda _: bad())
    bounded_json(result, max_depth=64, max_nodes=250000, allow_numbers=True)
    if canonical(result) != value:
        bad()
    return result


def counts(value, *, cumulative=False):
    _keys(value, TOTALS if cumulative else COUNTS)
    for key in value:
        _count(value[key])
    if (value['evaluated_pairs'] != sum(value[k] for k in ('true_pairs', 'unknown_pairs', 'not_matched_pairs'))
            or value['retained_results'] != value['true_pairs'] + value['unknown_pairs']
            or value['evaluated_pairs'] > (10000000 if cumulative else 50000)
            or not cumulative and (value['retained_results'] > 4096 or value['predicates'] > 500000)
            or cumulative and value['relevant_records'] > value['evaluated_pairs']):
        bad()


def validate_status(value):
    _keys(value, STATUS_KEYS)
    if not isinstance(value['run_id'], str) or not re.fullmatch('[0-9a-f]{32}', value['run_id']):
        bad()
    state = value['state']
    if (not isinstance(state, str) or state not in REASONS or not isinstance(value['stop_reason'], str)
            or value['stop_reason'] not in REASONS[state]):
        bad()
    _count(value['page_count'], 4096)
    for key in ('computation_complete', 'source_partial'):
        if type(value[key]) is not bool:
            bad()
    if value['computation_complete'] != (state == 'complete'):
        bad()
    _count(value['unexamined_pairs'], 0, nullable=True)
    if value['unexamined_pairs'] != (0 if state == 'complete' and not value['source_partial'] else None):
        bad()
    counts(value['cumulative'], cumulative=True)
    if state == 'ready' and (value['page_count'] or any(value['cumulative'].values())):
        bad()
    _codes(value['gaps'], GAPS)
    if not {'no-match-not-clearance', 'configuration/backport-unverified'} <= set(value['gaps']):
        bad()


def validate_page(value, summary, identity_mode):
    _keys(value, PAGE_KEYS)
    pattern = '[0-9a-f]{32}' if identity_mode == 'raw' else 'id-[0-9a-f]{24}'
    if value['scope'] != 'page' or not isinstance(value['run_id'], str) or not re.fullmatch(pattern, value['run_id']):
        bad()
    for key in ('page_number', 'total_pages'):
        _count(value[key], 4096)
    if not 1 <= value['page_number'] <= value['total_pages']:
        bad()
    state = value['run_state']
    if (not isinstance(state, str) or state not in REASONS or state == 'ready'
            or not isinstance(value['stop_reason'], str) or value['stop_reason'] not in REASONS[state]):
        bad()
    if (type(value['computation_complete']) is not bool or type(value['source_partial']) is not bool
            or value['computation_complete'] != (state == 'complete')):
        bad()
    counts(value['cumulative'], cumulative=True)
    if any(summary[k] > value['cumulative'][k] for k in TOTALS):
        bad()


def validate_frozen(value):
    _keys(value, {'report', 'inventory', 'report_sha256', 'inventory_sha256', 'synthetic',
                  'run_engine_version', 'matching_engine_version', 'page_size', 'catalog_sha256', 'catalog'})
    if value['run_engine_version'] != '1' or value['matching_engine_version'] != '1':
        bad()
    _count(value['page_size'], 4096)
    if not value['page_size']:
        bad()
    validate_report(value['report'])
    if value['report'].get('identifiers_included') is False:
        bad()
    if validate_inventory(value['inventory']) != value['inventory']:
        bad()
    _check_budget(dict(report=value['report'], inventory=value['inventory']))
    for key in ('report', 'inventory'):
        if value[key + '_sha256'] != digest(value[key]):
            bad()
    if not isinstance(value['catalog_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['catalog_sha256']):
        bad()
    synthetic = value['report'].get('synthetic', False) or any(
        c['source'] == 'synthetic' for a in value['inventory']['assets'] for c in a['components'])
    if type(value['synthetic']) is not bool or value['synthetic'] != synthetic:
        bad()
    # Reuse catalog/feed/inventory typing without manufacturing user-facing clearance.
    from .catalog_audit import _reserve_report
    from .catalog_audit_schema import validate_catalog_audit
    summary = dict.fromkeys(COUNTS, 0)
    summary.update(assets=len(value['inventory']['assets']), components=sum(
        len(a['components']) for a in value['inventory']['assets']), relevant_records=0,
        partial=True, unexamined_pairs=None)
    report, _, _ = _reserve_report(value['report'], value['inventory'], value['catalog'],
        summary, 'partial', {'no-match-not-clearance', 'configuration/backport-unverified'})
    validate_catalog_audit(report['catalog_audit'])


def source_gaps(frozen):
    gaps = {'no-match-not-clearance', 'configuration/backport-unverified'}
    if any(feed['partial'] for feed in frozen['catalog']['feeds']):
        gaps.add('catalog-input-partial')
    if frozen['inventory'].get('import_context', {}).get('partial'):
        gaps.add('inventory-input-partial')
    return gaps


def validate_checkpoint(value, frozen):
    _keys(value, {'status', 'cursor', 'payload_bytes', 'unpaged_work', 'unpaged_cursor'})
    validate_status(value['status'])
    _cursor(value['cursor'], len(frozen['inventory']['assets']))
    if value['unpaged_cursor'] is not None:
        _cursor(value['unpaged_cursor'], len(frozen['inventory']['assets']))
        if value['unpaged_cursor'] != value['cursor']:
            bad()
    _count(value['payload_bytes'], 512 * 1024**2)
    _keys(value['unpaged_work'], {'predicates', 'identity_queries', 'index_hits'})
    for count in value['unpaged_work'].values():
        _count(count)
    status = value['status']
    partial = bool(source_gaps(frozen) & {'catalog-input-partial', 'inventory-input-partial'})
    if (status['source_partial'] != partial or not source_gaps(frozen) <= set(status['gaps'])
            or status['computation_complete'] != (value['cursor']['asset_ordinal'] == len(frozen['inventory']['assets']))
            or status['cumulative']['relevant_records'] > frozen['catalog']['records']
            or status['state'] == 'ready' and value['cursor'] != {'asset_ordinal': 0, 'after': None}):
        bad()


def render_page(frozen, payload, status, number, relevant_records):
    _keys(payload, {'summary', 'results', 'gaps', 'cursor', 'evaluated_at'})
    counts(payload['summary'])
    timestamp(payload['evaluated_at'])
    if payload['evaluated_at'] is None:
        bad()
    _cursor(payload['cursor'], len(frozen['inventory']['assets']))
    _codes(payload['gaps'], GAPS)
    if not source_gaps(frozen) <= set(payload['gaps']):
        bad()
    summary = dict(payload['summary'], assets=len(frozen['inventory']['assets']),
        components=sum(len(a['components']) for a in frozen['inventory']['assets']),
        relevant_records=0, unexamined_pairs=None, partial=True)
    # The persisted pair ledger supplies the page's distinct relevant record count.
    summary['relevant_records'] = relevant_records
    result = copy.deepcopy(frozen['report'])
    if frozen['synthetic']:
        result['synthetic'] = True
    result['catalog_audit'] = dict(schema_version=1, engine_version='1', identity_mode='raw',
        catalog=copy.deepcopy(frozen['catalog']), inventory=copy.deepcopy(frozen['inventory']),
        summary=summary, status='partial', gaps=sorted(set(payload['gaps']) | {'audit-page-scope'}),
        results=copy.deepcopy(payload['results']), evaluated_at=payload['evaluated_at'],
        page=dict(scope='page', run_id=status['run_id'], page_number=number,
                  total_pages=status['page_count'], run_state=status['state'], stop_reason=status['stop_reason'],
                  computation_complete=status['computation_complete'], source_partial=status['source_partial'],
                  cumulative=copy.deepcopy(status['cumulative'])))
    result = build_investigation(result)
    validate_report(result)
    return result
