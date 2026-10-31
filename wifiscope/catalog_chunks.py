"""Pure bounded catalog traversal; only admitted pairs advance continuation."""
import copy
import time

from .applicability import MatchBudget, WorkLimit, _evaluate_prepared, _prepare_asset
from .case_validation import validate_report
from .catalog_audit import _identities, _nodes, _reserve_report, _result_row
from .catalog_audit_schema import CVE, validate_catalog_audit
from .catalog_records import canonical
from .inventory import bounded_json, validate_inventory
from .investigate import _check_budget, _digest

MAX_PAIRS = 50000
MAX_RESULTS = 4096
MAX_PREDICATES = 500000
MAX_RESULT_BYTES = 2 * 1024 * 1024


def _cursor(value, assets):
    if (not isinstance(value, dict) or set(value) != {'asset_ordinal', 'after'}
            or type(value['asset_ordinal']) is not int
            or not 0 <= value['asset_ordinal'] <= assets
            or value['after'] is not None and (
                not isinstance(value['after'], str) or not CVE.fullmatch(value['after']))
            or value['asset_ordinal'] == assets and value['after'] is not None):
        raise ValueError('Invalid catalog chunk cursor.')
    return dict(value)


def _page(page, after):
    """Validate the index page before any of its records can be committed.

    A limited union or unusable continuation is a block, never a skip.
    CatalogIndex remains the source-record validation boundary.
    """
    if (not isinstance(page, dict)
            or not {'records', 'truncated', 'next_after', 'examined', 'identity_queries',
                    'work_limited'} <= set(page)
            or not isinstance(page['records'], list) or len(page['records']) > 128
            or any(type(page[k]) is not bool for k in ('truncated', 'work_limited'))
            or any(type(page[k]) is not int or not 0 <= page[k] <= 10**12
                   for k in ('examined', 'identity_queries'))):
        raise ValueError('Invalid catalog index page.')
    if page['work_limited']:
        return False
    previous = after or ''
    for record in page['records']:
        if (not isinstance(record, dict) or not isinstance(record.get('cve'), str)
                or not CVE.fullmatch(record['cve']) or record['cve'] <= previous):
            raise ValueError('Invalid catalog index record order.')
        previous = record['cve']
    if page['truncated']:
        return bool(page['records']) and page['next_after'] == previous
    if page['next_after'] is not None:
        raise ValueError('Invalid catalog index continuation.')
    return True


def _audit_chunk(report, inventory, index, *, cursor, page_size=256,
                 cancel=None, progress=None):
    bounded_json(report, max_depth=64, max_nodes=200000, allow_numbers=True)
    validate_report(report)
    if report.get('identifiers_included') is False:
        raise ValueError('Catalog audit needs original local evidence or a new empty schema_version=1 report.')
    normalized = validate_inventory(inventory)
    next_cursor = _cursor(cursor, len(normalized['assets']))
    if type(page_size) is not int or not 1 <= page_size <= MAX_RESULTS:
        raise ValueError('Invalid catalog chunk page size.')
    _check_budget(dict(report=report, inventory=normalized))
    info = copy.deepcopy(index.info())
    summary = dict(evaluated_pairs=0, true_pairs=0, unknown_pairs=0, not_matched_pairs=0,
                   retained_results=0, predicates=0, identity_queries=0, index_hits=0)
    full_summary = dict(summary, assets=len(normalized['assets']),
        components=sum(len(a['components']) for a in normalized['assets']), relevant_records=0,
        unexamined_pairs=0, partial=False)
    gaps = {'no-match-not-clearance', 'configuration/backport-unverified'}
    snapshot, remaining_bytes, remaining_nodes = _reserve_report(
        report, normalized, info, full_summary, 'complete', gaps)
    validate_catalog_audit(snapshot['catalog_audit'])
    if any(f['partial'] for f in info['feeds']):
        gaps.add('catalog-input-partial')
    if normalized.get('import_context', {}).get('partial'):
        gaps.add('inventory-input-partial')
    fingerprint = _digest(normalized)
    budget = MatchBudget(MAX_PREDICATES, cancel)
    pairs, results, seen = [], [], set()
    result_bytes, last_event = 0, -1.0
    stop_reason = 'exhausted'

    def cancelled():
        try:
            return cancel is not None and (cancel() if callable(cancel) else cancel.is_set())
        except Exception:
            raise ValueError('Catalog audit cancellation callback failed.') from None

    def checkpoint():
        if cancelled():
            raise InterruptedError

    def event(final=False):
        nonlocal last_event
        now = time.monotonic()
        if progress is not None and (final or now - last_event >= .2):
            try:
                progress(dict(summary, predicates=budget.used,
                              status=stop_reason if final else 'running'))
            except Exception:
                raise ValueError('Catalog audit progress callback failed.') from None
            last_event = now

    try:
        while next_cursor['asset_ordinal'] < len(normalized['assets']):
            checkpoint()
            ordinal = next_cursor['asset_ordinal']
            asset = normalized['assets'][ordinal]
            prepared = _prepare_asset(asset, budget=budget)
            identities = _identities(asset, cancelled)
            while True:
                event()
                checkpoint()
                page = index.relevant(identities, limit=128, after=next_cursor['after'])
                usable = _page(page, next_cursor['after'])
                summary['identity_queries'] += page['identity_queries']
                summary['index_hits'] += page['examined']
                checkpoint()
                if not usable:
                    stop_reason = 'blocked-index'
                    break
                for record in page['records']:
                    checkpoint()
                    evaluated = _evaluate_prepared(record, prepared, budget=budget)
                    outcome = evaluated['applicability']
                    if outcome != 'false':
                        row = _result_row(record, evaluated, asset, info['catalog_id'], fingerprint)
                        row_bytes = len(canonical(row).encode('utf8'))
                        row_size, row_nodes = _check_budget(row), _nodes(row)
                        if (result_bytes + row_bytes > MAX_RESULT_BYTES
                                or row_size * 3 > remaining_bytes or row_nodes * 3 > remaining_nodes):
                            stop_reason = 'page-limit' if pairs else 'blocked-output'
                            break
                        checkpoint()
                        result_bytes += row_bytes
                        remaining_bytes -= row_size * 3
                        remaining_nodes -= row_nodes * 3
                        results.append(row)
                    else:
                        checkpoint()
                    # No callbacks or fallible work between admission and checkpoint.
                    pairs.append(dict(asset_ordinal=ordinal, cve=record['cve'], applicability=outcome))
                    next_cursor = dict(asset_ordinal=ordinal, after=record['cve'])
                    seen.add(record['cve'])
                    summary['evaluated_pairs'] += 1
                    summary[{'true': 'true_pairs', 'unknown': 'unknown_pairs',
                             'false': 'not_matched_pairs'}[outcome]] += 1
                    summary['retained_results'] = len(results)
                    event()
                    if len(results) >= page_size:
                        stop_reason = 'page-limit'
                        break
                    if len(pairs) >= MAX_PAIRS:
                        stop_reason = 'pair-limit'
                        break
                if stop_reason != 'exhausted':
                    break
                if not page['truncated']:
                    next_cursor = dict(asset_ordinal=ordinal + 1, after=None)
                    break
            if stop_reason != 'exhausted':
                break
    except (InterruptedError, KeyboardInterrupt):
        stop_reason = 'cancelled'
    except WorkLimit:
        stop_reason = 'work-limit' if pairs else 'blocked-predicate'
    except (KeyError, TypeError, AttributeError, IndexError):
        raise ValueError('Invalid catalog index data.') from None
    if stop_reason == 'cancelled':
        gaps.add('audit-cancelled')
    elif stop_reason != 'exhausted':
        gaps.add('audit-work-limit')
    summary['predicates'] = budget.used
    # Reuse the existing typed row validator, including IDs/provenance/model rules.
    full_summary.update(summary, relevant_records=len(seen))
    snapshot['catalog_audit'].update(summary=full_summary, results=results, gaps=sorted(gaps))
    validate_catalog_audit(snapshot['catalog_audit'])
    event(final=True)
    return dict(cursor=next_cursor, computation_complete=stop_reason == 'exhausted',
                stop_reason=stop_reason, summary=summary, pairs=pairs, results=results, gaps=sorted(gaps))
