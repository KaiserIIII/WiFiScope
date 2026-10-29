"""Local indexed catalog audit. All retained rows are review candidates."""
import copy
from datetime import datetime, timezone
import json
import time

from .applicability import MatchBudget, WorkLimit, evaluate_cve
from .case_validation import validate_report
from .cpe_names import parse_cpe
from .inventory import bounded_json, validate_inventory
from .investigate import _check_budget, _digest, build_investigation

MAX_PAIRS = 50000
MAX_RECORDS = 50000
MAX_RESULTS = 4096
MAX_PREDICATES = 500000
MAX_RESULT_BYTES = 2 * 1024 * 1024


def _nodes(value):
    pending, count = [value], 0
    while pending:
        item = pending.pop()
        count += 1
        if isinstance(item, dict):
            pending.extend(v for pair in item.items() for v in pair)
        elif isinstance(item, list):
            pending.extend(item)
    return count


def _identities(asset, cancel):
    values, seen = [], set()
    for component in asset['components']:
        if cancel():
            raise InterruptedError
        if 'cpe' in component:
            name = parse_cpe(component['cpe'])
            if any(name.field(k).kind != 'literal' for k in ('vendor', 'product')):
                raise ValueError('Inventory CPE vendor/product must be literal for indexed evaluation.')
            row = dict(kind='cpe', part=name.field('part').text,
                       vendor=name.field('vendor').text, product=name.field('product').text)
        else:
            row = dict(kind='cna', vendor=component['vendor'], product=component['product'])
        key = tuple(row.items())
        if key not in seen:
            values.append(row)
            seen.add(key)
    return values


def audit_catalog(report, inventory, index, *, cancel=None, progress=None):
    bounded_json(report, max_depth=64, max_nodes=200000, allow_numbers=True)
    validate_report(report)
    if report.get('identifiers_included') is False:
        raise ValueError('Catalog audit needs original local evidence or a new empty schema_version=1 report.')
    normalized = validate_inventory(inventory)
    _check_budget(dict(report=report, inventory=normalized))
    info = index.info()
    summary = dict(assets=len(normalized['assets']), components=sum(len(a['components']) for a in normalized['assets']),
        relevant_records=0, evaluated_pairs=0, true_pairs=0, unknown_pairs=0, not_matched_pairs=0,
        retained_results=0, unexamined_pairs=0, partial=False, predicates=0, identity_queries=0, index_hits=0)
    results, seen, gaps = [], set(), {'no-match-not-clearance', 'configuration/backport-unverified'}
    status, last_event = 'complete', -1.0
    budget = MatchBudget(MAX_PREDICATES, cancel)

    def event(final=False):
        nonlocal last_event
        now = time.monotonic()
        if progress is not None and (final or now-last_event >= .2):
            try:
                progress(dict(status=status if final else 'running', evaluated_pairs=summary['evaluated_pairs'],
                              retained_results=len(results), predicates=budget.used,
                              relevant_records=len(seen), identity_queries=summary['identity_queries']))
            except Exception:
                raise ValueError('Catalog audit progress callback failed.') from None
            last_event = now

    def cancelled():
        try:
            return cancel is not None and (cancel() if callable(cancel) else cancel.is_set())
        except Exception:
            raise ValueError('Catalog audit cancellation callback failed.') from None

    result = copy.deepcopy(report)
    result['catalog_audit'] = dict(schema_version=1, engine_version='1', identity_mode='raw', catalog=copy.deepcopy(info),
        evaluated_at=datetime.now(timezone.utc).isoformat(), status=status, inventory=normalized,
        summary=copy.deepcopy(summary), results=[], gaps=sorted(gaps))
    if any(c['source'] == 'synthetic' for a in normalized['assets'] for c in a['components']):
        result['synthetic'] = True
    # Reserve the real rebuilt baseline before reading candidates. Three times
    # each row's footprint conservatively covers its finding/evidence duplicate.
    baseline = build_investigation(result)
    remaining_bytes = 16 * 1024 * 1024 - _check_budget(baseline) - 65536
    remaining_nodes = 200000 - _nodes(baseline) - 1024
    result_bytes = 0
    inventory_fingerprint = _digest(normalized)
    try:
        for asset in normalized['assets']:
            if cancelled():
                raise InterruptedError
            identities = _identities(asset, cancelled)
            after = None
            while True:
                event()
                if cancelled():
                    raise InterruptedError
                page = index.relevant(identities, limit=128, after=after)
                summary['identity_queries'] += page['identity_queries']
                summary['index_hits'] += page['examined']
                for record in page['records']:
                    if cancelled():
                        raise InterruptedError
                    if (summary['evaluated_pairs'] >= MAX_PAIRS or len(results) >= MAX_RESULTS
                            or record['cve'] not in seen and len(seen) >= MAX_RECORDS):
                        raise WorkLimit('Catalog result/pair budget reached.')
                    seen.add(record['cve'])
                    evaluated = evaluate_cve(record, asset, budget=budget)
                    outcome = evaluated['applicability']
                    if outcome == 'false':
                        summary['evaluated_pairs'] += 1
                        summary['not_matched_pairs'] += 1
                        event()
                        continue
                    score = max((v['score'] for v in record.get('cvss', [])), default=None)
                    components = [c for c in asset['components'] if c['id'] in evaluated['component_ids']]
                    if not components:
                        components = asset['components']
                    row = dict(id='finding-'+_digest('catalog', info['catalog_id'], inventory_fingerprint, asset['id'], record['cve']),
                        asset_id=asset['id'], component_ids=evaluated['component_ids'], cve=record['cve'],
                        applicability=outcome, severity='info' if score is None or score == 0 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low',
                        score=score, status='imported-unverified' if any(c['identification'] in ('declared', 'imported') or c['source'] in ('sbom', 'nmap') for c in components) else 'needs-review',
                        reasons=evaluated['reasons'], gaps=['configuration/backport-unverified'], model=evaluated['model'],
                        observed_at=sorted({c['observed_at'] for c in components if c['observed_at'] is not None}),
                        sources=sorted({c['source'] for c in components}), published=record.get('published'), modified=record.get('modified'),
                        reference='https://nvd.nist.gov/vuln/detail/'+record['cve'],
                        feed_membership=list(record.get('feed_membership', [])), source_sha256=list(record.get('source_sha256', [])))
                    row_bytes = len(json.dumps(row, ensure_ascii=False, allow_nan=False).encode('utf8'))
                    row_size, row_nodes = _check_budget(row), _nodes(row)
                    if result_bytes + row_bytes > MAX_RESULT_BYTES or row_size * 3 > remaining_bytes or row_nodes * 3 > remaining_nodes:
                        # This evaluated in-flight pair is deliberately excluded
                        # from classified counters because its explanation cannot
                        # be retained. It remains unexamined/unknown coverage.
                        raise WorkLimit('Catalog snapshot result budget reached.')
                    result_bytes += row_bytes
                    remaining_bytes -= row_size * 3
                    remaining_nodes -= row_nodes * 3
                    summary['evaluated_pairs'] += 1
                    summary['true_pairs' if outcome == 'true' else 'unknown_pairs'] += 1
                    results.append(row)
                    event()
                if page['work_limited']:
                    raise WorkLimit('Catalog index work budget reached.')
                if not page['truncated']:
                    break
                if page['next_after'] is None or page['next_after'] == after:
                    raise WorkLimit('Catalog index continuation unavailable.')
                after = page['next_after']
    except (InterruptedError, KeyboardInterrupt):
        status = 'cancelled'
        gaps.add('audit-cancelled')
    except WorkLimit:
        status = 'partial'
        gaps.add('audit-work-limit')
    summary.update(relevant_records=len(seen), retained_results=len(results), predicates=budget.used,
                   partial=status != 'complete', unexamined_pairs=0 if status == 'complete' else None)
    if any(f['partial'] for f in info['feeds']) or normalized.get('import_context', {}).get('partial'):
        if any(f['partial'] for f in info['feeds']):
            gaps.add('catalog-input-partial')
        if normalized.get('import_context', {}).get('partial'):
            gaps.add('inventory-input-partial')
        if status == 'complete':
            status = 'partial'
        summary['partial'] = True
        summary['unexamined_pairs'] = None
    result['catalog_audit'].update(status=status, summary=summary, results=results, gaps=sorted(gaps))
    _check_budget(result)
    from .catalog_audit_schema import validate_catalog_audit
    validate_catalog_audit(result['catalog_audit'])
    result = build_investigation(result)
    validate_report(result)
    event(final=True)
    return result
