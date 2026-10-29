"""Local evidence audit: baseline checks plus explicit version candidates only."""
import copy
from datetime import datetime

from .advisory_catalog import builtin_catalog, matches_version, parse_version, validate_catalog
from .investigate import _check_budget, _digest, _rows, build_investigation
from .vulnerability_schema import EVIDENCE_STATUSES, OBSERVATION_SOURCES, validate_vulnerability_audit

MAX_SERVICES = 8192
MAX_CANDIDATES = 4096
MAX_MATCH_WORK = 500000


def audit_vulnerabilities(report: dict, catalog=None) -> dict:
    """Return an independent report; never perform IO or promote redacted IDs."""
    if not isinstance(report, dict):
        raise ValueError('Vulnerability audit requires a typed report dictionary.')
    _check_budget(report)
    observations = sum(len(_rows(asset.get('services'))) for asset in _rows(report.get('assets')))
    observations += sum(len(_rows(target.get('tcp'))) for target in _rows(report.get('connectivity')))
    if observations > MAX_SERVICES:
        raise ValueError('Vulnerability audit exceeds the 8192 service observation limit.')
    pack = builtin_catalog() if catalog is None else copy.deepcopy(catalog)
    validate_catalog(pack)
    model = build_investigation(report)
    result = copy.deepcopy(report)
    result.setdefault('schema_version', 1)
    products = {alias.casefold(): product for product in pack['products'] for alias in product['aliases']}
    rules = {}
    for rule in pack['rules']:
        rules.setdefault(rule['product'], []).append(rule)
    candidates, unevaluated, evaluated, unknown, work = [], [], 0, 0, 0
    candidate_ids = set()
    gaps = ['reviewed-subset-only', 'backports-unverified', 'configuration-unverified', 'no-match-not-clearance']
    gaps.extend(pack['import_gaps'])
    redacted = report.get('identifiers_included') is False
    if redacted:
        gaps.append('redacted-version-evidence')
    # Redacted asset identities cannot be parsed as IPs by the correlator. Count
    # original services directly as unknown, including connectivity TCP rows.
    # Do not also count derived investigation assets (copies of these contexts).
    assets = _rows(report.get('assets')) if redacted else model['investigation']['assets']
    if redacted:
        # Reuse the correlator's source-aware time/source context. Imported
        # observations without a time must not inherit local collection time.
        for target in _rows(model.get('connectivity')):
            for row in _rows(target.get('tcp')):
                service = dict(row, protocol='tcp')
                assets.append(dict(address=row.get('address'), services=[service]))
    if sum(len(_rows(asset.get('services'))) for asset in assets) > MAX_SERVICES:
        raise ValueError('Vulnerability audit exceeds the 8192 service observation limit.')
    for asset in assets:
        for service in _rows(asset.get('services')):
            source = service.get('source')
            source = source if source in OBSERVATION_SOURCES else 'unknown'
            observed_at = service.get('observed_at')
            try:
                observed_at = datetime.fromisoformat(observed_at.replace('Z', '+00:00')).isoformat() if isinstance(observed_at, str) else None
            except ValueError:
                observed_at = None
            state = service.get('status', 'unknown')
            base = dict(asset_id=asset.get('id'), address=asset.get('address'),
                port=service.get('port'), protocol=service.get('protocol') if service.get('protocol') in ('tcp', 'udp', 'sctp') else 'unknown',
                product=service.get('product'), version=service.get('version'), source=source,
                source_sha256=service.get('source_sha256'), observed_at=observed_at,
                identification=service.get('identification') if service.get('identification') in ('probed', 'table') else 'unknown',
                evidence_status=state if state in EVIDENCE_STATUSES else 'unknown')
            product = products.get(service['product'].casefold()) if isinstance(service.get('product'), str) else None
            reason = ('redacted-version-evidence' if redacted else 'product-unknown' if product is None
                else 'version-unknown' if parse_version(service.get('version'), product['scheme']) is None
                else 'source-unknown' if source == 'unknown' else None)
            applicable = rules.get(product['id'], []) if product else []
            if reason:
                unknown += 1
                unevaluated.append(dict(base, gaps=[reason]))
                if reason not in gaps:
                    gaps.append(reason)
                continue
            evaluated += 1
            predicate_work = sum(len(rule['exact']) + len(rule['ranges']) for rule in applicable)
            if work + predicate_work > MAX_MATCH_WORK:
                raise ValueError('Vulnerability audit exceeds the 500000 version/range predicate evaluation limit.')
            work += predicate_work
            for rule in applicable:
                if not matches_version(service.get('version'), product['scheme'], rule):
                    continue
                candidate = dict(base, id='finding-' + _digest('cve-version-match', asset.get('id'),
                    service.get('port'), service.get('protocol'), rule['id'], product['id'],
                    service.get('product'), service.get('version'), source, service.get('source_sha256'),
                    observed_at, base['identification'], base['evidence_status'], pack['sha256']),
                    canonical_product=product['id'], cve=rule['id'], severity=rule['priority'], score=rule.get('score'),
                    status='imported-unverified' if source in ('nmap', 'greenbone', 'scanner') else 'needs-review',
                    confidence='medium' if base['identification'] == 'probed' else 'low',
                    affected=dict(scheme=product['scheme'], exact=copy.deepcopy(rule['exact']), ranges=copy.deepcopy(rule['ranges'])),
                    reviewed_at=rule['reviewed_at'], references=copy.deepcopy(rule['references']),
                    gaps=list(dict.fromkeys(['backports-unverified', 'configuration-unverified'] + rule['gaps'])))
                if candidate['id'] not in candidate_ids:
                    if len(candidates) >= MAX_CANDIDATES:
                        raise ValueError('Vulnerability audit exceeds the 4096 retained candidate limit.')
                    candidates.append(candidate)
                    candidate_ids.add(candidate['id'])
    baseline = sum(row['category'] in ('wifi-configuration', 'local-firewall', 'tcp-exposure', 'tls-validation', 'http-posture')
                   and row['status'] in ('observed', 'imported') for row in model['investigation']['coverage'])
    result['vulnerability_audit'] = dict(schema_version=1, engine_version='1', rule_version='1',
        catalog=dict(catalog_version=pack['catalog_version'], sha256=pack['sha256'], reviewed_at=pack['reviewed_at'],
                     source=pack['source'], format=pack['format'], rule_count=len(pack['rules']), import_gaps=copy.deepcopy(pack['import_gaps'])),
        summary=dict(evaluated_services=evaluated, unknown_services=unknown, baseline_checks=baseline, candidates=len(candidates)),
        candidates=candidates, unevaluated=unevaluated, gaps=list(dict.fromkeys(gaps)))
    validate_vulnerability_audit(result['vulnerability_audit'])
    return build_investigation(result)
