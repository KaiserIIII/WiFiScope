"""Evidence-bound correlation and scope-aware findings, with no network IO."""
import copy
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .audit import assess
from .importers import MAX_ASSETS, MAX_ROWS, MAX_BYTES
from .rules import catalog
from .numeric import supported_number


def _rows(value):
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _numeric(value):
    return supported_number(value)


def _digest(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()[:24]


def _ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _check_budget(report):
    assets = _rows(report.get('assets'))
    rows = sum(len(_rows(a.get('services'))) for a in assets) + len(_rows(report.get('imported_findings')))
    rows += sum(sum(len(_rows(r.get(field))) for field in ('tcp', 'tls', 'http')) for r in _rows(report.get('connectivity')))
    if len(assets) > MAX_ASSETS or rows > MAX_ROWS:
        raise ValueError('Aggregate investigation exceeds 4096 assets or 65536 observation/result rows.')
    size, count = 0, 0
    pending = [(report, 0)]
    while pending:
        value, depth = pending.pop()
        supported_number(value)
        count += 1
        size += 8
        if depth > 64 or count > 200000:
            raise ValueError('Report nesting or element budget exceeded.')
        if isinstance(value, str):
            size += len(value.encode('utf-8'))
        elif isinstance(value, dict):
            pending.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        if size > MAX_BYTES:
            raise ValueError('Aggregate report data exceeds 16 MiB.')
    return size


def _contextual_rows(report, field):
    """Pin original local provenance before observations cross report boundaries."""
    rows = copy.deepcopy(_rows(report.get(field)))
    for row in rows:
        if field == 'connectivity':
            local_target = row.get('source', 'measured') in ('measured', 'local')
            original_time = row.get('observed_at', report.get('collected_at') if local_target else None)
            for child in ('tcp', 'tls', 'http', 'dns'):
                children = [row[child]] if child == 'dns' and isinstance(row.get(child), dict) else _rows(row.get(child))
                for observation in children:
                    source = observation.get('source', row.get('source', 'measured'))
                    fallback = original_time if source in ('measured', 'local') or source == row.get('source') else None
                    observation.setdefault('source', source)
                    observation.setdefault('observed_at', fallback)
            row.setdefault('observed_at', original_time)
        else:
            row.setdefault('source', 'local')
            row.setdefault('observed_at', report.get('collected_at'))
    return rows


def _run_contexts(report):
    contexts = copy.deepcopy(_rows(report.get('run_contexts')))
    if isinstance(report.get('run'), dict):
        context = copy.deepcopy(report['run'])
        context.setdefault('observed_at', report.get('collected_at'))
        if context not in contexts:
            contexts.insert(0, context)
    return contexts


def run_summary(report):
    """Conservative shared headline; unrelated runs have no unified counters."""
    contexts = _run_contexts(report)
    if len(contexts) > 1:
        return dict(status='partial', planned_connections=None, attempted_connections=None,
                    unattempted_endpoints=None)
    return contexts[0] if contexts else {}


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _partial_run(run):
    return (run.get('status') in ('partial', 'cancelled', 'deadline')
        or (_count(run.get('unattempted_endpoints')) or 0) > 0
        or any(_count(run.get(planned)) is not None and _count(run.get(attempted)) is not None
               and run[planned] > run[attempted]
               for planned, attempted in [('planned_hosts', 'attempted_hosts'), ('planned_connections', 'attempted_connections')]))


def _import_context(rows, sources):
    contexts = []
    missing = False
    for row in rows:
        matches = [s for s in sources if (s.get('sha256') == row['source_sha256']
                   if row.get('source_sha256') else s.get('type') == row.get('source'))]
        missing = missing or not matches
        for source in matches:
            if source not in contexts:
                contexts.append(source)
    partial = missing or len(contexts) > 1 or any(not isinstance(s.get('coverage'), dict)
        or s['coverage'].get('partial') is not False for s in contexts)
    return copy.deepcopy(contexts), partial


def _origin(row):
    source = row.get('source')
    return 'measured' if source in ('measured', 'local') else 'imported' if source in ('nmap', 'greenbone', 'scanner') else 'unknown'


def _attempted(row):
    if _count(row.get('attempts')) is not None:
        return row['attempts'] > 0
    return row.get('status') in ('ok', 'partial', 'timeout', 'refused', 'error', 'certificate_error',
        'certificate-error', 'tls_error', 'http_error', 'redirect', 'invalid_response', 'dns_error', 'no_addresses')


def _packet_contexts(report):
    contexts = _rows(report.get('packet_analysis_contexts'))
    return contexts if contexts else [report['packet_analysis']] if isinstance(report.get('packet_analysis'), dict) else []


def merge_reports(reports: list[dict]) -> dict:
    """Merge raw sources; correlation is a candidate, never persistent identity.

    Imported source hashes suppress repeated scans. Distinct observations remain
    attached to their source and time, including conflicting endpoint states.
    """
    if not isinstance(reports, list) or len(reports) > 16 or any(not isinstance(r, dict) for r in reports):
        raise ValueError('Merge accepts at most 16 report dictionaries.')
    if any('catalog_audit' in report for report in reports):
        raise ValueError('Merging catalog audits requires separate inventory contexts; merge original evidence and run a new catalog audit.')
    if any('vulnerability_audit' in report for report in reports):
        raise ValueError('Merging audited reports requires separate audit contexts. Merge original evidence first, then run a new local vulnerability audit.')
    if any('capture_session' in report for report in reports):
        raise ValueError('Merging live capture reports requires distinct capture contexts; keep sessions separate.')
    if any('wifi_survey' in report for report in reports):
        raise ValueError('Merging survey reports requires distinct selected-network and coordinate contexts; keep projects separate.')
    merged = dict(schema_version=1, assets=[], imported_findings=[], sources=[], gaps=[], connectivity=[])
    seen = set()
    size = 0
    for report in reports:
        if report.get('identifiers_included') is False:
            raise ValueError('Cannot merge independently pseudonymized exports. Use raw reports or explicitly export with identifiers included.')
        report_size = _check_budget(report)
        sources = _rows(report.get('sources'))
        hashes = {s['sha256'] for s in sources if isinstance(s.get('sha256'), str)}
        new = hashes - seen
        has_local = any(report.get(field) for field in ('connectivity', 'wifi', 'interfaces', 'routes', 'firewall', 'run', 'run_contexts'))
        if hashes and not new and not has_local:
            continue
        size += report_size
        if size > MAX_BYTES:
            raise ValueError('Aggregate report data exceeds 16 MiB.')
        for source in sources:
            if source.get('sha256') not in seen and source not in merged['sources']:
                merged['sources'].append(copy.deepcopy(source))
        for field in ('assets', 'imported_findings'):
            for row in _rows(report.get(field)):
                if row.get('source_sha256') is None or row.get('source_sha256') not in seen:
                    merged[field].append(copy.deepcopy(row))
        for field in ('connectivity', 'wifi', 'interfaces', 'routes', 'firewall'):
            merged.setdefault(field, []).extend(_contextual_rows(report, field))
        for gap in report.get('gaps', []) if isinstance(report.get('gaps'), list) else []:
            if isinstance(gap, str) and gap not in merged['gaps']:
                merged['gaps'].append(gap)
        for field in ('platform', 'collected_at', 'environment', 'packets'):
            if field in report:
                if field not in merged:
                    merged[field] = copy.deepcopy(report[field])
                elif merged[field] != report[field]:
                    merged['gaps'].append('multiple-' + field + '-contexts')
                    if field == 'packets':
                        merged.setdefault(field + '_contexts', [copy.deepcopy(merged[field])]).append(copy.deepcopy(report[field]))
        for context in _packet_contexts(report):
            if context.get('source_sha256') in seen:
                continue
            contexts = merged.setdefault('packet_analysis_contexts', [])
            contexts.append(copy.deepcopy(context))
            merged.setdefault('packet_analysis', copy.deepcopy(context))
        if len(merged.get('packet_analysis_contexts', [])) > 1 and 'multiple-packet_analysis-contexts' not in merged['gaps']:
            merged['gaps'].append('multiple-packet_analysis-contexts')
        for context in _run_contexts(report):
            contexts = merged.setdefault('run_contexts', [])
            # Equal counters/time do not identify a run or its target scope.
            # Retain each input context until actual shared identity is known.
            contexts.append(context)
            merged.setdefault('run', copy.deepcopy(context))
        if len(merged.get('run_contexts', [])) > 1 and 'multiple-run-contexts' not in merged['gaps']:
            merged['gaps'].append('multiple-run-contexts')
        seen.update(hashes)
        _check_budget(merged)
    return build_investigation(merged)


def build_investigation(report: dict) -> dict:
    """Return a fresh evidence model. No missing test is treated as a pass."""
    if not isinstance(report, dict):
        raise ValueError('Investigation requires a report dictionary.')
    if 'schema_version' in report and (type(report['schema_version']) is not int or report['schema_version'] != 1):
        raise ValueError('Investigation requires schema_version=1 evidence.')
    _check_budget(report)
    from .extensions import validate_extensions
    validate_extensions(report)
    result = copy.deepcopy(report)
    contexts = _run_contexts(result)
    if len(contexts) > 1:
        result['run_contexts'] = contexts
        result.pop('run', None)
    result.setdefault('schema_version', 1)
    templates = catalog()
    assets = {}
    findings = []
    finding_index = {}
    service_index = {}
    endpoint_values = {}
    gaps = list(result.get('gaps', [])) if isinstance(result.get('gaps'), list) else []

    def get_asset(row):
        address = _ip(row.get('address'))
        mac = row.get('mac')
        if address:
            key = ('address', address)
        elif isinstance(mac, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            key = ('mac', mac.lower())
        else:
            return None
        if key not in assets:
            if len(assets) >= MAX_ASSETS:
                raise ValueError('Aggregate investigation exceeds 4096 assets.')
            assets[key] = dict(id='asset-' + _digest(*key), address=address, mac=mac,
                family='IPv4' if address and ipaddress.ip_address(address).version == 4 else 'IPv6' if address else 'unknown',
                hostnames=[], status='unknown', services=[], observations=[], gaps=[])
        asset = assets[key]
        for hostname in row.get('hostnames', []) if isinstance(row.get('hostnames'), list) else []:
            if isinstance(hostname, str) and hostname not in asset['hostnames']:
                asset['hostnames'].append(hostname)
        if row.get('status') in ('up', 'down'):
            observation = {k: row.get(k) for k in ('status', 'source', 'source_sha256', 'observed_at')}
            if observation not in asset['observations']:
                asset['observations'].append(observation)
            states = {o['status'] for o in asset['observations']}
            asset['status'] = next(iter(states)) if len(states) == 1 else 'conflicting'
        if mac and not asset.get('mac'):
            asset['mac'] = mac
        return asset

    def service(asset, observation):
        if asset is None:
            return
        fingerprint = _digest(observation)
        fingerprints = service_index.setdefault(asset['id'], set())
        if fingerprint not in fingerprints:
            # Keep each provenance-bearing observation rather than merge state,
            # product or versions into a fictional single definitive service.
            asset['services'].append(copy.deepcopy(observation))
            fingerprints.add(fingerprint)
        endpoint = (observation.get('port'), observation.get('protocol'))
        values = endpoint_values.setdefault((asset['id'], *endpoint), {})
        for field in ('state', 'product', 'version'):
            value = observation.get(field)
            if isinstance(value, str) and value != 'unknown':
                values.setdefault(field, set()).add(value)
        if any(len(v) > 1 for v in values.values()):
            if 'conflicting-service-observations' not in asset['gaps']:
                asset['gaps'].append('conflicting-service-observations')

    def add(code, evidence, severity='low', confidence='low', status='needs-review', category='network', issue=None):
        title, recommendation, retest = templates[code]
        address = _ip(evidence.get('address'))
        asset = assets.get(('address', address)) if address else None
        if asset:
            evidence = dict(evidence, asset_id=asset['id'])
        identifier = 'finding-' + _digest(code, evidence.get('address') or evidence.get('host') or evidence.get('bssid') or evidence.get('ssid') or evidence.get('profile'),
            evidence.get('port'), evidence.get('protocol'), evidence.get('url'), issue)
        if _origin(evidence) == 'imported':
            status = 'imported-unverified'
        finding = dict(id=identifier, code=code, severity=severity, confidence=confidence, status=status,
                       category=category, title=title, evidence=evidence, recommendation=recommendation, retest=retest)
        prior = finding_index.get(identifier)
        if prior is None:
            findings.append(finding)
            finding_index[identifier] = finding
        elif prior['evidence'] != evidence:
            prior['evidence'].setdefault('observations', []).append(evidence)

    for row in _rows(result.get('assets')):
        asset = get_asset(row)
        for observation in _rows(row.get('services')):
            service(asset, observation)

    sources = result.setdefault('sources', [])
    result['connectivity'] = _contextual_rows(result, 'connectivity')
    for target in result['connectivity']:
        observations = [r for field in ('tcp', 'tls', 'http') for r in _rows(target.get(field))]
        if isinstance(target.get('dns'), dict):
            observations.append(target['dns'])
        for row in observations:
            if _origin(row) == 'measured' and _attempted(row):
                source = dict(type='measured', observed_at=row.get('observed_at'), imported_at=None)
                if source not in sources:
                    sources.append(source)
            elif _origin(row) == 'imported':
                matches, _ = _import_context([row], _rows(sources))
                if not matches:
                    sources.append(dict(type=row['source'], observed_at=row.get('observed_at'), imported_at=None,
                        sha256=row.get('source_sha256'), coverage=dict(planned=None, attempted=None, evaluated=None, unattempted=None, partial=True)))
    for target in _rows(result.get('connectivity')):
        for gap in target.get('gaps', []) if isinstance(target.get('gaps'), list) else []:
            if isinstance(gap, str) and gap not in gaps:
                gaps.append(gap)
        for row in _rows(target.get('tcp')):
            asset = get_asset(row)
            state = 'open' if _numeric(row.get('successes')) and row['successes'] > 0 else 'closed' if row.get('status') == 'refused' else 'unknown'
            observation = dict(port=row.get('port'), protocol='tcp', state=state, service=None, product=None,
                version=None, identification='unknown', confidence=None, source=row.get('source'), observed_at=row.get('observed_at'),
                status=row.get('status'), attempts=row.get('attempts'), successes=row.get('successes'))
            service(asset, observation)
        family_ports = {}
        for row in _rows(target.get('tcp')):
            if row.get('family') in ('IPv4', 'IPv6') and row.get('status') not in ('cancelled', 'not_run', 'not-run'):
                family_ports.setdefault(row.get('port'), {}).setdefault(row['family'], []).append(row)
        for port, families in family_ports.items():
            if set(families) == {'IPv4', 'IPv6'}:
                reached = {family: any(_numeric(r.get('successes')) and r['successes'] > 0 for r in rows) for family, rows in families.items()}
                if reached['IPv4'] != reached['IPv6']:
                    add('family-reachability', dict(host=target.get('host'), port=port, protocol='tcp', observations=families['IPv4'] + families['IPv6']), confidence='low', category='policy')
        for row in _rows(target.get('tls')):
            get_asset(row)
            evidence = dict(row)
            if row.get('status') in ('certificate_error', 'certificate-error'):
                add('tls-trust', evidence, 'medium', 'high', 'observed', 'tls')
            if row.get('status') == 'ok' or row.get('source') in ('nmap', 'greenbone'):
                days = row.get('days_remaining')
                if _numeric(days) and days <= 30:
                    add('tls-expired' if days < 0 else 'tls-expiring', evidence, 'medium' if days < 0 else 'low', 'high', 'observed', 'tls')
                if row.get('version') in ('TLSv1', 'TLSv1.0', 'TLSv1.1'):
                    add('tls-legacy', evidence, 'medium', 'high', 'observed', 'tls')
                cipher = row.get('cipher')
                if isinstance(cipher, str) and re.search(r'(?:RC4|3DES|DES-CBC|NULL|EXPORT|anon)', cipher, re.I):
                    add('tls-weak-cipher', evidence, 'medium', 'high', 'observed', 'tls')
        for row in _rows(target.get('http')):
            get_asset(row)
            code = row.get('status_code')
            if row.get('status') != 'ok' or type(code) is not int or not 200 <= code < 300:
                continue
            try:
                parsed_url = urlsplit(row.get('url', ''))
                scheme = parsed_url.scheme
            except (TypeError, ValueError):
                continue
            evidence = dict(row)
            if scheme == 'http':
                add('http-transport', evidence, confidence='high', status='observed', category='http')
            checks = row.get('security_checks') if isinstance(row.get('security_checks'), dict) else {}
            if scheme == 'https' and parsed_url.hostname and _ip(parsed_url.hostname) is None and checks.get('hsts_positive_max_age') is False:
                add('http-hsts', evidence, confidence='high', category='http')
            if row.get('content_kind') == 'html':
                for field, rule in [('csp', 'http-csp'), ('frame_protection', 'http-frame'), ('nosniff', 'http-nosniff')]:
                    if checks.get(field) is False:
                        add(rule, evidence, confidence='high', category='http')
            for field, rule in [('cookies_secure', 'cookie-secure'), ('cookies_httponly', 'cookie-httponly')]:
                if checks.get(field) is False:
                    add(rule, evidence, confidence='high', category='http')

    for asset in assets.values():
        for observation in asset['services']:
            if observation.get('state') != 'open' or observation.get('protocol') != 'tcp':
                continue
            port = observation.get('port')
            confidence = 'medium' if observation.get('identification') == 'probed' else 'low'
            evidence = dict(observation, address=asset['address'])
            if port in (21, 23, 110, 143):
                add('cleartext-exposure', evidence, 'medium', confidence)
            if port in (22, 3389, 445, 5900, 5985, 5986):
                add('management-exposure', evidence, 'low', confidence)
    for context in _packet_contexts(result):
        evidence = {key: copy.deepcopy(context.get(key)) for key in ('source_sha256', 'observed_at', 'packets',
            'captured_bytes', 'plaintext_http_packets', 'partial')}
        live = 'capture_session' in result and context.get('source_sha256') == result['capture_session']['source_sha256']
        evidence['source'] = 'measured' if live else 'packets'
        category = 'live-capture' if live else 'offline-packets'
        for endpoint in _rows(context.get('endpoints')):
            asset = get_asset(endpoint)
            if asset is not None:
                observation = dict(source=evidence['source'], source_sha256=context.get('source_sha256'),
                    observed_at=context.get('observed_at'), packets=endpoint.get('packets'), bytes=endpoint.get('bytes'))
                if observation not in asset['observations']:
                    asset['observations'].append(observation)
        if type(context.get('plaintext_http_packets')) is int and context['plaintext_http_packets'] > 0:
            add('packet-http', evidence, 'medium', 'high', 'observed', category, issue=context.get('source_sha256'))
        for observation in _rows(context.get('observations')):
            if observation.get('code') == 'arp-conflict':
                get_asset(observation)
                add('arp-conflict', dict(evidence, address=observation.get('address')), 'low', 'medium', 'needs-review',
                    category, issue=context.get('source_sha256'))
    for row in _rows(result.get('imported_findings')):
        get_asset(row)
        score = row.get('score')
        severity = 'high' if _numeric(score) and score >= 7 else 'medium' if _numeric(score) and score >= 4 else 'low' if _numeric(score) and score > 0 else 'info'
        add('scanner-finding', copy.deepcopy(row), severity, 'low', 'imported-unverified', 'scanner',
            issue=[row.get('issue_id'), sorted(row.get('cves', [])) if isinstance(row.get('cves'), list) else []])
    audit = result.get('vulnerability_audit')
    if isinstance(audit, dict):
        title, recommendation, retest = templates['cve-version-match']
        for candidate in audit['candidates']:
            evidence = {key: copy.deepcopy(candidate.get(key)) for key in ('asset_id', 'address', 'port', 'protocol',
                'product', 'version', 'source', 'source_sha256', 'observed_at', 'identification')}
            evidence['cves'] = [candidate['cve']]
            findings.append(dict(id=candidate['id'], code='cve-version-match', severity=candidate['severity'],
                confidence=candidate['confidence'], status=candidate['status'], category='local-vulnerability-audit',
                title=title, evidence=evidence, recommendation=recommendation, retest=retest))
    catalog_audit = result.get('catalog_audit')
    if isinstance(catalog_audit, dict):
        collected_ids = {asset['id'] for asset in assets.values()}
        for inventory_asset in catalog_audit['inventory']['assets']:
            if inventory_asset['id'] in collected_ids:
                raise ValueError('Inventory asset IDs conflict with collected asset IDs; choose distinct explicit IDs.')
            assets[('inventory', inventory_asset['id'])] = dict(id=inventory_asset['id'],
                type='inventory', address=inventory_asset.get('address'), services=[], observations=[], gaps=[])
        for candidate in catalog_audit['results']:
            code = 'catalog-modeled-match' if candidate['applicability'] == 'true' else 'catalog-applicability-unknown'
            title, recommendation, retest = templates[code]
            evidence = dict(asset_id=candidate['asset_id'], component_ids=list(candidate['component_ids']),
                            cves=[candidate['cve']], source='local')
            findings.append(dict(id=candidate['id'], code=code, severity=candidate['severity'],
                confidence='low', status=candidate['status'], category='catalog-applicability',
                title=title, evidence=evidence, recommendation=recommendation, retest=retest))
    for finding in assess(result):
        add(finding['code'], finding['evidence'], 'medium' if finding['severity'] == 'warning' else 'info',
            'low' if finding['code'] == 'mixed-security' else 'high',
            'needs-review' if finding['code'] == 'mixed-security' else 'observed', 'wifi' if 'firewall' not in finding['code'] else 'firewall')
    if isinstance(result.get('environment'), dict) and result['environment'].get('proxy_configured') is True:
        gaps.append('proxy-environment')
    priorities = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    findings.sort(key=lambda r: (priorities[r['severity']], r['code'], r['id']))
    coverage = _coverage(result)
    if 'wifi_survey' in result:
        from .survey_schema import validate_survey
        result['wifi_survey'] = validate_survey(result['wifi_survey'])
        samples = result['wifi_survey']['samples']
        known = [row for row in samples if row['value'] is not None]
        measured = [row for row in known if row.get('source') == 'measured']
        imported = len(known) - len(measured)
        contexts = [dict(status='observed' if source == 'measured' else 'imported', source='local',
                         reason='observed-evidence' if source == 'measured' else 'imported-evidence',
                         evaluated=count, count_unit='observations', partial=True)
                    for source, count in [('measured', len(measured)), ('imported', imported)] if count]
        status = 'observed' if measured else 'imported' if known else 'unavailable'
        coverage.append(dict(category='wireless-survey', status=status, source='local',
            reason='observed-evidence' if measured else 'imported-evidence' if known else 'evidence-unavailable',
            planned=None, attempted=len(samples), evaluated=len(known), unattempted=None,
            measured=len(measured), imported=imported, unknown=len(samples)-len(known),
            count_unit='observations', partial=True, contexts=contexts))
    if isinstance(audit, dict):
        has_versions = audit['summary']['evaluated_services'] > 0
        coverage.append(dict(category='local-vulnerability-audit', status='observed' if has_versions else 'unavailable', source='local',
            reason='observed-evidence' if has_versions else 'evidence-unavailable', planned=None, attempted=None, evaluated=audit['summary']['evaluated_services'],
            unattempted=audit['summary']['unknown_services'], count_unit='observations', partial=True))
    if isinstance(catalog_audit, dict):
        summary = catalog_audit['summary']
        coverage.append(dict(category='catalog-applicability', status='observed', source='local',
            reason='observed-evidence', planned=None, attempted=summary['evaluated_pairs'],
            evaluated=summary['true_pairs'] + summary['not_matched_pairs'],
            unattempted=summary['unexamined_pairs'], unknown=summary['unknown_pairs'],
            count_unit='observations', partial=True))
    result['investigation'] = dict(assets=list(assets.values()), findings=findings, coverage=coverage,
        gaps=list(dict.fromkeys(gaps)), summary=dict(
            priorities={severity: sum(f['severity'] == severity for f in findings) for severity in priorities},
            assets=len(assets), findings=len(findings),
            measured=sum(c['status'] == 'observed' or any(context.get('status') == 'observed' for context in c.get('contexts', [])) for c in coverage),
            imported=sum(c['status'] == 'imported' or any(context.get('status') == 'imported' for context in c.get('contexts', [])) for c in coverage),
            unknown=sum(c['status'] in ('unavailable', 'not-run') for c in coverage)))
    return result


def _coverage(report):
    targets = _rows(report.get('connectivity'))
    sources = _rows(report.get('sources'))
    runs = _run_contexts(report)
    run = runs[0] if len(runs) == 1 else {}
    scope_partial = len(runs) > 1 or any(_partial_run(context) for context in runs)
    coverage = []

    def add(category, available, source, rows=None, imported=False, planned=None, attempted=None, unattempted=None, partial=False):
        rows = rows or []
        status = 'imported' if imported and available else 'observed' if available else 'unavailable' if targets or report.get('gaps') else 'not-run'
        evaluated = len(rows) if rows else (len(available) if isinstance(available, list) and available else None)
        coverage.append(dict(category=category, status=status, source=source,
            reason='imported-evidence' if status == 'imported' else 'observed-evidence' if status == 'observed' else 'evidence-unavailable' if status == 'unavailable' else 'not-requested',
            planned=planned, attempted=attempted, evaluated=evaluated,
            unattempted=unattempted, partial=partial,
            target_gaps=[dict(host=t.get('host'), gaps=copy.deepcopy(t.get('gaps', []))) for t in targets if t.get('gaps')]))

    def provenance(row, measured, imported_rows, measured_count=None, measured_unit='observations'):
        contexts = []
        if measured:
            contexts.append(dict(status='observed', source='measured', reason='observed-evidence',
                count_unit=measured_unit, planned=row['planned'], attempted=row['attempted'],
                evaluated=measured_count if measured_count is not None else len(measured),
                unattempted=row['unattempted'], partial=row['partial']))
        groups = {}
        for observation in imported_rows:
            groups.setdefault((observation.get('source'), observation.get('source_sha256'), observation.get('observed_at')), []).append(observation)
        for (source, _, observed_at), observations in groups.items():
            scanner_contexts, partial = _import_context(observations, sources)
            contexts.append(dict(status='imported', source=source, reason='imported-evidence', observed_at=observed_at,
                count_unit='observations', planned=None, attempted=None, evaluated=len(observations), unattempted=None,
                partial=partial, observations=scanner_contexts))
        if contexts:
            row['contexts'] = contexts
            if len(contexts) == 1:
                row.update({k: contexts[0][k] for k in ('status', 'source', 'reason', 'count_unit', 'planned', 'attempted', 'evaluated', 'unattempted', 'partial')})
            else:
                row.update(status='observed' if measured else 'imported', source='mixed', reason='mixed-evidence',
                    count_unit=None, planned=None, attempted=None, evaluated=None, unattempted=None, partial=True)

    add('wifi-configuration', _rows(report.get('wifi')), 'local')
    firewall = [r for r in _rows(report.get('firewall')) if type(r.get('enabled')) is bool]
    add('local-firewall', firewall, 'local', partial=len(firewall) < len(_rows(report.get('firewall'))))
    dns_targets = [t for t in targets if isinstance(t.get('dns'), dict)]
    dns = [t['dns'] for t in dns_targets if t['dns'].get('status') == 'ok' and _origin(t['dns']) == 'measured']
    dns_statuses = [t['dns'].get('status') for t in dns_targets if _origin(t['dns']) == 'measured']
    dns_attempted = sum(s not in ('not_run', 'not-run') for s in dns_statuses) if dns_statuses and all(s not in (None, 'cancelled') for s in dns_statuses) else None
    dns_planned = _count(run.get('planned_hosts')) if runs else len(dns_statuses) if dns_statuses else None
    if _count(run.get('attempted_hosts')) is not None and run['attempted_hosts'] > len(targets):
        dns_attempted = None
    add('dns-resolution', dns, 'measured', planned=dns_planned, attempted=dns_attempted,
        partial=scope_partial or bool(targets) and len(dns) < (dns_planned if dns_planned is not None else len(targets)))
    coverage[-1]['count_unit'] = 'hosts'
    tcp_all = [row for target in targets for row in _rows(target.get('tcp'))]
    tcp = [r for r in tcp_all if _origin(r) == 'measured']
    attempted_tcp = [row for row in tcp if _count(row.get('attempts')) is not None and row['attempts'] > 0]
    for family in ('IPv4', 'IPv6'):
        rows = [r for r in attempted_tcp if r.get('family') == family]
        all_rows = [r for r in tcp if r.get('family') == family]
        add(family.lower(), rows, 'measured', partial=scope_partial or any(r.get('status') in ('partial', 'cancelled', 'not_run', 'not-run') for r in all_rows))
        coverage[-1].update(count_unit='connections', evaluated=sum(r['attempts'] for r in rows) if rows else None)
    imported_tcp = [s for a in _rows(report.get('assets')) for s in _rows(a.get('services'))
                    if s.get('protocol') == 'tcp' and s.get('source') in ('nmap', 'greenbone', 'scanner')]
    imported_tcp.extend(r for r in tcp_all if _origin(r) == 'imported')
    tcp_import_contexts, _ = _import_context(imported_tcp, sources)
    connection_count = sum(r['attempts'] for r in attempted_tcp) if attempted_tcp else None
    tcp_only_scope = (not any(_rows(t.get(field)) for t in targets for field in ('tls', 'http'))
                      and connection_count == _count(run.get('attempted_connections')) and connection_count is not None)
    planned_connections = _count(run.get('planned_connections')) if tcp_only_scope else None
    unattempted_connections = (planned_connections - connection_count
        if planned_connections is not None and planned_connections >= connection_count else None)
    add('tcp-exposure', attempted_tcp or imported_tcp, 'measured' if attempted_tcp else 'nmap',
        imported=not attempted_tcp and bool(imported_tcp), planned=planned_connections,
        attempted=connection_count, unattempted=unattempted_connections,
        partial=scope_partial or bool(runs) and not tcp_only_scope or any(r.get('status') in ('partial', 'cancelled', 'not_run', 'not-run') for r in tcp))
    coverage[-1].update(count_unit='connections' if attempted_tcp else 'endpoints',
        evaluated=connection_count if attempted_tcp else len(imported_tcp) if imported_tcp else None,
        observations=tcp_import_contexts)
    provenance(coverage[-1], attempted_tcp, imported_tcp, connection_count, 'connections')
    for category, field in [('tls-validation', 'tls'), ('http-posture', 'http')]:
        all_rows = [r for t in targets for r in _rows(t.get(field))]
        rows = [r for r in all_rows if r.get('status') in ('ok', 'certificate_error', 'certificate-error', 'http_error', 'redirect')]
        measured = [r for r in rows if _origin(r) == 'measured']
        imported_rows = [r for r in rows if _origin(r) == 'imported']
        add(category, measured, 'measured', partial=scope_partial or any(r.get('status') in ('cancelled', 'not_run', 'not-run') for r in all_rows if _origin(r) == 'measured'))
        provenance(coverage[-1], measured, imported_rows)
    packet_sources = [s for s in sources if s.get('type') in ('packets', 'pcap', 'pcapng')]
    packet_contexts = _packet_contexts(report)
    live = isinstance(report.get('capture_session'), dict)
    add('live-capture' if live else 'offline-packets', bool(packet_sources) or bool(report.get('packets')) or bool(packet_contexts),
        'measured' if live else 'packets', imported=not live)
    coverage[-1].update(count_unit='packets', planned=None, attempted=None, unattempted=None,
        evaluated=packet_contexts[0].get('packets') if len(packet_contexts) == 1 else None,
        partial=True,  # Decoding a capture does not establish its network/time scope.
        observations=copy.deepcopy(packet_sources), contexts=copy.deepcopy(packet_contexts))
    if len(packet_contexts) > 1:
        coverage[-1]['reason'] = 'multiple-scope-contexts'
    scanners = [s for s in sources if s.get('type') in ('nmap', 'greenbone')]
    def source_count(field):
        values = [s.get('coverage', {}).get(field) if isinstance(s.get('coverage'), dict) else None for s in scanners]
        return values[0] if len(values) == 1 and _count(values[0]) is not None else None
    add('external-vulnerability-scan', scanners, 'scanner', imported=True,
        planned=source_count('planned'), attempted=source_count('attempted'), unattempted=source_count('unattempted'),
        partial=len(scanners) > 1 or any(not isinstance(s.get('coverage'), dict) or s['coverage'].get('partial') is True for s in scanners))
    coverage[-1]['evaluated'] = source_count('evaluated')
    coverage[-1]['observations'] = copy.deepcopy(scanners)
    # Local environment context remains a separate checklist item: it supplies
    # provenance/caveats and is never interpreted as a passed control.
    add('environment-context', bool(report.get('environment')), 'local')
    for row in coverage:
        if row['category'] in ('dns-resolution', 'ipv4', 'ipv6', 'tcp-exposure', 'tls-validation', 'http-posture') and runs:
            row['run_contexts'] = copy.deepcopy(runs)
            row['partial'] = row['partial'] or scope_partial
            if len(runs) > 1:
                row.update(planned=None, attempted=None, evaluated=None, unattempted=None, reason='multiple-scope-contexts')
                for context in row.get('contexts', []):
                    if context.get('source') == 'measured':
                        context.update(planned=None, attempted=None, evaluated=None, unattempted=None,
                            partial=True, reason='multiple-scope-contexts', run_contexts=copy.deepcopy(runs))
    return coverage
