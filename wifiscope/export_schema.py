"""One allowlisted export projection for reports, cases and investigations.

Unknown keys and untrusted prose are discarded. Pseudonyms correlate inside one
snapshot only; they provide data minimization, not guaranteed anonymity.
"""
from datetime import datetime
import hashlib
import hmac
import re
import secrets

from .rules import catalog
from .wifi import _security_value
from .numeric import supported_number

IDENTITIES = frozenset(('ssid', 'bssid', 'name', 'mac', 'mac_address', 'interface',
    'interface_name', 'interface_alias', 'host', 'hostname', 'hostnames', 'address', 'addresses',
    'gateway', 'destination', 'url', 'urls', 'target', 'targets', 'ip', 'ipv4', 'ipv6',
    'dns_servers', 'profile', 'id', 'asset_id', 'component_ids', 'finding_id', 'source_sha256', 'sha256',
    'certificate_sha256', 'fingerprint', 'issue_id', 'product', 'service', 'cipher',
    'src_address', 'dst_address'))
STRUCTURES = frozenset(('wifi', 'interfaces', 'routes', 'firewall', 'connectivity',
    'findings', 'evidence', 'nested', 'observations', 'details', 'dns', 'answers', 'tcp',
    'tls', 'http', 'header_presence', 'security_checks', 'environment', 'assets',
    'services', 'sources', 'imported_findings', 'coverage', 'investigation', 'summary',
    'priorities', 'target_gaps', 'run', 'run_contexts', 'packets', 'packets_contexts', 'counts',
    'case', 'snapshots', 'contexts', 'packet_analysis', 'packet_analysis_contexts',
    'endpoints', 'conversations', 'arp_bindings', 'protocol_counts', 'limits',
    'comparison', 'before', 'after', 'asset_changes', 'wifi_changes'))
NUMBERS = frozenset(('signal_percent', 'channel', 'metric', 'port', 'attempts',
    'successes', 'failure_percent', 'rtt_min_ms', 'rtt_mean_ms', 'rtt_max_ms', 'jitter_ms',
    'status_code', 'elapsed_ms', 'duration_ms', 'score', 'qod', 'days_remaining',
    'planned', 'attempted', 'evaluated', 'unattempted', 'planned_hosts', 'attempted_hosts',
    'planned_connections', 'attempted_connections', 'unattempted_endpoints', 'deadline_seconds',
    'high', 'medium', 'low', 'info', 'measured', 'imported', 'unknown', 'captured_bytes', 'bytes', 'snapshot_id',
    'src_port', 'dst_port', 'tcp_syn_packets', 'tcp_reset_packets', 'dns_queries', 'dns_nxdomain',
    'plaintext_http_packets', 'max_input_bytes', 'max_packets', 'max_endpoints', 'max_conversations',
    'max_arp_bindings', 'max_observations', 'max_vlan_tags', 'max_ipv6_extension_headers',
    'max_ipv6_extension_bytes', 'input_bytes', 'wire_bytes'))
BOOLEANS = frozenset(('enabled', 'proxy_configured', 'server', 'location', 'partial',
    'content_type', 'content_length', 'strict_transport_security', 'content-type',
    'content-length', 'strict-transport-security', 'verified', 'hsts', 'hsts_positive_max_age',
    'csp', 'frame_protection', 'nosniff', 'cookies_secure', 'cookies_httponly', 'has_errors',
    'filtered', 'paginated', 'synthetic', 'identifiers_included'))
ENUMS = {
    'mode': {'identity', 'counts-only'},
    'triage_status': {'open', 'investigating', 'accepted-risk', 'resolved'},
    'family': {'IPv4', 'IPv6'},
    'status': {'ok', 'success', 'failed', 'failure', 'error', 'timeout', 'refused',
        'unavailable', 'cancelled', 'not-run', 'not_run', 'redirect', 'http-error',
        'http_error', 'tls-error', 'tls_error', 'dns-error', 'dns_error', 'partial',
        'resolved', 'no-addresses', 'no_addresses', 'invalid-response', 'invalid_response',
        'certificate-error', 'certificate_error', 'observed', 'needs-review', 'imported-unverified',
        'imported', 'up', 'down', 'conflicting', 'complete', 'deadline', 'not-observed'},
    'severity': {'info', 'warning', 'high', 'low', 'medium', 'critical'},
    'platform': {'Windows', 'Linux', 'Darwin', 'Demo', 'Other'},
    'protocol': {'tcp', 'udp', 'sctp', 'icmp', 'icmpv6', 'arp'},
    'state': {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'},
    'identification': {'probed', 'table'},
    'source': {'measured', 'local', 'nmap', 'greenbone', 'scanner', 'packets', 'pcap', 'pcapng', 'synthetic', 'mixed'},
    'type': {'measured', 'local', 'nmap', 'greenbone', 'scanner', 'packets', 'pcap', 'pcapng', 'synthetic', 'inventory'},
    'category': {'network', 'tls', 'http', 'policy', 'scanner', 'wifi', 'firewall', 'wifi-configuration',
        'local-firewall', 'dns-resolution', 'ipv4', 'ipv6', 'tcp-exposure', 'tls-validation',
        'http-posture', 'offline-packets', 'live-capture', 'external-vulnerability-scan', 'environment-context', 'local-vulnerability-audit', 'wireless-survey', 'catalog-applicability'},
    'reason': {'imported-evidence', 'observed-evidence', 'evidence-unavailable', 'not-requested', 'multiple-scope-contexts', 'mixed-evidence'},
    'count_unit': {'hosts', 'connections', 'endpoints', 'results', 'observations', 'packets'},
    'scan_status': {'complete', 'partial'},
    'content_kind': {'html', 'other'},
}
TIMES = frozenset(('collected_at', 'observed_at', 'imported_at', 'not_after', 'scan_start'))
GAPS = frozenset(source + suffix for source in ('wifi', 'interfaces', 'routes', 'firewall',
    'dns', 'tls', 'http', 'tcp', 'platform', 'interface-addresses', 'probe') for suffix in
    ('-unavailable', '-unsupported', '-timeout', '-cancelled')) | {
    'synthetic-demo', 'scanner-partial', 'scanner-scope-unknown', 'proxy-environment',
    'conflicting-service-observations', 'multiple-platform-contexts', 'multiple-collected_at-contexts',
    'multiple-environment-contexts', 'multiple-packets-contexts', 'multiple-run-contexts',
    'multiple-packet_analysis-contexts', 'packet-timing-limited', 'packet-offload-unknown',
    'packet-checksums-unverified', 'packet-retransmission-unknown', 'packet-truncated',
    'packet-linktype-unsupported', 'packet-block-unsupported', 'packet-time-unknown',
    'packet-vlan-limit', 'packet-transport-unsupported', 'packet-invalid-length',
    'packet-arp-unsupported', 'packet-ipv6-unsupported', 'packet-ipv6-extension-limit',
    'packet-network-unsupported', 'packet-fragment', 'packet-scope-unknown', 'comparison-scope-limited',
    'capture-analysis-limit'}


def project_report(report: dict, include_identifiers: bool = False) -> dict:
    if 'comparison' in report:
        from .case_validation import validate_comparison
        validate_comparison(report['comparison'])
    key = secrets.token_bytes(32)
    templates = catalog()

    def identity(value):
        if isinstance(value, list):
            return [identity(v) for v in value if isinstance(v, str)]
        if not isinstance(value, str):
            return None
        return value if include_identifiers or not value else 'id-' + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:24]

    def walk(value, field=None, path=()):
        supported_number(value)
        if field == 'protocol_counts':
            if isinstance(value, dict):
                for number in value.values():
                    supported_number(number)
            return {name: count for name, count in value.items()
                    if name in ('ipv4', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'arp')
                    and type(count) is int and count >= 0} if isinstance(value, dict) else {}
        if field in IDENTITIES or field == 'dns' and isinstance(value, (str, list)):
            return identity(value)
        if field in TIMES:
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00')).isoformat()
            except (ValueError, TypeError, AttributeError):
                return None
        if isinstance(value, dict):
            if field in NUMBERS:
                return None
            allowed = IDENTITIES | STRUCTURES | NUMBERS | BOOLEANS | ENUMS.keys() | TIMES | {
                'authentication', 'encryption', 'radio_type', 'gaps', 'code', 'title',
                'recommendation', 'retest', 'version', 'confidence', 'cves', 'schema_version'}
            result = {k: walk(v, k, path + (field,)) for k, v in value.items() if k in allowed}
            if 'code' in value or field in ('findings', 'imported_findings'):
                code = value.get('code')
                code = code if isinstance(code, str) and code in templates else 'scanner-finding' if field == 'imported_findings' else 'external-observation'
                title, recommendation, retest = templates.get(code, ('External observation', 'Review the original evidence locally.', 'Retest the same authorized scope independently.'))
                result.update(code=code, title=title, recommendation=recommendation, retest=retest)
                # Preserve the legacy identity-bearing top-level finding interface.
                # Investigation and imported prose always comes from the registry.
                if include_identifiers and field == 'findings' and 'investigation' not in path:
                    for prose in ('title', 'recommendation'):
                        if isinstance(value.get(prose), str):
                            result[prose] = value[prose]
            return result
        if isinstance(value, list):
            if field == 'gaps':
                return [v if v in GAPS else 'evidence-unavailable' for v in value if isinstance(v, str)]
            if field == 'cves':
                return [v for v in value if isinstance(v, str) and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}', v)]
            return [walk(v, field, path) for v in value if isinstance(v, (dict, list))]
        if field == 'schema_version':
            return 1
        if field in NUMBERS or field in ('assets', 'findings', 'packets') and type(value) is int:
            return value if supported_number(value) else None
        if field == 'confidence':
            if supported_number(value) and 0 <= value <= 1:
                return value
            return value if value in ('high', 'medium', 'low') else 'unknown'
        if field in BOOLEANS:
            return value if type(value) is bool else None
        if field in ENUMS:
            return value if isinstance(value, str) and value in ENUMS[field] else 'unknown'
        if field in ('authentication', 'encryption'):
            return _security_value(value, field)
        if field == 'version':
            if isinstance(value, str) and value in ('TLSv1', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'):
                return value
            return identity(value)
        if field == 'radio_type':
            return value if value in ('802.11a', '802.11b', '802.11g', '802.11n', '802.11ac', '802.11ax', '802.11be') else 'unknown'
        return None

    result = dict(schema_version=1, collected_at=walk(report.get('collected_at'), 'collected_at'), platform=walk(report.get('platform'), 'platform'))
    for field in ('wifi', 'interfaces', 'routes', 'firewall', 'connectivity', 'findings', 'gaps'):
        result[field] = walk(report.get(field) if isinstance(report.get(field), list) else [], field)
    for field in ('assets', 'imported_findings', 'sources', 'investigation', 'run', 'run_contexts', 'packets', 'packets_contexts', 'packet_analysis', 'packet_analysis_contexts', 'case', 'snapshots', 'comparison', 'synthetic'):
        if field in report:
            result[field] = walk(report[field], field)
    env = report.get('environment') if isinstance(report.get('environment'), dict) else {}
    result['environment'] = dict(proxy_configured=env.get('proxy_configured') is True)
    from .extensions import project_extensions
    result.update(project_extensions(report, identity))
    # Export cannot recover identifiers already removed by an earlier projection.
    # The opt-in may preserve persisted pseudonyms for local triage only.
    result['identifiers_included'] = include_identifiers and report.get('identifiers_included') is not False
    from .investigate import _run_contexts
    contexts = _run_contexts(report)
    if len(contexts) > 1:
        result['run_contexts'] = walk(contexts, 'run_contexts')
        result.pop('run', None)
    return result
