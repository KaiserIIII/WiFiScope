"""Bounded JSON and typed report validation before case persistence."""
import json

from .export_schema import NUMBERS, BOOLEANS, IDENTITIES, TIMES, ENUMS
from .numeric import supported_number

MAX_BYTES = 16 * 1024 * 1024
LIST_RECORDS = frozenset(('wifi', 'interfaces', 'routes', 'firewall', 'connectivity', 'sources',
    'imported_findings', 'endpoints', 'conversations', 'arp_bindings', 'packet_analysis_contexts',
    'run_contexts', 'services', 'observations', 'contexts', 'target_gaps', 'tcp', 'tls', 'http'))
DICT_RECORDS = frozenset(('packet_analysis', 'investigation', 'run', 'environment', 'summary', 'priorities', 'limits', 'protocol_counts', 'comparison'))
COUNTERS = frozenset(('packets', 'captured_bytes', 'bytes', 'tcp_syn_packets', 'tcp_reset_packets',
    'dns_queries', 'dns_nxdomain', 'plaintext_http_packets', 'planned', 'attempted', 'evaluated',
    'unattempted', 'planned_hosts', 'attempted_hosts', 'planned_connections', 'attempted_connections',
    'unattempted_endpoints', 'attempts', 'successes'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def validate_comparison(value):
    """Check the dedicated comparison schema before projection or persistence."""
    message = 'Invalid comparison shape; use typed before/after snapshots, counts and change records.'
    if (not isinstance(value, dict) or value.get('mode') not in ('identity', 'counts-only')
            or type(value.get('partial')) is not bool):
        raise ValueError(message)
    for key in ('before', 'after'):
        side = value.get(key)
        if not isinstance(side, dict) or not isinstance(side.get('summary'), dict):
            raise ValueError(message)
        for count in ('assets', 'findings'):
            if type(side['summary'].get(count)) is not int or side['summary'][count] < 0:
                raise ValueError(message)
        if 'snapshot_id' in side and (type(side['snapshot_id']) is not int or side['snapshot_id'] < 1):
            raise ValueError(message)
        for rows in ('assets', 'coverage', 'sources'):
            if not isinstance(side.get(rows), list) or any(not isinstance(r, dict) for r in side[rows]):
                raise ValueError(message)
        if not isinstance(side.get('gaps'), list) or any(not isinstance(gap, str) for gap in side['gaps']):
            raise ValueError(message)
    for key in ('asset_changes', 'wifi_changes'):
        rows = value.get(key)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(message)
        if key == 'wifi_changes':
            for row in rows:
                if any(row.get(side) is not None and not isinstance(row[side], dict) for side in ('before', 'after')):
                    raise ValueError(message)


def validate_report(report):
    if not isinstance(report, dict) or type(report.get('schema_version')) is not int or report['schema_version'] != 1:
        raise ValueError('Case snapshot requires schema_version=1 report.')
    from .extensions import validate_extensions
    validate_extensions(report)
    if 'comparison' in report:
        validate_comparison(report['comparison'])
    lists = {'wifi', 'interfaces', 'routes', 'firewall', 'connectivity', 'findings', 'sources',
             'assets', 'imported_findings', 'packet_analysis_contexts', 'run_contexts'}
    dictionaries = {'investigation', 'packet_analysis', 'run', 'environment'}
    for key in lists & report.keys():
        if not isinstance(report[key], list) or any(not isinstance(row, dict) for row in report[key]):
            raise ValueError('Case snapshot field ' + key + ' requires a list of records.')
    for key in dictionaries & report.keys():
        if not isinstance(report[key], dict):
            raise ValueError('Case snapshot field ' + key + ' requires a record.')
    pending = [(report, 0, None)]
    minimum_size = 0
    while pending:
        value, depth, field = pending.pop()
        if field in ('wifi_survey', 'catalog_audit') and depth == 1:
            # Dedicated validators own extension-specific field meanings (such
            # as survey metric and catalog counters). Their bounded traversal
            # and the final canonical byte cap cover the complete subtree.
            minimum_size += len(canonical(value).encode('utf-8'))
            if minimum_size > MAX_BYTES:
                raise ValueError('Case snapshot exceeds 16 MiB.')
            continue
        if depth > 64:
            raise ValueError('Case snapshot exceeds 64 nesting levels.')
        minimum_size += 1
        if isinstance(value, str):
            minimum_size += len(value.encode('utf-8'))
        elif isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError('Case snapshot JSON keys must be strings.')
            minimum_size += sum(len(key.encode('utf-8')) for key in value)
            for key, child in value.items():
                is_records = field != 'protocol_counts' and (key in LIST_RECORDS or key in ('assets', 'findings', 'coverage') and field != 'summary')
                if is_records and (not isinstance(child, list) or any(not isinstance(row, dict) for row in child)):
                    # Only an actual source row has record-shaped coverage.
                    # Investigation/checklist coverage always requires rows.
                    source_coverage = (key == 'coverage' and isinstance(child, dict)
                                       and field in ('sources', 'observations')
                                       and isinstance(value.get('type'), str)
                                       and value.get('type') in ENUMS['type'])
                    if not source_coverage:
                        raise ValueError('Case snapshot field ' + key + ' requires typed records.')
                if key in DICT_RECORDS and not isinstance(child, dict):
                    raise ValueError('Case snapshot field ' + key + ' requires a record.')
                if key == 'gaps' and (not isinstance(child, list) or any(not isinstance(gap, str) for gap in child)):
                    raise ValueError('Case snapshot gaps require a list of codes.')
            if field == 'protocol_counts' and any(type(n) is not int or n < 0 for n in value.values()):
                raise ValueError('Case snapshot protocol counters require nonnegative integers.')
            if field == 'protocol_counts':
                for number in value.values():
                    supported_number(number)
            if field != 'protocol_counts':
                pending.extend((child, depth + 1, key) for key, child in value.items())
        elif isinstance(value, list):
            pending.extend((child, depth + 1, field) for child in value)
        elif value is not None and type(value) not in (int, float, bool):
            raise ValueError('Case snapshot contains unsupported JSON data.')
        supported_number(value)
        if minimum_size > MAX_BYTES:
            raise ValueError('Case snapshot exceeds 16 MiB.')
        if value is None:
            continue
        if field in COUNTERS and not (field == 'packets' and isinstance(value, dict)) and (type(value) is not int or value < 0):
            raise ValueError('Case snapshot counter requires a nonnegative integer: ' + field)
        if field in ('src_port', 'dst_port', 'port') and (type(value) is not int or not 0 <= value <= 65535):
            raise ValueError('Case snapshot port requires an integer in 0..65535.')
        if field in NUMBERS and type(value) not in (int, float):
            raise ValueError('Case snapshot numeric field has invalid type: ' + field)
        if field in BOOLEANS and type(value) is not bool:
            raise ValueError('Case snapshot boolean field has invalid type: ' + field)
        if field in IDENTITIES and not isinstance(value, (str, list)):
            raise ValueError('Case snapshot identifier has invalid type: ' + field)
        if field in TIMES and not isinstance(value, str):
            raise ValueError('Case snapshot timestamp has invalid type: ' + field)
        if field in ENUMS and not isinstance(value, str):
            raise ValueError('Case snapshot enum has invalid type: ' + field)
    result = canonical(report)
    if len(result.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Case snapshot canonical JSON exceeds 16 MiB.')
    return result
