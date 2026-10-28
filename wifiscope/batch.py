"""Explicit bounded audit orchestration, preserving partial results."""
import math
import signal
import threading
import time

from .investigate import build_investigation
from .probe import probe_hosts, validate_request
from .scope import QUICK_PORTS, expand_scope


def plan_scope(scope, ports=None):
    """Plan bounded work; legacy minimum_seconds is an approximate N/4 estimate."""
    hosts = expand_scope(scope)
    ports = list(dict.fromkeys(QUICK_PORTS if ports is None else ports))
    if not hosts:
        raise ValueError('Enter at least one explicit IP/CIDR.')
    validate_request(hosts[:4], ports, 1, .5, [])
    connections = len(hosts) * (len(ports) + (443 in ports))
    return dict(hosts=hosts, ports=ports, planned_hosts=len(hosts), planned_connections=connections,
                minimum_seconds=connections / 4)


def audit_scope(scope, ports=None, *, authorized=False, timeout=.5, deadline=300,
                cancel=None, probe=probe_hosts, wait=None, progress=None):
    if authorized is not True:
        raise ValueError('Explicit authorization is required for this scope.')
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or not 0 < deadline <= 300:
        raise ValueError('Deadline must be greater than zero and at most 300 seconds.')
    plan = plan_scope(scope, ports)
    validate_request(plan['hosts'][:4], plan['ports'], 1, timeout, [])
    cancel = cancel if cancel is not None else threading.Event()
    wait = wait if wait is not None else cancel.wait
    absolute = time.monotonic() + deadline
    records = []
    old_handler = None
    # Turn Ctrl+C into cooperative cancellation so completed rows survive.
    if threading.current_thread() is threading.main_thread():
        old_handler = signal.signal(signal.SIGINT, lambda *_: cancel.set())
    status = 'complete'
    try:
        for offset in range(0, len(plan['hosts']), 4):
            if cancel.is_set():
                status = 'cancelled'
                break
            if time.monotonic() >= absolute:
                status = 'deadline'
                break
            if offset and wait(min(.25, max(0, absolute - time.monotonic()))):
                status = 'cancelled'
                break
            if time.monotonic() >= absolute:
                status = 'deadline'
                break
            rows = probe(plan['hosts'][offset:offset+4], plan['ports'], authorized=True,
                         attempts=1, timeout=timeout, cancel=cancel, deadline=absolute)
            records.extend(rows)
            if progress:
                progress(len(records), len(plan['hosts']))
        if cancel.is_set():
            status = 'cancelled'
        elif time.monotonic() >= absolute:
            status = 'deadline'
    finally:
        if old_handler is not None:
            signal.signal(signal.SIGINT, old_handler)
    actual = sum(row.get('attempts', 0) for record in records for row in record.get('tcp', []))
    actual += sum(row.get('attempts', int(row.get('status') not in ('not_run', 'not-run', 'cancelled'))) for record in records for row in record.get('tls', []) + record.get('http', []))
    attempted_endpoints = sum(row.get('attempts', 0) > 0 for record in records for row in record.get('tcp', []))
    if status == 'complete' and actual < plan['planned_connections']:
        status = 'partial'
    report = dict(connectivity=records, run=dict(status=status, planned_hosts=len(plan['hosts']),
        attempted_hosts=sum(r.get('dns', {}).get('status') not in ('not_run', 'not-run', 'cancelled') for r in records),
        planned_connections=plan['planned_connections'], attempted_connections=actual,
        unattempted_endpoints=max(0, len(plan['hosts']) * len(plan['ports']) - attempted_endpoints),
        deadline_seconds=deadline), gaps=[])
    from datetime import datetime, timezone
    report['collected_at'] = datetime.now(timezone.utc).isoformat()
    return build_investigation(report)
