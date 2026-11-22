"""Layered local network diagnosis and finite in-process monitoring."""

import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import probe
from .field_link import _cancelled, _cidr, _probe_address, echo_probe, read_link
from .field_path import _start_tls, path_checks, validate_path_plan
from .network_state import read_local_network, trace_path

_METHODS = {'gateway': ('gateway', 'icmp-echo'), 'peers': ('peer', 'icmp-echo'),
            'dns': ('dns', 'udp-dns'), 'doh': ('dns', 'https-doh-post'),
            'trace': ('path', 'icmp-trace'), 'ntp': ('path', 'udp-ntp'),
            'application': ('application', 'http-head')}
_ACTIVE_STAGES = ('gateway', 'peer', 'dns', 'path', 'application')
_POSITIVE = {'ok', 'reply'}
_NEGATIVE = {'certificate_error', 'dns_error', 'empty_response', 'error', 'http_error', 'invalid_response',
             'kiss_of_death', 'no_addresses', 'refused', 'timeout', 'tls_error', 'unreachable', 'unsynchronized'}
_PARTIAL = {'redirect', 'response_limit', 'truncated'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _numeric(value):
    address = _probe_address(value)
    if address is None:
        raise ValueError('Use a single unicast numeric IP address without a zone identifier.')
    return address


def _udp_target(endpoint):
    address, port = endpoint
    address = _numeric(str(address))
    return f'[{address}]:{port}' if address.version == 6 else f'{address}:{port}'


def diagnostic_plan(*, interface=None, source=None, gateway=None, peers=(), dns=None, trace=None,
                    application=None, ntp=None, doh=None, timeout=2.0, max_hops=12, samples=1,
                    interval=1.0, failure_threshold=2) -> dict:
    """Validate and normalize a diagnostic preview without collecting or sending traffic."""
    if interface is not None:
        if not isinstance(interface, str) or not 1 <= len(interface.strip()) <= 128 or not interface.isprintable():
            raise ValueError('Supply a printable interface name of at most 128 characters.')
        interface = interface.strip()
    if type(max_hops) is not int or not 1 <= max_hops <= 30:
        raise ValueError('Hop limit must be an integer from 1 to 30.')
    if type(samples) is not int or not 1 <= samples <= 60:
        raise ValueError('Samples must be an integer from 1 to 60.')
    if type(interval) not in (int, float) or not 0 <= interval <= 300:
        raise ValueError('Interval must be from 0 to 300 seconds.')
    if type(failure_threshold) is not int or not 1 <= failure_threshold <= 60:
        raise ValueError('Failure threshold must be an integer from 1 to 60.')
    if not isinstance(peers, (list, tuple)) or len(peers) > 8:
        raise ValueError('Supply a list of up to 8 explicit peer addresses.')
    binding = _numeric(source) if source is not None else None
    addresses = {name: _numeric(value) if value is not None else None
                 for name, value in (('gateway', gateway), ('trace', trace))}
    peers = tuple(dict.fromkeys(_numeric(peer) for peer in peers))
    targets, _ = validate_path_plan(dns=dns, ntp=ntp, doh=doh, source=source, timeout=timeout)
    application = probe._url(application) if application is not None else None
    literals = list(peers) + [address for address in addresses.values() if address is not None]
    for url in (application, targets['doh'].geturl() if targets['doh'] is not None else None):
        if url:
            host = urlsplit(url).hostname
            if probe._literal(host) is not None:
                literals.append(_numeric(host))
    if binding is not None and any(address.version != binding.version for address in literals):
        raise ValueError('Source and numeric destinations must use the same IP family.')
    endpoints = {'gateway': str(addresses['gateway']) if addresses['gateway'] is not None else None,
                 'peers': [str(peer) for peer in peers],
                 'dns': _udp_target(targets['dns']) if targets['dns'] is not None else None,
                 'doh': targets['doh'].geturl() if targets['doh'] is not None else None,
                 'trace': str(addresses['trace']) if addresses['trace'] is not None else None,
                 'ntp': _udp_target(targets['ntp']) if targets['ntp'] is not None else None,
                 'application': application}
    checks = [{'stage': stage, 'method': method, 'target': target}
              for name, (stage, method) in _METHODS.items()
              for target in (endpoints[name] if name == 'peers' else [endpoints[name]]) if target is not None]
    if checks and interface is not None and binding is None:
        raise ValueError('Supply a source address for an explicitly selected interface.')
    return {'interface': interface, 'source': str(binding) if binding is not None else None, **endpoints,
            'timeout_seconds': float(timeout), 'max_hops': max_hops, 'samples': samples,
            'interval_seconds': float(interval), 'failure_threshold': failure_threshold,
            'requires_authorization': bool(checks), 'active_checks': checks}


def _evidence_status(status):
    if status in _POSITIVE:
        return 'ok'
    if status in _NEGATIVE:
        return 'failed'
    if status in _PARTIAL:
        return 'partial'
    return 'cancelled' if status == 'cancelled' else 'unknown'


def _stage_status(checks):
    statuses = {check['status'] for check in checks}
    if not statuses:
        return 'not_requested'
    return next(iter(statuses)) if len(statuses) == 1 else 'partial'


def _active_stage(checks):
    latency = next((row['ms'] for row in checks if row['status'] == 'ok' and row.get('ms') is not None), None)
    return {'status': _stage_status(checks), 'checks': checks, 'latency_ms': latency}


def _application(target, *, timeout, source, broadcasts, cancel):
    host = urlsplit(target).hostname
    result = {'http_status': None, 'address': None, 'ms': None,
              'system_resolver_used': probe._literal(host) is None}
    start = time.monotonic()
    deadline = start + timeout
    try:
        status, answers = probe._resolve(host, timeout, cancel)
    except probe._Cancelled:
        return dict(result, status='cancelled')
    if status != 'ok':
        return dict(result, status=status)
    binding = _probe_address(source) if source is not None else None
    compatible = [item for item in answers if (address := _probe_address(item['address'])) is not None
                  and (binding is None or address.version == binding.version)]
    answer = next((item for item in compatible if item['address'] not in broadcasts), None)
    if answer is None:
        return dict(result, status='local_broadcast_target' if compatible else 'no_compatible_address')
    observation = probe._http_probe(target, answer, timeout, probe._Limiter(cancel, deadline), cancel,
                                    source=source, tls_starter=_start_tls)
    return dict(result, http_status=observation['status_code'], address=observation['address'],
                status='timeout' if observation['status'] == 'not_run' else observation['status'],
                ms=(time.monotonic() - start) * 1000)


def _interface_matches(name, selected, platform):
    if selected is None:
        return True
    if platform == 'Windows' and isinstance(name, str):
        return name.casefold() == selected.casefold()
    return name == selected


def _link_stage(link, local, interface):
    interface_states = [{'interface': row['interface'], 'state': row['state']} for row in local.get('interfaces', ())
                        if row.get('state') and _interface_matches(row.get('interface'), interface,
                                                                   local.get('platform'))]
    states = {row['state'].casefold().replace(' ', '') for row in interface_states}
    down = bool(interface and states and states <= {'down', 'lowerlayerdown', 'disconnected', 'disabled', 'notpresent'})
    if 'local-cancelled' in link.get('gaps', ()):
        status = 'cancelled'
    elif link.get('ssid') and link.get('bssid'):
        signal = link.get('signal_dbm') is not None or link.get('signal_percent') is not None
        status = 'ok' if signal and not down else 'partial'
    elif link.get('ssid') or link.get('bssid'):
        status = 'partial'
    elif 'up' in states:
        status = 'ok'
    elif down:
        status = 'failed'
    else:
        status = 'unknown'
    return dict(link, status=status, interface_states=interface_states)


def _source_status(plan, link, local):
    source = plan['source']
    if not plan['requires_authorization'] or source is None:
        return 'system_selected'
    interface, platform = plan['interface'], local.get('platform')
    rows = [row for row in (link, *local.get('interfaces', ()))
            if _interface_matches(row.get('interface'), interface, platform)]
    observed = {str(address.ip) for row in rows for value in row.get('addresses', ())
                if (address := _cidr(value)) is not None}
    if source in observed:
        return 'bound_source'
    if observed or interface is not None:
        return 'source_unavailable'
    return 'bound_source_unverified'


def _target_ip(target, method):
    if method in ('http-head', 'https-doh-post'):
        return urlsplit(target).hostname
    if method in ('udp-ntp', 'udp-dns'):
        return urlsplit('//' + target).hostname
    return target


def _active_check(check, plan, source_status, broadcasts, cancel):
    method, target = check['method'], check['target']
    if _cancelled(cancel):
        return dict(check, status='cancelled', observation='cancelled')
    if source_status == 'source_unavailable':
        return dict(check, status='unknown', observation='source_unavailable')
    if _target_ip(target, method) in broadcasts:
        return dict(check, status='unknown', observation='local_broadcast_target')
    options = {'timeout': plan['timeout_seconds'], 'source': plan['source'], 'cancel': cancel}
    if method == 'icmp-trace':
        return {**check, **trace_path(target, max_hops=plan['max_hops'], authorized=True, **options)}
    if method == 'icmp-echo':
        evidence = echo_probe(target, **options)
    elif method == 'http-head':
        evidence = _application(target, broadcasts=broadcasts, **options)
    else:
        name = {'udp-dns': 'dns', 'udp-ntp': 'ntp', 'https-doh-post': 'doh'}[method]
        evidence = path_checks(authorized=True, **{name: target}, **options)[name]
    observation = evidence['status']
    return {**evidence, **check, 'status': _evidence_status(observation), 'observation': observation}


def _local_broadcasts(link, local):
    return {str(address.network.broadcast_address) for row in (link, *local.get('interfaces', ()))
            for value in row.get('addresses', ()) if (address := _cidr(value)) is not None
            and address.version == 4 and address.network.prefixlen < 31}


def _sample(plan, sequence, cancel):
    observed_at = _now()
    link = read_link(plan['interface'], cancel=cancel)
    local = read_local_network(cancel=cancel)
    link = _link_stage(link, local, plan['interface'])
    source_status = _source_status(plan, link, local)
    broadcasts = _local_broadcasts(link, local)
    by_stage = {stage: [] for stage in _ACTIVE_STAGES}
    for check in plan['active_checks']:
        by_stage[check['stage']].append(_active_check(check, plan, source_status, broadcasts, cancel))
    stages = {'link': link, 'local': local}
    stages.update({stage: _active_stage(checks) for stage, checks in by_stage.items()})
    routes = [hop['gateway'] for route in local.get('routes', ()) if route['destination'] in ('0.0.0.0/0', '::/0')
              for hop in (route, *route.get('nexthops', ())) if hop.get('gateway')]
    resolvers = [target for row in local.get('interfaces', ()) for target in row.get('dns', ())]
    stages['gateway']['configured_gateways'] = list(dict.fromkeys([*link.get('gateways', ()), *routes]))
    stages['dns']['configured_servers'] = list(dict.fromkeys([*link.get('dns', ()), *resolvers]))
    checks = [row for rows in by_stage.values() for row in rows]
    health = _stage_status(checks or [link, local])
    coverage = [row['status'] for row in [link, local, *checks]]
    if _cancelled(cancel) or 'cancelled' in coverage:
        status = 'cancelled'
    else:
        status = 'partial' if set(coverage) & {'partial', 'unknown'} else 'complete'
    return {'sequence': sequence, 'observed_at': observed_at, 'ended_at': _now(), 'status': status,
            'health': health, 'source_status': source_status, 'stages': stages, 'alerts': []}


def _alert_transitions(sample, states, threshold):
    for stage in _ACTIVE_STAGES:
        for row in sample['stages'][stage]['checks']:
            target, method, status = row['target'], row['method'], row['status']
            state = states.setdefault((stage, method, target), {'consecutive_failures': 0, 'active': False})
            state['consecutive_failures'] = state['consecutive_failures'] + 1 if status == 'failed' else 0
            event = None
            if not state['active'] and state['consecutive_failures'] >= threshold:
                state['active'] = True
                event = 'failure'
            elif state['active'] and status == 'ok':
                state['active'] = False
                event = 'recovery'
            if event is not None:
                yield {'type': event, 'stage': stage, 'method': method, 'target': target,
                       'status': status, 'observation': row['observation'], 'sequence': sample['sequence'],
                       'timestamp': sample['ended_at']}


def _wait_interval(interval, cancel):
    deadline = time.monotonic() + interval
    while not _cancelled(cancel):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(remaining, .05))
    return False


def _run(kind, plan, authorized, cancel, on_sample=None):
    if plan['requires_authorization'] and authorized is not True:
        raise ValueError('Explicit authorization is required for active diagnostic checks.')
    report = {'schema_version': 1, 'kind': kind, 'plan': plan, 'started_at': _now(), 'samples': [], 'alerts': [],
              'notices': ['ICMP timeouts measure the specified probe and may reflect filtering.',
                          'Cached neighbors and listening sockets are local observations.']}
    monitoring = kind == 'network-monitor'
    alert_states = {}
    for sequence in range(1, plan['samples'] + 1):
        if _cancelled(cancel) or (sequence > 1 and not _wait_interval(plan['interval_seconds'], cancel)):
            break
        sample = _sample(plan, sequence, cancel)
        if monitoring and sample['status'] != 'cancelled':
            sample['alerts'] = list(_alert_transitions(sample, alert_states, plan['failure_threshold']))
            report['alerts'].extend(sample['alerts'])
        report['samples'].append(sample)
        if on_sample is not None:
            on_sample(sample)
        if sample['status'] == 'cancelled':
            break
    statuses = {sample['status'] for sample in report['samples']}
    if _cancelled(cancel) or 'cancelled' in statuses or len(report['samples']) < plan['samples']:
        status = 'cancelled'
    else:
        status = 'partial' if 'partial' in statuses else 'complete'
    if monitoring:
        report['alert_state'] = [{'stage': stage, 'method': method, 'target': target, **state}
                                 for (stage, method, target), state in alert_states.items()]
    report.update(status=status, ended_at=_now())
    return report


def diagnose_network(*, authorized=False, cancel=None, **plan_options) -> dict:
    """Return one or more layered diagnostic samples using an explicit plan."""
    return _run('network-diagnostics', diagnostic_plan(**plan_options), authorized, cancel)


def monitor_network(*, authorized=False, cancel=None, on_sample=None, samples=5, **plan_options) -> dict:
    """Sample a finite plan and report local failure and recovery transitions."""
    plan = diagnostic_plan(samples=samples, **plan_options)
    return _run('network-monitor', plan, authorized, cancel, on_sample=on_sample)
