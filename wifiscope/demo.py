"""Offline synthetic observations."""
import struct

from .audit import assess


def vulnerability_demo():
    """Synthetic vulnerable and adjacent fixed controls through the real matcher."""
    from .vulnerabilities import audit_vulnerabilities
    report = demo_report()
    stamp = '2026-10-28T12:00:00+00:00'
    for index, (product, version) in enumerate([('Apache httpd', '2.4.49'), ('Apache httpd', '2.4.60'),
                                               ('OpenSSH', '9.7p1'), ('OpenSSH', '9.8p1'),
                                               ('nginx', '1.20.0'), ('nginx', '1.20.1')]):
        report['assets'].append(dict(address=f'192.0.2.{100 + index}', status='up', source='nmap', observed_at=stamp,
                                    services=[dict(port=443 if product != 'OpenSSH' else 22, protocol='tcp', state='open',
                                                   product=product, version=version, identification='probed', source='nmap', observed_at=stamp)]))
    return audit_vulnerabilities(report)


def capture_demo():
    """Real offline packet parser only; never opens a live/native handle."""
    from .capture_schema import validate_capture_session
    from .investigate import build_investigation
    report = demo_report()
    packet = report['packet_analysis']
    report['capture_session'] = dict(schema_version=1, id='synthetic-capture', interface='synthetic-offline-adapter',
        backend='npcap', source_sha256=packet['source_sha256'], source='measured', timestamp_source='native-unspecified',
        started_at='2026-01-01T00:00:00+00:00', ended_at='2026-01-01T00:00:00+00:00', duration_ms=0,
        status='complete', stop_reason='eof', packets=packet['packets'], analyzed_packets=packet['packets'],
        captured_bytes=packet['captured_bytes'], wire_bytes=packet['wire_bytes'], storage_bytes=packet['input_bytes'],
        raw_packets=0, raw_retained=False, retain_packets=False, promiscuous=False, filter_applied=False,
        filter_requested=False, linktype=1, partial=True, analysis_limited=False,
        limits=dict(duration_seconds=10, max_packets=2000, max_bytes=8388608, snaplen=96, max_storage_bytes=16777216),
        pcap_stats=dict(received=None, dropped=None, interface_dropped=None))
    validate_capture_session(report['capture_session'])
    return build_investigation(report)


def survey_demo():
    """Actual IDW engine with synthetic dots, estimated center and unknown area."""
    from .heatmap import interpolate_survey
    from .investigate import build_investigation
    data = dict(schema_version=1, id='synthetic-survey', ssid='Synthetic Survey SSID', bssid='02:00:00:00:00:33',
                metric='signal_percent', samples=[])
    for index, (x, y, value) in enumerate([(.2, .2, 85), (.65, .2, 55), (.2, .65, 35), (.55, .55, 65), (.9, .9, None)]):
        data['samples'].append(dict(id=f'synthetic-point-{index}', x=x, y=y, value=value,
                                    observed_at='2026-10-28T12:00:00+00:00', source='imported',
                                    gap='signal-unavailable' if value is None else None))
    return build_investigation(dict(schema_version=1, synthetic=True, gaps=['synthetic-demo'],
                                    wifi_survey=interpolate_survey(data, radius=.7)))


def demo_report() -> dict:
    """Return a fresh fixture using documentation-only addresses."""
    report = dict(schema_version=1, collected_at='2026-01-01T00:00:00+00:00', platform='Demo',
        wifi=[dict(ssid='Example Lab', bssid='02:00:00:00:00:01', authentication='WPA2-Personal', encryption='CCMP', signal_percent=72, channel=36, radio_type='802.11ax'),
              dict(ssid='Example Guest', bssid='02:00:00:00:00:02', authentication='Open', encryption='None', signal_percent=20, channel=6, radio_type='802.11n')],
        interfaces=[dict(name='Example Adapter', mac='02:00:00:00:00:09', addresses=['192.0.2.2', '2001:db8::2'], dns=['192.0.2.53'])],
        routes=[dict(destination='0.0.0.0/0', gateway='192.0.2.1', interface='Example Adapter', metric=10)],
        firewall=[dict(name='Public', enabled=True)], environment={'proxy_configured': False},
        connectivity=[dict(host='example.invalid', dns=dict(status='ok', answers=[dict(family='IPv4', address='192.0.2.80'), dict(family='IPv6', address='2001:db8::80')]),
            tcp=[dict(address=address, family=family, port=443, status='ok', attempts=3, successes=3, failure_percent=0.0, rtt_min_ms=10.0, rtt_mean_ms=12.0, rtt_max_ms=14.0, jitter_ms=2.0) for address, family in [('192.0.2.80', 'IPv4'), ('2001:db8::80', 'IPv6')]],
            tls=[], http=[], gaps=[])], findings=[], gaps=['synthetic-demo'])
    report['findings'] = assess(report)
    report['synthetic'] = True
    report['connectivity'][0]['tls'] = [
        dict(address='192.0.2.80', family='IPv4', port=443, status='ok', verified=True,
             version='TLSv1.3', cipher='TLS_AES_256_GCM_SHA384', days_remaining=14,
             not_after='2026-01-15T00:00:00+00:00', certificate_sha256='0' * 64),
        dict(address='2001:db8::80', family='IPv6', port=443, status='certificate_error', verified=False)]
    report['connectivity'][0]['http'] = [dict(url='https://example.invalid/', address='192.0.2.80', family='IPv4',
        status='ok', status_code=200, content_kind='html', security_checks=dict(hsts=False, hsts_positive_max_age=False,
        csp=False, frame_protection=False, nosniff=False, cookies_secure=False, cookies_httponly=False))]
    report['assets'] = [dict(address='192.0.2.90', family='IPv4', hostnames=['scanner.example.invalid'],
        status='up', source='nmap', observed_at='2025-12-30T00:00:00+00:00', services=[dict(port=23, protocol='tcp',
        state='open', service='telnet', product=None, version=None, identification='table', confidence=.3,
        source='nmap', observed_at='2025-12-30T00:00:00+00:00')])]
    report['imported_findings'] = [dict(address='192.0.2.90', port=23, protocol='tcp', score=5.0, qod=70,
        cves=[], issue_id='synthetic-issue', source='greenbone', status='imported-unverified',
        observed_at='2025-12-30T00:00:00+00:00')]
    report['sources'] = [dict(type=kind, sha256=digit * 64, synthetic=True,
        imported_at='2026-01-01T00:00:00+00:00', observed_at='2025-12-30T00:00:00+00:00',
        coverage=dict(planned=1, attempted=1, evaluated=1, unattempted=0, partial=False))
        for kind, digit in [('nmap', '1'), ('greenbone', '2')]]
    # A hand-built synthetic request exercises the actual offline metadata parser.
    from .packets import analyze_capture
    request = b'GET / HTTP/1.1\r\n\r\n'
    tcp = struct.pack('!HHIIBBHHH', 12345, 80, 0, 0, 80, 24, 8192, 0, 0) + request
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
        bytes([192, 0, 2, 2]), bytes([192, 0, 2, 80])) + tcp
    frame = bytes.fromhex('0200000000800200000000020800') + ip
    capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    capture += struct.pack('<IIII', 1767225600, 0, len(frame), len(frame)) + frame
    packet_report = analyze_capture(capture)
    report['packet_analysis'] = packet_report['packet_analysis']
    report['sources'].extend(dict(source, synthetic=True) for source in packet_report['sources'])
    report['gaps'].extend(packet_report['gaps'])
    from .investigate import build_investigation
    return build_investigation(report)
