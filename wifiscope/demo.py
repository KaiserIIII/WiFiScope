"""Offline synthetic observations."""
import struct

from .audit import assess


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
