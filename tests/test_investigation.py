import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wifiscope import importers, investigate, scope
from wifiscope.reports import prepare_export, export_report


NMAP = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun start="1700000000"><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/><hostnames><hostname name="private.example"/></hostnames><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="table" conf="3"/></port><port protocol="tcp" portid="443"><state state="filtered"/><service name="https" method="probed" conf="10" product="PRIVATE-PRODUCT" version="1.2"/></port></ports></host><host><address addr="2001:db8::8" addrtype="ipv6"/></host><runstats><finished exit="success"/><hosts total="2" up="1" down="1"/></runstats></nmaprun>'''
GB = b'''<get_reports_response status="200"><report><report><scan_start>2026-01-01T00:00:00Z</scan_start><scan_run_status>Done</scan_run_status><results><result id="private-result"><host>2001:db8::8<hostname>private.example</hostname></host><port>443/tcp</port><severity>7.5</severity><qod><value>80</value></qod><nvt oid="1.3.6.1.4.1.25623.1.0.123"><name>SECRET-TITLE</name><refs><ref type="cve" id="CVE-2025-12345"/></refs></nvt></result><result><host>192.0.2.8</host><port>general/tcp</port><severity>0</severity></result></results></report></report></get_reports_response>'''


class ScopeTests(unittest.TestCase):
    def test_scope_is_ordered_deduplicated_and_handles_small_networks(self):
        self.assertEqual(scope.expand_scope(['192.0.2.0/30', '192.0.2.1', '2001:db8::/127']),
                         ['192.0.2.1', '192.0.2.2', '2001:db8::', '2001:db8::1'])
        self.assertEqual(scope.expand_scope(['192.0.2.0/31', '192.0.2.2/32', '2001:db8::8/128']),
                         ['192.0.2.0', '192.0.2.1', '192.0.2.2', '2001:db8::8'])

    def test_scope_rejects_unsafe_or_unbounded_targets(self):
        for entries in [['::/64'], ['2001:db8::/64'], ['192.0.2.0/24'], ['0.0.0.0'],
                        ['224.0.0.1'], ['255.255.255.255'], ['example.invalid'], ['::']]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                scope.expand_scope(entries)
        with self.assertRaises(ValueError):
            scope.expand_scope(['192.0.2.0/26', '198.51.100.0/30', '203.0.113.1'])
        with self.assertRaises(ValueError):
            scope.expand_scope([], max_hosts=65)

    def test_scope_rejects_aggregate_size_before_host_enumeration(self):
        with patch('ipaddress.IPv4Network.hosts', side_effect=AssertionError('enumerated before budget')):
            with self.assertRaises(ValueError):
                scope.expand_scope(['192.0.2.0/26', '198.51.100.0/29'])


class ImporterTests(unittest.TestCase):
    def test_nmap_preserves_identity_confidence_state_and_provenance(self):
        report = importers.import_nmap(NMAP)
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(len(report['assets']), 2)
        service = report['assets'][0]['services'][0]
        self.assertEqual((service['identification'], service['confidence']), ('table', .3))
        self.assertEqual(report['assets'][0]['services'][1]['state'], 'filtered')
        self.assertEqual(report['assets'][1]['address'], '2001:db8::8')
        source = report['sources'][0]
        self.assertEqual(len(source['sha256']), 64)
        self.assertNotEqual(source['imported_at'], source['observed_at'])
        self.assertEqual(source['coverage']['planned'], 2)
        self.assertEqual(source['coverage']['evaluated'], 2)

    def test_greenbone_preserves_score_qod_issue_identity_and_unknown_port(self):
        report = importers.import_greenbone(GB)
        result = report['imported_findings'][0]
        self.assertEqual((result['score'], result['qod']), (7.5, 80))
        self.assertEqual(result['cves'], ['CVE-2025-12345'])
        self.assertEqual(result['status'], 'imported-unverified')
        self.assertEqual(result['source'], 'greenbone')
        self.assertEqual(result['address'], '2001:db8::8')
        self.assertIsNone(report['imported_findings'][1]['port'])
        self.assertNotIn('SECRET-TITLE', json.dumps(report))

    def test_xml_guards_reject_entities_encodings_nesting_and_large_attributes(self):
        for data in [b'<!DOCTYPE nmaprun SYSTEM "file:///secret"><nmaprun/>',
                     b'<!DOCTYPE nmaprun [<!ENTITY x "secret">]><nmaprun>&x;</nmaprun>',
                     '<!DOCTYPE nmaprun [<!ENTITY x "secret">]><nmaprun/>'.encode('utf-16'),
                     b'<nmaprun>' + b'<x>' * 65 + b'</x>' * 65 + b'</nmaprun>',
                     b'<nmaprun x="' + b'a' * 4097 + b'"/>', b'<nmaprun><x>' + b'a' * 65537 + b'</x></nmaprun>',
                     b'<nmaprun/> ' + b' ' * (16 * 1024 * 1024), b'<nmaprun>',
                     b'<?xml version="1.0" encoding="ISO-8859-1"?><nmaprun/>']:
            with self.subTest(data=data[:70]), self.assertRaises(ValueError):
                importers.import_nmap(data)

    def test_wrong_dialects_invalid_values_and_failed_responses_rejected(self):
        for function, data in [(importers.import_nmap, b'<report/>'),
                               (importers.import_greenbone, b'<get_reports_response status="500"/>'),
                               (importers.import_greenbone, b'<report><results><result host="1.2.3.4"/></results></report>'),
                               (importers.import_nmap, NMAP.replace(b'portid="23"', b'portid="70000"')),
                               (importers.import_greenbone, GB.replace(b'>7.5<', b'>NaN<')),
                               (importers.import_greenbone, GB.replace(b'>80<', b'>101<')),
                               (importers.import_greenbone, GB.replace(b'>443/tcp<', b'>garbage<'))]:
            with self.subTest(data=data[:90]), self.assertRaises(ValueError):
                function(data)

    def test_empty_and_partial_scans_are_distinct(self):
        empty = importers.import_nmap(b'<nmaprun><runstats><finished exit="success"/><hosts total="0" up="0" down="0"/></runstats></nmaprun>')
        self.assertEqual(empty['assets'], [])
        self.assertFalse(empty['sources'][0]['coverage']['partial'])
        partial = importers.import_nmap(NMAP.replace(b'exit="success"', b'exit="error" errormsg="SECRET"'))
        self.assertTrue(partial['sources'][0]['coverage']['partial'])
        self.assertNotIn('SECRET', json.dumps(partial))
        gb = importers.import_greenbone(GB.replace(b'>Done<', b'>Running<'))
        self.assertTrue(gb['sources'][0]['coverage']['partial'])
        unknown = importers.import_nmap(b'<nmaprun/>')
        self.assertIsNone(unknown['sources'][0]['coverage']['planned'])

    def test_importer_record_caps(self):
        with self.assertRaises(ValueError):
            importers.import_nmap(b'<nmaprun>' + b'<host/>' * 4097 + b'</nmaprun>')
        with self.assertRaises(ValueError):
            importers.import_greenbone(b'<report><results>' + b'<result/>' * 65537 + b'</results></report>')

    def test_nmap_absent_status_is_unknown_and_bounds_count_results_not_port_text(self):
        report = importers.import_nmap(b'<nmaprun start="1700000000"><host><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"/></ports></host></nmaprun>')
        self.assertEqual(report['assets'][0]['services'][0]['state'], 'unknown')
        self.assertIsNotNone(report['assets'][0].get('observed_at'))
        with self.assertRaises(ValueError):
            importers.import_nmap(b'<nmaprun>' + b'<x/>' * 200000 + b'</nmaprun>')

    def test_greenbone_filtered_errors_and_unknown_scope_are_explicit(self):
        for addition in (b'<filters><term>SECRET</term></filters>', b'<errors><error>SECRET</error></errors>', b'<result_count><full>100</full></result_count>'):
            report = importers.import_greenbone(GB.replace(b'<scan_start>', addition + b'<scan_start>'))
            self.assertTrue(report['sources'][0]['coverage']['partial'])
            self.assertNotIn('SECRET', json.dumps(report))


def measured():
    return dict(schema_version=1, collected_at='2026-01-01T00:00:00Z',
                connectivity=[dict(host='private.example', dns=dict(status='ok', answers=[]), gaps=['tcp-timeout'],
                    tcp=[dict(address='192.0.2.8', family='IPv4', port=23, status='ok', attempts=1, successes=1),
                         dict(address='2001:db8::8', family='IPv6', port=23, status='timeout', attempts=1, successes=0),
                         dict(address='192.0.2.8', family='IPv4', port=443, status='ok', attempts=1, successes=1)],
                    tls=[], http=[])])


class InvestigationTests(unittest.TestCase):
    def test_stable_findings_no_mutation_and_no_port_based_tls_or_cve_claims(self):
        original = measured()
        saved = copy.deepcopy(original)
        one = investigate.build_investigation(original)
        two = investigate.build_investigation(original)
        self.assertEqual(original, saved)
        self.assertEqual(one, two)
        self.assertIn('investigation', one)
        findings = one['investigation']['findings']
        self.assertIn('cleartext-exposure', {r['code'] for r in findings})
        self.assertIn('family-reachability', {r['code'] for r in findings})
        self.assertFalse(any(r['code'].startswith('tls-') for r in findings))
        self.assertNotIn('CVE-', json.dumps(findings))
        self.assertNotIn('bypass', json.dumps(findings))
        self.assertEqual(len({r['id'] for r in findings}), len(findings))

    def test_tls_and_conditional_http_rules(self):
        report = measured()
        row = report['connectivity'][0]
        row['tls'] = [dict(address='192.0.2.8', port=443, status='certificate_error'),
                      dict(address='192.0.2.9', port=443, status='ok', verified=True, days_remaining=-1, version='TLSv1', cipher='RC4-SHA')]
        checks = dict(hsts_positive_max_age=False, csp=False, frame_protection=False, nosniff=False, cookies_secure=None, cookies_httponly=None)
        row['http'] = [dict(address='192.0.2.8', url='http://private.example/', status='ok', status_code=200, content_kind='other', security_checks=checks)]
        findings = investigate.build_investigation(report)['investigation']['findings']
        codes = {f['code'] for f in findings}
        self.assertTrue({'tls-trust', 'tls-expired', 'tls-legacy', 'tls-weak-cipher', 'http-transport'} <= codes)
        self.assertFalse({'http-hsts', 'http-csp', 'http-frame', 'http-nosniff', 'cookie-secure'} & codes)
        row['http'][0].update(url='https://private.example/', content_kind='html')
        row['http'][0]['security_checks']['cookies_secure'] = False
        codes = {f['code'] for f in investigate.build_investigation(report)['investigation']['findings']}
        self.assertTrue({'http-hsts', 'http-csp', 'http-frame', 'http-nosniff', 'cookie-secure'} <= codes)
        row['http'][0]['status_code'] = 500
        codes = {f['code'] for f in investigate.build_investigation(report)['investigation']['findings']}
        self.assertNotIn('http-csp', codes)

    def test_ip_literal_https_does_not_require_hsts(self):
        report = measured()
        report['connectivity'][0]['http'] = [dict(address='192.0.2.8', url='https://192.0.2.8/', status='ok', status_code=200,
            content_kind='html', security_checks=dict(hsts_positive_max_age=False))]
        findings = investigate.build_investigation(report)['investigation']['findings']
        self.assertNotIn('http-hsts', {f['code'] for f in findings})

    def test_empty_coverage_unknown_and_partial_accounting(self):
        result = investigate.build_investigation({})['investigation']
        self.assertEqual(len(result['coverage']), 11)
        self.assertTrue(all(row['status'] in ('not-run', 'unavailable') for row in result['coverage']))
        report = measured()
        report['run'] = dict(status='cancelled', planned_hosts=4, attempted_hosts=1, planned_connections=12,
                             attempted_connections=3, unattempted_endpoints=9, deadline_seconds=5)
        coverage = {r['category']: r for r in investigate.build_investigation(report)['investigation']['coverage']}
        self.assertTrue(coverage['tcp-exposure']['partial'])
        self.assertEqual(coverage['tcp-exposure']['planned'], 12)
        self.assertEqual(coverage['tcp-exposure']['unattempted'], 9)
        self.assertNotIn('score', result['summary'])

    def test_same_ssid_is_uncertain_and_proxy_is_caveat(self):
        report = dict(wifi=[dict(ssid='same', authentication='Open', encryption='None'), dict(ssid='same', authentication='WPA2', encryption='CCMP')], environment=dict(proxy_configured=True))
        findings = investigate.build_investigation(report)['investigation']['findings']
        mixed = next(f for f in findings if f['code'] == 'mixed-security')
        self.assertEqual(mixed['status'], 'needs-review')
        self.assertNotIn('evil twin', mixed['title'].lower())
        self.assertIn('proxy-environment', investigate.build_investigation(report)['investigation']['gaps'])

    def test_merge_dedup_conflicts_distinct_issues_and_provenance(self):
        nmap = importers.import_nmap(NMAP)
        gb = importers.import_greenbone(GB)
        gb['imported_findings'].append(dict(gb['imported_findings'][0], issue_id='1.2.3.4', cves=['CVE-2025-99999']))
        packets = dict(schema_version=1, packets=dict(status='imported', counts=dict(packets=2)), sources=[dict(type='packets', sha256='a' * 64)])
        inputs = [measured(), nmap, gb, packets, copy.deepcopy(nmap)]
        saved = copy.deepcopy(inputs)
        result = investigate.merge_reports(inputs)
        self.assertEqual(inputs, saved)
        self.assertEqual(len(result['sources']), 4)
        self.assertEqual(result['packets']['counts']['packets'], 2)
        asset = next(a for a in result['investigation']['assets'] if a['address'] == '192.0.2.8')
        self.assertIn('conflicting-service-observations', asset['gaps'])
        imported = [f for f in result['investigation']['findings'] if f['code'] == 'scanner-finding']
        self.assertEqual(len(imported), 3)
        self.assertEqual(len({f['id'] for f in imported}), 3)
        with self.assertRaises(ValueError):
            investigate.merge_reports([prepare_export(result)])
        with self.assertRaises(ValueError):
            investigate.merge_reports([{}] * 17)

    def test_merge_aggregate_asset_and_record_caps(self):
        a = dict(assets=[dict(address=f'192.0.{i // 256}.{i % 256}', services=[]) for i in range(2500)])
        b = dict(assets=[dict(address=f'198.51.{i // 256}.{i % 256}', services=[]) for i in range(2500)])
        with self.assertRaises(ValueError):
            investigate.merge_reports([a, b])
        rows = [dict(port=22, protocol='tcp', state='open')] * 33000
        with self.assertRaises(ValueError):
            investigate.merge_reports([dict(assets=[dict(address='192.0.2.1', services=rows)]), dict(assets=[dict(address='192.0.2.2', services=rows)])])

    def test_merge_size_cap_and_mac_ip_noncorrelation(self):
        with self.assertRaises(ValueError):
            investigate.merge_reports([dict(unknown='x' * (9 * 1024 * 1024)), dict(unknown='y' * (9 * 1024 * 1024))])
        report = dict(assets=[dict(mac='02:00:00:00:00:01'), dict(address='192.0.2.8')])
        self.assertEqual(len(investigate.build_investigation(report)['investigation']['assets']), 2)

    def test_source_scope_counts_survive_coverage_without_invented_dns_attempts(self):
        report = investigate.build_investigation(importers.import_nmap(NMAP))
        coverage = {c['category']: c for c in report['investigation']['coverage']}
        self.assertEqual(coverage['external-vulnerability-scan']['planned'], 2)
        self.assertEqual(coverage['external-vulnerability-scan']['evaluated'], 2)
        self.assertIsNone(coverage['dns-resolution']['attempted'])

    def test_reachability_findings_remain_distinct_by_target_and_unknown_counts_null(self):
        report = measured()
        report['connectivity'].append(copy.deepcopy(report['connectivity'][0]))
        report['connectivity'][1]['host'] = 'other.example'
        findings = investigate.build_investigation(report)['investigation']['findings']
        self.assertEqual(sum(f['code'] == 'family-reachability' for f in findings), 2)
        empty = investigate.build_investigation({})['investigation']['coverage']
        self.assertTrue(all(c['evaluated'] is None for c in empty))

    def test_imported_observations_keep_unverified_status_even_with_tls_metadata(self):
        report = dict(connectivity=[dict(tls=[dict(address='192.0.2.1', port=443, source='nmap', status='ok', days_remaining=-1, version='TLSv1')])])
        findings = investigate.build_investigation(report)['investigation']['findings']
        self.assertTrue(all(f['status'] == 'imported-unverified' for f in findings if f['code'].startswith('tls-')))

    def test_deduplicating_scan_does_not_discard_new_local_evidence(self):
        scan = importers.import_nmap(NMAP)
        combined = copy.deepcopy(scan)
        combined.update(measured())
        result = investigate.merge_reports([scan, combined])
        self.assertEqual(len(result['connectivity']), 1)
        self.assertEqual(sum(s['type'] == 'nmap' for s in result['sources']), 1)

    def test_unstarted_dns_does_not_count_as_attempted(self):
        report = dict(connectivity=[dict(host='private.example', dns=dict(status='not_run', answers=[]))])
        row = next(c for c in investigate.build_investigation(report)['investigation']['coverage'] if c['category'] == 'dns-resolution')
        self.assertEqual(row['attempted'], 0)


class InvestigationExportTests(unittest.TestCase):
    def test_typed_export_filters_free_text_and_preserves_security_measurements(self):
        report = investigate.merge_reports([measured(), importers.import_nmap(NMAP), importers.import_greenbone(GB)])
        report['run'] = dict(status='partial', planned_hosts=4, attempted_hosts=1, unattempted_endpoints=9)
        report['assets'][0].update(product='SECRET-DUMP', note='SECRET-DUMP')
        report['investigation']['findings'][0].update(title='SECRET-DUMP', recommendation='SECRET-DUMP', retest='SECRET-DUMP')
        report['investigation']['findings'][0]['evidence']['nested'] = dict(product='SECRET-DUMP', address='192.0.2.8', unknown='SECRET-DUMP', title='SECRET-DUMP')
        prepared = prepare_export(report)
        encoded = json.dumps(prepared)
        for secret in ('192.0.2.8', '2001:db8::8', 'private.example', 'PRIVATE-PRODUCT', 'SECRET-DUMP', 'private-result'):
            self.assertNotIn(secret, encoded)
        self.assertEqual(prepared['run']['unattempted_endpoints'], 9)
        self.assertEqual(prepared['imported_findings'][0]['qod'], 80)
        asset = prepared['investigation']['assets'][0]
        finding = next(f for f in prepared['investigation']['findings'] if f['code'] == 'cleartext-exposure')
        self.assertEqual(asset['address'], finding['evidence']['address'])
        self.assertEqual(asset['id'], finding['evidence']['asset_id'])
        self.assertIsNone(next(s for s in prepared['sources'] if s['type'] == 'measured')['imported_at'])
        self.assertIn('score', prepared['imported_findings'][0])

    def test_html_prominently_renders_findings_assets_coverage_and_csv(self):
        report = investigate.build_investigation(measured())
        with tempfile.TemporaryDirectory() as temp:
            paths = export_report(report, Path(temp) / 'bundle')
            html = Path(paths['html']).read_text(encoding='utf-8')
            for label in ('Prioritized findings', 'Assets', 'Coverage', 'Cleartext service exposure'):
                self.assertIn(label, html)
            csv = Path(paths['csv']).read_text(encoding='utf-8-sig')
            self.assertIn('investigation.findings', csv)
            self.assertIn('investigation.assets', csv)

    def test_all_security_fields_and_untrusted_nested_known_fields(self):
        report = measured()
        report['connectivity'][0]['http'] = [dict(url='https://private.example/', status='ok', content_kind='html',
            security_checks=dict(hsts=False, hsts_positive_max_age=False, csp=True, frame_protection=None, nosniff=True, cookies_secure=False, cookies_httponly=None))]
        report['investigation'] = dict(findings=[dict(code='tls-trust', title='SECRET', recommendation='SECRET', retest='SECRET', evidence=dict(title='SECRET', note='SECRET', product='SECRET', nested=dict(hostnames=['private.example'], certificate_sha256='SECRET', version='SECRET', source='SECRET', category='SECRET', reason='SECRET', status='SECRET')))])
        report['run'] = dict(status='deadline', planned_hosts=4, attempted_hosts=1, planned_connections=8, attempted_connections=2, unattempted_endpoints=6, deadline_seconds=1.2)
        result = prepare_export(report)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertFalse(result['connectivity'][0]['http'][0]['security_checks']['hsts'])
        self.assertIsNone(result['connectivity'][0]['http'][0]['security_checks']['frame_protection'])
        self.assertEqual(result['run']['status'], 'deadline')
        self.assertEqual(result['run']['attempted_connections'], 2)

    def test_demo_exercises_synthetic_investigation(self):
        from wifiscope.demo import demo_report
        report = demo_report()
        self.assertIn('investigation', report)
        codes = {f['code'] for f in report['investigation']['findings']}
        self.assertTrue({'tls-trust', 'tls-expiring', 'http-csp', 'scanner-finding'} <= codes)
        tls = report['connectivity'][0]['tls'][0]
        self.assertEqual(tls['version'], 'TLSv1.3')
        self.assertGreater(tls['days_remaining'], 0)
        self.assertIn('synthetic-demo', report['gaps'])


class ReviewRegressionTests(unittest.TestCase):
    def test_identical_run_accounting_does_not_establish_shared_scope_identity(self):
        for collected_at in (None, '2026-01-01T00:00:00+00:00'):
            reports = []
            for number in (1, 2):
                report = self.scoped_report('complete', 1, 1)
                if collected_at is None:
                    report.pop('collected_at')
                else:
                    report['collected_at'] = collected_at
                report['connectivity'][0]['host'] = f'host-{number}.example'
                report['connectivity'][0]['tcp'][0]['address'] = f'192.0.2.{number}'
                reports.append(report)
            saved = copy.deepcopy(reports)
            result = investigate.merge_reports(reports)
            self.assertEqual(reports, saved)
            for snapshot in (result, prepare_export(result)):
                self.assertEqual(len(snapshot['run_contexts']), 2)
                for row in snapshot['investigation']['coverage']:
                    if row['category'] in ('dns-resolution', 'ipv4', 'ipv6', 'tcp-exposure'):
                        self.assertTrue(row['partial'])
                        self.assertTrue(all(row[field] is None for field in ('planned', 'attempted', 'evaluated', 'unattempted')))
                        self.assertEqual(len(row['run_contexts']), 2)
            rebuilt = investigate.merge_reports([result])
            self.assertEqual(len(rebuilt['run_contexts']), 2)

    def test_target_import_origin_never_uses_collection_time_as_scan_time(self):
        report = dict(collected_at='2026-03-01T00:00:00+00:00', connectivity=[dict(source='nmap',
            tls=[dict(address='192.0.2.1', port=443, status='ok', days_remaining=-1)],
            http=[dict(address='192.0.2.1', url='http://private.example/', status='ok', status_code=200)],
            tcp=[dict(address='192.0.2.1', family='IPv4', port=23, status='ok', attempts=1, successes=1)])])
        report['connectivity'][0]['tls'].append(dict(address='192.0.2.2', source='nmap', port=443, status='ok', days_remaining=-1))
        saved = copy.deepcopy(report)
        built = investigate.build_investigation(report)
        for result in (built, investigate.build_investigation(built), investigate.merge_reports([report]), investigate.merge_reports([built])):
            for snapshot in (result, prepare_export(result)):
                self.assertIsNone(snapshot['connectivity'][0]['observed_at'])
                self.assertTrue(all(source['observed_at'] is None for source in snapshot['sources']))
                for asset in snapshot['investigation']['assets']:
                    self.assertTrue(all(service['observed_at'] is None for service in asset['services']))
                for finding in snapshot['investigation']['findings']:
                    if finding['category'] in ('tls', 'http', 'network'):
                        self.assertIsNone(finding['evidence']['observed_at'])
                        self.assertEqual(finding['evidence']['source'], 'nmap')
        self.assertEqual(report, saved)

    def test_merged_local_tcp_http_and_sources_retain_original_times(self):
        reports = []
        for month, address in [('01', '192.0.2.1'), ('02', '192.0.2.2')]:
            reports.append(dict(collected_at=f'2026-{month}-01T00:00:00+00:00', connectivity=[dict(host='private.example',
                tcp=[dict(address=address, family='IPv4', port=23, status='ok', attempts=1, successes=1)],
                http=[dict(address=address, url='http://private.example/', status='ok', status_code=200, content_kind='html')])]))
        saved = copy.deepcopy(reports)
        result = investigate.merge_reports(reports)
        self.assertEqual(reports, saved)
        expected = {r['collected_at'] for r in reports}
        for snapshot in (result, prepare_export(result)):
            services = [s for a in snapshot['investigation']['assets'] for s in a['services']]
            self.assertEqual({s['observed_at'] for s in services}, expected)
            http_findings = [f for f in snapshot['investigation']['findings'] if f['code'] == 'http-transport']
            evidence_times = {f['evidence']['observed_at'] for f in http_findings}
            for finding in http_findings:
                evidence_times.update(o['observed_at'] for o in finding['evidence'].get('observations', []))
            self.assertEqual(evidence_times, expected)
            self.assertEqual({s['observed_at'] for s in snapshot['sources'] if s['type'] == 'measured'}, expected)

    def test_explicit_observation_time_and_unknown_time_are_not_overwritten(self):
        one = dict(collected_at='2026-01-01T00:00:00Z', connectivity=[dict(tcp=[
            dict(address='192.0.2.1', port=23, status='ok', successes=1, observed_at=None),
            dict(address='192.0.2.2', port=23, status='ok', successes=1, observed_at='2025-12-01T00:00:00Z')])])
        result = investigate.build_investigation(one)
        observations = {a['address']: a['services'][0] for a in result['investigation']['assets']}
        self.assertIsNone(observations['192.0.2.1']['observed_at'])
        self.assertEqual(observations['192.0.2.2']['observed_at'], '2025-12-01T00:00:00Z')

    @staticmethod
    def scoped_report(status='cancelled', planned=3, attempted=1, month='01'):
        return dict(collected_at=f'2026-{month}-01T00:00:00+00:00', run=dict(status=status,
            planned_hosts=planned, attempted_hosts=attempted, planned_connections=planned,
            attempted_connections=attempted, unattempted_endpoints=planned-attempted),
            connectivity=[dict(host='private.example', dns=dict(status='ok', answers=[]),
                tcp=[dict(address='192.0.2.1', family='IPv4', port=23, status='ok', attempts=1, successes=1)])])

    def test_known_partial_scope_remains_partial_for_dns_and_families(self):
        result = investigate.build_investigation(self.scoped_report())
        for snapshot in (result, prepare_export(result)):
            coverage = {c['category']: c for c in snapshot['investigation']['coverage']}
            self.assertEqual(coverage['dns-resolution']['planned'], 3)
            self.assertEqual(coverage['dns-resolution']['evaluated'], 1)
            for category in ('dns-resolution', 'ipv4', 'ipv6', 'tcp-exposure'):
                self.assertTrue(coverage[category]['partial'], category)
            self.assertEqual(coverage['tcp-exposure']['unattempted'], 2)

    def test_multiple_run_scopes_retain_contexts_and_do_not_mix_counters(self):
        result = investigate.merge_reports([self.scoped_report('complete', 1, 1), self.scoped_report(month='02')])
        for snapshot in (result, prepare_export(result)):
            coverage = {c['category']: c for c in snapshot['investigation']['coverage']}
            for category in ('dns-resolution', 'ipv4', 'ipv6', 'tcp-exposure'):
                row = coverage[category]
                self.assertTrue(row['partial'], category)
                self.assertTrue(all(row[field] is None for field in ('planned', 'attempted', 'evaluated', 'unattempted')), category)
                self.assertEqual(len(row['run_contexts']), 2)
                self.assertEqual(row['reason'], 'multiple-scope-contexts')
                for context in row.get('contexts', []):
                    if context['source'] == 'measured':
                        self.assertTrue(all(context[field] is None for field in ('planned', 'attempted', 'evaluated', 'unattempted')))
        # Rebuilding/merging an already merged report must keep the same contexts.
        again = investigate.merge_reports([result])
        self.assertEqual(len(again['run_contexts']), 2)

    def test_connection_counts_do_not_use_endpoint_record_or_endpoint_gap_units(self):
        report = self.scoped_report(planned=12, attempted=6)
        report['run'].update(planned_hosts=1, attempted_hosts=1, unattempted_endpoints=2)
        report['connectivity'][0]['tcp'][0].update(attempts=6, successes=6)
        coverage = {c['category']: c for c in investigate.build_investigation(report)['investigation']['coverage']}
        self.assertEqual(coverage['tcp-exposure']['evaluated'], 6)
        self.assertEqual(coverage['tcp-exposure']['unattempted'], 6)
        self.assertEqual(coverage['tcp-exposure']['count_unit'], 'connections')

    def test_run_connection_budget_with_tls_is_not_claimed_as_tcp_scope(self):
        report = self.scoped_report('complete', 2, 2)
        report['run'].update(planned_hosts=1, attempted_hosts=1)
        report['connectivity'][0]['tls'] = [dict(address='192.0.2.1', port=443, status='ok')]
        row = next(c for c in investigate.build_investigation(report)['investigation']['coverage'] if c['category'] == 'tcp-exposure')
        self.assertIsNone(row['planned'])
        self.assertTrue(row['partial'])

    def test_external_scanner_host_and_result_units_are_not_summed(self):
        result = investigate.merge_reports([importers.import_nmap(NMAP), importers.import_greenbone(GB)])
        row = next(c for c in result['investigation']['coverage'] if c['category'] == 'external-vulnerability-scan')
        self.assertIsNone(row['evaluated'])
        self.assertTrue(row['partial'])
        self.assertEqual(len(row['observations']), 2)

    def test_udp_only_failed_scan_does_not_claim_tcp_coverage(self):
        data = b'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open"/></port></ports></host><runstats><finished exit="error"/></runstats></nmaprun>'
        result = investigate.build_investigation(importers.import_nmap(data))
        for snapshot in (result, prepare_export(result)):
            row = next(c for c in snapshot['investigation']['coverage'] if c['category'] == 'tcp-exposure')
            self.assertIn(row['status'], ('unavailable', 'not-run'))
            self.assertIsNone(row['evaluated'])

    def test_failed_tcp_scan_keeps_source_partial_context(self):
        result = investigate.build_investigation(importers.import_nmap(NMAP.replace(b'exit="success"', b'exit="error"')))
        for snapshot in (result, prepare_export(result)):
            row = next(c for c in snapshot['investigation']['coverage'] if c['category'] == 'tcp-exposure')
            self.assertEqual(row['status'], 'imported')
            self.assertTrue(row['partial'])
            self.assertEqual(row['evaluated'], 2)
            self.assertTrue(row['observations'][0]['coverage']['partial'])

    def test_imported_only_tls_http_keep_sources_coverage_summary_and_export_imported(self):
        report = dict(connectivity=[dict(tls=[dict(address='192.0.2.1', port=443, source='nmap', status='ok', days_remaining=-1)],
            http=[dict(address='192.0.2.1', source='greenbone', url='https://private.example/', status='ok', status_code=200,
                       content_kind='html', security_checks=dict(csp=False))])])
        result = investigate.build_investigation(report)
        for snapshot in (result, prepare_export(result)):
            coverage = {c['category']: c for c in snapshot['investigation']['coverage']}
            for category, source in [('tls-validation', 'nmap'), ('http-posture', 'greenbone')]:
                self.assertEqual(coverage[category]['status'], 'imported')
                self.assertEqual(coverage[category]['source'], source)
            self.assertFalse(any(s['type'] == 'measured' for s in snapshot['sources']))
            self.assertEqual({s['type'] for s in snapshot['sources']}, {'nmap', 'greenbone'})
            self.assertEqual(snapshot['investigation']['summary']['measured'], 0)
            self.assertGreaterEqual(snapshot['investigation']['summary']['imported'], 2)
            self.assertTrue(all(f['status'] == 'imported-unverified' for f in snapshot['investigation']['findings'] if f['category'] in ('tls', 'http')))

    def test_mixed_tls_provenance_has_separate_contexts_and_unknown_combined_counts(self):
        report = dict(connectivity=[dict(tls=[dict(address='192.0.2.1', port=443, source='nmap', status='ok', days_remaining=-1),
            dict(address='192.0.2.2', port=443, status='ok', days_remaining=20)])])
        result = investigate.build_investigation(report)
        for snapshot in (result, prepare_export(result)):
            row = next(c for c in snapshot['investigation']['coverage'] if c['category'] == 'tls-validation')
            self.assertEqual({(c['status'], c['source']) for c in row['contexts']}, {('observed', 'measured'), ('imported', 'nmap')})
            self.assertEqual(row['source'], 'mixed')
            self.assertIsNone(row['evaluated'])
            self.assertTrue(row['partial'])
            self.assertGreater(snapshot['investigation']['summary']['measured'], 0)
            self.assertGreater(snapshot['investigation']['summary']['imported'], 0)

    def test_unstarted_connectivity_does_not_create_a_measured_source(self):
        result = investigate.build_investigation(dict(connectivity=[dict(tls=[dict(status='not_run')], dns=dict(status='not_run', answers=[]))]))
        self.assertFalse(any(s['type'] == 'measured' for s in result['sources']))

    def test_greenbone_encoded_text_and_misplaced_results_are_not_empty_scans(self):
        unsupported = [
            b'<get_reports_response status="200"><report content_type="application/pdf">JVBERi0xLjQ=</report></get_reports_response>',
            b'<report>BASE64-DATA</report>',
            b'<report content_type="application/pdf"><results/></report>',
            b'<report><scan_run_status>Done</scan_run_status><result host="192.0.2.1"/></report>',
            b'<report><results/><other><result host="192.0.2.1"/></other></report>',
            b'<report><results>BASE64-DATA</results></report>',
            b'<report><results><finding host="192.0.2.1"/></results></report>',
            b'<report><result host="192.0.2.1"/><report><results/></report></report>',
        ]
        for data in unsupported:
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'Unsupported Greenbone'):
                importers.import_greenbone(data)
        for data in [b'<report><scan_run_status>Done</scan_run_status><results/></report>',
                     b'<get_reports_response status="200"><report><report><scan_run_status>Done</scan_run_status><results/></report></report></get_reports_response>']:
            report = importers.import_greenbone(data)
            self.assertEqual(report['imported_findings'], [])
            self.assertEqual(report['sources'][0]['coverage']['evaluated'], 0)
            self.assertFalse(report['sources'][0]['coverage']['partial'])


if __name__ == '__main__':
    unittest.main()
