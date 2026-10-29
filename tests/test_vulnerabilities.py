"""Synthetic local advisory boundaries; no scanner or network activity."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr


def native():
    return dict(schema_version=1, catalog_version='test-1', reviewed_at='2026-10-28',
        products=[dict(id='httpd', aliases=['Apache httpd'], scheme='numeric')],
        rules=[dict(id='CVE-2021-41773', product='httpd', exact=['2.4.49'], ranges=[],
                    priority='high', score=7.5, reviewed_at='2026-10-28',
                    references=['https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773'])])


def evidence(product='Apache httpd', version='2.4.49', **changes):
    service = dict(port=8080, protocol='tcp', state='open', identification='probed',
                   product=product, version=version, source='nmap', observed_at='2026-01-01T00:00:00Z')
    service.update(changes)
    return dict(schema_version=1, collected_at='2026-01-02T00:00:00Z', platform='Other',
                assets=[dict(address='192.0.2.18', services=[service])], wifi=[], firewall=[],
                gaps=[], sources=[dict(type='nmap', coverage=dict(partial=True))])


class CatalogTests(unittest.TestCase):
    def load(self, value, **options):
        from wifiscope.advisory_catalog import load_catalog
        return load_catalog(json.dumps(value).encode(), **options)

    def test_numeric_and_portable_comparison_and_unknown_versions(self):
        from wifiscope.advisory_catalog import parse_version, matches_version
        self.assertLess(parse_version('1.9', 'numeric'), parse_version('1.10', 'numeric'))
        self.assertLess(parse_version('9.7p2', 'openssh-portable'), parse_version('9.7p10', 'openssh-portable'))
        for version in ('2.4.49-ubuntu1', '2.4.49rc1', 'v2.4.49', '', '1.' + '9' * 30, True):
            self.assertIsNone(parse_version(version, 'numeric'))
        rule = dict(exact=[], ranges=[dict(start='1.9', start_inclusive=False, end='1.11', end_inclusive=False)])
        self.assertFalse(matches_version('1.9', 'numeric', rule))
        self.assertTrue(matches_version('1.10', 'numeric', rule))
        self.assertFalse(matches_version('1.11', 'numeric', rule))

    def test_native_hash_pin_and_untrusted_metadata(self):
        from wifiscope.advisory_catalog import load_catalog
        data = json.dumps(native()).encode()
        value = load_catalog(data, expected_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(value['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(value['source'], 'user-supplied-sha256-checked')
        self.assertEqual(self.load(native())['source'], 'user-supplied-unverified')
        for pin in ('0' * 64, '../secret', True):
            with self.assertRaises(ValueError):
                load_catalog(data, expected_sha256=pin)
        pack = native()
        pack['rules'][0]['references'].append('https://private.example/secret')
        self.assertNotIn('private.example', json.dumps(self.load(pack)))

    def test_native_rejects_ambiguous_executable_and_extreme_data(self):
        mutations = [lambda p: p.update(command='run'),
            lambda p: p['rules'][0].update(regex='.*'),
            lambda p: p['rules'][0].update(id='CVE-invalid'),
            lambda p: p['rules'][0].update(score=True),
            lambda p: p['rules'][0].update(score=float('inf')),
            lambda p: p['rules'][0].update(exact=['2.4.49-ubuntu']),
            lambda p: p['rules'].append(copy.deepcopy(p['rules'][0])),
            lambda p: p['products'].append(dict(id='other', aliases=['Apache httpd'], scheme='numeric')),
            lambda p: p['rules'][0].update(exact=[], ranges=[dict(start='2', end='1', start_inclusive=True, end_inclusive=True)]),
            lambda p: p['rules'][0].update(ranges=[{}] * 33),
            lambda p: p.update(catalog_version='x' * 257),
            lambda p: p.update(rules=p['rules'] * 5001)]
        for mutation in mutations:
            value = native()
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.load(value)

    def test_size_depth_duplicate_keys_and_invalid_json_rejected(self):
        from wifiscope.advisory_catalog import load_catalog
        for data in (b'x' * (16 * 1024 * 1024 + 1), b'[]', b'{"schema_version":1,"schema_version":1}',
                     b'[' * 18 + b'0' + b']' * 18, b'{"x":NaN}'):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                load_catalog(data)

    def test_alias_range_and_metadata_boundaries_are_strict(self):
        changes = [lambda p: p['products'][0].update(aliases=['a'] * 33),
            lambda p: p['products'][0].update(scheme='python-expression'),
            lambda p: p['rules'][0].update(reviewed_at='2026-02-30'),
            lambda p: p['rules'][0].update(score=-.1),
            lambda p: p['rules'][0].update(score=10.1),
            lambda p: p['rules'][0].update(exact=[], ranges=[dict(start='2', start_inclusive=True, end='2', end_inclusive=False)]),
            lambda p: p['rules'][0].update(exact=[], ranges=[dict(start='2', start_inclusive='yes')]),
            lambda p: p['rules'][0].update(exact=[], ranges=[dict(end='2', end_inclusive=True, operator='eval')])]
        for change in changes:
            pack = native()
            change(pack)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load(pack)

    def test_nvd_modification_is_not_a_verified_review_and_negation_is_not_flattened(self):
        pack = dict(vulnerabilities=[dict(cve=dict(id='CVE-2021-41773', lastModified='2026-10-28T00:00:00Z',
            configurations=[dict(nodes=[dict(cpeMatch=[dict(vulnerable=True,
                criteria='cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')])])]))])
        catalog = self.load(pack, format='nvd2')
        self.assertIsNone(catalog['reviewed_at'])
        self.assertIsNone(catalog['rules'][0]['reviewed_at'])
        pack['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['negate'] = True
        negative = self.load(pack, format='nvd2')
        self.assertEqual(negative['rules'], [])
        self.assertGreater(negative['import_gaps']['nvd-applicability-unverified'], 0)

    def test_nvd_conflicting_bounds_and_oversized_models_are_rejected(self):
        match = dict(vulnerable=True, criteria='cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
                     versionStartIncluding='2.4.50', versionEndExcluding='2.4.49')
        pack = dict(vulnerabilities=[dict(cve=dict(id='CVE-2021-41773', configurations=[dict(cpeMatch=[match])]))])
        with self.assertRaises(ValueError):
            self.load(pack, format='nvd2')
        pack['vulnerabilities'] *= 5001
        with self.assertRaises(ValueError):
            self.load(pack, format='nvd2')

    def test_nvd_only_explicit_cpes_and_unknown_applicability(self):
        pack = dict(vulnerabilities=[dict(cve=dict(id='CVE-2021-41773', lastModified='2026-10-28T00:00:00Z',
            descriptions=[dict(value='PRIVATE-PROSE<script>')], metrics=dict(cvssMetricV31=[dict(cvssData=dict(baseScore=7.5))]),
            configurations=[dict(operator='AND', nodes=[dict(operator='OR', cpeMatch=[dict(vulnerable=True,
                criteria='cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartIncluding='2.4.49', versionEndExcluding='2.4.50'),
                dict(vulnerable=False, criteria='cpe:2.3:o:vendor:system:*:*:*:*:*:*:*:*')])])]))])
        catalog = self.load(pack, format='nvd2')
        self.assertEqual(len(catalog['rules']), 1)
        self.assertGreater(catalog['import_gaps']['nvd-applicability-unverified'], 0)
        self.assertNotIn('PRIVATE-PROSE', json.dumps(catalog))
        from wifiscope.vulnerabilities import audit_vulnerabilities
        candidate = audit_vulnerabilities(evidence(), catalog)['vulnerability_audit']['candidates'][0]
        self.assertIn('nvd-applicability-unverified', candidate['gaps'])
        self.assertEqual(candidate['status'], 'imported-unverified')
        for criteria in ('cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:x',
                         'cpe:2.3:a:apache:other:*:*:*:*:*:*:*:*',
                         'cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*',
                         'cpe:2.3:a:apache:http_server:2.4.49\\:*:*:*:*:*:*:*:*'):
            altered = copy.deepcopy(pack)
            altered['vulnerabilities'][0]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria'] = criteria
            normalized = self.load(altered, format='nvd2')
            self.assertEqual(normalized['rules'], [])
            self.assertGreater(sum(normalized['import_gaps'].values()), 0)


class VulnerabilityTests(unittest.TestCase):
    def audit(self, report, catalog=None):
        from wifiscope.vulnerabilities import audit_vulnerabilities
        return audit_vulnerabilities(report, catalog)

    def test_builtin_boundaries_do_not_infer_fixed_or_exploitable(self):
        cases = [('Apache httpd', '2.4.49', {'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2024-38475', 'CVE-2024-27316'}),
            ('Apache httpd', '2.4.50', {'CVE-2021-42013', 'CVE-2024-38475', 'CVE-2024-27316'}),
            ('Apache httpd', '2.4.16', {'CVE-2024-38475'}), ('Apache httpd', '2.4.17', {'CVE-2024-38475', 'CVE-2024-27316'}),
            ('Apache httpd', '2.4.59', {'CVE-2024-38475'}), ('Apache httpd', '2.4.60', set()),
            ('OpenSSH', '8.4p1', set()), ('OpenSSH', '8.5p1', {'CVE-2024-6387'}),
            ('OpenSSH', '9.7p1', {'CVE-2024-6387'}), ('OpenSSH', '9.8p1', set()),
            ('nginx', '0.6.17', set()), ('nginx', '0.6.18', {'CVE-2021-23017'}),
            ('nginx', '1.20.0', {'CVE-2021-23017'}), ('nginx', '1.20.1', set())]
        for product, version, expected in cases:
            audit = self.audit(evidence(product, version))['vulnerability_audit']
            with self.subTest(product=product, version=version):
                self.assertEqual({r['cve'] for r in audit['candidates']}, expected)
                self.assertEqual(audit['summary']['evaluated_services'], 1)
                self.assertIn('reviewed-subset-only', audit['gaps'])
                self.assertTrue(all(c['status'] == 'imported-unverified' for c in audit['candidates']))

    def test_explicit_evidence_unknown_backports_and_confidence(self):
        for report in (evidence(None, None), evidence('http', '2.4.49', identification='table'),
                       evidence(version='2.4.49-ubuntu1'), evidence(version='2.4.49rc1')):
            audit = self.audit(report)['vulnerability_audit']
            self.assertEqual(audit['candidates'], [])
            self.assertEqual(audit['summary']['unknown_services'], 1)
        low = self.audit(evidence(identification='table'))['vulnerability_audit']['candidates'][0]
        measured = self.audit(evidence(source='measured'))['vulnerability_audit']['candidates'][0]
        self.assertEqual(low['confidence'], 'low')
        self.assertEqual(measured['status'], 'needs-review')
        self.assertEqual(measured['evidence_status'], 'unknown')
        self.assertIn('backports-unverified', measured['gaps'])

    def test_distinct_identification_evidence_does_not_hide_probed_confidence(self):
        report = evidence(identification='table')
        report['assets'][0]['services'].append(dict(report['assets'][0]['services'][0], identification='probed'))
        candidates = self.audit(report)['vulnerability_audit']['candidates']
        self.assertEqual(len(candidates), 8)
        self.assertEqual({r['identification'] for r in candidates}, {'table', 'probed'})
        self.assertEqual({r['confidence'] for r in candidates}, {'low', 'medium'})

    def test_baseline_combines_wifi_firewall_tls_http_and_exposure(self):
        report = evidence()
        report.update(wifi=[dict(ssid='synthetic', authentication='Open', encryption='Open')],
            firewall=[dict(name='Public', enabled=False)],
            connectivity=[dict(host='example.invalid', tls=[dict(address='192.0.2.18', port=443,
                status='certificate-error', source='measured')], http=[dict(address='192.0.2.18',
                port=80, status='ok', status_code=200, url='http://example.invalid', source='measured')])])
        audited = self.audit(report)
        codes = {r['code'] for r in audited['investigation']['findings']}
        self.assertTrue({'open-wifi', 'firewall-disabled', 'tls-trust', 'http-transport', 'cve-version-match'} <= codes)
        self.assertEqual(audited['vulnerability_audit']['summary']['baseline_checks'], 5)

    def test_unsupported_product_and_no_evidence_keep_coverage_unknown(self):
        audit = self.audit(dict(schema_version=1))
        coverage = next(r for r in audit['investigation']['coverage'] if r['category'] == 'local-vulnerability-audit')
        self.assertEqual(coverage['status'], 'unavailable')
        for product in ('Apacheish httpd', 'Apache Tomcat', 'Apache'):
            unknown = self.audit(evidence(product))['vulnerability_audit']
            self.assertEqual(unknown['summary']['unknown_services'], 1)
            self.assertEqual(unknown['candidates'], [])

    def test_match_work_service_and_result_limits_refuse_before_excess(self):
        from unittest.mock import patch
        with patch('wifiscope.vulnerabilities.MAX_CANDIDATES', 4):
            self.assertEqual(len(self.audit(evidence())['vulnerability_audit']['candidates']), 4)
        with patch('wifiscope.vulnerabilities.MAX_CANDIDATES', 3), self.assertRaisesRegex(ValueError, 'candidate'):
            self.audit(evidence())
        # Four Apache rules contain five exact/range predicates, not four units.
        with patch('wifiscope.vulnerabilities.MAX_MATCH_WORK', 5):
            self.assertEqual(self.audit(evidence())['vulnerability_audit']['summary']['evaluated_services'], 1)
        with patch('wifiscope.vulnerabilities.MAX_MATCH_WORK', 4), self.assertRaisesRegex(ValueError, 'predicate'):
            self.audit(evidence())
        report = evidence()
        report['assets'][0]['services'].append(dict(report['assets'][0]['services'][0], port=8081))
        with patch('wifiscope.vulnerabilities.MAX_SERVICES', 2):
            self.assertEqual(self.audit(report)['vulnerability_audit']['summary']['evaluated_services'], 2)
        with patch('wifiscope.vulnerabilities.MAX_SERVICES', 1), self.assertRaisesRegex(ValueError, 'service'):
            self.audit(report)

    def test_memory_catalog_tampering_cannot_claim_builtin_authority(self):
        from wifiscope.advisory_catalog import builtin_catalog
        catalog = builtin_catalog()
        catalog['rules'][0]['exact'] = ['99']
        with self.assertRaises(ValueError):
            self.audit(evidence(), catalog)
        from wifiscope.advisory_catalog import load_catalog
        catalog = load_catalog(json.dumps(native()).encode())
        catalog['products'].append(dict(id='other', aliases=['other'], scheme='numeric'))
        catalog['rules'].append(dict(catalog['rules'][0], product='other'))
        with self.assertRaises(ValueError):
            self.audit(evidence(), catalog)

    def test_audit_preserves_original_idempotently_and_enters_investigation(self):
        from wifiscope.investigate import build_investigation, merge_reports
        original = evidence()
        saved = copy.deepcopy(original)
        first = self.audit(original)
        self.assertEqual(original, saved)
        self.assertEqual(first['assets'], original['assets'])
        second = self.audit(first)
        self.assertEqual(first, second)
        candidates = first['vulnerability_audit']['candidates']
        findings = [r for r in first['investigation']['findings'] if r['code'] == 'cve-version-match']
        self.assertEqual({r['id'] for r in candidates}, {r['id'] for r in findings})
        self.assertEqual(len(findings), 4)
        self.assertEqual(build_investigation(first)['investigation']['findings'], first['investigation']['findings'])
        coverage = [r for r in first['investigation']['coverage'] if r['category'] == 'local-vulnerability-audit'][0]
        self.assertEqual(coverage['evaluated'], 1)
        self.assertTrue(coverage['partial'])
        with self.assertRaises(ValueError):
            merge_reports([first, original])

    def test_shared_projection_joins_case_roundtrip_and_no_resurrection(self):
        from wifiscope.cases import CaseStore
        from wifiscope.reports import prepare_export
        from wifiscope.case_validation import validate_report
        report = self.audit(evidence())
        raw_id = report['vulnerability_audit']['candidates'][0]['id']
        projected = prepare_export(report)
        validate_report(projected)
        audit = projected['vulnerability_audit']
        candidate = audit['candidates'][0]
        finding = next(r for r in projected['investigation']['findings'] if r['id'] == candidate['id'])
        self.assertEqual(candidate['address'], projected['assets'][0]['address'])
        self.assertEqual(candidate['product'], projected['assets'][0]['services'][0]['product'])
        self.assertEqual(candidate['version'], projected['assets'][0]['services'][0]['version'])
        self.assertEqual(candidate['asset_id'], projected['investigation']['assets'][0]['id'])
        self.assertEqual(candidate['id'], finding['id'])
        self.assertNotEqual(raw_id, candidate['id'])
        self.assertEqual(candidate['cve'], 'CVE-2021-41773')
        self.assertNotIn('192.0.2.18', json.dumps(projected))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'case.db'
            with CaseStore(path) as store:
                snapshot = store.add_snapshot(projected)
            with CaseStore(path) as store:
                restored = store.load_snapshot(snapshot)
                validate_report(prepare_export(restored))
                self.assertEqual(len(restored['vulnerability_audit']['candidates']), 4)
        redone = self.audit(projected)
        self.assertFalse(redone['identifiers_included'])
        self.assertEqual(redone['vulnerability_audit']['summary']['evaluated_services'], 0)
        self.assertIn('redacted-version-evidence', redone['vulnerability_audit']['gaps'])
        self.assertFalse(prepare_export(redone, True)['identifiers_included'])

    def test_hostile_unknown_fields_are_discarded_and_typed_shape_rejected(self):
        from wifiscope.reports import export_report, prepare_export
        from wifiscope.case_validation import validate_report
        report = self.audit(evidence())
        report['vulnerability_audit']['private_note'] = 'SECRET-NOTE<script>'
        report['vulnerability_audit']['candidates'][0]['description'] = '=SECRET-COMMAND<script>'
        report['vulnerability_audit']['candidates'][0]['affected']['private_note'] = 'SECRET-RANGE'
        with tempfile.TemporaryDirectory() as directory:
            paths = export_report(report, Path(directory) / 'new')
            for path in paths.values():
                text = Path(path).read_text(encoding='utf-8-sig')
                for secret in ('SECRET-NOTE', 'SECRET-COMMAND', 'SECRET-RANGE', '192.0.2.18', 'Apache httpd'):
                    self.assertNotIn(secret, text)
        for key, value in [('candidates', 'wrong'), ('summary', []), ('schema_version', True)]:
            bad = self.audit(evidence())
            bad['vulnerability_audit'][key] = value
            with self.assertRaises(ValueError):
                validate_report(bad)
            with self.assertRaises(ValueError):
                prepare_export(bad)

    def test_typed_candidate_values_and_public_references_are_enforced(self):
        from wifiscope.case_validation import validate_report
        from wifiscope.reports import prepare_export
        mutations = [('score', True), ('score', float('nan')), ('score', 11), ('severity', 'critical'),
                     ('observed_at', 'PRIVATE-TIME'), ('port', True), ('cve', 'CVE-bad'),
                     ('references', ['https://httpd.apache.org/private/path']),
                     ('affected', dict(scheme='numeric', exact=['2.4.49-ubuntu'], ranges=[]))]
        for key, value in mutations:
            report = self.audit(evidence())
            report['vulnerability_audit']['candidates'][0][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    validate_report(report)
                with self.assertRaises(ValueError):
                    prepare_export(report)
        report = self.audit(evidence())
        candidate = report['vulnerability_audit']['candidates'][0]
        report['vulnerability_audit']['candidates'].append(copy.deepcopy(candidate))
        report['vulnerability_audit']['summary']['candidates'] += 1
        with self.assertRaises(ValueError):
            validate_report(report)
        report = self.audit(evidence())
        report['vulnerability_audit']['summary']['unknown_services'] = 8192
        with self.assertRaises(ValueError):
            prepare_export(report)

    def test_custom_catalog_cli_and_cross_export_id_joins(self):
        from wifiscope.cli import main
        from wifiscope.reports import prepare_export
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path, catalog_path = root / 'input.json', root / 'catalog.json'
            report_path.write_text(json.dumps(evidence()), encoding='utf-8')
            data = json.dumps(native()).encode()
            catalog_path.write_bytes(data)
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(['vuln', '--input', str(report_path), '--catalog', str(catalog_path),
                    '--catalog-sha256', hashlib.sha256(data).hexdigest(), '--include-identifiers'])
            self.assertEqual(code, 0, errors.getvalue())
            report = json.loads(output.getvalue())
            self.assertTrue(report['identifiers_included'])
            candidate = report['vulnerability_audit']['candidates'][0]
            self.assertEqual(candidate['score'], 7.5)
            self.assertEqual(candidate['address'], '192.0.2.18')
            self.assertEqual(report['vulnerability_audit']['catalog']['source'], 'user-supplied-sha256-checked')
        first = prepare_export(report)
        second = prepare_export(first)
        candidate = second['vulnerability_audit']['candidates'][0]
        self.assertEqual(candidate['address'], second['assets'][0]['address'])
        self.assertEqual(candidate['asset_id'], second['investigation']['assets'][0]['id'])
        self.assertEqual(candidate['id'], next(r['id'] for r in second['investigation']['findings'] if r['code'] == 'cve-version-match'))
        self.assertNotEqual(candidate['id'], first['vulnerability_audit']['candidates'][0]['id'])

    def test_forged_builtin_catalog_metadata_rejected_at_import_and_export(self):
        from wifiscope.case_validation import validate_report
        from wifiscope.reports import prepare_export
        from wifiscope.workstation import load_json
        original = self.audit(evidence())
        for key, value in [('catalog_version', 'PRIVATE-CATALOG-NOTE'), ('sha256', '0' * 64),
                           ('reviewed_at', '2026-10-27'), ('format', 'nvd2'), ('rule_count', 5),
                           ('import_gaps', {'nvd-cpe-unsupported': 1})]:
            forged = copy.deepcopy(original)
            forged['vulnerability_audit']['catalog'][key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_report(forged)
                with self.assertRaises(ValueError):
                    prepare_export(forged)
                projected = prepare_export(original)
                projected['vulnerability_audit']['catalog'][key] = value
                with self.assertRaises(ValueError):
                    prepare_export(projected)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'forged.json'
                    path.write_text(json.dumps(forged), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        load_json(path)
        projected = prepare_export(prepare_export(original))
        validate_report(projected)
        self.assertEqual(projected['vulnerability_audit']['catalog']['catalog_version'], 'reviewed-subset-2026-10-28.1')

    def test_redacted_connectivity_and_mixed_reaudits_retain_all_unknown_observations(self):
        from wifiscope.reports import prepare_export
        tcp = dict(address='192.0.2.19', port=80, protocol='tcp', source='measured',
                   observed_at='2026-01-01T00:00:00Z', status='ok', attempts=1, successes=1)
        for mixed, expected in ((False, 1), (True, 2)):
            report = evidence() if mixed else dict(schema_version=1)
            report['connectivity'] = [dict(host='example.invalid', tcp=[tcp])]
            first = self.audit(report)
            self.assertEqual(first['vulnerability_audit']['summary']['unknown_services'], 1)
            projected = prepare_export(first)
            for iteration in range(3):
                with self.subTest(mixed=mixed, iteration=iteration):
                    redone = self.audit(projected)
                    audit = redone['vulnerability_audit']
                    self.assertEqual(audit['summary']['unknown_services'], expected)
                    self.assertEqual(audit['summary']['evaluated_services'], 0)
                    self.assertEqual(audit['candidates'], [])
                    self.assertEqual(len(audit['unevaluated']), expected)
                    self.assertTrue(all(row['gaps'] == ['redacted-version-evidence'] for row in audit['unevaluated']))
                    self.assertFalse(redone['identifiers_included'])
                    self.assertNotIn('192.0.2.19', json.dumps(redone))
                    self.assertEqual(redone['connectivity'], projected['connectivity'])
                    projected = prepare_export(redone)

    def test_redacted_tcp_missing_time_uses_source_aware_original_context(self):
        from wifiscope.reports import prepare_export
        collected = '2026-10-28T12:00:00Z'
        for source, expected_time in (('nmap', None), ('greenbone', None),
                                      ('measured', '2026-10-28T12:00:00+00:00')):
            report = dict(schema_version=1, collected_at=collected,
                connectivity=[dict(host='example.invalid', tcp=[dict(address='192.0.2.19',
                    port=80, source=source, status='ok', attempts=1, successes=1)])])
            self.assertEqual(self.audit(report)['vulnerability_audit']['unevaluated'][0]['observed_at'], expected_time)
            projected = prepare_export(report)
            for iteration in range(2):
                with self.subTest(source=source, iteration=iteration):
                    redone = self.audit(projected)
                    audit = redone['vulnerability_audit']
                    self.assertEqual(audit['summary']['unknown_services'], 1)
                    self.assertEqual(audit['summary']['evaluated_services'], 0)
                    self.assertEqual(audit['unevaluated'][0]['source'], source)
                    self.assertEqual(audit['unevaluated'][0]['observed_at'], expected_time)
                    self.assertFalse(redone['identifiers_included'])
                    self.assertEqual(audit['candidates'], [])
                    projected = prepare_export(redone)

    def test_cli_vuln_uses_bounded_local_inputs_privacy_and_error_semantics(self):
        from wifiscope.cli import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text(json.dumps(evidence()), encoding='utf-8')
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(['vuln', '--input', str(path)])
            self.assertEqual(code, 0, err.getvalue())
            report = json.loads(out.getvalue())
            self.assertFalse(report['identifiers_included'])
            self.assertEqual(len(report['vulnerability_audit']['candidates']), 4)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(['vuln', '--input', str(path), '--catalog-sha256', 'bad'])
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
