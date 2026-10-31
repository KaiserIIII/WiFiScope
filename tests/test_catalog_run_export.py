"""Real saved-run export privacy, scope, snapshot and publication controls."""
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_catalog_chunks import inventory, source_record
from wifiscope.catalog_store import build_catalog
from wifiscope.catalog_runs import create_run, advance_run, read_run_page, run_status
from wifiscope.case_validation import validate_report
from wifiscope.reports import export_report, prepare_export


class RunExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / 'private-run.db'
        self.catalog = self.root / 'private-catalog.db'
        source = self.root / 'private-source.json'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=3,
            startIndex=0, resultsPerPage=3, vulnerabilities=[dict(cve=source_record(n, n == 90003))
            for n in (90001, 90002, 90003)])), encoding='utf8')
        build_catalog([source], self.catalog)
        inv = inventory()
        inv['assets'] = inv['assets'][:1]
        inv['assets'][0].update(id='private-asset', address='192.0.2.177')
        inv['assets'][0]['components'][0].update(id='private-component', source_sha256='d' * 64)
        create_run(self.run, {'schema_version': 1}, inv, self.catalog,
                   store_raw_identifiers=True, page_size=2)

    def export(self, name='bundle', **kwargs):
        from wifiscope.catalog_runs import export_run
        return export_run(self.run, self.root / name, **kwargs)

    def complete(self):
        advance_run(self.run, self.catalog)
        return advance_run(self.run, self.catalog)

    def page(self, number=1, name='bundle'):
        return json.loads((self.root / name / f'page-{number:04d}' / 'report.json').read_text(encoding='utf8'))

    def bundle_text(self, name='bundle'):
        return ''.join(p.read_text(encoding='utf-8-sig') for p in (self.root / name).rglob('*') if p.is_file())

    def assert_joins(self, report):
        validate_report(report)
        audit = report['catalog_audit']
        asset = audit['inventory']['assets'][0]
        components = {c['id'] for c in asset['components']}
        findings = {f['id']: f for f in report['investigation']['findings']}
        self.assertTrue(audit['results'])
        for result in audit['results']:
            self.assertEqual(result['asset_id'], asset['id'])
            self.assertTrue(set(result['component_ids']) <= components)
            self.assertIn(result['id'], findings)
            self.assertEqual(findings[result['id']]['evidence']['asset_id'], asset['id'])

    def test_two_pages_share_private_pseudonyms_without_raw_bundle_data(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.catalog_run_export'),
                             'whole-run export is missing')
        state = self.complete()
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.run, self.catalog)}
        self.assertEqual(self.export(), dict(status='complete', page_count=2, bundle_created=True))
        p1, p2 = self.page(), self.page(2)
        a1 = p1['catalog_audit']['inventory']['assets'][0]['id']
        self.assertEqual(a1, p2['catalog_audit']['inventory']['assets'][0]['id'])
        self.assertRegex(a1, r'^id-[0-9a-f]{24}$')
        self.assertFalse(p1['identifiers_included'])
        for page in (p1, p2):
            self.assert_joins(page)
            self.assertEqual(page['catalog_audit']['status'], 'partial')
            self.assertIsNone(page['catalog_audit']['summary']['unexamined_pairs'])
        text = self.bundle_text()
        for secret in ('private-asset', 'private-component', '192.0.2.177', 'd' * 64,
                       str(self.run), str(self.catalog), str(self.root), state['run_id']):
            self.assertNotIn(secret, text)
        summary = json.loads((self.root / 'bundle' / 'summary.json').read_text(encoding='utf8'))
        self.assertEqual(set(summary), set(state) | {'scope', 'identifiers_included'})
        self.assertEqual(summary['scope'], 'run')
        self.assertFalse(summary['identifiers_included'])
        self.assertEqual(summary['run_id'], p1['catalog_audit']['page']['run_id'])
        self.assertEqual(summary['run_id'], p2['catalog_audit']['page']['run_id'])
        self.assertEqual(summary['cumulative']['evaluated_pairs'], 3)
        self.assertEqual({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before}, before)
        self.assertEqual({p.name for p in (self.root / 'bundle').iterdir()},
                         {'summary.json', 'page-0001', 'page-0002'})
        self.assertEqual({p.name for p in (self.root / 'bundle' / 'page-0001').iterdir()},
                         {'report.json', 'report.csv', 'report.html'})

    def test_independent_bundle_and_page_exports_use_fresh_keys_raw_opt_in_is_explicit(self):
        self.complete()
        self.export()
        self.export('second')
        raw = read_run_page(self.run, 1)
        first = self.page()['catalog_audit']
        self.assertNotEqual(first['inventory']['assets'][0]['id'],
                            self.page(name='second')['catalog_audit']['inventory']['assets'][0]['id'])
        self.assertNotEqual(prepare_export(raw)['catalog_audit']['page']['run_id'],
                            prepare_export(raw)['catalog_audit']['page']['run_id'])
        self.export('raw', include_identifiers=True)
        self.assertEqual(self.page(name='raw')['catalog_audit']['inventory']['assets'][0]['id'], 'private-asset')
        self.assertTrue(self.page(name='raw')['identifiers_included'])
        self.assertIn('192.0.2.177', self.bundle_text('raw'))

    def test_page_case_triage_reexport_preserves_joins_and_cannot_recover_identifiers(self):
        from wifiscope.cases import CaseStore
        self.complete()
        self.export()
        projected = self.page()
        with CaseStore(self.root / 'case.db') as store:
            number = store.add_snapshot(projected, include_identifiers=True)
            loaded = store.load_snapshot(number)
            self.assert_joins(loaded)
            finding = loaded['catalog_audit']['results'][0]['id']
            store.triage(finding, 'investigating', snapshot_id=number)
            self.assertEqual(store.triage_state(snapshot_id=number)[finding]['status'], 'investigating')
        paths = export_report(loaded, self.root / 'reexport', include_identifiers=True)
        result = json.loads(Path(paths['json']).read_text(encoding='utf8'))
        self.assert_joins(result)
        self.assertFalse(result['identifiers_included'])
        self.assertEqual(result['catalog_audit']['page'], projected['catalog_audit']['page'])
        self.assertNotIn('private-asset', json.dumps(result))

    def test_html_scope_and_parsed_csv_contain_delta_and_cumulative_counts(self):
        self.complete()
        self.export()
        document = (self.root / 'bundle/page-0001/report.html').read_text(encoding='utf8')
        for label in ('Page 1 of 2', 'Run state', 'Computational completion', 'Source partial',
                      'Page counts', 'Cumulative run counts', 'Every page remains partial'):
            self.assertIn(label, document)
        with (self.root / 'bundle/page-0001/report.csv').open(encoding='utf-8-sig', newline='') as stream:
            rows = dict(list(csv.reader(stream))[1:])
        self.assertEqual(rows['report.catalog_audit.page.total_pages'], '2')
        self.assertEqual(rows['report.catalog_audit.page.run_state'], 'complete')
        self.assertEqual(rows['report.catalog_audit.summary.retained_results'], '2')
        self.assertEqual(rows['report.catalog_audit.page.cumulative.retained_results'], '3')
        self.assertEqual(rows['report.catalog_audit.results[0].score'], '')

    def test_existing_destinations_and_racing_empty_directory_are_never_replaced(self):
        self.complete()
        for name, kind in (('directory', 'directory'), ('file', 'file')):
            target = self.root / name
            if kind == 'directory':
                target.mkdir()
            else:
                target.write_text('unrelated', encoding='utf8')
            with self.assertRaises(ValueError):
                self.export(name)
            self.assertTrue(target.exists())
            if kind == 'file':
                self.assertEqual(target.read_text(encoding='utf8'), 'unrelated')
        def race():
            target = self.root / 'racing'
            if not target.exists():
                target.mkdir()
            return False
        with self.assertRaises(ValueError):
            self.export('racing', cancel=race)
        self.assertTrue((self.root / 'racing').is_dir())
        self.assertEqual(list((self.root / 'racing').iterdir()), [])

    def test_cancellation_and_callback_failure_leave_no_partial_bundle(self):
        self.complete()
        sentinel = self.root / 'unrelated.txt'
        sentinel.write_text('keep', encoding='utf8')
        cancelled = threading.Event()
        cancelled.set()
        for cancel in (cancelled, lambda: True):
            with self.assertRaises(ValueError):
                self.export(cancel=cancel)
            self.assertFalse((self.root / 'bundle').exists())
        def broken():
            raise RuntimeError('PRIVATE CALLBACK DETAIL')
        with self.assertRaises(ValueError) as caught:
            self.export(cancel=broken)
        self.assertNotIn('PRIVATE CALLBACK DETAIL', str(caught.exception))
        self.assertEqual(sentinel.read_text(encoding='utf8'), 'keep')
        self.assertFalse(list(self.root.glob('.wifiscope-run-*')))

    def test_cancel_after_first_page_discards_only_owned_staging(self):
        self.complete()
        def cancel():
            return any(self.root.glob('.wifiscope-run-*/page-0001/report.json'))
        with self.assertRaises(ValueError):
            self.export(cancel=cancel)
        self.assertFalse((self.root / 'bundle').exists())
        self.assertFalse(list(self.root.glob('.wifiscope-run-*')))

    def test_zero_page_run_exports_status_without_inventing_a_report(self):
        self.assertEqual(self.export(), dict(status='ready', page_count=0, bundle_created=True))
        self.assertEqual({p.name for p in (self.root / 'bundle').iterdir()}, {'summary.json'})
        summary = json.loads((self.root / 'bundle/summary.json').read_text(encoding='utf8'))
        self.assertRegex(summary['run_id'], '^id-[0-9a-f]{24}$')
        self.assertFalse(summary['computation_complete'])

    def test_explicit_key_requires_32_bytes_and_never_enters_export(self):
        from wifiscope.export_schema import _project_report
        self.complete()
        raw = read_run_page(self.run, 1)
        for key in (b'', b'x' * 31, b'x' * 33, 'x' * 32, bytearray(32)):
            with self.subTest(key_type=type(key), size=len(key)), self.assertRaises(ValueError):
                _project_report(raw, False, key)
        result = _project_report(raw, False, b'K' * 32)
        self.assertEqual(result, _project_report(raw, False, b'K' * 32))
        self.assertNotEqual(result['catalog_audit']['page']['run_id'],
                            _project_report(raw, False, b'J' * 32)['catalog_audit']['page']['run_id'])
        self.assertNotIn('K' * 32, json.dumps(result))

    def test_concurrent_continuation_cannot_mix_snapshot_totals(self):
        from wifiscope import catalog_run_export as exports
        before = advance_run(self.run, self.catalog)
        advanced = threading.Event()
        errors = []
        def writer():
            try:
                advance_run(self.run, self.catalog, progress=lambda _: advanced.set())
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=writer)
        def write_page(*args, **kwargs):
            worker.start()
            self.assertTrue(advanced.wait(5), 'real writer did not evaluate during reader snapshot')
            return export_report(*args, **kwargs)
        with patch.object(exports, 'export_report', write_page):
            self.export()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(run_status(self.run)['page_count'], 2)
        summary = json.loads((self.root / 'bundle/summary.json').read_text(encoding='utf8'))
        self.assertEqual((summary['state'], summary['page_count']), ('paused', 1))
        self.assertEqual(summary['cumulative'], before['cumulative'])
        self.assertEqual(self.page()['catalog_audit']['page']['cumulative'], before['cumulative'])
        self.assertFalse((self.root / 'bundle/page-0002').exists())

    def test_publication_failure_preserves_unrelated_file_in_reserved_bundle(self):
        self.complete()
        real_link = os.link
        def fail_link(source, target, *args, **kwargs):
            if Path(target).parent == self.root / 'bundle':
                (self.root / 'bundle/unrelated.txt').write_text('keep', encoding='utf8')
                raise OSError('private disk diagnostic')
            return real_link(source, target, *args, **kwargs)
        with patch('wifiscope.catalog_run_export.os.link', fail_link):
            with self.assertRaises(ValueError) as caught:
                self.export()
        self.assertNotIn('private disk diagnostic', str(caught.exception))
        self.assertEqual((self.root / 'bundle/unrelated.txt').read_text(encoding='utf8'), 'keep')
        self.assertEqual({p.name for p in (self.root / 'bundle').iterdir()}, {'unrelated.txt'})
        self.assertFalse(list(self.root.glob('.wifiscope-run-*')))

    def test_cancel_during_publication_rolls_back_owned_files_and_directories(self):
        self.complete()
        def cancel():
            return (self.root / 'bundle/summary.json').exists()
        with self.assertRaises(ValueError):
            self.export(cancel=cancel)
        self.assertFalse((self.root / 'bundle').exists())
        self.assertFalse(list(self.root.glob('.wifiscope-run-*')))

    def test_page_write_failure_removes_staging_and_never_exposes_diagnostics(self):
        self.complete()
        write_text = Path.write_text
        def failing_write(path, *args, **kwargs):
            if path.name == 'report.csv':
                raise OSError('PRIVATE DISK PATH')
            return write_text(path, *args, **kwargs)
        with patch.object(Path, 'write_text', failing_write):
            with self.assertRaises(ValueError) as caught:
                self.export()
        self.assertNotIn('PRIVATE DISK PATH', str(caught.exception))
        self.assertFalse((self.root / 'bundle').exists())
        self.assertFalse(list(self.root.glob('.wifiscope-*')))

    def test_network_and_invalid_destinations_fail_without_creating_outputs(self):
        from wifiscope.catalog_runs import export_run
        for destination in ('//invalid.example/share/bundle', r'\\invalid.example\share\bundle',
                            'https://invalid.example/bundle', self.root / 'missing/bundle'):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                export_run(self.run, destination)
        for choice in (None, 'yes', 1):
            with self.subTest(choice=choice), self.assertRaises(ValueError):
                self.export(include_identifiers=choice)
        self.assertFalse((self.root / 'missing').exists())

    def test_csv_formula_defense_and_html_escaping_apply_to_raw_page_values(self):
        inv = inventory()
        inv['assets'] = inv['assets'][:1]
        inv['assets'][0]['id'] = '=2+3<script>'
        formula_run = self.root / 'formula.db'
        create_run(formula_run, {'schema_version': 1}, inv, self.catalog,
                   store_raw_identifiers=True)
        advance_run(formula_run, self.catalog)
        from wifiscope.catalog_runs import export_run
        export_run(formula_run, self.root / 'raw', include_identifiers=True)
        with (self.root / 'raw/page-0001/report.csv').open(encoding='utf-8-sig', newline='') as stream:
            rows = dict(list(csv.reader(stream))[1:])
        self.assertEqual(rows['report.catalog_audit.inventory.assets[0].id'], "'=2+3<script>")
        document = (self.root / 'raw/page-0001/report.html').read_text(encoding='utf8')
        self.assertNotIn('<script>', document)
        self.assertIn('=2+3&lt;script&gt;', document)

    def test_cleanup_failure_is_a_controlled_error_without_local_path_disclosure(self):
        self.complete()
        real_remove = __import__('shutil').rmtree
        def fail_run_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith('.wifiscope-run-'):
                real_remove(path, *args, **kwargs)
                raise OSError('PRIVATE CLEANUP PATH')
            return real_remove(path, *args, **kwargs)
        with patch('wifiscope.catalog_run_export.shutil.rmtree', fail_run_cleanup):
            with self.assertRaises(ValueError) as caught:
                self.export()
        self.assertNotIn('PRIVATE CLEANUP PATH', str(caught.exception))

    def test_scanner_hypothesis_nulls_and_original_times_survive_projection(self):
        from wifiscope.catalog_runs import export_run
        inv = inventory()
        inv['assets'] = inv['assets'][:1]
        scanner = dict(origin='service', method='table', protocol='tcp', state='open',
            host_status='up', binding='uri', timestamp_origin='host-end', presence='possible',
            confidence=None, accuracy=None, port=443, host_ordinal=0, entry_ordinal=0,
            cpe_ordinal=0, metadata_valid=True)
        inv['assets'][0]['components'][0].update(source='nmap', identification='imported',
            observed_at='2026-02-03T04:05:06+00:00', scanner=scanner)
        path = self.root / 'scanner.db'
        create_run(path, {'schema_version': 1}, inv, self.catalog, store_raw_identifiers=True)
        advance_run(path, self.catalog)
        export_run(path, self.root / 'scanner-bundle')
        projected = self.page(name='scanner-bundle')
        self.assert_joins(projected)
        component = projected['catalog_audit']['inventory']['assets'][0]['components'][0]
        self.assertEqual(component['scanner'], scanner)
        self.assertEqual(component['observed_at'], '2026-02-03T04:05:06+00:00')
        self.assertIsNone(component['source_sha256'])
        self.assertEqual(projected['catalog_audit']['results'][0]['applicability'], 'unknown')
        self.assertEqual(projected['catalog_audit']['results'][0]['published'], '2026-01-01T00:00:00.000')

    def test_staging_enumeration_error_cannot_publish_an_incomplete_bundle(self):
        self.complete()
        real_scan = os.scandir
        failed = False
        def fail_once(path):
            nonlocal failed
            if not failed and not isinstance(path, int) and Path(path).name == 'page-0001':
                failed = True
                raise OSError('PRIVATE ENUMERATION PATH')
            return real_scan(path)
        with patch('wifiscope.catalog_run_export.os.scandir', fail_once):
            with self.assertRaises(ValueError) as caught:
                self.export()
        self.assertNotIn('PRIVATE ENUMERATION PATH', str(caught.exception))
        self.assertFalse((self.root / 'bundle').exists())
        self.assertFalse(list(self.root.glob('.wifiscope-run-*')))


if __name__ == '__main__':
    unittest.main()
