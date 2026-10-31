import contextlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


class CliTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'wifiscope', *map(str, args)], capture_output=True, text=True, encoding='utf-8', timeout=20)

    def test_demo_bundle_help_invalid_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'demo'
            run = self.cli('demo', '--out', out)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads((out / 'report.json').read_text(encoding='utf-8'))
            self.assertIn('investigation', report)
            self.assertFalse(report['identifiers_included'])
            self.assertNotIn('192.0.2.80', json.dumps(report))
            html = (out / 'report.html').read_text(encoding='utf-8')
            self.assertIn('SYNTHETIC', html)
            self.assertIn('<details', html)
            self.assertNotEqual(self.cli('demo', '--out', out).returncode, 0)
        self.assertEqual(self.cli('--help').returncode, 0)
        self.assertEqual(self.cli('unknown').returncode, 2)

    def test_offline_commands_merge_comparison_and_malformed(self):
        from wifiscope.demo import demo_report
        from wifiscope.reports import prepare_export
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            xml = root / 'scan.xml'
            xml.write_text('<nmaprun><host><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>')
            self.assertEqual(self.cli('import-scan', '--format', 'nmap', '--input', xml).returncode, 0)
            wifi = root / 'wifi.txt'
            wifi.write_text('SSID 1 : PRIVATE\n Authentication : Open\n BSSID 1 : 02:00:00:00:00:01\n Signal : 20%\n')
            run = self.cli('analyze', '--format', 'netsh', '--input', wifi)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertNotIn('PRIVATE', run.stdout)
            raw = root / 'raw.json'
            raw.write_text(json.dumps(prepare_export(demo_report(), True)), encoding='utf-8')
            run = self.cli('compare', raw, raw)
            self.assertEqual(run.returncode, 0, run.stderr)
            comparison = json.loads(run.stdout)['comparison']
            self.assertGreater(comparison['before']['summary']['findings'], 0)
            self.assertIn('coverage', comparison['after'])
            self.assertNotIn('192.0.2.80', run.stdout)
            self.assertEqual(self.cli('merge', '--input', raw, '--input', raw, '--out', root / 'merged').returncode, 0)
            raw.write_text('{broken')
            bad = self.cli('compare', raw, raw)
            self.assertEqual(bad.returncode, 2)
            self.assertNotIn('Traceback', bad.stderr)
            bad = self.cli('packets', '--input', raw)
            self.assertEqual(bad.returncode, 2)

    def test_collect_uses_adapter_and_stdout_privacy(self):
        from wifiscope.cli import main
        from wifiscope.demo import demo_report
        output = io.StringIO()
        with patch('wifiscope.cli.collect_local', return_value=demo_report()), contextlib.redirect_stdout(output):
            self.assertEqual(main(['collect']), 0)
        self.assertNotIn('192.0.2.80', output.getvalue())

    def test_missing_tk_has_actionable_cli_fallback(self):
        from wifiscope.cli import main
        output = io.StringIO()
        with patch.dict(sys.modules, {'wifiscope.gui': None}), contextlib.redirect_stderr(output):
            self.assertEqual(main(['gui']), 2)
        self.assertIn('demo --out', output.getvalue())

    def test_case_listing_drops_identity_bearing_summary_fields(self):
        from wifiscope.cases import CaseStore
        from wifiscope.demo import demo_report
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'case.db'
            report = demo_report()
            report['investigation']['summary']['address'] = 'PRIVATE SUMMARY'
            with CaseStore(path) as store:
                store.add_snapshot(report, include_identifiers=True)
            run = self.cli('case', 'list', '--db', path)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertNotIn('PRIVATE SUMMARY', run.stdout)

    def test_existing_case_actions_never_create_missing_database(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'missing.db'
            for action in ('list', 'verify'):
                run = self.cli('case', action, '--db', path)
                self.assertEqual(run.returncode, 2)
                self.assertNotIn('Traceback', run.stderr)
                self.assertFalse(path.exists())

    def test_malformed_comparisons_reject_before_case_persistence_or_export(self):
        import copy
        from wifiscope.cases import CaseStore
        from wifiscope.comparison import compare_snapshots
        from wifiscope.demo import demo_report
        from wifiscope.reports import export_report
        base = compare_snapshots(demo_report(), demo_report())
        malformed = [dict(schema_version=1, comparison=[]), dict(schema_version=1, comparison=None)]
        for key, value in [('before', []), ('after', 'PRIVATE'), ('asset_changes', [1]), ('wifi_changes', {})]:
            report = copy.deepcopy(base)
            report['comparison'][key] = value
            malformed.append(report)
        for key, value in [('summary', []), ('assets', [1]), ('coverage', 'PRIVATE'), ('snapshot_id', 1.5)]:
            report = copy.deepcopy(base)
            report['comparison']['before'][key] = value
            malformed.append(report)
        report = copy.deepcopy(base)
        report['comparison']['before']['summary']['findings'] = 'PRIVATE'
        malformed.append(report)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index, report in enumerate(malformed):
                source = root / 'bad.json'
                source.write_text(json.dumps(report), encoding='utf-8')
                db = root / f'case{index}.db'
                with self.subTest(index=index):
                    run = self.cli('case', 'add', '--db', db, '--input', source)
                    self.assertEqual(run.returncode, 2)
                    self.assertNotIn('Traceback', run.stderr)
                    self.assertNotIn('PRIVATE', run.stdout)
                    with CaseStore(db) as store:
                        self.assertEqual(store.snapshots(), [])
                        self.assertEqual(store.events(), [])
                    with self.assertRaises(ValueError):
                        export_report(report, root / f'bad{index}')
                    self.assertFalse((root / f'bad{index}').exists())

    def test_valid_empty_capture_cli_and_invalid_json_version(self):
        import struct
        with tempfile.TemporaryDirectory() as temp:
            capture = Path(temp) / 'empty.pcap'
            capture.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            run = self.cli('packets', '--input', capture)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['packet_analysis']['packets'], 0)
            bad = Path(temp) / 'invalid.json'
            bad.write_text('{"schema_version":99}')
            self.assertEqual(self.cli('compare', bad, bad).returncode, 2)
            bad.write_text('{"schema_version":1,"connectivity":[{"dns":"MALFORMED PRIVATE"}]}')
            run = self.cli('compare', bad, bad)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn('Traceback', run.stderr)
            self.assertNotIn('MALFORMED PRIVATE', run.stdout)
            bad.write_text('{"schema_version":1,"run":{"planned_connections":NaN}}')
            self.assertEqual(self.cli('compare', bad, bad).returncode, 2)

    def test_probe_loopback_and_authorization(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = server.getsockname()[1]
            self.assertEqual(self.cli('probe', '--host', '127.0.0.1', '--port', port).returncode, 2)
            run = self.cli('probe', '--host', '127.0.0.1', '--port', port, '--attempts', 1, '--authorized')
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['connectivity'][0]['tcp'][0]['successes'], 1)

    def test_case_persisted_ids_and_triage_reopen_without_notes_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.cli('demo', '--out', root / 'demo')
            db = root / 'case.db'
            add = self.cli('case', 'add', '--db', db, '--input', root / 'demo/report.json')
            self.assertEqual(add.returncode, 0, add.stderr)
            show = self.cli('case', 'show', '--db', db, '--snapshot', 1, '--include-identifiers')
            stored = json.loads(show.stdout)
            fid = stored['investigation']['findings'][0]['id']
            triage = self.cli('case', 'triage', '--db', db, '--snapshot', 1, '--finding', fid, '--status', 'investigating', '--note', 'PRIVATE NOTE')
            self.assertEqual(triage.returncode, 0, triage.stderr)
            show = self.cli('case', 'show', '--db', db, '--snapshot', 1, '--include-identifiers')
            self.assertNotIn('PRIVATE NOTE', show.stdout)
            self.assertEqual(json.loads(show.stdout)['investigation']['findings'][0]['triage_status'], 'investigating')
            fresh = self.cli('case', 'show', '--db', db, '--snapshot', 1)
            freshid = json.loads(fresh.stdout)['investigation']['findings'][0]['id']
            self.assertNotEqual(fid, freshid)
            self.assertEqual(self.cli('case', 'triage', '--db', db, '--snapshot', 1, '--finding', freshid, '--status', 'resolved').returncode, 2)
            self.assertTrue(json.loads(self.cli('case', 'verify', '--db', db).stdout)['ok'])
            self.assertEqual(len(json.loads(self.cli('case', 'list', '--db', db).stdout)), 1)

    def test_bounded_read_checks_limit_at_read_time(self):
        from wifiscope.workstation import read_bounded
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'large'
            path.write_bytes(b'x' * 12)
            with self.assertRaises(ValueError):
                read_bounded(path, limit=10)

    def test_reexport_cannot_restore_identity_correlation_or_lose_assets(self):
        from wifiscope.demo import demo_report
        from wifiscope.reports import prepare_export
        from wifiscope.cases import CaseStore
        from wifiscope.investigate import merge_reports
        original = prepare_export(demo_report())
        attempted_raw = prepare_export(original, True)
        self.assertFalse(attempted_raw['identifiers_included'])
        self.assertEqual(attempted_raw['investigation']['assets'], original['investigation']['assets'])
        with self.assertRaises(ValueError):
            merge_reports([attempted_raw, attempted_raw])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'report.json'
            source.write_text(json.dumps(original), encoding='utf-8')
            db = root / 'case.db'
            run = self.cli('case', 'add', '--db', db, '--input', source, '--include-identifiers')
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertFalse(json.loads(run.stdout)['identifiers_included'])
            with CaseStore(db) as store:
                loaded = store.load_snapshot(1)
                self.assertEqual(len(loaded['investigation']['assets']), len(original['investigation']['assets']))
                self.assertFalse(store.snapshots()[0]['identifiers_included'])
                self.assertFalse(store.events()[0]['payload']['identifiers_included'])
                self.assertTrue(store.verify()['ok'])
            show = self.cli('case', 'show', '--db', db, '--snapshot', 1, '--include-identifiers')
            shown = json.loads(show.stdout)
            self.assertFalse(shown['identifiers_included'])
            self.assertEqual(len(shown['investigation']['assets']), len(original['investigation']['assets']))
            compare = self.cli('case', 'compare', '--db', db, 1, 1)
            comparison = json.loads(compare.stdout)['comparison']
            self.assertEqual(comparison['mode'], 'counts-only')
            self.assertEqual(comparison['before']['snapshot_id'], 1)

    def test_audit_subprocess_loopback_and_unauthorized(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            out = Path(temp) / 'audit'
            args = ['audit', '--scope', '127.0.0.1', '--port', server.getsockname()[1], '--out', out]
            self.assertEqual(self.cli(*args).returncode, 2)
            run = self.cli(*args, '--authorized')
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('Planned: 1 hosts', run.stderr)
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['run']['attempted_connections'], 1)
            self.assertEqual(report['run']['unattempted_endpoints'], 0)

    def test_stdout_does_not_export_arbitrary_prose_even_raw_opt_in(self):
        from wifiscope.cli import main
        from wifiscope.demo import demo_report
        report = demo_report()
        report['findings'][0]['title'] = 'PRIVATE UNKNOWN PROSE'
        report['findings'][0]['recommendation'] = 'PRIVATE UNKNOWN PROSE'
        output = io.StringIO()
        with patch('wifiscope.cli.collect_local', return_value=report), contextlib.redirect_stdout(output):
            self.assertEqual(main(['collect', '--include-identifiers']), 0)
        self.assertNotIn('PRIVATE UNKNOWN PROSE', output.getvalue())


class BatchTests(unittest.TestCase):
    def test_tls_actual_connection_count_survives_inflight_cancellation(self):
        from wifiscope import probe as module
        from wifiscope.batch import audit_scope
        class Limiter:
            deadline = None
            def wait(self):
                return None
        with patch.object(module, '_connect', side_effect=module._Cancelled(started=True)):
            tls = module._tls_probe('example.invalid', dict(address='192.0.2.1', family='IPv4'), 443, .5, Limiter(), None)
        self.assertEqual(tls['attempts'], 1)
        cancel = threading.Event()
        def fake(hosts, ports, **kwargs):
            cancel.set()
            return [dict(host=hosts[0], dns=dict(status='ok', answers=[]), tcp=[dict(address=hosts[0], port=443, status='ok', attempts=1, successes=1)], tls=[tls], http=[])]
        report = audit_scope(['192.0.2.1'], [443], authorized=True, cancel=cancel, probe=fake)
        self.assertEqual(report['run']['attempted_connections'], 2)

    def test_ctrl_c_signal_cooperates_and_retains_current_batch(self):
        import signal
        from wifiscope.batch import audit_scope
        def probe(hosts, ports, **kwargs):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            return [dict(host=hosts[0], dns=dict(status='ok', answers=[]), tcp=[dict(address=hosts[0], port=23, status='ok', attempts=1, successes=1)], tls=[], http=[])]
        previous = signal.getsignal(signal.SIGINT)
        report = audit_scope(['192.0.2.0/29'], [23], authorized=True, probe=probe)
        self.assertEqual(report['run']['status'], 'cancelled')
        self.assertEqual(report['run']['attempted_connections'], 1)
        self.assertEqual(report['run']['unattempted_endpoints'], 5)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_expired_deadline_skips_later_batches_and_marks_partial(self):
        from wifiscope.batch import audit_scope
        ticks = [0]
        def probe(hosts, ports, **kwargs):
            ticks[0] = 400
            return [dict(host=hosts[0], dns=dict(status='error', answers=[]), tcp=[], tls=[], http=[])]
        with patch('wifiscope.batch.time.monotonic', side_effect=lambda: ticks[0]):
            report = audit_scope(['192.0.2.0/29'], [23], authorized=True, probe=probe)
        self.assertEqual(report['run']['status'], 'deadline')
        self.assertEqual(report['run']['attempted_connections'], 0)
        self.assertEqual(report['run']['unattempted_endpoints'], 6)

    def test_plan_and_cancel_preserves_partial_and_shared_deadline(self):
        from wifiscope.batch import audit_scope, plan_scope
        plan = plan_scope(['192.0.2.0/26'])
        self.assertEqual(plan['planned_connections'], 62 * 9)
        self.assertEqual(plan['minimum_seconds'], 62 * 9 / 4)
        cancel = threading.Event()
        calls = []

        def probe(hosts, ports, **kwargs):
            calls.append(kwargs)
            cancel.set()
            return [dict(host=h, dns=dict(status='ok', answers=[]), tcp=[dict(address=h, port=23, status='ok', attempts=1, successes=1)], tls=[], http=[]) for h in hosts]

        report = audit_scope(['192.0.2.0/29'], ports=[23], authorized=True, cancel=cancel, probe=probe)
        self.assertEqual(report['run']['status'], 'cancelled')
        self.assertEqual(report['run']['attempted_connections'], 4)
        self.assertEqual(report['run']['unattempted_endpoints'], 2)
        self.assertEqual(len(report['connectivity']), 4)
        self.assertTrue(all(row['partial'] for row in report['investigation']['coverage'] if row['category'] == 'tcp-exposure'))

    def test_batches_wait_and_deadline_is_shared(self):
        from wifiscope.batch import audit_scope
        calls, waits = [], []
        def probe(hosts, ports, **kwargs):
            calls.append(kwargs['deadline'])
            return [dict(host=h, dns=dict(status='error', answers=[]), tcp=[], tls=[], http=[]) for h in hosts]
        report = audit_scope(['192.0.2.0/29'], ports=[23], authorized=True, probe=probe, wait=lambda n: waits.append(n) or False)
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(waits, [0.25])
        self.assertEqual(report['run']['attempted_connections'], 0)
        self.assertEqual(report['run']['status'], 'partial')

class CatalogRunCliTests(unittest.TestCase):
    cli = CliTests.cli
    def test_saved_run_subprocess_consent_pages_status_and_whole_bundle(self):
        from test_catalog_gui import feed
        from wifiscope.catalog_store import build_catalog
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, db, inventory, saved = [root/name for name in ('source.json', 'catalog.db', 'inventory.json', 'run.db')]
            source.write_text(json.dumps(feed(2)), encoding='utf8')
            build_catalog([source], db)
            inventory.write_text(json.dumps(dict(schema_version=1, assets=[dict(id='PRIVATE-ASSET', components=[dict(
                id='PRIVATE-COMPONENT', cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*', source='local', identification='declared')])])), encoding='utf8')
            args = ('catalog', 'run', 'start', '--db', db, '--inventory', inventory, '--run', saved, '--page-size', 1)
            refused = self.cli(*args)
            self.assertEqual(refused.returncode, 2)
            self.assertFalse(saved.exists())
            started = self.cli(*args, '--store-raw-identifiers')
            self.assertEqual(started.returncode, 1, started.stderr)
            self.assertEqual(json.loads(started.stdout)['page_count'], 1)
            valid_inventory = inventory.read_text(encoding='utf8')
            inventory.write_text('{}', encoding='utf8')
            continued = self.cli('catalog', 'run', 'continue', '--db', db, '--run', saved)
            self.assertEqual(continued.returncode, 1, continued.stderr)
            finished = self.cli('catalog', 'run', 'continue', '--db', db, '--run', saved)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            status = self.cli('catalog', 'run', 'status', '--run', saved)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(json.loads(status.stdout)['cumulative']['evaluated_pairs'], 2)
            self.assertNotIn(str(root), status.stdout)
            page = self.cli('catalog', 'run', 'page', '--run', saved, '--number', 1)
            self.assertEqual(page.returncode, 0, page.stderr)
            report = json.loads(page.stdout)
            self.assertEqual(report['catalog_audit']['page']['scope'], 'page')
            self.assertFalse(report['identifiers_included'])
            self.assertNotIn('PRIVATE-ASSET', page.stdout)
            bundle = root/'bundle'
            exported = self.cli('catalog', 'run', 'export', '--run', saved, '--out', bundle)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertTrue((bundle/'page-0002/report.html').exists())
            self.assertEqual(json.loads((bundle/'summary.json').read_text())['scope'], 'run')
            original = (bundle/'summary.json').read_bytes()
            self.assertEqual(self.cli('catalog', 'run', 'export', '--run', saved, '--out', bundle).returncode, 2)
            self.assertEqual((bundle/'summary.json').read_bytes(), original)
            inventory.write_text(valid_inventory, encoding='utf8')
            db.write_bytes(b'invalid changed catalog')
            self.assertEqual(self.cli('catalog', 'run', 'start', '--db', db, '--inventory', inventory, '--run', root/'bad.db', '--store-raw-identifiers').returncode, 2)
            self.assertFalse((root/'bad.db').exists())

    def test_source_partial_changed_catalog_page_output_and_cooperative_sigint(self):
        from test_catalog_gui import feed
        from wifiscope.catalog_store import build_catalog
        from wifiscope.catalog_runs import create_run, run_status
        from wifiscope.inventory import validate_inventory
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, db, partial_db, saved, invfile = [root/name for name in ('source.json', 'catalog.db', 'partial.db', 'run.db', 'inventory.json')]
            raw = feed(2)
            source.write_text(json.dumps(raw), encoding='utf8')
            build_catalog([source], db)
            inventory = validate_inventory(dict(schema_version=1, assets=[dict(id='private', components=[dict(
                id='private-component', cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*', source='local', identification='declared')])]))
            invfile.write_text(json.dumps(inventory), encoding='utf8')
            create_run(saved, dict(schema_version=1), inventory, db, store_raw_identifiers=True)
            # Actual CLI parsing, signal handler and real advance in a child;
            # only timing is controlled at the per-pair progress boundary.
            code = '''import signal, sys
from unittest.mock import patch
from wifiscope import catalog_runs
from wifiscope.cli import main
advance = catalog_runs.advance_run
def interrupt(*args, **kwargs):
    def progress(value):
        if value['evaluated_pairs']:
            signal.raise_signal(signal.SIGINT)
    kwargs['progress'] = progress
    with patch('wifiscope.catalog_chunks.time.monotonic', side_effect=range(10000)):
        return advance(*args, **kwargs)
catalog_runs.advance_run = interrupt
raise SystemExit(main(sys.argv[1:]))
'''
            cancelled = subprocess.run([sys.executable, '-c', code, 'catalog', 'run', 'continue', '--run', str(saved), '--db', str(db)],
                                       capture_output=True, text=True, encoding='utf8', timeout=20)
            self.assertEqual(cancelled.returncode, 130, cancelled.stderr)
            self.assertEqual(run_status(saved)['cumulative']['evaluated_pairs'], 1)
            before = run_status(saved)
            changed = root/'changed.db'
            changed.write_bytes(db.read_bytes()+b'changed')
            failed = self.cli('catalog', 'run', 'continue', '--run', saved, '--db', changed)
            self.assertEqual(failed.returncode, 2, failed.stderr)
            self.assertEqual(run_status(saved), before)
            self.assertNotIn(str(changed), failed.stdout+failed.stderr)
            out = root/'page'
            page = self.cli('catalog', 'run', 'page', '--run', saved, '--number', 1, '--out', out)
            self.assertEqual(page.returncode, 0, page.stderr)
            self.assertTrue((out/'report.html').exists())
            self.assertEqual(self.cli('catalog', 'run', 'page', '--run', saved, '--number', 99).returncode, 2)
            raw['totalResults'] = 10
            source.write_text(json.dumps(raw), encoding='utf8')
            build_catalog([source], partial_db)
            partial = self.cli('catalog', 'run', 'start', '--run', root/'partial-run.db', '--db', partial_db,
                               '--inventory', invfile, '--store-raw-identifiers')
            self.assertEqual(partial.returncode, 1, partial.stderr)
            state = json.loads(partial.stdout)
            self.assertTrue(state['computation_complete'])
            self.assertTrue(state['source_partial'])
            self.assertIsNone(state['unexamined_pairs'])


    def test_status_ctrl_c_is_not_swallowed_by_mutating_operation_handler(self):
        code = """import signal, sys
from wifiscope import catalog_runs
from wifiscope.cli import main
def interrupted(path):
    signal.raise_signal(signal.SIGINT)
    return {}
catalog_runs.run_status = interrupted
raise SystemExit(main(['catalog', 'run', 'status', '--run', 'not-read.db']))
"""
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, encoding='utf8', timeout=20)
        self.assertEqual(result.returncode, 130, result.stderr)


if __name__ == '__main__':
    unittest.main()
