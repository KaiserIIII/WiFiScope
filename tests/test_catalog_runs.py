"""Durable local audit checkpoints and bounded typed page controls."""
import importlib.util
from contextlib import closing
import copy
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wifiscope.catalog_store import build_catalog
from test_catalog_chunks import inventory, source_record


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = self.root / 'catalog.db'
        self.run = self.root / 'run.db'
        source = self.root / 'source.json'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=3,
            startIndex=0, resultsPerPage=3, vulnerabilities=[dict(cve=source_record(n))
            for n in (90001, 90002, 90003)])), encoding='utf8')
        build_catalog([source], self.catalog)

    def test_consent_then_reopened_checkpoint_advances_once(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.catalog_runs'),
                             'durable audit store is missing')
        from wifiscope.catalog_runs import create_run, advance_run, run_status
        with self.assertRaises(ValueError):
            create_run(self.run, {'schema_version': 1}, inventory(), self.catalog)
        self.assertFalse(self.run.exists())
        state = create_run(self.run, {'schema_version': 1}, inventory(), self.catalog,
                           store_raw_identifiers=True, page_size=1)
        self.assertEqual((state['state'], state['page_count']), ('ready', 0))
        advance_run(self.run, self.catalog)
        self.assertEqual(run_status(self.run)['cumulative']['evaluated_pairs'], 1)
        advance_run(self.run, self.catalog)
        self.assertEqual(run_status(self.run)['cumulative']['evaluated_pairs'], 2)

    def start(self, **kwargs):
        from wifiscope.catalog_runs import create_run
        return create_run(self.run, kwargs.pop('report', {'schema_version': 1}),
                          kwargs.pop('inv', inventory()), self.catalog,
                          store_raw_identifiers=True, **kwargs)

    def test_pages_are_partial_deltas_with_snapshot_totals_and_projection(self):
        from wifiscope.catalog_runs import advance_run, read_run_page, run_status, _RunReader
        from wifiscope.case_validation import validate_report
        from wifiscope.export_schema import project_report
        self.start(page_size=2)
        advance_run(self.run, self.catalog)
        state = advance_run(self.run, self.catalog)
        self.assertEqual((state['state'], state['page_count']), ('complete', 2))
        self.assertEqual(state['cumulative']['evaluated_pairs'], 6)
        self.assertEqual(state['cumulative']['relevant_records'], 3)
        self.assertEqual(state['unexamined_pairs'], 0)
        self.assertEqual(advance_run(self.run, self.catalog), state)
        with _RunReader(self.run) as reader:
            self.assertEqual(reader.status(), run_status(self.run))
            page = reader.read_page(1)
        validate_report(page)
        audit = page['catalog_audit']
        self.assertEqual((audit['status'], audit['summary']['partial']), ('partial', True))
        self.assertIsNone(audit['summary']['unexamined_pairs'])
        self.assertEqual(audit['summary']['retained_results'], 2)
        self.assertIn('audit-page-scope', audit['gaps'])
        self.assertEqual(audit['page']['scope'], 'page')
        self.assertEqual(audit['page']['run_state'], 'complete')
        self.assertEqual(audit['page']['cumulative']['retained_results'], 3)
        projected = project_report(page)
        validate_report(projected)
        self.assertRegex(projected['catalog_audit']['page']['run_id'], '^id-[0-9a-f]{24}$')
        for number in (0, 3, True):
            with self.assertRaises(ValueError):
                read_run_page(self.run, number)

    def test_frozen_inputs_and_all_false_tail(self):
        from wifiscope.catalog_runs import advance_run, read_run_page
        inv = inventory()
        self.start(inv=inv, page_size=3)
        inv['assets'][0]['id'] = 'changed-after-creation'
        advance_run(self.run, self.catalog)
        state = advance_run(self.run, self.catalog)
        self.assertEqual(state['state'], 'complete')
        self.assertEqual(state['cumulative']['not_matched_pairs'], 3)
        first = read_run_page(self.run, 1)
        self.assertEqual(first['catalog_audit']['inventory']['assets'][0]['id'], 'matching')
        last = read_run_page(self.run, 2)
        self.assertEqual(last['catalog_audit']['results'], [])
        self.assertEqual(last['catalog_audit']['summary']['evaluated_pairs'], 3)

    def test_cancel_and_callback_error_preserve_checkpoint(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=1)
        before = run_status(self.run)
        advance_run(self.run, self.catalog, cancel=lambda: True)
        self.assertEqual(run_status(self.run), before)
        def broken(_):
            raise RuntimeError('private-marker')
        with self.assertRaises(ValueError) as caught:
            advance_run(self.run, self.catalog, progress=broken)
        self.assertNotIn('private-marker', str(caught.exception))
        self.assertEqual(run_status(self.run), before)

    def test_schema_trigger_refused_before_any_application_write(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start()
        with closing(sqlite3.connect(self.run)) as db, db:
            db.execute('CREATE TABLE attacker (value TEXT)')
            db.execute("CREATE TRIGGER poison AFTER UPDATE ON metadata BEGIN INSERT INTO attacker VALUES ('fired'); END")
        for operation in (lambda: advance_run(self.run, self.catalog), lambda: run_status(self.run)):
            with self.assertRaises(ValueError):
                operation()
        with closing(sqlite3.connect(self.run)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM attacker').fetchone()[0], 0)

    def test_existing_destination_missing_run_and_sidecars_protected(self):
        from wifiscope.catalog_runs import create_run, run_status
        with self.assertRaises(ValueError):
            run_status(self.run)
        self.assertFalse(self.run.exists())
        for suffix in ('-journal', '-wal', '-shm'):
            sidecar = Path(str(self.run) + suffix)
            sidecar.write_bytes(b'owned-other-data')
            with self.assertRaises(ValueError):
                self.start()
            self.assertFalse(self.run.exists())
            self.assertEqual(sidecar.read_bytes(), b'owned-other-data')
            sidecar.unlink()
        self.run.write_bytes(b'keep-me')
        with self.assertRaises(ValueError):
            create_run(self.run, {'schema_version': 1}, inventory(), self.catalog,
                       store_raw_identifiers=True)
        self.assertEqual(self.run.read_bytes(), b'keep-me')

    def test_catalog_binding_failure_rolls_back(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start()
        before = run_status(self.run)
        with open(self.catalog, 'ab') as stream:
            stream.write(b'changed')
        with self.assertRaises(ValueError):
            advance_run(self.run, self.catalog)
        self.assertEqual(run_status(self.run), before)

    def test_page_and_pair_lifetime_limits_keep_checkpoint_and_exact_empty_exhaustion(self):
        from wifiscope.catalog_runs import advance_run, run_status
        inv = inventory()
        inv['assets'] = inv['assets'][:1]
        self.start(inv=inv, page_size=3)
        with patch('wifiscope.catalog_runs.MAX_PAGES', 1), patch('wifiscope.catalog_runs.MAX_PAIRS', 3):
            first = advance_run(self.run, self.catalog)
            self.assertEqual(first['page_count'], 1)
            final = advance_run(self.run, self.catalog)
            self.assertEqual(final['state'], 'complete')
            self.assertEqual(final['cumulative']['evaluated_pairs'], 3)
        self.assertEqual(run_status(self.run)['state'], 'complete')

    def mutate_metadata(self, key, change):
        from wifiscope.catalog_records import canonical
        with closing(sqlite3.connect(self.run)) as db, db:
            value = json.loads(db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()[0])
            change(value)
            db.execute('UPDATE metadata SET value=? WHERE key=?', (canonical(value), key))

    def test_cursor_cannot_skip_uncommitted_pair(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=1)
        advance_run(self.run, self.catalog)
        original = self.run.read_bytes()
        for cursor in (dict(asset_ordinal=0, after='CVE-2026-90002'), dict(asset_ordinal=1, after=None)):
            with self.subTest(cursor=cursor):
                self.run.write_bytes(original)
                self.mutate_metadata('checkpoint', lambda value: value.update(cursor=cursor))
                with self.assertRaises(ValueError):
                    run_status(self.run)

    def test_empty_exhaustion_accounts_for_query_work_without_an_extra_page(self):
        from wifiscope.catalog_runs import advance_run
        inv = inventory()
        inv['assets'] = inv['assets'][:1]
        self.start(inv=inv, page_size=3)
        first = advance_run(self.run, self.catalog)
        last = advance_run(self.run, self.catalog)
        self.assertEqual(last['page_count'], 1)
        self.assertGreater(last['cumulative']['identity_queries'], first['cumulative']['identity_queries'])

    def test_cancel_after_classified_pair_commits_it_then_resumes_without_duplicates(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=3)
        cancelled = False
        def progress(value):
            nonlocal cancelled
            if value['evaluated_pairs']:
                cancelled = True
        # Force the real chunk progress throttle to emit each admission.
        with patch('wifiscope.catalog_chunks.time.monotonic', side_effect=range(100)):
            first = advance_run(self.run, self.catalog, cancel=lambda: cancelled, progress=progress)
        self.assertEqual((first['state'], first['stop_reason'], first['page_count']), ('paused', 'cancelled', 1))
        self.assertEqual(first['cumulative']['evaluated_pairs'], 1)
        final = advance_run(self.run, self.catalog)
        self.assertEqual(final['cumulative']['evaluated_pairs'], 6)
        self.assertEqual(run_status(self.run), final)

    def test_post_step_catalog_change_rolls_back(self):
        from wifiscope import catalog_runs as runs
        self.start(page_size=1)
        before = runs.run_status(self.run)
        chunk = runs._audit_chunk
        def change_catalog(*args, **kwargs):
            result = chunk(*args, **kwargs)
            with self.catalog.open('ab') as stream:
                stream.write(b'post-evaluation-tamper')
            return result
        with patch.object(runs, '_audit_chunk', change_catalog):
            with self.assertRaises(ValueError):
                runs.advance_run(self.run, self.catalog)
        self.assertEqual(runs.run_status(self.run), before)

    def test_source_partial_exhaustion_keeps_unknown_coverage(self):
        from wifiscope.catalog_runs import advance_run, read_run_page
        source = self.root / 'partial.json'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=5,
            startIndex=0, resultsPerPage=1, vulnerabilities=[dict(cve=source_record(90001))])), encoding='utf8')
        partial = self.root / 'partial.db'
        build_catalog([source], partial)
        from wifiscope.catalog_runs import create_run
        create_run(self.run, {'schema_version': 1}, inventory(), partial, store_raw_identifiers=True)
        final = advance_run(self.run, partial)
        self.assertEqual(final['state'], 'complete')
        self.assertTrue(final['computation_complete'])
        self.assertTrue(final['source_partial'])
        self.assertIsNone(final['unexamined_pairs'])
        self.assertIn('catalog-input-partial', final['gaps'])
        self.assertTrue(read_run_page(self.run, 1)['catalog_audit']['page']['source_partial'])

    def test_lifetime_stops_commit_no_partial_batch_and_are_idempotent(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=1)
        first = advance_run(self.run, self.catalog)
        with patch('wifiscope.catalog_runs.MAX_PAGES', 1):
            limited = advance_run(self.run, self.catalog)
        self.assertEqual(limited['state'], 'limited')
        self.assertEqual(limited['stop_reason'], 'run-page-limit')
        self.assertEqual(limited['cumulative'], first['cumulative'])
        self.assertEqual(limited['page_count'], 1)
        self.assertEqual(advance_run(self.run, self.root / 'missing.db'), limited)
        self.assertEqual(run_status(self.run), limited)

    def test_zero_progress_block_does_not_create_empty_page_or_retry(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start()
        with patch('wifiscope.catalog_chunks.MAX_PREDICATES', 1):
            blocked = advance_run(self.run, self.catalog)
        self.assertEqual((blocked['state'], blocked['page_count']), ('blocked', 0))
        self.assertEqual(blocked['stop_reason'], 'blocked-predicate')
        self.assertEqual(advance_run(self.run, self.root / 'missing.db'), blocked)
        self.assertEqual(run_status(self.run), blocked)

    def test_conflicting_writer_and_commit_failure_leave_durable_checkpoint(self):
        from wifiscope import catalog_runs as runs
        self.start(page_size=1)
        before = runs.run_status(self.run)
        with closing(sqlite3.connect(self.run, isolation_level=None)) as blocker:
            blocker.execute('BEGIN IMMEDIATE')
            with self.assertRaises(ValueError):
                runs.advance_run(self.run, self.catalog)
            blocker.execute('ROLLBACK')
        self.assertEqual(runs.run_status(self.run), before)
        original_connect = sqlite3.connect
        class FailingCommit(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql == 'COMMIT':
                    raise sqlite3.OperationalError('injected disk I/O error')
                return super().execute(sql, parameters)
        def connect(*args, **kwargs):
            kwargs['factory'] = FailingCommit
            return original_connect(*args, **kwargs)
        with patch.object(runs.sqlite3, 'connect', connect):
            with self.assertRaises(ValueError):
                runs.advance_run(self.run, self.catalog)
        self.assertEqual(runs.run_status(self.run), before)
        resumed = runs.advance_run(self.run, self.catalog)
        self.assertEqual(resumed['cumulative']['evaluated_pairs'], 1)

    def test_spilled_hot_journal_process_crash_recovers_previous_checkpoint(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=1)
        before = advance_run(self.run, self.catalog)
        main_hash = hashlib.sha256(self.run.read_bytes()).hexdigest()
        code = r'''
import hashlib, json, pathlib, sqlite3, sys
p = pathlib.Path(sys.argv[1])
db = sqlite3.connect(p, isolation_level=None)
db.execute('PRAGMA cache_size=2')
db.execute('PRAGMA cache_spill=ON')
db.execute('PRAGMA synchronous=FULL')
db.execute('BEGIN IMMEDIATE')
db.execute("UPDATE metadata SET value=? WHERE key='checkpoint'", ('uncommitted-' * 30000,))
db.execute('UPDATE pages SET body=? WHERE number=1', ('uncommitted-page-' * 30000,))
db.executemany('INSERT INTO pairs VALUES (?,?,?,?)', [(0, 'CVE-2026-'+str(100000+i), 'true', 2) for i in range(1000)])
j = pathlib.Path(str(p)+'-journal')
print(json.dumps(dict(main=hashlib.sha256(p.read_bytes()).hexdigest(), journal=j.stat().st_size, header=j.read_bytes()[:8].hex())), flush=True)
sys.stdin.readline()
'''
        child = subprocess.Popen([sys.executable, '-c', code, str(self.run)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = child.stdout.readline()
            self.assertTrue(line, child.stderr.read() if child.poll() is not None else 'missing crash handshake')
            spill = json.loads(line)
            self.assertNotEqual(spill['main'], main_hash)
            self.assertGreater(spill['journal'], 4096)
            self.assertEqual(spill['header'], 'd9d505f920a163d7')
            child.kill()
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()
        self.assertEqual(run_status(self.run), before)
        after = advance_run(self.run, self.catalog)
        self.assertEqual(after['cumulative']['evaluated_pairs'], 2)
        with closing(sqlite3.connect(self.run)) as db:
            self.assertEqual(db.execute('SELECT asset_ordinal,cve FROM pairs ORDER BY asset_ordinal,cve').fetchall(),
                             [(0, 'CVE-2026-90001'), (0, 'CVE-2026-90002')])

    def test_fresh_process_resumes_saved_inputs(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=1)
        advance_run(self.run, self.catalog)
        child = subprocess.run([sys.executable, '-c',
            'import json,sys; from wifiscope.catalog_runs import advance_run; print(json.dumps(advance_run(sys.argv[1],sys.argv[2])))',
            str(self.run), str(self.catalog)], capture_output=True, text=True, timeout=20, check=True)
        self.assertEqual(json.loads(child.stdout)['cumulative']['evaluated_pairs'], 2)
        self.assertEqual(run_status(self.run)['cumulative']['retained_results'], 2)

    def test_more_than_4096_candidates_and_shared_cves_are_retained_once(self):
        from wifiscope.catalog_runs import create_run, advance_run, read_run_page
        source = self.root / 'many.json'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=2050,
            startIndex=0, resultsPerPage=2050, vulnerabilities=[dict(cve=source_record(100000+n))
            for n in range(2050)])), encoding='utf8')
        catalog = self.root / 'many.db'
        build_catalog([source], catalog)
        inv = inventory()
        inv['assets'][1]['components'][0]['cpe'] = inv['assets'][0]['components'][0]['cpe']
        create_run(self.run, {'schema_version': 1}, inv, catalog, store_raw_identifiers=True, page_size=1024)
        for _ in range(6):
            status = advance_run(self.run, catalog)
            if status['computation_complete']:
                break
        self.assertEqual(status['state'], 'complete')
        self.assertEqual(status['cumulative']['retained_results'], 4100)
        self.assertEqual(status['cumulative']['relevant_records'], 2050)
        keys = []
        for number in range(1, status['page_count'] + 1):
            keys.extend((r['asset_id'], r['cve']) for r in read_run_page(self.run, number)['catalog_audit']['results'])
        self.assertEqual(len(keys), 4100)
        self.assertEqual(len(set(keys)), 4100)

    def test_status_counts_and_cursor_tampering_refused(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start()
        advance_run(self.run, self.catalog)
        original = self.run.read_bytes()
        changes = [
            lambda v: v['status'].update(unexamined_pairs=False),
            lambda v: v['status'].update(page_count=2),
            lambda v: v['status']['cumulative'].update(evaluated_pairs=7),
            lambda v: v['status']['cumulative'].update(relevant_records=2),
            lambda v: v['cursor'].update(asset_ordinal=0, after=None),
            lambda v: v['status'].update(state='paused'),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.run.write_bytes(original)
                self.mutate_metadata('checkpoint', change)
                with self.assertRaises(ValueError):
                    run_status(self.run)

    def test_input_engine_hash_and_json_tampering_refused(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start()
        original = self.run.read_bytes()
        changes = [lambda v: v.update(run_engine_version='2'),
                   lambda v: v.update(matching_engine_version='2'),
                   lambda v: v['report'].update(synthetic=True),
                   lambda v: v['inventory']['assets'][0].update(id='tampered'),
                   lambda v: v.update(page_size=0)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.run.write_bytes(original)
                self.mutate_metadata('frozen', change)
                with self.assertRaises(ValueError):
                    advance_run(self.run, self.catalog)
        self.run.write_bytes(original)
        with closing(sqlite3.connect(self.run)) as db, db:
            db.execute("UPDATE metadata SET value=? WHERE key='checkpoint'", ('{"status":{},"status":{}}',))
        with self.assertRaises(ValueError):
            run_status(self.run)

    def test_page_join_and_saved_cursor_tampering_refused(self):
        from wifiscope.catalog_runs import advance_run, read_run_page
        from wifiscope.catalog_records import canonical
        self.start(page_size=1)
        advance_run(self.run, self.catalog)
        original = self.run.read_bytes()
        for field in ('asset_id', 'cve', 'cursor', 'pair_page'):
            with self.subTest(field=field):
                self.run.write_bytes(original)
                with closing(sqlite3.connect(self.run)) as db, db:
                    payload = json.loads(db.execute('SELECT body FROM pages WHERE number=1').fetchone()[0])
                    if field == 'cursor':
                        payload['cursor']['after'] = 'CVE-2026-90002'
                    elif field == 'pair_page':
                        db.execute('UPDATE pairs SET page_number=2')
                    else:
                        payload['results'][0][field] = 'wrong-version' if field == 'asset_id' else 'CVE-2026-90002'
                    db.execute('UPDATE pages SET body=? WHERE number=1', (canonical(payload),))
                with self.assertRaises(ValueError):
                    read_run_page(self.run, 1)

    def test_optional_page_extension_rejects_false_source_scope_and_bad_types(self):
        from wifiscope.catalog_runs import advance_run, read_run_page
        from wifiscope.case_validation import validate_report
        self.start()
        advance_run(self.run, self.catalog)
        report = read_run_page(self.run, 1)
        changes = [lambda p: p.update(source_partial=True),
                   lambda p: p.update(stop_reason=[]),
                   lambda p: p.update(total_pages=0),
                   lambda p: p.update(computation_complete=False),
                   lambda p: p.update(extra='unknown'),
                   lambda p: p['cumulative'].update(retained_results=0),
                   lambda p: p.update(run_id='private-identifier')]
        for change in changes:
            altered = copy.deepcopy(report)
            change(altered['catalog_audit']['page'])
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                validate_report(altered)

    def test_pair_and_payload_one_over_limits_save_none_of_nonfitting_batch(self):
        from wifiscope.catalog_runs import advance_run, run_status
        self.start(page_size=2)
        original = self.run.read_bytes()
        for bound, value, reason in [('MAX_PAIRS', 1, 'run-pair-limit'),
                                     ('MAX_PAYLOAD_BYTES', 1, 'run-byte-limit')]:
            with self.subTest(bound=bound):
                self.run.write_bytes(original)
                with patch('wifiscope.catalog_runs.' + bound, value):
                    limited = advance_run(self.run, self.catalog)
                self.assertEqual((limited['state'], limited['stop_reason']), ('limited', reason))
                self.assertEqual(limited['page_count'], 0)
                self.assertEqual(limited['cumulative']['evaluated_pairs'], 0)
                self.assertEqual(run_status(self.run), limited)

    def test_final_hash_cancellation_finishes_verification_but_callback_error_rolls_back(self):
        from wifiscope import catalog_runs as runs
        self.start(page_size=1)
        original = self.run.read_bytes()
        chunk = runs._audit_chunk
        after_chunk = False
        def completed(*args, **kwargs):
            nonlocal after_chunk
            value = chunk(*args, **kwargs)
            after_chunk = True
            return value
        with patch.object(runs, '_audit_chunk', completed):
            result = runs.advance_run(self.run, self.catalog, cancel=lambda: after_chunk)
        self.assertEqual(result['stop_reason'], 'cancelled')
        self.assertEqual(result['cumulative']['evaluated_pairs'], 1)
        self.run.write_bytes(original)
        before = runs.run_status(self.run)
        after_chunk = False
        def raising_cancel():
            if after_chunk:
                raise RuntimeError('private-callback-text')
            return False
        with patch.object(runs, '_audit_chunk', completed):
            with self.assertRaises(ValueError):
                runs.advance_run(self.run, self.catalog, cancel=raising_cancel)
        self.assertEqual(runs.run_status(self.run), before)

    def test_reader_snapshot_owned_values_and_writer_commit_conflict(self):
        from wifiscope.catalog_runs import advance_run, _RunReader, run_status
        self.start(page_size=1)
        before = advance_run(self.run, self.catalog)
        with _RunReader(self.run) as reader:
            value = reader.status()
            value['cumulative']['evaluated_pairs'] = 999
            page = reader.read_page(1)
            page['catalog_audit']['results'][0]['asset_id'] = 'mutated'
            with self.assertRaises(ValueError):
                advance_run(self.run, self.catalog)
            self.assertEqual(reader.status(), before)
            self.assertEqual(reader.read_page(1)['catalog_audit']['results'][0]['asset_id'], 'matching')
        self.assertEqual(run_status(self.run), before)
        self.assertEqual(advance_run(self.run, self.catalog)['cumulative']['evaluated_pairs'], 2)

    def test_network_paths_links_and_nonregular_companions_refused(self):
        from wifiscope.catalog_runs import create_run, run_status
        for name in ('https://example.invalid/run.db', '//server/share/run.db', '\\\\server\\share\\run.db'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                run_status(name)
        journal = Path(str(self.run) + '-journal')
        journal.mkdir()
        with self.assertRaises(ValueError):
            self.start()
        journal.rmdir()
        link = self.root / 'linked.db'
        try:
            link.symlink_to(self.catalog)
        except OSError:
            # Windows often denies unprivileged symbolic links; junction/network
            # checks still run through production path validation.
            return
        with self.assertRaises(ValueError):
            run_status(link)
        with self.assertRaises(ValueError):
            create_run(self.run, {'schema_version': 1}, inventory(), link, store_raw_identifiers=True)

    def test_status_contains_only_controlled_metadata_and_page_bounds(self):
        from wifiscope.catalog_runs import advance_run, create_run, read_run_page
        for size in (0, 4097, True):
            with self.assertRaises(ValueError):
                create_run(self.run, {'schema_version': 1}, inventory(), self.catalog,
                           store_raw_identifiers=True, page_size=size)
            self.assertFalse(self.run.exists())
        state = self.start()
        with self.assertRaises(ValueError):
            read_run_page(self.run, 1)
        self.assertEqual(set(state), {'run_id', 'state', 'stop_reason', 'page_count', 'computation_complete',
                         'source_partial', 'cumulative', 'unexamined_pairs', 'gaps'})
        state = advance_run(self.run, self.catalog)
        encoded = json.dumps(state)
        for secret in ('matching', 'wrong-version', 'component-', 'source_sha256', str(self.root), 'cpe:2.3'):
            self.assertNotIn(secret, encoded)

    def test_schema_is_rechecked_under_transaction_before_mutation(self):
        from wifiscope import catalog_runs as runs
        self.start()
        with closing(sqlite3.connect(self.run)) as db:
            before = db.execute("SELECT value FROM metadata WHERE key='checkpoint'").fetchone()[0]
        enable = runs._Store.enable_writes
        def race(store):
            with closing(sqlite3.connect(self.run)) as other, other:
                other.execute('CREATE TABLE added_between_open_and_begin (value TEXT)')
            enable(store)
        with patch.object(runs._Store, 'enable_writes', race):
            with self.assertRaises(ValueError):
                runs.advance_run(self.run, self.catalog)
        with closing(sqlite3.connect(self.run)) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='checkpoint'").fetchone()[0], before)

    def test_cancel_during_pinned_index_open_preserves_ready_checkpoint(self):
        from wifiscope import catalog_runs as runs
        self.start()
        before = runs.run_status(self.run)
        original = runs.CatalogIndex
        entered = False
        def opening(*args, **kwargs):
            nonlocal entered
            entered = True
            return original(*args, **kwargs)
        with patch.object(runs, 'CatalogIndex', opening):
            state = runs.advance_run(self.run, self.catalog, cancel=lambda: entered)
        self.assertEqual(state, before)
        self.assertEqual(runs.run_status(self.run), before)

    def test_exact_payload_limit_admits_page_then_rejects_next_page(self):
        from wifiscope import catalog_runs as runs
        from datetime import datetime, timezone
        self.start(page_size=1)
        before = self.run.read_bytes()
        class FixedTime:
            @staticmethod
            def now(_):
                return datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch.object(runs, 'datetime', FixedTime):
            runs.advance_run(self.run, self.catalog)
            with closing(sqlite3.connect(self.run)) as db:
                size = len(db.execute('SELECT body FROM pages WHERE number=1').fetchone()[0].encode('utf8'))
            self.run.write_bytes(before)
            with patch.object(runs, 'MAX_PAYLOAD_BYTES', size):
                first = runs.advance_run(self.run, self.catalog)
                second = runs.advance_run(self.run, self.catalog)
        self.assertEqual(first['page_count'], 1)
        self.assertEqual(first['state'], 'paused')
        self.assertEqual(second['stop_reason'], 'run-byte-limit')
        self.assertEqual(second['cumulative'], first['cumulative'])

    def test_imported_partial_scope_is_independent_of_exhaustion(self):
        from wifiscope.catalog_runs import advance_run, read_run_page
        inv = inventory()
        inv['import_context'] = dict(format='native', source_sha256=None, document_observed_at=None,
            partial=True, gaps=['input-partial'], input_entries=3, input_cpe_identifiers=2,
            retained_components=2, unmapped_entries=1, unsupported_identifiers=0, duplicate_identifiers=0)
        self.start(inv=inv)
        state = advance_run(self.run, self.catalog)
        self.assertEqual(state['state'], 'complete')
        self.assertTrue(state['source_partial'])
        self.assertIn('inventory-input-partial', state['gaps'])
        self.assertIsNone(state['unexamined_pairs'])
        self.assertTrue(read_run_page(self.run, 1)['catalog_audit']['page']['source_partial'])

    def test_creation_rejects_metadata_that_its_reader_cannot_admit(self):
        with patch('wifiscope.catalog_run_schema.MAX_PAYLOAD', 100):
            with self.assertRaises(ValueError):
                self.start()
        self.assertFalse(self.run.exists())


if __name__ == '__main__':
    unittest.main()
