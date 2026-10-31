import builtins
import copy
import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from wifiscope.catalog_records import parse_cpe23
from wifiscope.catalog_store import CatalogIndex, build_catalog
from wifiscope.catalog_stream import CatalogCancelled, CatalogError


def cve(identifier='CVE-2026-12345', vendor='vendor_z', product='product_z', part='a'):
    return {'id': identifier, 'vulnStatus': 'Analyzed', 'published': '2026-01-01T00:00:00.000',
            'lastModified': '2026-01-02T00:00:00.000',
            'configurations': [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [
                {'vulnerable': True, 'criteria': f'cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*',
                 'versionEndExcluding': '2.0', 'matchCriteriaId': 'public-id'}]}]}]}


class CatalogTests(unittest.TestCase):
    def test_pinned_index_hash_observes_cancel_and_preserves_source(self):
        self.assertIn('cancel', inspect.signature(CatalogIndex).parameters,
                      'pinned index hashing must accept cooperative cancellation')
        feed = self.feed(cve())
        build_catalog([feed], self.db)
        before = self.db.read_bytes()
        pin = hashlib.sha256(before).hexdigest()
        with self.assertRaises(CatalogCancelled):
            CatalogIndex(self.db, expected_sha256=pin, cancel=lambda: True)
        with CatalogIndex(self.db, expected_sha256=pin, cancel=lambda: False) as index:
            self.assertEqual(index.info()['records'], 1)
        with self.assertRaises(CatalogError):
            CatalogIndex(self.db, expected_sha256='0' * 64, cancel=lambda: False)
        def broken():
            raise RuntimeError('private-cancel-marker')
        with self.assertRaises(CatalogError) as caught:
            CatalogIndex(self.db, expected_sha256=pin, cancel=broken)
        self.assertNotIn('private-cancel-marker', str(caught.exception))
        self.assertEqual(self.db.read_bytes(), before)

    def test_hash_cancel_before_between_and_after_64k_reads(self):
        from wifiscope.catalog_store import _file_hash
        self.assertIn('cancel', inspect.signature(_file_hash).parameters,
                      'chunked file hashing must check cancellation')
        source = self.root / 'hash-input.bin'
        content = b'x' * (65536 * 2 + 3)
        source.write_bytes(content)
        for stop in (1, 2, 4):
            calls = 0
            def cancel():
                nonlocal calls
                calls += 1
                return calls == stop
            with self.subTest(stop=stop), self.assertRaises(CatalogCancelled):
                _file_hash(source, cancel=cancel)
            self.assertEqual(source.read_bytes(), content)
        self.assertEqual(_file_hash(source, cancel=lambda: False), hashlib.sha256(content).hexdigest())

    def test_cna_dual_upper_bounds_normalize_to_visible_unknown_without_mutation(self):
        from wifiscope.applicability import evaluate_cve
        rows = []
        for i, upper in enumerate(('1', '2')):
            rows.append(dict(id=f'CVE-2026-{12000+i}', vulnStatus='Analyzed', affected=[dict(
                affectedData=[dict(vendor='acme', product='app', defaultStatus='unaffected', versions=[
                    dict(version='0', lessThan='2', lessThanOrEqual=upper, versionType='numeric', status='affected')])])]))
        before = copy.deepcopy(rows)
        feed = self.feed(*rows)
        input_bytes = feed.read_bytes()
        build_catalog([feed], self.db)
        observed = dict(id='asset', components=[dict(id='component', vendor='acme', product='app',
                                                   version='2', version_scheme='numeric')])
        with CatalogIndex(self.db) as index:
            for raw in rows:
                stored = index.get(raw['id'])
                version = stored['affected'][0]['affectedData'][0]['versions'][0]
                self.assertTrue(version['unsupported'])
                self.assertEqual((version['lessThan'], version['lessThanOrEqual']),
                                 ('2', raw['affected'][0]['affectedData'][0]['versions'][0]['lessThanOrEqual']))
                self.assertIn('cna_version_unknown', stored['gaps'])
                self.assertEqual(evaluate_cve(stored, observed)['applicability'], 'unknown')
                stored['configurations'] = [dict(operator='OR', negate=False, unsupported=False, nodes=[],
                    cpeMatch=[dict(vulnerable=True, unsupported=False, criteria='cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*')])]
                observed['components'].append(dict(id='cpe', cpe='cpe:2.3:a:acme:app:2:*:*:*:*:*:*:*'))
                self.assertEqual(evaluate_cve(stored, observed)['applicability'], 'true')
                observed['components'].pop()
        self.assertEqual(rows, before)
        self.assertEqual(feed.read_bytes(), input_bytes)

    @staticmethod
    def many_affected_record(count):
        rows = [dict(vendor='synthetic vendor', product=f'package-{i:04d}', defaultStatus='unaffected',
                     versions=[dict(version=str(i), lessThan=str(i+1), versionType='numeric', status='affected')])
                for i in range(count)]
        split = count//2
        raw = dict(id='CVE-2026-13000', vulnStatus='Analyzed', affected=[
            dict(source='first', affectedData=rows[:split]), dict(source='second', affectedData=rows[split:])])
        return raw, rows

    def test_2749_and_4096_affected_rows_retain_every_row_in_source_order(self):
        for count in (2749, 4096):
            with self.subTest(count=count):
                raw, rows = self.many_affected_record(count)
                before = copy.deepcopy(raw)
                feed = self.feed(raw)
                source_bytes = feed.read_bytes()
                db = self.root/f'affected-{count}.db'
                info = build_catalog([feed], db)
                self.assertEqual(info['records'], 1)
                with CatalogIndex(db) as index:
                    stored = index.get(raw['id'])
                    self.assertEqual([s['source'] for s in stored['affected']], ['first', 'second'])
                    self.assertEqual([len(s['affectedData']) for s in stored['affected']], [count//2, count-count//2])
                    retained = [r for s in stored['affected'] for r in s['affectedData']]
                    expected = [dict(r, cpes=[], context={}, unsupported=False,
                        versions=[dict(r['versions'][0], changes=[], unsupported=False)]) for r in rows]
                    self.assertEqual(retained, expected)
                    self.assertEqual(index.search(vendor='synthetic vendor', product=f'package-{count-1:04d}')[0]['cve'],
                                     'CVE-2026-13000')
                self.assertEqual(feed.read_bytes(), source_bytes)
                self.assertEqual(raw, before)

    def test_4097_affected_rows_fail_atomically_preserving_inputs_and_existing_database(self):
        build_catalog([self.feed(cve())], self.db)
        generation = self.db.read_bytes()
        raw, _ = self.many_affected_record(4097)
        feed = self.feed(raw)
        original = feed.read_bytes()
        entries = set(self.root.iterdir())
        destination = self.root/'too-many-affected.db'
        with self.assertRaisesRegex(CatalogError, 'CNA affected-row budget exceeded'):
            build_catalog([feed], destination)
        self.assertFalse(destination.exists())
        self.assertEqual(set(self.root.iterdir()), entries)
        self.assertEqual(feed.read_bytes(), original)
        self.assertEqual(self.db.read_bytes(), generation)
        with CatalogIndex(self.db) as index:
            self.assertEqual(index.get('CVE-2026-12345')['status'], 'Analyzed')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / 'catalog.db'
        self.serial = 0

    def feed(self, *records, **envelope):
        self.serial += 1
        path = self.root / f'feed{self.serial}.json'
        data = {'format': 'NVD_CVE', 'version': '2.0', 'totalResults': len(records),
                'startIndex': 0, 'resultsPerPage': len(records),
                'vulnerabilities': [{'cve': r} for r in records]}
        data.update(envelope)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf8')
        return path

    def test_any_vendor_and_metadata_only_rows_survive(self):
        minimal = {'id': 'CVE-2026-12348', 'vulnStatus': 'Rejected'}
        cna = {'id': 'CVE-2026-12349', 'vulnStatus': 'Awaiting Analysis', 'affected': [
            {'source': 'cna@example.org', 'affectedData': [{'vendor': 'UnknownVendor', 'product': 'OtherProduct',
             'defaultStatus': 'unaffected', 'versions': [{'version': '0', 'lessThan': '2.*',
             'status': 'affected', 'versionType': 'custom', 'changes': [{'at': '1.2', 'status': 'unaffected'}]}],
             'platforms': ['linux']}]}]}
        missing = {'id': 'CVE-2026-12350', 'vulnStatus': 'Future state', 'descriptions': [{'value': 'PRIVATE PROSE'}]}
        feed = self.feed(cve(), cve('CVE-2026-12346', part='h'), cve('CVE-2026-12347', part='o'), minimal, cna, missing)
        before = feed.read_bytes()
        info = build_catalog([feed], self.db)
        self.assertEqual(feed.read_bytes(), before)
        self.assertEqual(info['records'], 6)
        self.assertEqual(info['input_records'], 6)
        self.assertEqual(info['rejected_records'], 1)
        self.assertEqual(info['without_applicability'], 2)
        with CatalogIndex(self.db) as index:
            rows = index.search(vendor='VENDOR_Z', product='PRODUCT_Z')
            self.assertEqual([r['cve'] for r in rows], ['CVE-2026-12345', 'CVE-2026-12346', 'CVE-2026-12347'])
            self.assertNotIn('configurations', rows[0])
            row = index.get('CVE-2026-12349')
            self.assertEqual(row['affected'][0]['affectedData'][0]['versions'][0]['lessThan'], '2.*')
            self.assertIn('cna_context_unknown', row['gaps'])
            self.assertEqual(index.get('CVE-2026-12348')['status'], 'Rejected')
            self.assertEqual(index.get('CVE-2026-12350')['status'], 'Unknown')
            self.assertNotIn('PRIVATE PROSE', json.dumps(index.get('CVE-2026-12350')))
            self.assertEqual(index.get('CVE-2026-12345')['catalog_id'], info['catalog_id'])
            self.assertEqual(index.get('CVE-2026-12345')['source_sha256'], [hashlib.sha256(before).hexdigest()])

    def test_cpe_escape_and_tree_semantics_and_broad_candidates(self):
        parsed = parse_cpe23(r'cpe:2.3:o:ven\:dor:pro\\duct:1.0:*:*:*:*:*:*:*')
        self.assertEqual((parsed['part'], parsed['vendor'], parsed['product']), ('o', 'ven:dor', 'pro\\duct'))
        row = cve(vendor='*')
        row['configurations'][0]['operator'] = 'AND'
        row['configurations'][0]['negate'] = True
        row['configurations'][0]['nodes'][0]['cpeMatch'][0]['vulnerable'] = False
        build_catalog([self.feed(row, cve('CVE-2026-54321'))], self.db)
        with CatalogIndex(self.db) as index:
            tree = index.get('CVE-2026-12345')['configurations'][0]
            self.assertEqual(tree['operator'], 'AND')
            self.assertTrue(tree['negate'])
            self.assertFalse(tree['nodes'][0]['cpeMatch'][0]['vulnerable'])
            page = index.relevant([{'kind': 'cpe', 'part': 'a', 'vendor': 'somebody', 'product': 'product_z'}], limit=1)
            self.assertEqual([r['cve'] for r in page['records']], ['CVE-2026-12345'])
            self.assertFalse(page['truncated'])
            self.assertEqual(page['examined'], 1)

    def test_duplicate_resolution_membership_and_conflict(self):
        old = cve()
        new = copy.deepcopy(old)
        new['lastModified'] = '2026-02-01T00:00:00.000'
        new['vulnStatus'] = 'Modified'
        feeds = [self.feed(old), self.feed(new), self.feed(new)]
        info = build_catalog(feeds, self.db)
        self.assertEqual((info['records'], info['input_records'], info['duplicate_records']), (1, 3, 2))
        with CatalogIndex(self.db) as index:
            self.assertEqual(index.get(old['id'])['status'], 'Modified')
            self.assertEqual(len(index.get(old['id'])['source_sha256']), 2)
            self.assertEqual(len(index.get(old['id'])['feed_membership']), 3)
        new['vulnStatus'] = 'Analyzed'
        for variant in [new, dict(new, lastModified=None)]:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                build_catalog([feeds[1], self.feed(variant)], self.root / 'conflict.db')
            self.assertFalse((self.root / 'conflict.db').exists())

    def test_input_preflight_pins_noclobber_and_failure_cleanup(self):
        feed = self.feed(cve())
        for pins in [[], ['wrong'], ['0' * 64]]:
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                build_catalog([feed], self.db, expected_sha256=pins)
            self.assertFalse(self.db.exists())
        self.db.write_bytes(b'KEEP')
        with self.assertRaises(ValueError):
            build_catalog([self.root / 'does-not-exist'], self.db)
        self.assertEqual(self.db.read_bytes(), b'KEEP')
        self.db.unlink()
        for callback in [lambda _: (_ for _ in ()).throw(RuntimeError('private path')), None]:
            with self.assertRaises(ValueError):
                build_catalog([feed], self.db, progress=callback, cancel=None if callback else lambda: True)
            self.assertFalse(self.db.exists())
            self.assertEqual(sorted(p.name for p in self.root.iterdir()), [feed.name])
        with self.assertRaises(ValueError):
            build_catalog([feed], self.root / 'no-parent' / 'new.db')
        # The output ancestor must not redirect through symlinks.
        try:
            (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        except OSError:
            pass
        else:
            with self.assertRaises(ValueError):
                build_catalog([feed], self.root / 'linked' / 'new.db')

    def test_progress_fresh_throttled_and_typed(self):
        events = []
        def changed(event):
            events.append(dict(event))
            event['records'] = -100
            event['private'] = 'not reusable'
        with patch('wifiscope.catalog_store.time.monotonic', return_value=10):
            build_catalog([self.feed(cve(), cve('CVE-2026-54321'))], self.db, progress=changed)
        self.assertEqual([e['status'] for e in events], ['running', 'complete'])
        self.assertEqual(events[-1]['records'], 2)
        self.assertEqual(set(events[0]), {'status', 'records', 'expanded_bytes', 'feed_index', 'elapsed_ms'})
        self.assertTrue(all(type(e[k]) is int and e[k] >= 0 for e in events for k in ('records', 'expanded_bytes', 'feed_index', 'elapsed_ms')))

    def test_build_integrity_scan_outgrows_ordinary_query_budget(self):
        feed = self.feed(*[cve(f'CVE-2026-{n:05d}') for n in range(10000, 10200)])
        original = feed.read_bytes()
        with patch('wifiscope.catalog_store.QUERY_STEPS', 1000):
            info = build_catalog([feed], self.db)
            self.assertEqual(info['records'], 200)
            with CatalogIndex(self.db) as index:
                self.assertEqual(index.info()['records'], 200)
                # The same real scan remains bounded on an ordinary readonly index.
                with self.assertRaisesRegex(sqlite3.OperationalError, 'interrupted'):
                    index._connection.execute('PRAGMA quick_check').fetchall()
                with self.assertRaises(CatalogError):
                    index.search(vendor='vendor_z', product='product_z', offset=190)
        self.assertEqual(feed.read_bytes(), original)

    def test_build_integrity_scan_cancellation_cleans_only_owned_staging(self):
        build_catalog([self.feed(cve())], self.db)
        generation = self.db.read_bytes()
        feed = self.feed(*[cve(f'CVE-2026-{n:05d}') for n in range(10000, 10200)])
        original = feed.read_bytes()
        entries = set(self.root.iterdir())
        destination = self.root / 'cancelled.db'
        state = {'scanning': False, 'checks': 0}
        events = []
        connect = sqlite3.connect

        class ScanConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql != 'PRAGMA quick_check':
                    return super().execute(sql, *args, **kwargs)
                state['scanning'] = True
                try:
                    return super().execute(sql, *args, **kwargs)
                finally:
                    state['scanning'] = False

        def traced_connect(*args, **kwargs):
            if kwargs.get('uri'):
                kwargs['factory'] = ScanConnection
            return connect(*args, **kwargs)

        def cancel():
            if state['scanning']:
                state['checks'] += 1
            return state['checks'] >= 2

        with patch('wifiscope.catalog_store.sqlite3.connect', side_effect=traced_connect):
            with self.assertRaises(CatalogCancelled):
                build_catalog([feed], destination, cancel=cancel, progress=events.append)
        self.assertGreaterEqual(state['checks'], 2)
        self.assertEqual(events[-1]['status'], 'cancelled')
        self.assertNotIn('complete', [event['status'] for event in events])
        self.assertFalse(destination.exists())
        self.assertEqual(set(self.root.iterdir()), entries)
        self.assertEqual(feed.read_bytes(), original)
        self.assertEqual(self.db.read_bytes(), generation)

    def test_build_integrity_failure_prevents_publication(self):
        build_catalog([self.feed(cve())], self.db)
        generation = self.db.read_bytes()
        feed = self.feed(cve('CVE-2026-54321'))
        original = feed.read_bytes()
        entries = set(self.root.iterdir())
        destination = self.root / 'corrupted.db'
        scans = []
        connect = sqlite3.connect

        def corrupt_staging_connect(*args, **kwargs):
            if kwargs.get('uri'):
                staging, = self.root.glob('.wifiscope-catalog-*.db')
                # Create a real NOT NULL violation, then restore the exact schema.
                # Metadata/count validation still passes; SQLite must inspect rows.
                with closing(connect(staging)) as writable:
                    sql = writable.execute("SELECT sql FROM sqlite_schema WHERE name='records'").fetchone()[0]
                    writable.execute('PRAGMA writable_schema=ON')
                    writable.execute("UPDATE sqlite_schema SET sql=? WHERE name='records'",
                                     (sql.replace('status TEXT NOT NULL', 'status TEXT'),))
                    writable.commit()
                with closing(connect(staging)) as writable:
                    writable.execute('UPDATE records SET status=NULL')
                    writable.execute('PRAGMA writable_schema=ON')
                    writable.execute("UPDATE sqlite_schema SET sql=? WHERE name='records'", (sql,))
                    writable.commit()
            connection = connect(*args, **kwargs)
            if kwargs.get('uri'):
                connection.set_trace_callback(lambda sql: scans.append(sql) if sql == 'PRAGMA quick_check' else None)
            return connection

        with patch('wifiscope.catalog_store.sqlite3.connect', side_effect=corrupt_staging_connect):
            with self.assertRaisesRegex(CatalogError, 'generation integrity failed'):
                build_catalog([feed], destination)
        self.assertEqual(scans, ['PRAGMA quick_check'])
        self.assertFalse(destination.exists())
        self.assertEqual(set(self.root.iterdir()), entries)
        self.assertEqual(feed.read_bytes(), original)
        self.assertEqual(self.db.read_bytes(), generation)

    def test_build_integrity_scan_work_and_deadline_exhaustion_are_atomic(self):
        build_catalog([self.feed(cve())], self.db)
        generation = self.db.read_bytes()
        feed = self.feed(*[cve(f'CVE-2026-{n:05d}') for n in range(10000, 10200)])
        original = feed.read_bytes()
        entries = set(self.root.iterdir())
        connect = sqlite3.connect
        for bound in ('instructions', 'deadline'):
            with self.subTest(bound=bound):
                state = {'scanning': False}
                destination = self.root / f'{bound}.db'

                def trace(sql, state=state):
                    if sql == 'PRAGMA quick_check':
                        state['scanning'] = True

                def traced_connect(*args, trace=trace, **kwargs):
                    connection = connect(*args, **kwargs)
                    if kwargs.get('uri'):
                        connection.set_trace_callback(trace)
                    return connection

                def clock(state=state):
                    return 601 if state['scanning'] else 0

                guard = (patch('wifiscope.catalog_store._BUILD_INTEGRITY_STEPS_PER_BYTE', 0, create=True)
                         if bound == 'instructions' else patch('wifiscope.catalog_store.time.monotonic', side_effect=clock))
                with patch('wifiscope.catalog_store.sqlite3.connect', side_effect=traced_connect), guard:
                    with self.assertRaisesRegex(CatalogError, 'integrity .*work budget'):
                        build_catalog([feed], destination)
                self.assertTrue(state['scanning'])
                self.assertFalse(destination.exists())
                self.assertEqual(set(self.root.iterdir()), entries)
                self.assertEqual(feed.read_bytes(), original)
                self.assertEqual(self.db.read_bytes(), generation)

    def test_readonly_pin_schema_corrupt_rows_and_no_sidecars(self):
        build_catalog([self.feed(cve())], self.db)
        original = self.db.read_bytes()
        with CatalogIndex(self.db, expected_sha256=hashlib.sha256(original).hexdigest()) as index:
            self.assertEqual(index.info()['records'], 1)
            self.assertIsNone(index.get('CVE-2026-99999'))
            for kwargs in [{'vendor': 'x'}, {'cve': "x' OR 1=1--"}, {'limit': True}, {'offset': 1000001}, {'limit': 101}]:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    index.search(**kwargs)
            self.assertEqual(index.search(vendor="x' OR 1=1--", product='%_'), [])
            with self.assertRaises(sqlite3.DatabaseError):
                index._connection.execute('CREATE TABLE bad (a)')
            with self.assertRaises(sqlite3.DatabaseError):
                index._connection.execute("SELECT load_extension('missing')")
        self.assertEqual(self.db.read_bytes(), original)
        self.assertFalse(Path(str(self.db) + '-wal').exists())
        self.assertFalse(Path(str(self.db) + '-journal').exists())
        for sql in ['CREATE VIEW bad AS SELECT 1', 'CREATE TRIGGER bad AFTER INSERT ON records BEGIN SELECT 1; END',
                    'PRAGMA application_id=1', 'PRAGMA user_version=999', 'CREATE TABLE unknown (x)',
                    'CREATE INDEX unknown_index ON records(cve)', 'ANALYZE', "UPDATE records SET body='{}'"]:
            bad = self.root / 'bad.db'
            bad.write_bytes(original)
            with closing(sqlite3.connect(bad)) as connection:
                connection.execute(sql)
                connection.commit()
            with self.subTest(sql=sql), self.assertRaises(ValueError), CatalogIndex(bad) as index:
                index.get('CVE-2026-12345')
        with self.assertRaises(ValueError):
            CatalogIndex(self.db, expected_sha256='0' * 64)

    def test_future_semantics_keep_metadata_and_budget_failure_is_atomic(self):
        row = cve()
        row['configurations'][0]['futureCondition'] = 'do not infer'
        build_catalog([self.feed(row)], self.db)
        with CatalogIndex(self.db) as index:
            self.assertIn('configuration_unknown_field', index.get(row['id'])['gaps'])
            self.assertEqual(index.info()['unsupported_records'], 1)
        self.db.unlink()
        for setting in [('MAX_RECORDS', 1), ('MAX_DB_BYTES', 1024)]:
            with patch('wifiscope.catalog_store.' + setting[0], setting[1]), self.assertRaises(ValueError):
                build_catalog([self.feed(cve(), cve('CVE-2026-54321'))], self.db)
            self.assertFalse(self.db.exists())

    def many_leaf_record(self, count):
        # Synthetic conditions only; no official CVE fixture is copied here.
        matches = [{'vulnerable': number % 2 == 0,
                    'criteria': 'cpe:2.3:a:vendor_many:product_many:*:*:*:*:*:*:*:*',
                    'versionStartIncluding': f'{number}.0',
                    'versionEndExcluding': f'{number + 1}.0',
                    'matchCriteriaId': f'00000000-0000-4000-8000-{number:012d}'}
                   for number in range(count)]
        row = cve()
        row['configurations'] = [{'operator': 'AND', 'negate': False, 'nodes': [
            {'operator': 'OR', 'negate': False, 'cpeMatch': matches[:count // 2]},
            {'operator': 'AND', 'negate': True, 'cpeMatch': matches[count // 2:]}]}]
        return row, matches

    def test_large_cpe_tree_preserves_5821_and_exact_8192_leaf_conditions(self):
        for count in (5821, 8192):
            with self.subTest(count=count):
                row, original_matches = self.many_leaf_record(count)
                feed = self.feed(row)
                original_bytes = feed.read_bytes()
                destination = self.root / f'leaves-{count}.db'
                try:
                    info = build_catalog([feed], destination)
                except CatalogError as error:
                    self.fail(f'Valid synthetic {count}-leaf record must be retained: {error}')
                self.assertEqual(info['records'], 1)
                self.assertEqual(feed.read_bytes(), original_bytes)
                with CatalogIndex(destination) as index:
                    tree = index.get(row['id'])['configurations'][0]
                self.assertEqual((tree['operator'], tree['negate']), ('AND', False))
                self.assertEqual([(node['operator'], node['negate']) for node in tree['nodes']],
                                 [('OR', False), ('AND', True)])
                matches = tree['nodes'][0]['cpeMatch'] + tree['nodes'][1]['cpeMatch']
                self.assertEqual(len(matches), count)
                self.assertEqual(matches[0]['matchCriteriaId'], '00000000-0000-4000-8000-000000000000')
                self.assertEqual(matches[-1]['matchCriteriaId'], f'00000000-0000-4000-8000-{count - 1:012d}')
                self.assertEqual(matches[0]['versionStartIncluding'], '0.0')
                self.assertEqual(matches[-1]['versionEndExcluding'], f'{count}.0')
                self.assertTrue(all(match['unsupported'] is False for match in matches))
                self.assertEqual([{key: value for key, value in match.items() if key != 'unsupported'}
                                  for match in matches], original_matches)

    def test_8193_cpe_leaves_fail_atomically_and_preserve_input_and_generation(self):
        build_catalog([self.feed(cve())], self.db)
        generation_bytes = self.db.read_bytes()
        row, _ = self.many_leaf_record(8193)
        feed = self.feed(row)
        input_bytes = feed.read_bytes()
        entries = set(self.root.iterdir())
        destination = self.root / 'over-budget.db'
        with self.assertRaisesRegex(CatalogError, 'CPE leaf budget exceeded'):
            build_catalog([feed], destination)
        self.assertFalse(destination.exists())
        self.assertEqual(set(self.root.iterdir()), entries)
        self.assertEqual(feed.read_bytes(), input_bytes)
        self.assertEqual(self.db.read_bytes(), generation_bytes)
        with CatalogIndex(self.db) as index:
            self.assertEqual(index.get('CVE-2026-12345')['status'], 'Analyzed')

    def test_relevant_pages_deduplicate_and_exclude_rejected(self):
        rows = [cve(f'CVE-2026-{n:05d}') for n in range(10000, 10005)]
        rows[-1]['vulnStatus'] = 'Rejected'
        build_catalog([self.feed(*rows)], self.db)
        identities = [{'kind': 'cpe', 'part': 'a', 'vendor': 'vendor_z', 'product': 'product_z'}] * 2
        with CatalogIndex(self.db) as index:
            page = index.relevant(identities, limit=2)
            self.assertEqual([r['cve'] for r in page['records']], ['CVE-2026-10000', 'CVE-2026-10001'])
            self.assertTrue(page['truncated'])
            self.assertEqual(page['next_after'], 'CVE-2026-10001')
            page = index.relevant(identities, limit=2, after=page['next_after'])
            self.assertEqual([r['cve'] for r in page['records']], ['CVE-2026-10002', 'CVE-2026-10003'])
            self.assertFalse(page['truncated'])
            self.assertFalse(page['work_limited'])
            for invalid in [[], [{}], [{'kind': 'cpe', 'part': 'a', 'vendor': '*', 'product': '*'}] * 8193]:
                with self.assertRaises(ValueError):
                    index.relevant(invalid)
        with CatalogIndex(self.db) as index, patch('wifiscope.catalog_store.MAX_RELEVANT_BYTES', 2200):
            page = index.relevant(identities)
            self.assertLessEqual(len(json.dumps(page['records'], separators=(',', ':'), ensure_ascii=False).encode('utf8')), 2200)
            self.assertTrue(page['truncated'])
        with CatalogIndex(self.db) as index, patch('wifiscope.catalog_store.MAX_IDENTITY_ROWS', 1):
            page = index.relevant(identities)
            self.assertTrue(page['work_limited'])
            self.assertIsNone(page['next_after'])

    def test_relevant_merge_comparisons_are_bounded_across_disjoint_identities(self):
        # Removing the bounded merge makes comparisons grow with hits * page size.
        for count in (128, 512):
            with self.subTest(count=count):
                comparisons = [0]
                sorted_elements = [0]
                class CountedCVE(str):
                    counter = comparisons
                    def __lt__(self, other):
                        self.counter[0] += 1
                        return super().__lt__(other)
                index = CatalogIndex.__new__(CatalogIndex)
                index._connection = object()
                index._get = lambda identifier: {'cve': identifier}
                def query(sql, values=(), count=count):
                    kind, _part, vendor, _product, _after, _bound = values
                    if kind != 'cna':
                        return iter(())
                    # Later identity sorts earlier, forcing replacements as well
                    # as testing the skip path for larger candidates.
                    start = {'a': 300000, 'b': 100000, 'c': 200000}[vendor]
                    return ((CountedCVE(f'CVE-2026-{number}'),) for number in range(start, start + count + 1))
                index._query = query
                def counted_sorted(values, *args, element_counter=sorted_elements, **kwargs):
                    if isinstance(values, set) and values and isinstance(next(iter(values)), CountedCVE):
                        element_counter[0] += len(values)
                    return builtins.sorted(values, *args, **kwargs)
                identities = [{'kind': 'cna', 'vendor': vendor, 'product': 'p'} for vendor in ('a', 'b', 'c')]
                with patch('wifiscope.catalog_store.sorted', counted_sorted, create=True):
                    page = index.relevant(identities, limit=count)
                self.assertEqual(page['examined'], 3 * (count + 1))
                self.assertEqual(len(page['records']), count)
                self.assertEqual(page['records'][0]['cve'], 'CVE-2026-100000')
                self.assertEqual(page['records'][-1]['cve'], f'CVE-2026-{100000 + count - 1}')
                self.assertTrue(page['truncated'])
                self.assertEqual(page['next_after'], f'CVE-2026-{100000 + count - 1}')
                self.assertFalse(page['work_limited'])
                # Heap updates and the one final ordering are O(hits log limit).
                self.assertLessEqual(comparisons[0], 8 * page['examined'] * (count + 1).bit_length())
                self.assertLessEqual(sorted_elements[0], 2 * page['examined'])

    def test_relevant_merge_interleaves_overlap_and_common_cursor(self):
        index = CatalogIndex.__new__(CatalogIndex)
        index._connection = object()
        index._get = lambda identifier: {'cve': identifier}
        sources = {'a': ['CVE-2026-10000', 'CVE-2026-10002', 'CVE-2026-10004', 'CVE-2026-10006'],
                   'b': ['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003', 'CVE-2026-10005'],
                   'c': ['CVE-2026-10000', 'CVE-2026-10003', 'CVE-2026-10006']}
        cursors = []
        def query(sql, values=()):
            kind, _part, vendor, _product, after, bound = values
            cursors.append(after)
            values = sources[vendor] if kind == 'cna' else []
            return iter((value,) for value in [value for value in values if value > after][:bound])
        index._query = query
        identities = [{'kind': 'cna', 'vendor': vendor, 'product': 'p'} for vendor in ('a', 'b', 'c', 'a')]
        first = index.relevant(identities, limit=3)
        self.assertEqual([row['cve'] for row in first['records']],
                         ['CVE-2026-10000', 'CVE-2026-10001', 'CVE-2026-10002'])
        self.assertTrue(first['truncated'])
        self.assertEqual(first['next_after'], 'CVE-2026-10002')
        self.assertEqual(cursors, [''] * 4)
        cursors.clear()
        second = index.relevant(identities, limit=3, after=first['next_after'])
        self.assertEqual([row['cve'] for row in second['records']],
                         ['CVE-2026-10003', 'CVE-2026-10004', 'CVE-2026-10005'])
        self.assertTrue(second['truncated'])
        self.assertEqual(second['next_after'], 'CVE-2026-10005')
        self.assertEqual(cursors, ['CVE-2026-10002'] * 4)
        third = index.relevant(identities, limit=3, after=second['next_after'])
        self.assertEqual([row['cve'] for row in third['records']], ['CVE-2026-10006'])
        self.assertFalse(third['truncated'])
        self.assertIsNone(third['next_after'])
        # Keep the same completeness rules when either independent budget binds.
        with patch('wifiscope.catalog_store.MAX_RELEVANT_BYTES', 28):
            byte_page = index.relevant(identities, limit=3)
        self.assertEqual([row['cve'] for row in byte_page['records']], ['CVE-2026-10000'])
        self.assertTrue(byte_page['truncated'])
        self.assertEqual(byte_page['next_after'], 'CVE-2026-10000')
        self.assertFalse(byte_page['work_limited'])
        with patch('wifiscope.catalog_store.MAX_IDENTITY_ROWS', 5):
            limited = index.relevant(identities, limit=3)
        self.assertEqual(limited['examined'], 5)
        self.assertTrue(limited['work_limited'])
        self.assertTrue(limited['truncated'])
        self.assertIsNone(limited['next_after'])

    def test_malformed_applicability_is_unknown_and_cna_cpes_are_indexed(self):
        row = {'id': 'CVE-2026-12345', 'vulnStatus': [], 'metrics': {'cvssMetricV31': [None]},
               'published': 'PRIVATE IMPORTED PROSE', 'lastModified': 'PRIVATE PATH /x',
               'configurations': [{'operator': {}, 'negate': 1, 'cpeMatch': [{'vulnerable': 1, 'criteria': None}]}],
               'affected': [{'source': 'cna@example.org', 'affectedData': [
                   {'vendor': 'literal', 'product': 'name', 'packageURL': 'pkg:example/name',
                    'cpes': ['cpe:2.3:h:hardware_vendor:router:*:*:*:*:*:*:*:*'],
                    'versions': [{'version': '0', 'lessThan': '9' * 1024, 'status': 'affected', 'versionType': 'custom'}]}]}]}
        build_catalog([self.feed(row)], self.db)
        with CatalogIndex(self.db) as index:
            stored = index.get(row['id'])
            self.assertIsNone(stored['published'])
            self.assertIsNone(stored['modified'])
            self.assertIn('timestamp_unknown', stored['gaps'])
            self.assertIn('configuration_shape_unknown', stored['gaps'])
            self.assertEqual(index.search(vendor='hardware_vendor', product='router')[0]['cve'], row['id'])
            self.assertEqual(stored['affected'][0]['affectedData'][0]['context']['packageURL'], 'pkg:example/name')
            self.assertEqual(len(stored['affected'][0]['affectedData'][0]['versions'][0]['lessThan']), 1024)
        self.db.unlink()
        for setting in [('MAX_CPE_LEAVES', 0), ('MAX_AFFECTED_ROWS', 0)]:
            with patch('wifiscope.catalog_records.' + setting[0], setting[1]), self.assertRaises(ValueError):
                build_catalog([self.feed(row)], self.db)
            self.assertFalse(self.db.exists())

    def test_cancellation_midstream_final_callback_and_query_work_bounds(self):
        feed = self.feed(*[cve(f'CVE-2026-{n:05d}') for n in range(10000, 10020)])
        events = []
        cancelled = [False]
        def callback(event):
            events.append(event)
            if event['status'] == 'running':
                cancelled[0] = True
        with self.assertRaises(ValueError):
            build_catalog([feed], self.db, cancel=lambda: cancelled[0], progress=callback)
        self.assertEqual(events[-1]['status'], 'cancelled')
        self.assertFalse(self.db.exists())
        def fail_final(event):
            if event['status'] == 'complete':
                raise RuntimeError('private callback error')
        with self.assertRaises(ValueError):
            build_catalog([feed], self.db, progress=fail_final)
        self.assertFalse(self.db.exists())
        build_catalog([feed], self.db)
        with CatalogIndex(self.db) as index:
            index._connection.set_progress_handler(index._step, 1)
            with patch('wifiscope.catalog_store.QUERY_STEPS', 0), self.assertRaises(ValueError):
                index.search(offset=10)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [self.db.name, feed.name])

    def test_network_paths_are_refused_before_filesystem_io(self):
        paths = ['https://example.org/feed.json', '//example.org/share/feed.json',
                 r'\\example.org\share\feed.json', r'\\?\UNC\example.org\share\feed.json',
                 'file://example.org/share/feed.json']
        for value in paths:
            with self.subTest(value=value), patch('pathlib.Path.is_symlink', side_effect=AssertionError('filesystem touched')):
                with self.assertRaises(ValueError):
                    build_catalog([value], self.db)
                with self.assertRaises(ValueError):
                    CatalogIndex(value)
                with self.assertRaises(ValueError):
                    build_catalog([self.root / 'irrelevant'], value)

    @unittest.skipUnless(os.environ.get('WIFISCOPE_CATALOG_STRESS') == '1', 'explicit 50001-record capacity check')
    def test_generated_50001_record_capacity(self):
        path = self.root / 'generated.json'
        with path.open('w', encoding='utf8') as file:
            file.write('{"format":"NVD_CVE","version":"2.0","totalResults":50001,"startIndex":0,"resultsPerPage":50001,"vulnerabilities":[')
            for number in range(50001):
                if number:
                    file.write(',')
                file.write(json.dumps({'cve': cve(f'CVE-2026-{100000 + number}')}))
            file.write(']}')
        started = time.monotonic()
        info = build_catalog([path], self.db)
        elapsed = time.monotonic() - started
        self.assertEqual((info['input_records'], info['records']), (50001, 50001))
        with CatalogIndex(self.db) as index:
            self.assertEqual(index.search(cve='CVE-2026-150000')[0]['cve'], 'CVE-2026-150000')
            self.assertEqual(index.get('CVE-2026-100000')['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria'],
                             'cpe:2.3:a:vendor_z:product_z:*:*:*:*:*:*:*:*')
        peak = None
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            class Memory(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in ('peak_working_set', 'working_set', 'peak_paged', 'paged',
                                                      'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile')]
            memory = Memory()
            memory.cb = ctypes.sizeof(memory)
            ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD)
            ctypes.windll.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            process = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(memory), memory.cb):
                peak = memory.peak_working_set
        print(json.dumps({'synthetic_records': info['records'], 'elapsed_seconds': round(elapsed, 3),
                          'source_bytes': path.stat().st_size, 'db_bytes': self.db.stat().st_size,
                          'peak_process_working_set_bytes': peak}), flush=True)

    def test_untrusted_summary_cannot_export_timestamp_prose(self):
        build_catalog([self.feed(cve())], self.db)
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE records SET published='PRIVATE PATH /x'")
            connection.commit()
        with CatalogIndex(self.db) as index, self.assertRaises(ValueError):
            index.search()

    def test_cli_subprocess_build_info_search_and_safe_error(self):
        feed = self.feed(cve())
        def run(*args):
            return subprocess.run([sys.executable, '-m', 'wifiscope', 'catalog', *args], capture_output=True, text=True, timeout=20, check=False)
        result = run('build', '--input', str(feed), '--out', str(self.db))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['records'], 1)
        self.assertNotIn(str(self.root), result.stdout)
        self.assertEqual(json.loads(run('info', '--db', str(self.db)).stdout)['records'], 1)
        self.assertEqual(json.loads(run('search', '--db', str(self.db), '--vendor', 'vendor_z', '--product', 'product_z').stdout)[0]['cve'], 'CVE-2026-12345')
        result = run('info', '--db', str(self.root / 'SECRET-PATH'))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('SECRET-PATH', result.stderr)


if __name__ == '__main__':
    unittest.main()
