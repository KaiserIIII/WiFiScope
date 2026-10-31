"""Independent small-catalog controls for exact resumable pair admission."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wifiscope.catalog_store import CatalogIndex, build_catalog


def cpe(version='1', part='a', vendor='acme', product='app'):
    return f'cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


def source_record(number, environment=False):
    leaves = [dict(vulnerable=True, criteria=cpe())]
    if environment:
        leaves.append(dict(vulnerable=False, criteria=cpe('*', 'o', 'linux', 'kernel')))
    return dict(id=f'CVE-2026-{number}', vulnStatus='Analyzed',
                published='2026-01-01T00:00:00.000', lastModified='2026-01-02T00:00:00.000',
                configurations=[dict(nodes=[dict(operator='AND' if environment else 'OR',
                                                 negate=False, cpeMatch=leaves)])])


def inventory():
    return dict(schema_version=1, assets=[dict(id=name, components=[dict(
        id='component-'+name, cpe=cpe(version), source='synthetic', identification='declared')])
        for name, version in [('matching', '1'), ('wrong-version', '2')]])


class ChunkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = root/'source.json'
        rows = [source_record(90001), source_record(90002), source_record(90003, True)]
        self.source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=3,
            startIndex=0, resultsPerPage=3, vulnerabilities=[dict(cve=r) for r in rows])), encoding='utf8')
        self.db = root/'catalog.db'
        build_catalog([self.source], self.db)
        self.index = CatalogIndex(self.db)
        self.addCleanup(self.index.close)

    def test_first_page_commits_only_retained_pair(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.catalog_chunks'),
                             'bounded resumable matching is missing')
        from wifiscope.catalog_chunks import _audit_chunk
        self.assertTrue(callable(_audit_chunk))
        chunk = _audit_chunk({'schema_version': 1}, inventory(), self.index,
                             cursor={'asset_ordinal': 0, 'after': None}, page_size=1)
        self.assertEqual([(p['asset_ordinal'], p['cve'], p['applicability']) for p in chunk['pairs']],
                         [(0, 'CVE-2026-90001', 'true')])
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-90001'})
        self.assertEqual(chunk['stop_reason'], 'page-limit')
        self.assertFalse(chunk['computation_complete'])

    def chunk(self, **kwargs):
        from wifiscope.catalog_chunks import _audit_chunk
        return _audit_chunk(kwargs.pop('report', {'schema_version': 1}),
                            kwargs.pop('inv', inventory()), kwargs.pop('index', self.index),
                            cursor=kwargs.pop('cursor', {'asset_ordinal': 0, 'after': None}), **kwargs)

    def catalog(self, rows):
        root = Path(self.temp.name)
        path = root/'extra.json'
        path.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=len(rows),
            startIndex=0, resultsPerPage=len(rows), vulnerabilities=[dict(cve=r) for r in rows])), encoding='utf8')
        path = root/'extra.db'
        build_catalog([root/'extra.json'], path)
        index = CatalogIndex(path)
        self.addCleanup(index.close)
        return index

    def test_real_query_pages_and_default_256_result_boundary(self):
        index = self.catalog([source_record(91000 + i) for i in range(260)])
        first = self.chunk(index=index)
        self.assertEqual(first['stop_reason'], 'page-limit')
        self.assertEqual(len(first['results']), 256)
        self.assertEqual(first['pairs'][0], dict(asset_ordinal=0, cve='CVE-2026-91000', applicability='true'))
        self.assertEqual(first['pairs'][-1], dict(asset_ordinal=0, cve='CVE-2026-91255', applicability='true'))
        self.assertEqual(first['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-91255'})
        second = self.chunk(index=index, cursor=first['cursor'])
        self.assertEqual(second['pairs'][0], dict(asset_ordinal=0, cve='CVE-2026-91256', applicability='true'))
        self.assertEqual(second['summary']['true_pairs'], 4)
        self.assertEqual(second['summary']['not_matched_pairs'], 260)
        self.assertEqual(second['cursor'], {'asset_ordinal': 2, 'after': None})
        self.assertTrue(second['computation_complete'])
        self.assertEqual(len({(p['asset_ordinal'], p['cve']) for p in first['pairs']+second['pairs']}), 520)
        # A later incomplete identity union retains only the earlier safe page.
        relevant = index.relevant
        def limited(*args, **kwargs):
            value = relevant(*args, **kwargs)
            if kwargs['after'] is not None:
                value.update(work_limited=True, truncated=True, next_after=None)
            return value
        with patch.object(index, 'relevant', limited):
            blocked = self.chunk(index=index)
        self.assertEqual(blocked['stop_reason'], 'blocked-index')
        self.assertEqual(len(blocked['pairs']), 128)
        self.assertEqual(blocked['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-91127'})

    def test_models_witnesses_versions_and_source_time_remain_conservative(self):
        conflict, witness, version = [source_record(n) for n in (92001, 92002, 92003)]
        conflict['affected'] = [dict(affectedData=[dict(vendor='acme', product='app',
            defaultStatus='unaffected', versions=[], cpes=[cpe('*')])])]
        witness['configurations'][0]['nodes'][0]['cpeMatch'][0]['vulnerable'] = False
        version['configurations'][0]['nodes'][0]['cpeMatch'][0].update(
            criteria=cpe('*'), versionEndIncluding='2')
        index = self.catalog([conflict, witness, version])
        result = self.chunk(index=index)
        self.assertEqual([(r['cve'], r['model'], r['applicability'], r['reasons'])
                          for r in result['results'] if r['asset_id'] == 'matching'], [
            ('CVE-2026-92001', 'mixed', 'unknown', ['applicability-unknown', 'model-conflict']),
            ('CVE-2026-92002', 'cpe', 'unknown', ['applicability-unknown', 'positive-witness-missing']),
            ('CVE-2026-92003', 'cpe', 'unknown', ['applicability-unknown'])])
        self.assertTrue(all(r['observed_at'] == [] for r in result['results']))
        inv = inventory()
        for asset in inv['assets']:
            asset['components'][0]['version_scheme'] = 'numeric'
        result = self.chunk(index=index, inv=inv)
        self.assertEqual([r['applicability'] for r in result['results'] if r['cve'] == 'CVE-2026-92003'],
                         ['true', 'true'])
        inv['assets'][0]['complete_parts'] = ['o']
        result = self.chunk(inv=inv)
        self.assertEqual(result['pairs'][2]['applicability'], 'false')

    def test_full_inventory_binding_and_cross_asset_cve_are_distinct(self):
        original = self.chunk(page_size=1)['results'][0]['id']
        inv = inventory()
        inv['assets'][1]['components'][0]['cpe'] = cpe()
        chunk = self.chunk(inv=inv)
        self.assertEqual(chunk['summary']['true_pairs'], 4)
        self.assertEqual(chunk['summary']['unknown_pairs'], 2)
        self.assertEqual(len({r['id'] for r in chunk['results']}), 6)
        self.assertNotEqual(original, chunk['results'][0]['id'])

    def test_possible_scanner_evidence_stays_unknown_with_original_time(self):
        inv = inventory()
        inv['assets'] = inv['assets'][1:]
        component = inv['assets'][0]['components'][0]
        component.update(source='nmap', identification='imported', observed_at='2026-10-01T00:00:00Z',
            source_sha256='a'*64, scanner=dict(origin='service', method='table', confidence=9,
                accuracy=None, protocol='tcp', port=80, state='open', host_status='up', host_ordinal=0,
                entry_ordinal=0, cpe_ordinal=0, binding='formatted', timestamp_origin='host-end',
                metadata_valid=True, presence='possible'))
        before = copy.deepcopy(inv)
        chunk = self.chunk(inv=inv)
        self.assertEqual([p['applicability'] for p in chunk['pairs']], ['unknown', 'unknown', 'unknown'])
        for row in chunk['results']:
            self.assertEqual(row['observed_at'], ['2026-10-01T00:00:00Z'])
            self.assertEqual(row['sources'], ['nmap'])
            self.assertEqual(row['status'], 'imported-unverified')
            self.assertEqual(row['reasons'], ['applicability-unknown'])
        self.assertEqual(inv, before)

    def test_malformed_catalog_data_has_controlled_errors(self):
        relevant = self.index.relevant
        for corruption in ('missing-key', 'bad-shape', 'bad-score'):
            def page(*args, **kwargs):
                value = relevant(*args, **kwargs)
                if corruption == 'missing-key':
                    del value['records']
                elif corruption == 'bad-shape':
                    value['records'][0]['configurations'] = [None]
                else:
                    value['records'][0]['cvss'] = [{'score': 'PRIVATE_SENTINEL'}]
                return value
            with self.subTest(corruption=corruption), patch.object(self.index, 'relevant', page):
                with self.assertRaises(ValueError) as caught:
                    self.chunk()
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_follow_cursors_preserves_order_truth_unknown_provenance_and_inputs(self):
        report, inv = {'schema_version': 1}, inventory()
        before = json.dumps([report, inv], sort_keys=True)
        source, database = self.source.read_bytes(), self.db.read_bytes()
        cursor, pairs, rows = {'asset_ordinal': 0, 'after': None}, [], []
        for _ in range(8):
            chunk = self.chunk(report=report, inv=inv, cursor=cursor, page_size=1)
            self.assertEqual(set(chunk), {'cursor', 'computation_complete', 'stop_reason',
                                         'summary', 'pairs', 'results', 'gaps'})
            self.assertEqual(set(chunk['summary']), {'evaluated_pairs', 'true_pairs', 'unknown_pairs',
                'not_matched_pairs', 'retained_results', 'predicates', 'identity_queries', 'index_hits'})
            pairs.extend((p['asset_ordinal'], p['cve'], p['applicability']) for p in chunk['pairs'])
            rows.extend(chunk['results'])
            cursor = chunk['cursor']
            if chunk['computation_complete']:
                break
        self.assertEqual(pairs, [(0, 'CVE-2026-90001', 'true'), (0, 'CVE-2026-90002', 'true'),
            (0, 'CVE-2026-90003', 'unknown'), (1, 'CVE-2026-90001', 'false'),
            (1, 'CVE-2026-90002', 'false'), (1, 'CVE-2026-90003', 'false')])
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertEqual(cursor, {'asset_ordinal': 2, 'after': None})
        self.assertTrue(chunk['computation_complete'])
        self.assertEqual(chunk['stop_reason'], 'exhausted')
        # Independently spell the documented normalization and ID hash contract.
        normalized = copy.deepcopy(inv)
        for asset in normalized['assets']:
            asset['complete_parts'] = []
            asset['components'][0].update(observed_at=None, source_sha256=None, version_scheme='unknown')
        def digest(values):
            return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]
        fingerprint = digest([normalized])
        catalog_id = self.index.info()['catalog_id']
        for row, (identifier, outcome, reasons) in zip(rows, [
                ('CVE-2026-90001', 'true', []), ('CVE-2026-90002', 'true', []),
                ('CVE-2026-90003', 'unknown', ['applicability-unknown'])]):
            self.assertEqual(row, dict(id='finding-'+digest(['catalog', catalog_id, fingerprint, 'matching', identifier]),
                asset_id='matching', component_ids=['component-matching'], cve=identifier,
                applicability=outcome, severity='info', score=None, status='imported-unverified',
                reasons=reasons, gaps=['configuration/backport-unverified'], model='cpe', observed_at=[],
                sources=['synthetic'], published='2026-01-01T00:00:00.000', modified='2026-01-02T00:00:00.000',
                reference='https://nvd.nist.gov/vuln/detail/'+identifier, feed_membership=[0],
                source_sha256=[hashlib.sha256(source).hexdigest()]))
        self.assertEqual(json.dumps([report, inv], sort_keys=True), before)
        self.assertEqual((self.source.read_bytes(), self.db.read_bytes()), (source, database))
        rows[0]['sources'].append('local')
        self.assertEqual(self.chunk(page_size=1)['results'][0]['sources'], ['synthetic'])

    def test_false_pair_limit_and_asset_exhaustion(self):
        with patch('wifiscope.catalog_chunks.MAX_PAIRS', 1):
            chunk = self.chunk(cursor={'asset_ordinal': 1, 'after': None})
        self.assertEqual(chunk['pairs'], [dict(asset_ordinal=1, cve='CVE-2026-90001', applicability='false')])
        self.assertEqual(chunk['results'], [])
        self.assertEqual(chunk['stop_reason'], 'pair-limit')
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 1, 'after': 'CVE-2026-90001'})
        with patch('wifiscope.catalog_chunks.MAX_PAIRS', 4):
            chunk = self.chunk()
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 1, 'after': 'CVE-2026-90001'})
        self.assertEqual(chunk['summary']['not_matched_pairs'], 1)
        self.assertFalse(chunk['computation_complete'])

    def test_zero_candidate_asset_and_terminal_cursor(self):
        inv = inventory()
        inv['assets'].insert(0, dict(id='empty', components=[dict(id='empty-component',
            cpe=cpe(product='unrelated'), source='synthetic', identification='declared')]))
        chunk = self.chunk(inv=inv, page_size=1)
        self.assertEqual(chunk['pairs'], [dict(asset_ordinal=1, cve='CVE-2026-90001', applicability='true')])
        terminal = self.chunk(cursor={'asset_ordinal': 2, 'after': None})
        self.assertEqual(terminal['pairs'], [])
        self.assertEqual(terminal['summary']['predicates'], 0)
        self.assertTrue(terminal['computation_complete'])

    def test_output_rejection_never_commits_an_unretained_pair(self):
        with patch('wifiscope.catalog_chunks.MAX_RESULT_BYTES', 1):
            chunk = self.chunk()
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': None})
        self.assertEqual(chunk['pairs'], [])
        self.assertEqual(chunk['results'], [])
        self.assertEqual(chunk['summary']['evaluated_pairs'], 0)
        self.assertEqual(chunk['stop_reason'], 'blocked-output')
        # Both explanations are smaller than 1000 bytes; their sum is larger.
        with patch('wifiscope.catalog_chunks.MAX_RESULT_BYTES', 1000):
            chunk = self.chunk()
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-90001'})
        self.assertEqual(chunk['summary']['evaluated_pairs'], 1)
        self.assertEqual(chunk['stop_reason'], 'page-limit')
        retry = self.chunk(cursor=chunk['cursor'])
        self.assertEqual(retry['pairs'][0], dict(asset_ordinal=0, cve='CVE-2026-90002', applicability='true'))
        self.assertEqual(retry['summary']['unknown_pairs'], 1)

    def test_report_bytes_and_nodes_reserve_before_admission(self):
        from wifiscope.catalog_audit import _reserve_report
        for field in ('bytes', 'nodes'):
            def reserve(*args):
                report, byte_budget, node_budget = _reserve_report(*args)
                return report, 1 if field == 'bytes' else byte_budget, 1 if field == 'nodes' else node_budget
            with self.subTest(field=field), patch('wifiscope.catalog_chunks._reserve_report', reserve):
                chunk = self.chunk()
            self.assertEqual(chunk['stop_reason'], 'blocked-output')
            self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': None})
            self.assertEqual(chunk['pairs'], [])

    def test_work_limit_retries_uncommitted_pair_with_fresh_budget(self):
        with patch('wifiscope.catalog_chunks.MAX_PREDICATES', 50):
            chunk = self.chunk()
        self.assertEqual(chunk['stop_reason'], 'work-limit')
        self.assertEqual(chunk['pairs'], [dict(asset_ordinal=0, cve='CVE-2026-90001', applicability='true')])
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-90001'})
        self.assertLessEqual(chunk['summary']['predicates'], 50)
        retry = self.chunk(cursor=chunk['cursor'])
        self.assertEqual(retry['pairs'][0], dict(asset_ordinal=0, cve='CVE-2026-90002', applicability='true'))
        self.assertTrue(retry['computation_complete'])
        for cap in (1, 30):
            with self.subTest(cap=cap), patch('wifiscope.catalog_chunks.MAX_PREDICATES', cap):
                blocked = self.chunk()
            self.assertEqual(blocked['stop_reason'], 'blocked-predicate')
            self.assertEqual(blocked['cursor'], {'asset_ordinal': 0, 'after': None})
            self.assertEqual(blocked['pairs'], [])

    def test_incomplete_index_union_discards_whole_page(self):
        with patch('wifiscope.catalog_store.MAX_IDENTITY_ROWS', 1):
            chunk = self.chunk()
        self.assertEqual(chunk['stop_reason'], 'blocked-index')
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': None})
        self.assertEqual(chunk['pairs'], [])
        self.assertEqual(chunk['summary']['evaluated_pairs'], 0)
        self.assertGreater(chunk['summary']['index_hits'], 0)

    def test_invalid_index_cursor_blocks_and_invalid_record_order_errors(self):
        relevant = self.index.relevant
        for after in (None, 42, 'bad', 'CVE-2026-90001', 'CVE-2026-99999'):
            def page(*args, **kwargs):
                value = relevant(*args, **kwargs)
                value.update(truncated=True, next_after=after)
                return value
            with self.subTest(after=after), patch.object(self.index, 'relevant', page):
                chunk = self.chunk()
            self.assertEqual(chunk['stop_reason'], 'blocked-index')
            self.assertEqual(chunk['pairs'], [])
            self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': None})
        def reversed_page(*args, **kwargs):
            value = relevant(*args, **kwargs)
            value['records'].reverse()
            return value
        with patch.object(self.index, 'relevant', reversed_page), self.assertRaises(ValueError):
            self.chunk()

    def test_validation_precedes_matching(self):
        bad_cursors = [None, {}, {'asset_ordinal': True, 'after': None}, {'asset_ordinal': -1, 'after': None},
            {'asset_ordinal': 3, 'after': None}, {'asset_ordinal': 2, 'after': 'CVE-2026-90001'},
            {'asset_ordinal': 0, 'after': 'CVE-２０２６-90001'}, {'asset_ordinal': 0, 'after': 1},
            {'asset_ordinal': 0, 'after': None, 'extra': 0}]
        for cursor in bad_cursors:
            with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                self.chunk(cursor=cursor, cancel=lambda: self.fail('matching invalid cursor'))
        for size in (True, False, 0, -1, 4097, 1.5, '1', None):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.chunk(page_size=size, cancel=lambda: self.fail('matching invalid size'))
        for args in ({'inv': {}}, {'report': {}}, {'report': {'schema_version': 1, 'identifiers_included': False}}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.chunk(**args)

    def test_cancellation_before_during_preparation_and_cached_matching(self):
        from wifiscope.applicability import MatchBudget, _PreparedAsset
        chunk = self.chunk(cancel=lambda: True)
        self.assertEqual(chunk['stop_reason'], 'cancelled')
        self.assertEqual(chunk['pairs'], [])
        # The actual budget invokes the callback inside preparation, no fake outcomes.
        state = {'budget': None}
        def factory(limit, cancel):
            state['budget'] = MatchBudget(limit, cancel)
            return state['budget']
        with patch('wifiscope.catalog_chunks.MatchBudget', factory):
            chunk = self.chunk(cancel=lambda: state['budget'] is not None and state['budget'].used >= 3)
        self.assertEqual(chunk['stop_reason'], 'cancelled')
        self.assertEqual(chunk['pairs'], [])
        state = {'cached': False}
        evidence = _PreparedAsset._evidence
        def cached(prepared, identifier, budget):
            state['cached'] = identifier in prepared._cache
            return evidence(prepared, identifier, budget)
        with patch.object(_PreparedAsset, '_evidence', cached):
            chunk = self.chunk(cancel=lambda: state['cached'])
        self.assertEqual(chunk['stop_reason'], 'cancelled')
        self.assertEqual(chunk['pairs'], [dict(asset_ordinal=0, cve='CVE-2026-90001', applicability='true')])
        self.assertEqual(chunk['cursor'], {'asset_ordinal': 0, 'after': 'CVE-2026-90001'})
        self.assertIn('audit-cancelled', chunk['gaps'])

    def test_progress_and_cancel_errors_are_controlled_including_final_event(self):
        def broken(*args):
            raise RuntimeError('PRIVATE_SENTINEL')
        for args in ({'cancel': broken}, {'progress': broken}):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'callback') as caught:
                self.chunk(**args)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        def final(event):
            if event['status'] != 'running':
                broken()
        with self.assertRaisesRegex(ValueError, 'callback'):
            self.chunk(progress=final)
        events = []
        self.chunk(progress=lambda event: events.append(event))
        self.assertEqual(events[-1]['status'], 'exhausted')
        self.assertEqual(events[-1]['evaluated_pairs'], 6)
        for before, after in zip(events, events[1:]):
            self.assertIsNot(before, after)
            self.assertLessEqual(before['evaluated_pairs'], after['evaluated_pairs'])
        # Event mutation cannot rewrite committed counters.
        chunk = self.chunk(progress=lambda event: event.update(evaluated_pairs=999))
        self.assertEqual(chunk['summary']['evaluated_pairs'], 6)

    def test_source_partial_does_not_prevent_computational_exhaustion(self):
        info = self.index.info()
        info['feeds'][0]['partial'] = True
        with patch.object(self.index, 'info', return_value=info):
            chunk = self.chunk()
        self.assertTrue(chunk['computation_complete'])
        self.assertEqual(chunk['stop_reason'], 'exhausted')
        self.assertIn('catalog-input-partial', chunk['gaps'])


if __name__ == '__main__':
    unittest.main()
