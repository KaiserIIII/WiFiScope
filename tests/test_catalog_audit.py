import copy
import json
from pathlib import Path
import tempfile
import unittest

from wifiscope.catalog_audit import audit_catalog
from wifiscope.catalog_audit_schema import validate_catalog_audit
from wifiscope.investigate import build_investigation, merge_reports
from wifiscope.reports import prepare_export, export_report
from wifiscope.case_validation import validate_report
from tests.test_applicability import cpe, leaf, node, record


def inventory():
    return dict(schema_version=1, assets=[dict(id='private-asset', components=[dict(
        id='private-component', cpe=cpe(), source='synthetic', identification='imported')])])


class Index:
    def info(self):
        return dict(schema_version=1, catalog_id='a'*64, records=3, input_records=4,
                    duplicate_records=1, rejected_records=1, without_applicability=1,
                    unsupported_records=0, feeds=[dict(feed_index=0, source_sha256='b'*64, expanded_sha256='b'*64, source_bytes=100, expanded_bytes=100, records=4, total_results=4, start_index=0, results_per_page=4, timestamp=None, partial=False, pin_verified=False)])

    def relevant(self, identities, *, limit=50000, after=None):
        value = record(node(leaf()))
        value.update(cve='CVE-2026-1234567890123456789', cvss=[], published=None, modified=None,
                     feed_membership=[], source_sha256=[])
        return dict(records=[value], truncated=False, next_after=None, examined=1,
                    identity_queries=1, identity_queries_total=1, work_limited=False)


class AuditTests(unittest.TestCase):
    def test_real_index_unsupported_configuration_retained_with_independent_cna_model(self):
        from wifiscope.catalog_store import CatalogIndex, build_catalog
        from wifiscope.catalog_records import parse_cpe23
        report, inv = dict(schema_version=1), inventory()
        before = copy.deepcopy((report, inv))
        records = []
        mismatch = cpe(version='v' * 1025)
        self.assertIsNotNone(parse_cpe23(mismatch))
        for i, criteria in enumerate(('malformed-retained-cpe', 'cpe:/a:acme:app:1', mismatch)):
            for supported in (False, True):
                raw = dict(id=f'CVE-2026-{11000 + 2*i + supported}', vulnStatus='Analyzed',
                           configurations=[dict(operator='OR', cpeMatch=[dict(criteria=criteria, vulnerable=True)])])
                if supported:
                    raw['affected'] = [dict(affectedData=[dict(vendor='acme', product='app',
                        cpes=[cpe(version='*')], defaultStatus='unaffected',
                        versions=[dict(version='1.2', status='affected')])])]
                records.append(raw)
        with tempfile.TemporaryDirectory() as root:
            source, db = Path(root)/'source.json', Path(root)/'catalog.db'
            source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=6,
                startIndex=0, resultsPerPage=6, vulnerabilities=[dict(cve=r) for r in records])), encoding='utf8')
            source_bytes = source.read_bytes()
            build_catalog([source], db)
            database_bytes = db.read_bytes()
            with CatalogIndex(db) as index:
                for raw in records:
                    stored = index.get(raw['id'])
                    self.assertEqual(stored['configurations'][0]['cpeMatch'][0]['criteria'],
                                     raw['configurations'][0]['cpeMatch'][0]['criteria'])
                    if raw['id'] in ('CVE-2026-11000', 'CVE-2026-11002'):
                        self.assertIn('cpe_unknown', stored['gaps'])
                result = audit_catalog(report, inv, index)['catalog_audit']
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(result['summary']['unknown_pairs'], 3)
            self.assertEqual(result['summary']['true_pairs'], 3)
            self.assertEqual([r['applicability'] for r in result['results']],
                             ['unknown', 'true', 'unknown', 'true', 'unknown', 'true'])
            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertEqual(db.read_bytes(), database_bytes)
        self.assertEqual((report, inv), before)

    def test_pure_audit_and_projection_join_reexport_and_rebuild(self):
        report, inv = dict(schema_version=1), inventory()
        original = copy.deepcopy((report, inv))
        result = audit_catalog(report, inv, Index())
        self.assertEqual((report, inv), original)
        audit = result['catalog_audit']
        self.assertEqual(audit['summary']['true_pairs'], 1)
        self.assertEqual(audit['catalog']['without_applicability'], 1)
        self.assertTrue(result['synthetic'])
        self.assertEqual(build_investigation(result), result)
        for include in (False, True):
            exported = prepare_export(result, include)
            validate_report(exported)
            row = exported['catalog_audit']['results'][0]
            finding = next(f for f in exported['investigation']['findings'] if f['id'] == row['id'])
            self.assertEqual(finding['evidence']['asset_id'], row['asset_id'])
            self.assertEqual(exported['catalog_audit']['inventory']['assets'][0]['id'], row['asset_id'])
            self.assertEqual(finding['evidence']['cves'], [row['cve']])
            self.assertTrue(next(c for c in exported['investigation']['coverage'] if c['category'] == 'catalog-applicability')['partial'])
            if not include:
                self.assertNotIn('private-', json.dumps(exported))
                self.assertFalse(prepare_export(exported, True)['identifiers_included'])
                with self.assertRaises(ValueError):
                    audit_catalog(exported, inv, Index())
        with self.assertRaises(ValueError):
            merge_reports([result])

    def test_cancel_progress_and_callback_failure_leave_inputs(self):
        events = []
        result = audit_catalog(dict(schema_version=1), inventory(), Index(), cancel=lambda: True, progress=events.append)
        self.assertEqual(result['catalog_audit']['status'], 'cancelled')
        self.assertIsNone(result['catalog_audit']['summary']['unexamined_pairs'])
        self.assertEqual(events[-1]['status'], 'cancelled')
        with self.assertRaisesRegex(ValueError, 'callback'):
            audit_catalog(dict(schema_version=1), inventory(), Index(), progress=lambda event: 1/0)

    def test_schema_refuses_unknown_fields_and_invalid_join(self):
        result = audit_catalog(dict(schema_version=1), inventory(), Index())['catalog_audit']
        for field in ('prose', 'badjoin', 'count'):
            value = copy.deepcopy(result)
            if field == 'prose':
                value['results'][0]['description'] = 'PRIVATE_SENTINEL'
            elif field == 'badjoin':
                value['results'][0]['component_ids'] = ['missing']
            else:
                value['summary']['true_pairs'] += 1
            with self.assertRaises(ValueError):
                validate_catalog_audit(value)

    def test_bundle_cve_preservation(self):
        result = audit_catalog(dict(schema_version=1), inventory(), Index())
        with tempfile.TemporaryDirectory() as root:
            export_report(result, Path(root)/'bundle')
            files = list((Path(root)/'bundle').iterdir())
            self.assertTrue(any('CVE-2026-1234567890123456789' in p.read_text(encoding='utf8') for p in files if p.suffix == '.csv'))
            self.assertTrue(any('CVE-2026-1234567890123456789' in p.read_text(encoding='utf8') for p in files if p.suffix == '.html'))

    def test_real_index_cli_no_collection_and_error_new_bundle(self):
        import contextlib
        import hashlib
        import io
        from unittest.mock import patch
        from wifiscope.catalog_store import build_catalog
        from wifiscope.cli import main
        from tests.test_catalog_store import cve
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            feed, db, inv = root/'feed.json', root/'catalog.db', root/'inventory.json'
            row = cve(vendor='acme', product='app')
            del row['configurations'][0]['nodes'][0]['cpeMatch'][0]['versionEndExcluding']
            feed.write_text(json.dumps(dict(vulnerabilities=[dict(cve=row)], totalResults=1,
                startIndex=0, resultsPerPage=1, format='NVD_CVE', version='2.0')), encoding='utf8')
            build_catalog([feed], db)
            inv.write_text(json.dumps(inventory()), encoding='utf8')
            argv = ['catalog', 'audit', '--db', str(db), '--inventory', str(inv), '--sha256', hashlib.sha256(db.read_bytes()).hexdigest()]
            out, err = io.StringIO(), io.StringIO()
            with patch('wifiscope.cli.collect_local', side_effect=AssertionError('collection forbidden')), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main(argv), 0)
            projected = json.loads(out.getvalue())
            self.assertEqual(projected['catalog_audit']['summary']['true_pairs'], 1)
            self.assertNotIn('private-', out.getvalue())
            self.assertNotIn(str(root), out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(argv+['--out', str(root/'bundle')]), 0)
            self.assertNotIn(str(root), out.getvalue())
            with contextlib.redirect_stderr(err):
                self.assertEqual(main(argv+['--out', str(root/'bundle')]), 2)
                self.assertEqual(main(argv[:-1]+['0'*64]), 2)
            self.assertNotIn(str(root), err.getvalue())

    def test_compare_explicitly_refuses_audit_context_loss(self):
        from wifiscope.comparison import compare_snapshots
        result = audit_catalog(dict(schema_version=1), inventory(), Index())
        with self.assertRaisesRegex(ValueError, 'catalog'):
            compare_snapshots(result, result)

    def test_import_context_privacy_and_case_triage_roundtrip(self):
        from wifiscope.cases import CaseStore
        inv = inventory()
        inv['assets'][0]['components'][0]['source_sha256'] = 'c'*64
        inv['import_context'] = dict(format='cyclonedx', source_sha256='c'*64,
            document_observed_at=None, input_entries=2, input_cpe_identifiers=3,
            retained_components=1, unmapped_entries=1, unsupported_identifiers=1,
            duplicate_identifiers=1, partial=True, gaps=['sbom-import-unverified', 'source-time-unknown'])
        result = audit_catalog(dict(schema_version=1, collected_at='2026-10-29T00:00:00Z'), inv, Index())
        row = result['catalog_audit']['results'][0]
        self.assertEqual(row['observed_at'], [])
        projected = prepare_export(result)
        inv = projected['catalog_audit']['inventory']
        self.assertEqual(inv['import_context']['source_sha256'], inv['assets'][0]['components'][0]['source_sha256'])
        self.assertEqual(inv['import_context']['input_cpe_identifiers'], 3)
        with tempfile.TemporaryDirectory() as root, CaseStore(Path(root)/'case.db') as case:
            snapshot = case.add_snapshot(result)
            persisted = case.load_snapshot(snapshot)
            finding = persisted['catalog_audit']['results'][0]
            case.triage(finding['id'], 'investigating', snapshot_id=snapshot)
            self.assertEqual(case.triage_state(snapshot_id=snapshot)[finding['id']]['status'], 'investigating')
            self.assertTrue(case.verify()['ok'])
            validate_report(prepare_export(persisted, True))

    def test_unknown_projection_fields_and_forged_projected_cpe_refused(self):
        result = audit_catalog(dict(schema_version=1), inventory(), Index())['catalog_audit']
        value = copy.deepcopy(result)
        value['inventory']['assets'][0]['components'][0]['id'] = 'id-'+'a'*24
        value['inventory']['assets'][0]['components'][0]['cpe'] = 'PRIVATE_SENTINEL'
        value['results'] = []
        value['summary'].update(true_pairs=0, evaluated_pairs=0, retained_results=0)
        with self.assertRaises(ValueError):
            validate_catalog_audit(value)
        for where, key, bad in [('catalog', 'catalog_id', 'PRIVATE_SENTINEL'),
                                ('summary', 'partial', 1)]:
            value = copy.deepcopy(result)
            value[where][key] = bad
            with self.assertRaises(ValueError):
                validate_catalog_audit(value)

    def test_paginated_three_outcomes_and_partial_budgets(self):
        from unittest.mock import patch
        import wifiscope.catalog_audit as module
        class Pages(Index):
            def __init__(self):
                self.calls = []
            def relevant(self, identities, *, limit=50000, after=None):
                self.calls.append(after)
                page = super().relevant(identities)
                number = 0 if after is None else int(after.rsplit('-', 1)[1])-1000+1
                row = page['records'][0]
                row['cve'] = 'CVE-2026-'+str(1000+number)
                if number == 1:
                    row['configurations'] = [node(leaf(cpe(version='*'), versionEndIncluding='2'))]
                if number == 2:
                    row['configurations'] = [node(leaf(cpe(version='2')))]
                page.update(truncated=number < 2, next_after=row['cve'] if number < 2 else None)
                return page
        index = Pages()
        result = audit_catalog(dict(schema_version=1), inventory(), index)['catalog_audit']
        self.assertEqual(index.calls, [None, 'CVE-2026-1000', 'CVE-2026-1001'])
        self.assertEqual([result['summary'][k] for k in ('true_pairs','unknown_pairs','not_matched_pairs')], [1,1,1])
        for field, cap in [('MAX_PAIRS',1), ('MAX_RECORDS',1), ('MAX_RESULTS',1), ('MAX_PREDICATES',2)]:
            with patch.object(module, field, cap):
                result = audit_catalog(dict(schema_version=1), inventory(), Pages())['catalog_audit']
            self.assertEqual(result['status'], 'partial')
            self.assertIsNone(result['summary']['unexamined_pairs'])
            self.assertEqual(result['summary']['evaluated_pairs'], sum(result['summary'][k] for k in ('true_pairs','unknown_pairs','not_matched_pairs')))

    def test_real_index_broad_byte_pages_and_cross_asset_environment(self):
        from unittest.mock import patch
        from wifiscope.catalog_store import CatalogIndex, build_catalog
        from tests.test_catalog_store import cve
        from tests.test_applicability import component
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            rows = [cve('CVE-2026-'+str(2000+i), vendor='*', product='app') for i in range(5)]
            for row in rows:
                row['configurations'][0]['nodes'][0]['cpeMatch'][0].pop('versionEndExcluding')
            feed = root/'feed.json'
            feed.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=7,
                startIndex=0, resultsPerPage=7, vulnerabilities=[dict(cve=r) for r in rows]+[
                    dict(cve=dict(id='CVE-2026-9000', vulnStatus='Rejected')),
                    dict(cve=dict(id='CVE-2026-9001', vulnStatus='Analyzed'))])), encoding='utf8')
            build_catalog([feed], root/'catalog.db')
            with CatalogIndex(root/'catalog.db') as index:
                with patch('wifiscope.catalog_store.MAX_RELEVANT_BYTES', 1800):
                    result = audit_catalog(dict(schema_version=1), inventory(), index)['catalog_audit']
                self.assertEqual(result['summary']['true_pairs'], 5)
                self.assertEqual(result['catalog']['rejected_records'], 1)
                self.assertEqual(result['catalog']['without_applicability'], 2)
                self.assertEqual(result['status'], 'complete')
                with patch('wifiscope.catalog_store.MAX_IDENTITY_ROWS', 2):
                    limited = audit_catalog(dict(schema_version=1), inventory(), index)['catalog_audit']
                self.assertEqual(limited['status'], 'partial')
            inv = inventory()
            inv['assets'].append(dict(id='other-asset', components=[dict(id='os',
                cpe=cpe(part='o', vendor='linux', product='kernel', version='6'))]))
            class Environment(Index):
                def relevant(self, identities, **kwargs):
                    page = super().relevant(identities, **kwargs)
                    page['records'][0]['configurations'] = [node(leaf(), leaf(cpe(part='o', vendor='linux', product='kernel', version='*'), False), operator='AND')]
                    return page
            result = audit_catalog(dict(schema_version=1), inv, Environment())['catalog_audit']
            self.assertEqual(result['summary']['true_pairs'], 0)
            self.assertEqual(result['summary']['unknown_pairs'], 2)
            self.assertEqual({r['asset_id'] for r in result['results']}, {'private-asset', 'other-asset'})
            self.assertEqual(len(component()['cpe'].split(':')), 13)

    def test_progress_fresh_monotonic_throttled_and_mid_predicate_cancel(self):
        from unittest.mock import patch
        import wifiscope.catalog_audit as module
        ticks = iter([n/100 for n in range(100)])
        events = []
        report, inv = dict(schema_version=1), inventory()
        before = copy.deepcopy((report, inv))
        with patch.object(module.time, 'monotonic', side_effect=lambda: next(ticks)):
            audit_catalog(report, inv, Index(), progress=lambda e: events.append(e))
        self.assertEqual(len(events), 2)  # first + final even under 0.2s
        self.assertIsNot(events[0], events[1])
        for key in ('evaluated_pairs','retained_results','predicates','relevant_records','identity_queries'):
            self.assertLessEqual(events[0][key], events[1][key])
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls > 10
        result = audit_catalog(report, inv, Index(), cancel=cancel)['catalog_audit']
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual((report, inv), before)
        def broken():
            raise RuntimeError('PRIVATE_SENTINEL')
        with self.assertRaisesRegex(ValueError, 'callback') as caught:
            audit_catalog(report, inv, Index(), cancel=broken)
        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_public_cve_allowlist_refuses_twenty_digits_and_unicode(self):
        raw = dict(schema_version=1, findings=[dict(code='catalog-modeled-match', evidence=dict(cves=[
            'CVE-2026-1234567890123456789', 'CVE-2026-12345678901234567890', 'CVE-２０２６-1234']))])
        self.assertEqual(prepare_export(raw)['findings'][0]['evidence']['cves'], ['CVE-2026-1234567890123456789'])

    def test_snapshot_size_limit_retains_partial_without_false_counts(self):
        import wifiscope.catalog_audit as module
        from unittest.mock import patch
        with patch.object(module, 'MAX_RESULT_BYTES', 1):
            result = audit_catalog(dict(schema_version=1), inventory(), Index())['catalog_audit']
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['summary']['evaluated_pairs'], 0)
        self.assertEqual(result['results'], [])

    def test_legacy_extensions_coexist_and_partial_inventory_disclosed(self):
        from wifiscope.vulnerabilities import audit_vulnerabilities
        from wifiscope.demo import demo_report
        from tests.test_heatmap import survey
        from tests.test_live_capture import LiveTests
        report = LiveTests().capture()
        report['wifi_survey'] = survey([(0,0,42)])
        report = audit_vulnerabilities(report)
        result = audit_catalog(report, inventory(), Index())
        for key in ('capture_session','wifi_survey','vulnerability_audit'):
            self.assertEqual(result[key], report[key])
        validate_report(prepare_export(result))
        # Re-auditing replaces only the catalog extension and yields the same IDs.
        repeated = audit_catalog(result, inventory(), Index())
        self.assertEqual([r['id'] for r in result['catalog_audit']['results']], [r['id'] for r in repeated['catalog_audit']['results']])
        self.assertEqual(len(result['investigation']['findings']),len(repeated['investigation']['findings']))
        report = demo_report()
        report['assets'] = [dict(address='192.0.2.1',services=[])]
        inv = inventory()
        inv['assets'][0]['address'] = '192.0.2.1'
        result = audit_catalog(report, inv, Index())
        same_address = [a for a in result['investigation']['assets'] if a['address']=='192.0.2.1']
        self.assertEqual(len(same_address), 2)
        self.assertNotEqual(same_address[0]['id'],same_address[1]['id'])

    def test_inventory_and_collected_asset_id_collision_refused(self):
        report = build_investigation(dict(schema_version=1, assets=[dict(address='192.0.2.7', services=[])]))
        inv = inventory()
        inv['assets'][0]['id'] = report['investigation']['assets'][0]['id']
        with self.assertRaisesRegex(ValueError, 'conflict'):
            audit_catalog(report, inv, Index())

    def test_malicious_types_across_every_extension_field_are_controlled(self):
        extension = audit_catalog(dict(schema_version=1), inventory(), Index())['catalog_audit']
        paths = []
        def gather(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    paths.append(path+(key,))
                    gather(child,path+(key,))
            elif isinstance(value,list):
                for i, child in enumerate(value):
                    gather(child,path+(i,))
        gather(extension)
        for path in paths:
            mutated = copy.deepcopy(extension)
            parent = mutated
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = {'PRIVATE_SENTINEL': []}
            with self.subTest(path=path), self.assertRaises(ValueError) as caught:
                validate_catalog_audit(mutated)
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))

    def test_cli_partial_and_cancel_exit_codes_and_final_callback_failure(self):
        import contextlib
        import io
        from unittest.mock import patch
        from wifiscope.cli import main
        class Context(Index):
            def __enter__(self):
                return self
            def __exit__(self,*args):
                pass
            def relevant(self,*args,**kwargs):
                raise KeyboardInterrupt
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'inventory.json'
            path.write_text(json.dumps(inventory()),encoding='utf8')
            stream = io.StringIO()
            with patch('wifiscope.catalog_cli.CatalogIndex', return_value=Context()), contextlib.redirect_stdout(stream):
                self.assertEqual(main(['catalog','audit','--db','unused-local.db','--inventory',str(path)]),130)
            self.assertEqual(json.loads(stream.getvalue())['catalog_audit']['status'],'cancelled')
        def callback(event):
            if event['status'] == 'complete':
                raise RuntimeError('PRIVATE_SENTINEL')
        with self.assertRaisesRegex(ValueError,'callback'):
            audit_catalog(dict(schema_version=1), inventory(), Index(),progress=callback)
        class Partial(Index):
            def info(self):
                value = super().info()
                value['feeds'][0]['partial'] = True
                return value
        result = audit_catalog(dict(schema_version=1),inventory(),Partial())['catalog_audit']
        self.assertEqual(result['status'],'partial')
        self.assertIn('catalog-input-partial',result['gaps'])

    def test_retained_legacy_cna_cpes_do_not_abort_audit_or_independent_model(self):
        for unsupported in (False,True):
            for nvd in (False,True):
                class Legacy(Index):
                    def relevant(self,*args,**kwargs):
                        page = super().relevant(*args,**kwargs)
                        row = page['records'][0]
                        row['affected'] = [dict(affectedData=[dict(vendor='acme',product='app',defaultStatus='affected',
                            versions=[],context={},cpes=['cpe:/a:acme:app:1'],unsupported=unsupported)])]
                        if not nvd:
                            row['configurations'] = []
                        return page
                with self.subTest(unsupported=unsupported,nvd=nvd):
                    report,inv = dict(schema_version=1),inventory()
                    before = copy.deepcopy((report,inv))
                    result = audit_catalog(report,inv,Legacy())
                    audit = result['catalog_audit']
                    self.assertEqual(audit['status'],'complete')
                    self.assertEqual(audit['results'][0]['applicability'],'true' if nvd else 'unknown')
                    self.assertEqual(audit['summary']['true_pairs' if nvd else 'unknown_pairs'],1)
                    validate_report(prepare_export(result))
                    self.assertEqual((report,inv),before)

    def test_work_limited_no_continuation(self):
        class Limited(Index):
            def relevant(self, *args, **kwargs):
                result = super().relevant(*args, **kwargs)
                result.update(work_limited=True, truncated=True, next_after=None)
                return result
        result = audit_catalog(dict(schema_version=1), inventory(), Limited())['catalog_audit']
        self.assertEqual(result['status'], 'partial')
        self.assertIsNone(result['summary']['unexamined_pairs'])
        self.assertEqual(result['summary']['evaluated_pairs'], 1)


if __name__ == '__main__':
    unittest.main()
