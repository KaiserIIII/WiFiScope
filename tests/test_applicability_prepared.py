"""Prepared matching uses real parsers and synthetic, bounded local evidence."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
import weakref
from unittest.mock import patch

from wifiscope import applicability as app
from wifiscope import catalog_audit as audit
from wifiscope.catalog_store import CatalogIndex, build_catalog
from tests.test_applicability import asset, component, cpe, leaf, node, record


def cna_row(**overrides):
    row = dict(vendor='acme', product='app', cpes=[cpe(version='*')],
               context={}, unsupported=False, defaultStatus='unaffected',
               versions=[dict(version='1.2', status='affected', changes=[], unsupported=False)])
    row.update(overrides)
    return row


def possible_component(identifier='possible', **values):
    row = dict(id=identifier, cpe=cpe(version='9'), source='nmap', identification='imported',
               version_scheme='numeric', observed_at='2026-10-01T00:00:00Z', source_sha256='a' * 64,
               scanner=dict(origin='service', method='table', confidence=9, accuracy=None,
                   protocol='tcp', port=80, state='open', host_status='up', host_ordinal=0,
                   entry_ordinal=0, cpe_ordinal=0, binding='formatted', timestamp_origin='host-end',
                   metadata_valid=True, presence='possible'))
    row.update(values)
    return row


@contextmanager
def tiny_catalog():
    inv = dict(schema_version=1, assets=[
        dict(id='first', components=[dict(id='declared', cpe=cpe(), version_scheme='numeric',
             source='sbom', identification='imported', observed_at='2026-10-01T00:00:00Z'),
             dict(id='native', vendor='acme', product='app', version='1.2', source='native')]),
        dict(id='second', components=[possible_component(),
             dict(id='native-new', vendor='acme', product='app', version='9', source='native')])])
    records = [dict(id=f'CVE-2026-{1000+i}', vulnStatus='Analyzed', configurations=[dict(
        operator='OR', cpeMatch=[dict(criteria=cpe(version='9' if i == 1 else '*'), vulnerable=True,
                                    **({'versionEndExcluding': '2'} if i == 2 else {}))])]) for i in range(3)]
    records[0]['affected'] = [dict(affectedData=[dict(vendor='acme', product='app',
        cpes=[cpe(version='*')], defaultStatus='unaffected', versions=[dict(version='1.2', status='affected')])])]
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        source, database = root/'source.json', root/'catalog.db'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=3,
            startIndex=0, resultsPerPage=3, vulnerabilities=[dict(cve=r) for r in records])), encoding='utf8')
        build_catalog([source], database)
        before = (source.read_bytes(), database.read_bytes())
        with CatalogIndex(database) as index:
            yield index, inv
        if (source.read_bytes(), database.read_bytes()) != before:
            raise AssertionError('Catalog matching mutated source or SQLite bytes')


class PreparedTests(unittest.TestCase):
    def test_repeated_leaves_reuse_real_parsed_evidence_and_preserve_mixed_result(self):
        observed = asset(component(), dict(id='native', vendor='acme', product='app', version='1.2'))
        rec = record(node(*(leaf() for _ in range(12))),
                     affected=[dict(affectedData=[cna_row()])])
        before = json.dumps([rec, observed], sort_keys=True).encode()
        with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
            result = app.evaluate_cve(rec, observed)
        self.assertEqual(result, dict(applicability='true', component_ids=['component-a', 'native'],
                                      model='mixed', reasons=[]))
        self.assertEqual(json.dumps([rec, observed], sort_keys=True).encode(), before)
        # At most one transient class parse plus one lazy evidence parse, never
        # twelve component parses for the twelve leaves (or a further CNA parse).
        self.assertLessEqual(sum(call.args == (cpe(),) for call in parser.call_args_list), 2)

    def test_owned_snapshot_and_reject_raw_context(self):
        self.assertTrue(hasattr(app, '_prepare_asset'), 'missing private prepared factory')
        observed = asset(component(version_scheme='numeric'))
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        observed['components'][0]['cpe'] = cpe(version='9')
        observed['components'][0]['version_scheme'] = 'unknown'
        observed['complete_parts'].append('o')
        rec = record(node(leaf(versionEndExcluding='2')))
        self.assertEqual(app._evaluate_prepared(rec, prepared, budget=app.MatchBudget())['applicability'], 'true')
        self.assertEqual(app.evaluate_cve(rec, observed)['applicability'], 'unknown')
        for forged in (observed, {'asset': observed, 'validated': True}, None):
            with self.assertRaises(ValueError):
                app._evaluate_prepared(rec, forged, budget=app.MatchBudget())

    def test_entry_capacity_evicts_without_losing_matching_components(self):
        self.assertTrue(hasattr(app, '_prepare_asset'), 'missing private prepared factory')
        observed = asset(*(component(f'c{i}') for i in range(257)))
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        budget = app.MatchBudget()
        for i in range(256):
            prepared._evidence(f'c{i}', budget)
        self.assertEqual(len(prepared._cache), 256)
        prepared._evidence('c256', budget)
        self.assertEqual(len(prepared._cache), 256)
        with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
            prepared._evidence('c0', budget)
        self.assertEqual(parser.call_count, 1)  # evicted evidence is recomputed
        result = app._evaluate_prepared(record(node(leaf())), prepared, budget=budget)
        self.assertEqual(result['applicability'], 'true')
        self.assertEqual(result['component_ids'], sorted(f'c{i}' for i in range(257)))

    def test_exact_and_one_over_token_capacity_with_real_names(self):
        self.assertTrue(hasattr(app, '_prepare_asset'), 'missing private prepared factory')
        # 1 part + 4 vendor + 3 product + 1009 version + 7 ANY = 1024 tokens.
        for extra, retained in ((0, 128), (1, 127)):
            with self.subTest(extra=extra):
                observed = asset(*(dict(id=f'c{i}', cpe=cpe(version='v' * (1009 + (extra if i == 127 else 0))))
                                   for i in range(128)))
                prepared = app._prepare_asset(observed, budget=app.MatchBudget())
                budget = app.MatchBudget()
                for i in range(128):
                    prepared._evidence(f'c{i}', budget)
                self.assertEqual(len(prepared._cache), retained)
                self.assertEqual(prepared._cache_tokens, 131072 if not extra else 130049)
                self.assertLessEqual(prepared._cache_tokens, 131072)
                result = app._evaluate_prepared(record(node(leaf())), prepared, budget=budget)
                self.assertEqual(result['applicability'], 'true')
                self.assertEqual(len(result['component_ids']), 128)

    def test_large_name_bypass_still_matches_and_charges_each_miss(self):
        self.assertTrue(hasattr(app, '_prepare_asset'), 'missing private prepared factory')
        huge = cpe(vendor='v' * 1024, product='p' * 1024, version='1' * 1024, update='u' * 980)
        observed = asset(dict(id='large', cpe=huge))
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        rec = record(node(leaf(cpe(vendor='v' * 1024, product='p' * 1024, version='*'))))
        with patch.object(app, '_MAX_PREPARED_TOKENS', 128):
            budget = app.MatchBudget()
            with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
                for _ in range(2):
                    result = app._evaluate_prepared(rec, prepared, budget=budget)
                    self.assertEqual(result['applicability'], 'true')
                    self.assertEqual(result['component_ids'], ['large'])
            self.assertEqual(sum(call.args == (huge,) for call in parser.call_args_list), 2)
            self.assertEqual((len(prepared._cache), prepared._cache_tokens), (0, 0))
            self.assertGreater(budget.used, 2)

    def test_cna_criteria_streamed_once_for_multiple_targets_and_original_version(self):
        observed = asset(*(dict(id=f'c{i}', cpe=cpe(version='1.0.0-RC.1'), version_scheme='semver2')
                           for i in range(3)))
        rec = record(affected=[dict(affectedData=[cna_row(
            cpes=[cpe(version='*'), 'cpe:/a:acme:app:1'],
            versions=[dict(version='1.0.0-RC.1', status='affected', changes=[], unsupported=False)])])])
        before = copy.deepcopy((rec, observed))
        with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
            result = app.evaluate_cve(rec, observed)
        self.assertEqual(result, dict(applicability='true', component_ids=['c0', 'c1', 'c2'], model='cna', reasons=[]))
        self.assertEqual((rec, observed), before)
        self.assertEqual(sum(call.args == (cpe(version='*'),) for call in parser.call_args_list), 1)

    def test_source_without_cpe_target_preserves_rich_validation_boundary(self):
        observed = asset(dict(id='native', vendor='acme', product='app', version='1.2'))
        rich_overflow = cpe(version='\ufb03' * 1024)
        for rec in (record(node(leaf(rich_overflow))),
                    record(affected=[dict(affectedData=[cna_row(cpes=[rich_overflow])])])):
            result = app.evaluate_cve(rec, observed)
            self.assertEqual(result['applicability'], 'true' if rec['affected'] else 'unknown')
        with self.assertRaisesRegex(ValueError, 'typed CPE'):
            app.evaluate_cve(record(node(leaf(rich_overflow))), asset())

    def test_possible_view_is_cached_separately_and_source_metadata_is_owned(self):
        observed = asset(possible_component())
        before = copy.deepcopy(observed)
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        rec = record(node(leaf(cpe(version='1.2'))))
        for _ in range(2):
            self.assertEqual(app._evaluate_prepared(rec, prepared, budget=app.MatchBudget()),
                dict(applicability='unknown', component_ids=['possible'], model='cpe', reasons=['applicability-unknown']))
        original, evaluated = prepared._evidence('possible', app.MatchBudget())
        self.assertEqual(original.field('version').original_text, '9')
        self.assertEqual([a.kind for a in evaluated.attributes[3:]], ['any'] * 8)
        self.assertEqual(prepared._cache_tokens, 32)  # distinct 16-token names
        self.assertEqual(observed, before)
        observed['components'][0]['scanner']['presence'] = 'asserted'
        observed['components'][0]['cpe'] = cpe(version='1.2')
        self.assertEqual(app._evaluate_prepared(rec, prepared, budget=app.MatchBudget())['applicability'], 'unknown')

    def test_prepare_hit_miss_eviction_and_matching_honor_work_and_callbacks(self):
        observed = asset(component('first'), component('second'))
        before = copy.deepcopy(observed)
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        prepared._evidence('first', app.MatchBudget())
        operations = [lambda b: app._prepare_asset(observed, budget=b),
                      lambda b: prepared._evidence('first', b),
                      lambda b: prepared._evidence('second', b),
                      lambda b: app._evaluate_prepared(record(node(leaf())), prepared, budget=b)]
        for operation in operations:
            for stop in (1, 2):
                for broken in (False, True):
                    # Hits have one charge; only other operations reach charge 2.
                    if operation is operations[1] and stop == 2:
                        continue
                    calls = 0
                    def cancel():
                        nonlocal calls
                        calls += 1
                        if calls == stop:
                            if broken:
                                raise RuntimeError('PRIVATE_SENTINEL')
                            return True
                        return False
                    with self.subTest(operation=operations.index(operation), stop=stop, broken=broken):
                        with self.assertRaises(ValueError if broken else InterruptedError) as caught:
                            operation(app.MatchBudget(cancel=cancel))
                        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        with self.assertRaises(app.WorkLimit):
            app._prepare_asset(observed, budget=app.MatchBudget(1))
        with self.assertRaises(app.WorkLimit):
            prepared._evidence('second', app.MatchBudget(1))
        # Cancellation at eviction must not lose a valid cached first entry.
        with patch.object(app, '_MAX_PREPARED_ENTRIES', 1):
            budget = app.MatchBudget(2)
            with self.assertRaises(app.WorkLimit):
                prepared._evidence('second', budget)
        with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
            prepared._evidence('first', app.MatchBudget())
        self.assertEqual(parser.call_count, 0)
        self.assertEqual(observed, before)

    def test_semantic_controls_on_reused_context(self):
        observed = asset(component(version_scheme='numeric'),
                         dict(id='native', vendor='acme', product='app', version='1.2'))
        prepared = app._prepare_asset(observed, budget=app.MatchBudget())
        cases = [
            (record(node(leaf(cpe(vendor='ACME', product='APP', version='9')))), 'false', [], 'cpe', []),
            (record(node(leaf(cpe(product='other')))), 'unknown', [], 'cpe', ['applicability-unknown']),
            (record(node(leaf(vulnerable=False))), 'unknown', [], 'cpe', ['applicability-unknown', 'positive-witness-missing']),
            (record(node(leaf(cpe(version='9')), negate=True)), 'unknown', [], 'cpe', ['applicability-unknown', 'positive-witness-missing']),
            (record(node(leaf()), affected=[dict(affectedData=[cna_row(versions=[], defaultStatus='unaffected')])]),
             'unknown', ['component-a', 'native'], 'mixed', ['applicability-unknown', 'model-conflict']),
            (record(affected=[dict(affectedData=[cna_row(context={'platforms': ['linux']})])]),
             'unknown', ['component-a', 'native'], 'cna', ['applicability-unknown'])]
        for rec, value, ids, model, reasons in cases:
            with self.subTest(value=value, model=model, reasons=reasons):
                self.assertEqual(app._evaluate_prepared(rec, prepared, budget=app.MatchBudget()),
                    dict(applicability=value, component_ids=ids, model=model, reasons=reasons))

    def test_cna_stream_retains_no_growing_rich_criteria_list(self):
        observed = asset(component('old'), dict(id='new', cpe=cpe(version='2')))
        criteria = [cpe(version='*', other='x' * 1000 + str(i)) for i in range(24)]
        rec = record(affected=[dict(affectedData=[cna_row(cpes=criteria)])])
        live, high_water = [], 0
        real_parse = app.parse_cpe
        def parse(value):
            nonlocal high_water
            name = real_parse(value)
            if value in criteria:
                live.append(weakref.ref(name))
                high_water = max(high_water, sum(ref() is not None for ref in live))
            return name
        with patch.object(app, 'parse_cpe', side_effect=parse):
            result = app.evaluate_cve(rec, observed)
        self.assertEqual(result, dict(applicability='unknown', component_ids=['new', 'old'],
                                     model='cna', reasons=['applicability-unknown']))
        # During assignment the previous and next criterion can coexist, but
        # the row must never accumulate all 24 rich parsed names.
        self.assertLessEqual(high_water, 2)
        self.assertEqual(sum(ref() is not None for ref in live), 0)

    def test_validation_checks_original_other_field_before_class_false_or_abstraction(self):
        for candidate in (dict(id='raw', cpe=cpe(vendor='other', other='\ufb03' * 1024)),
                          possible_component(cpe=cpe(vendor='other', other='\ufb03' * 1024))):
            with self.subTest(possible='scanner' in candidate):
                with self.assertRaisesRegex(ValueError, 'typed CPE'):
                    app.evaluate_cve(record(node(leaf())), asset(candidate))

    def test_unused_rich_overflow_evidence_preserves_unknown_and_native_cna(self):
        overflow = cpe(version=chr(0x0390) * 1024)
        observed = asset(dict(id='unused', cpe=overflow),
                         dict(id='native', vendor='acme', product='app', version='1.2'))
        before = copy.deepcopy(observed)
        cases = [
            (record(), dict(applicability='unknown', component_ids=[], model='unknown',
                            reasons=['applicability-unknown'])),
            (record(affected=[dict(affectedData=[cna_row(cpes=[], defaultStatus='unknown', versions=[])])]),
             dict(applicability='unknown', component_ids=['native'], model='cna', reasons=['applicability-unknown'])),
            (record(affected=[dict(affectedData=[cna_row(cpes=[])])]),
             dict(applicability='true', component_ids=['native'], model='cna', reasons=[]))]
        for rec, expected in cases:
            with self.subTest(model=expected['model'], value=expected['applicability']):
                try:
                    result = app.evaluate_cve(rec, observed)
                except ValueError as exc:
                    self.fail(f'Unused parse-valid evidence was refused: {exc}')
                self.assertEqual(result, expected)
        self.assertEqual(observed, before)
        # The same original is still invalid once a real CPE comparison uses it.
        for rec in (record(node(leaf())), record(affected=[dict(affectedData=[cna_row()])])):
            with self.assertRaisesRegex(ValueError, 'typed CPE'):
                app.evaluate_cve(rec, observed)

    def test_unparseable_cna_identity_preserves_unknown_without_unused_rich_evidence(self):
        for possible in (False, True):
            candidate = dict(id='overflow', cpe=cpe(version=chr(0x0390) * 1024))
            if possible:
                candidate = possible_component(**candidate)
            observed = asset(candidate)
            prepared = app._prepare_asset(observed, budget=app.MatchBudget())
            for criteria in (['cpe:/a:acme:app:1'], ['malformed', 'cpe:2.3:bad']):
                rec = record(affected=[dict(affectedData=[cna_row(cpes=criteria, versions=[])])])
                before = json.dumps([rec, observed], sort_keys=True).encode()
                for reused in (False, True, True):
                    with self.subTest(possible=possible, criteria=criteria, reused=reused):
                        try:
                            result = (app._evaluate_prepared(rec, prepared, budget=app.MatchBudget())
                                      if reused else app.evaluate_cve(rec, observed))
                        except ValueError as exc:
                            self.fail(f'Unknown CNA identity requested unused rich evidence: {exc}')
                        self.assertEqual(result, dict(applicability='unknown', component_ids=['overflow'],
                            model='cna', reasons=['applicability-unknown']))
                self.assertEqual(json.dumps([rec, observed], sort_keys=True).encode(), before)

    def test_mixed_cna_criteria_validate_original_before_unknown_or_possible_abstraction(self):
        for possible in (False, True):
            candidate = dict(id='overflow', cpe=cpe(vendor='other', other=chr(0x0390) * 1024))
            if possible:
                candidate = possible_component(**candidate)
            observed = asset(candidate)
            prepared = app._prepare_asset(observed, budget=app.MatchBudget())
            for criteria in ([cpe(version='*'), 'cpe:/a:acme:app:1'],
                             ['malformed', cpe(version='*')]):
                rec = record(affected=[dict(affectedData=[cna_row(cpes=criteria)])])
                before = json.dumps([rec, observed], sort_keys=True).encode()
                for reused in (False, True):
                    with self.subTest(possible=possible, criteria=criteria, reused=reused):
                        with self.assertRaisesRegex(ValueError, 'typed CPE'):
                            if reused:
                                app._evaluate_prepared(rec, prepared, budget=app.MatchBudget())
                            else:
                                app.evaluate_cve(rec, observed)
                self.assertEqual(json.dumps([rec, observed], sort_keys=True).encode(), before)

    def test_matching_loop_hit_miss_eviction_and_pattern_callbacks_propagate(self):
        observed = asset(component('first'), component('second'))
        rec = record(node(leaf(cpe(product='*app*'))))
        for warm, stop in ((False, 3), (False, 6), (True, 5), (True, 10)):
            for broken in (False, True):
                prepared = app._prepare_asset(observed, budget=app.MatchBudget())
                if warm:
                    prepared._evidence('first', app.MatchBudget())
                calls = 0
                def cancel():
                    nonlocal calls
                    calls += 1
                    if calls == stop:
                        if broken:
                            raise OverflowError('PRIVATE_SENTINEL')
                        return True
                    return False
                with self.subTest(warm=warm, stop=stop, broken=broken):
                    with self.assertRaises(ValueError if broken else InterruptedError) as caught:
                        app._evaluate_prepared(rec, prepared, budget=app.MatchBudget(cancel=cancel))
                    self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        for broken in (False, True):
            prepared = app._prepare_asset(observed, budget=app.MatchBudget())
            prepared._evidence('first', app.MatchBudget())
            calls = 0
            def at_eviction():
                nonlocal calls
                calls += 1
                if calls == 3:
                    if broken:
                        raise RuntimeError('PRIVATE_SENTINEL')
                    return True
                return False
            with patch.object(app, '_MAX_PREPARED_ENTRIES', 1):
                with self.assertRaises(ValueError if broken else InterruptedError):
                    prepared._evidence('second', app.MatchBudget(cancel=at_eviction))
            self.assertEqual(list(prepared._cache), ['first'])


class PreparedAuditTests(unittest.TestCase):
    def test_tiny_real_catalog_reuses_one_context_per_asset(self):
        with tiny_catalog() as (index, inv):
            before = copy.deepcopy(inv)
            with patch.object(app, 'parse_cpe', wraps=app.parse_cpe) as parser:
                result = audit.audit_catalog(dict(schema_version=1, synthetic=True), inv, index)
            summary = result['catalog_audit']['summary']
            self.assertEqual([summary[k] for k in ('assets', 'components', 'relevant_records',
                'evaluated_pairs', 'true_pairs', 'unknown_pairs', 'not_matched_pairs', 'retained_results')],
                [2, 4, 3, 6, 2, 3, 1, 5])
            self.assertEqual(inv, before)
            # Three catalog rows must share the declared component's rich parse.
            self.assertLessEqual(sum(call.args == (cpe(),) for call in parser.call_args_list), 2)

    def test_factory_failure_is_inside_audit_partial_boundary_before_queries(self):
        with tiny_catalog() as (index, inv), patch.object(audit, 'MAX_PREDICATES', 1):
            result = audit.audit_catalog(dict(schema_version=1), inv, index)['catalog_audit']
        self.assertEqual(result['status'], 'partial')
        self.assertIsNone(result['summary']['unexamined_pairs'])
        self.assertEqual(result['summary']['evaluated_pairs'], 0)
        self.assertEqual(result['summary']['relevant_records'], 0)
        self.assertEqual(result['summary']['identity_queries'], 0)
        self.assertEqual(result['results'], [])

    def test_direct_expected_outcomes_projection_and_case_joins(self):
        from wifiscope.cases import CaseStore
        from wifiscope.case_validation import validate_report
        from wifiscope.reports import prepare_export
        from wifiscope.investigate import build_investigation
        with tiny_catalog() as (index, inv):
            expected = [('true', ['declared', 'native'], 'mixed'), ('false', [], 'cpe'),
                        ('true', ['declared'], 'cpe'), ('unknown', ['native-new', 'possible'], 'mixed'),
                        ('unknown', ['possible'], 'cpe'), ('unknown', ['possible'], 'cpe')]
            direct = []
            for observed in inv['assets']:
                for i in range(3):
                    value = app.evaluate_cve(index.get(f'CVE-2026-{1000+i}'), observed)
                    direct.append((value['applicability'], value['component_ids'], value['model']))
            self.assertEqual(direct, expected)
            result = audit.audit_catalog(dict(schema_version=1, synthetic=True), inv, index)
            rows = result['catalog_audit']['results']
            self.assertEqual([(r['applicability'], r['component_ids'], r['model']) for r in rows],
                             [value for value in expected if value[0] != 'false'])
            self.assertEqual(rows[0]['sources'], ['native', 'sbom'])
            self.assertEqual(rows[0]['observed_at'], ['2026-10-01T00:00:00Z'])
            self.assertEqual(rows[-1]['sources'], ['nmap'])
            self.assertEqual(result['catalog_audit']['inventory']['assets'][1]['components'][0]['scanner'],
                             inv['assets'][1]['components'][0]['scanner'])
            self.assertEqual(build_investigation(result), result)
            for include in (True, False):
                exported = prepare_export(result, include)
                validate_report(exported)
                for row in exported['catalog_audit']['results']:
                    finding = next(f for f in exported['investigation']['findings'] if f['id'] == row['id'])
                    self.assertEqual(finding['evidence']['asset_id'], row['asset_id'])
                    inventory_ids = {c['id'] for a in exported['catalog_audit']['inventory']['assets']
                                     if a['id'] == row['asset_id'] for c in a['components']}
                    self.assertTrue(set(row['component_ids']) <= inventory_ids)
            with tempfile.TemporaryDirectory() as root, CaseStore(Path(root)/'case.db') as case:
                snapshot = case.add_snapshot(result, include_identifiers=True)
                self.assertEqual(case.load_snapshot(snapshot)['catalog_audit'], result['catalog_audit'])
                case.triage(rows[0]['id'], 'investigating', snapshot_id=snapshot)
                self.assertEqual(case.triage_state(snapshot_id=snapshot)[rows[0]['id']]['status'], 'investigating')
                self.assertTrue(case.verify()['ok'])

    def test_cancel_preparation_and_inflight_second_pair_are_honest(self):
        with tiny_catalog() as (index, inv):
            original = copy.deepcopy(inv)
            for during_prepare, expected_pairs in ((True, 0), (False, 1)):
                for broken in (False, True):
                    phase, pairs = None, 0
                    real_prepare, real_evaluate = audit._prepare_asset, audit._evaluate_prepared
                    def prepare(value, *, budget):
                        nonlocal phase
                        phase = 'prepare'
                        result = real_prepare(value, budget=budget)
                        phase = None
                        return result
                    def evaluate(value, prepared, *, budget):
                        nonlocal phase, pairs
                        pairs += 1
                        phase = 'second' if pairs == 2 else None
                        result = real_evaluate(value, prepared, budget=budget)
                        phase = None
                        return result
                    def cancel():
                        if phase == ('prepare' if during_prepare else 'second'):
                            if broken:
                                raise RuntimeError('PRIVATE_SENTINEL')
                            return True
                        return False
                    with patch.object(audit, '_prepare_asset', side_effect=prepare), \
                            patch.object(audit, '_evaluate_prepared', side_effect=evaluate):
                        if broken:
                            with self.assertRaisesRegex(ValueError, 'callback') as caught:
                                audit.audit_catalog(dict(schema_version=1), inv, index, cancel=cancel)
                            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
                        else:
                            result = audit.audit_catalog(dict(schema_version=1), inv, index, cancel=cancel)['catalog_audit']
                            self.assertEqual(result['status'], 'cancelled')
                            self.assertIsNone(result['summary']['unexamined_pairs'])
                            self.assertEqual(result['summary']['evaluated_pairs'], expected_pairs)
                            self.assertEqual(len(result['results']), expected_pairs)
            self.assertEqual(inv, original)

    def test_new_audit_does_not_reuse_previous_scheme_or_evidence(self):
        with tiny_catalog() as (index, inv):
            before = audit.audit_catalog(dict(schema_version=1), inv, index)['catalog_audit']
            inv['assets'][0]['components'][0]['version_scheme'] = 'unknown'
            after = audit.audit_catalog(dict(schema_version=1), inv, index)['catalog_audit']
            first = next(r for r in before['results'] if r['asset_id'] == 'first' and r['cve'] == 'CVE-2026-1002')
            second = next(r for r in after['results'] if r['asset_id'] == 'first' and r['cve'] == 'CVE-2026-1002')
            self.assertEqual((first['applicability'], second['applicability']), ('true', 'unknown'))
            self.assertNotEqual(first['id'], second['id'])
            self.assertEqual(first['component_ids'], second['component_ids'])


if __name__ == '__main__':
    unittest.main()
