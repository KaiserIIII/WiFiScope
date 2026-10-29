"""Actual catalog buttons and shared queue, using invented local data only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch

from wifiscope.gui import Workstation
from wifiscope.gui_controller import Controller


def feed(count=25):
    return dict(format='NVD_CVE', version='2.0', totalResults=count, startIndex=0, resultsPerPage=count, vulnerabilities=[
        dict(cve=dict(id=f'CVE-2026-{10000+i}', vulnStatus='Analyzed',
            configurations=[dict(nodes=[dict(operator='OR', cpeMatch=[dict(vulnerable=True,
                criteria='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*')])])],
            affected=[dict(affectedData=[dict(vendor='Other Vendor', product='CNA model', versions=[dict(version='4.0.0', status='affected')])])]
            if i == 0 else [])) for i in range(count)])


class CatalogProgressTests(unittest.TestCase):
    def test_detail_identity_choices_omit_strict_parser_mismatch_keep_other_literals(self):
        import copy
        from wifiscope.catalog_records import normalize, parse_cpe23
        from wifiscope.catalog_view import identity_choices
        mismatch = 'cpe:2.3:a:acme:widget:' + 'v'*1025 + ':*:*:*:*:*:*:*'
        self.assertIsNotNone(parse_cpe23(mismatch))
        raw = feed(1)['vulnerabilities'][0]['cve']
        raw['configurations'][0]['nodes'][0]['cpeMatch'].extend([
            dict(vulnerable=True, criteria=mismatch),
            dict(vulnerable=True, criteria='malformed-retained-cpe')])
        normalized, _ = normalize(raw)
        before = copy.deepcopy(normalized)
        self.assertEqual(identity_choices(normalized), [
            dict(part='a', vendor='acme', product='widget', kind='cpe'),
            dict(kind='cna', vendor='Other Vendor', product='CNA model')])
        self.assertEqual(normalized, before)

    def test_manual_remove_then_append_keeps_distinct_component_ids(self):
        from wifiscope.catalog_view import manual_inventory
        identity = dict(kind='cna', vendor='Local vendor', product='Declared product')
        value = manual_inventory(None, 'Laptop', identity, '1.0.0', 'unknown')
        value = manual_inventory(value, 'Laptop', identity, '1.0.0', 'unknown')
        value['assets'][0]['components'].pop(0)
        value = manual_inventory(value, 'Laptop', identity, '1.0.0', 'unknown')
        self.assertEqual(len({c['id'] for c in value['assets'][0]['components']}), 2)

    def test_typed_progress_separate_units_bounded_queue_and_regression(self):
        c = Controller()
        c.tool_owner = 'p'
        def work(cancel, progress):
            for i in range(10000):
                progress(dict(status='running', evaluated_pairs=i, retained_results=0,
                    predicates=i, relevant_records=i, identity_queries=i))
            progress(dict(status='complete', evaluated_pairs=9999, retained_results=0,
                predicates=9999, relevant_records=9999, identity_queries=9999))
            progress(dict(status='running', evaluated_pairs=0, retained_results=0,
                predicates=0, relevant_records=0, identity_queries=0))
            return {'metadata': True}
        try:
            c.start_tool('audit', work, 'p', progress_kind='catalog-audit')
        except TypeError:
            self.fail('catalog audit typed progress is missing')
        c.worker.join(3)
        self.assertLessEqual(c.messages.qsize(), 3)
        c.poll()
        self.assertEqual(c.tool_progress['evaluated_pairs'], 9999)
        self.assertNotIn('packets', c.tool_progress)
        def invalid(cancel, progress):
            progress(dict(status='running', evaluated_pairs=0, retained_results=0,
                predicates=0, relevant_records=0, identity_queries=0, private='secret'))
        c.start_tool('invalid', invalid, 'p', progress_kind='catalog-audit')
        c.worker.join(3)
        c.poll()
        self.assertIsNotNone(c.tool_error)
        self.assertNotIn('secret', c.tool_error)

    def test_cancel_and_closed_owner_ignore_real_queued_catalog_result(self):
        c = Controller()
        c.tool_owner = 'closed'
        def work(cancel, progress):
            cancel.wait(2)
            progress(dict(status='cancelled', records=1, expanded_bytes=20, feed_index=0, elapsed_ms=1))
            return {'metadata': True}
        c.start_tool('build', work, 'closed', progress_kind='catalog-build')
        with self.assertRaises(Exception):
            c.start_tool('duplicate', work, 'closed', progress_kind='catalog-build')
        c.tool_owner = None
        c.cancel()
        c.worker.join(3)
        c.poll()
        self.assertFalse(c.busy)
        self.assertIsNone(c.tool_result)
        self.assertIsNone(c.tool_progress)


class CatalogTkTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.catalog_view'), 'dedicated catalog panel missing')
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest('Actual Tk display unavailable.')
        self.app = Workstation(self.root)
        self.addCleanup(self.app.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.source = self.folder / 'synthetic.json'
        self.source.write_text(json.dumps(feed()), encoding='utf-8')
        self.db = self.folder / 'catalog.sqlite'
        self.app.open_security_tools('catalog')
        self.tools = self.app.security_tools
        self.panel = self.tools.panels['catalog']
        self.root.update()

    def finish(self):
        worker = self.app.controller.worker
        if worker:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.app.pump()
        self.root.update()

    def build(self):
        self.panel.feed_paths = (str(self.source),)
        self.panel.db_path.set(str(self.db))
        self.panel.build_button.invoke()
        self.finish()
        self.assertIsNone(self.app.controller.tool_error)
        self.assertEqual(self.panel.catalog_info['records'], 25)

    def detail(self):
        self.panel.search_button.invoke()
        self.finish()
        self.panel.rows.selection_set(self.panel.rows.get_children()[0])
        self.panel.detail_button.invoke()
        self.finish()

    def test_open_switch_has_no_io_or_collection(self):
        self.tools.close()
        with (patch('wifiscope.catalog_view.CatalogIndex') as index,
              patch('wifiscope.catalog_view.build_catalog') as build,
              patch('wifiscope.catalog_view.import_inventory') as importer,
              patch('wifiscope.gui.collect_local') as collector):
            for mode in ('novice', 'professional'):
                self.app.set_mode(mode)
                self.app.open_security_tools('catalog')
                self.app.security_tools.show('capture')
                self.app.security_tools.show('catalog')
            index.assert_not_called()
            build.assert_not_called()
            importer.assert_not_called()
            collector.assert_not_called()
        self.assertIsNone(self.app.controller.report)

    def test_database_connections_and_import_execute_outside_tk_thread(self):
        import threading
        from wifiscope.catalog_store import CatalogIndex
        seen = []
        def tracked(*args, **kwargs):
            seen.append(threading.get_ident())
            return CatalogIndex(*args, **kwargs)
        with patch('wifiscope.catalog_view.CatalogIndex', side_effect=tracked):
            self.build()
            self.panel.open_button.invoke()
            self.finish()
            self.detail()
        self.assertGreaterEqual(len(seen), 3)
        self.assertTrue(all(identifier != threading.get_ident() for identifier in seen))

    def test_real_build_search_pages_detail_manual_audit_apply_export(self):
        c = self.app.controller
        c.snapshot_id, c.case_path, c.overlay = 7, 'saved-case', {'f': {'status': 'investigating'}}
        self.build()
        self.detail()
        self.assertEqual(len(self.panel.rows.get_children()), 20)
        self.panel.next_button.invoke()
        self.finish()
        self.assertEqual(len(self.panel.rows.get_children()), 5)
        self.panel.previous_button.invoke()
        self.finish()
        self.panel.identity_choice.current(0)
        self.panel.asset_label.set('My declared laptop')
        self.panel.version.set('9.0:User*?\\value')
        self.panel.add_button.invoke()
        self.finish()
        component = self.panel.inventory['assets'][0]['components'][0]
        from wifiscope.cpe_names import parse_cpe
        self.assertEqual(parse_cpe(component['cpe']).field('version').text, '9.0:user*?\\value')
        self.assertNotIn(':1.2.3:', component['cpe'])
        self.assertTrue(component['cpe'].endswith(':*:*:*:*:*:*:*'))
        self.assertIsNone(component['observed_at'])
        self.assertEqual(self.panel.inventory['assets'][0]['complete_parts'], [])
        self.panel.audit_button.invoke()
        self.finish()
        self.assertIsNotNone(self.panel.result)
        self.assertEqual(c.snapshot_id, 7)
        self.assertEqual(c.overlay, {'f': {'status': 'investigating'}})
        bundle = self.folder / 'bundle'
        with patch('wifiscope.security_tools_view.filedialog.asksaveasfilename', return_value=str(bundle)):
            self.tools.export_button.invoke()
        self.finish()
        raw = (bundle / 'report.json').read_text(encoding='utf-8')
        self.assertNotIn('My declared laptop', raw)
        self.assertNotIn('9.0:User', raw)
        self.tools.replace_current.set(True)
        self.tools.apply_button.invoke()
        self.finish()
        self.assertIn('catalog_audit', c.report)
        self.assertIsNone(c.snapshot_id)

    def test_metadata_cannot_apply_and_query_change_resets_rows(self):
        self.build()
        self.detail()
        self.panel.cve.set('CVE-2026-10001')
        self.assertEqual(self.panel.offset, 0)
        self.assertEqual(self.panel.rows.get_children(), ())
        self.assertIsNone(self.panel.result)
        self.tools.replace_current.set(True)
        self.tools.apply_button.invoke()
        self.assertIsNone(self.app.controller.report)
        self.panel.open_button.invoke()
        self.finish()
        self.assertIsNone(self.panel.result)

    def test_import_native_then_remove_and_empty_audit_refused(self):
        self.build()
        path = self.folder / 'native.json'
        path.write_text(json.dumps(dict(schema_version=1, assets=[dict(id='asset', components=[dict(
            id='component', vendor='Other Vendor', product='CNA model', version='4.0.0')])])), encoding='utf-8')
        self.panel.inventory_path.set(str(path))
        self.panel.import_button.invoke()
        self.finish()
        self.assertEqual(len(self.panel.inventory['assets']), 1)
        self.panel.inventory_rows.selection_set(self.panel.inventory_rows.get_children()[0])
        self.panel.remove_button.invoke()
        self.finish()
        self.assertIsNone(self.panel.inventory)
        self.panel.audit_button.invoke()
        self.assertIsNone(self.panel.result)

    def test_demo_has_multiple_vendors_cna_and_separate_unknowns(self):
        self.panel.demo_button.invoke()
        self.finish()
        report = self.panel.result
        self.assertTrue(report['synthetic'])
        summary = report['catalog_audit']['summary']
        self.assertGreater(summary['true_pairs'], 0)
        self.assertGreater(summary['unknown_pairs'], 0)
        self.assertGreater(summary['not_matched_pairs'], 0)
        self.assertTrue(any(r['model'] == 'cna' for r in report['catalog_audit']['results']))

    def test_manual_cna_multiple_assets_and_no_advisory_version_copy(self):
        self.build()
        self.detail()
        cna = next(i for i, row in enumerate(self.panel.choices) if row['kind'] == 'cna')
        self.panel.identity_choice.current(cna)
        self.panel.asset_label.set('Declared server')
        self.assertEqual(self.panel.version.get(), '')
        self.panel.version.set('4.0.0+MyBuild')
        self.panel.add_button.invoke()
        self.finish()
        self.panel.asset_label.set('Second server')
        self.panel.version.set('5.0.0')
        self.panel.add_button.invoke()
        self.finish()
        self.assertEqual(len(self.panel.inventory['assets']), 2)
        first = self.panel.inventory['assets'][0]['components'][0]
        self.assertEqual(first['version'], '4.0.0+MyBuild')
        self.assertEqual(first['vendor'], 'Other Vendor')
        self.assertEqual(first['source'], 'local')
        self.assertEqual(first['identification'], 'declared')
        self.assertIsNone(first['observed_at'])
        self.panel.audit_button.invoke()
        self.finish()
        self.assertIsNotNone(self.panel.result)
        self.panel.search_button.invoke()
        self.finish()
        self.assertIsNone(self.panel.result)

    def test_rejected_pattern_detail_cannot_replace_prior_inventory(self):
        self.build()
        self.detail()
        self.panel.identity_choice.current(0)
        self.panel.asset_label.set('Declared server')
        self.panel.version.set('1.2.3')
        self.panel.add_button.invoke()
        self.finish()
        prior = self.panel.inventory
        other = self.folder / 'pattern.json'
        data = feed(1)
        record = data['vulnerabilities'][0]['cve']
        record['affected'] = []
        record['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria'] = 'cpe:2.3:a:ac*:wid?get:*:*:*:*:*:*:*:*'
        other.write_text(json.dumps(data), encoding='utf-8')
        self.panel.feed_paths = (str(other),)
        self.panel.db_path.set(str(self.folder / 'pattern.sqlite'))
        self.panel.build_button.invoke()
        self.finish()
        self.detail()
        self.assertEqual(self.panel.choices, [])
        self.panel.add_button.invoke()
        self.assertIs(self.panel.inventory, prior)

    def test_new_destination_refuses_overwrite_and_actual_open(self):
        self.build()
        original = self.db.read_bytes()
        self.panel.build_button.invoke()
        self.finish()
        self.assertIsNotNone(self.app.controller.tool_error)
        self.assertEqual(self.db.read_bytes(), original)
        self.panel.open_button.invoke()
        self.finish()
        self.assertIsNone(self.app.controller.tool_error)
        self.assertEqual(self.panel.catalog_info['records'], 25)

    def test_sbom_edits_preserve_gap_counts_and_require_explicit_new_manual_scope(self):
        self.build()
        self.detail()
        path = self.folder / 'sbom.json'
        path.write_text(json.dumps(dict(bomFormat='CycloneDX', specVersion='1.7', components=[
            dict(cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*'),
            dict(cpe='cpe:2.3:a:acme:widget:9.0.0:*:*:*:*:*:*:*'), dict(purl='pkg:unknown/example')])), encoding='utf-8')
        self.panel.inventory_path.set(str(path))
        self.panel.inventory_format.set('cyclonedx')
        self.panel.import_button.invoke()
        self.finish()
        prior = self.panel.inventory
        self.panel.identity_choice.current(0)
        self.panel.asset_label.set('Manual laptop')
        self.panel.version.set('7.0.0')
        self.panel.add_button.invoke()
        self.finish()
        self.assertIs(self.panel.inventory, prior)
        self.panel.inventory_rows.selection_set(self.panel.inventory_rows.get_children()[0])
        self.panel.remove_button.invoke()
        self.finish()
        context = self.panel.inventory['import_context']
        self.assertEqual(context['input_entries'], 3)
        self.assertEqual(context['unmapped_entries'], 1)
        self.assertEqual(context['retained_components'], 1)
        self.assertTrue(context['partial'])
        self.assertIn('input-partial', context['gaps'])
        self.panel.new_inventory_button.invoke()
        self.finish()
        self.assertIsNone(self.panel.inventory)
        self.panel.add_button.invoke()
        self.finish()
        self.assertEqual(self.panel.inventory['assets'][0]['id'], 'manual:Manual laptop')

    def test_input_edit_during_real_queued_demo_invalidates_late_preview(self):
        import threading
        from wifiscope.catalog_view import catalog_demo
        ready, finish = threading.Event(), threading.Event()
        def paused(cancel, progress):
            report = catalog_demo(cancel, progress)
            ready.set()
            finish.wait(3)
            return report
        with patch('wifiscope.catalog_view.catalog_demo', side_effect=paused):
            self.panel.demo_button.invoke()
            self.assertTrue(ready.wait(3))
            self.panel.version.set('edited while worker was finishing')
            finish.set()
            self.finish()
        self.assertIsNone(self.panel.result)

    def test_applied_unknowns_are_neutral_and_main_summary_keeps_units(self):
        from wifiscope.catalog_view import catalog_demo
        from wifiscope.investigate import build_investigation
        report = catalog_demo()
        for row in report['catalog_audit']['results']:
            row.update(score=9.8, severity='high')
        self.app.controller.accept(build_investigation(report), 'synthetic fixture')
        self.app.render()
        self.assertIn('未知条件 1', self.app.overview.get('1.0', 'end'))
        self.assertIn('未知条件 1', self.app.guided.results.get('1.0', 'end'))
        unknown = next(key for key, row in self.app.finding_rows.items() if row['code'] == 'catalog-applicability-unknown')
        self.assertIn('unknown', self.app.tables['findings'].item(unknown, 'tags'))

    def test_preview_associates_same_cve_with_asset_component_version_and_provenance(self):
        self.build()
        path = self.folder / 'two-assets.json'
        path.write_text(json.dumps(dict(schema_version=1, assets=[dict(id='declared-laptop', components=[dict(
            id='component-laptop', cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*', source='local',
            identification='declared', observed_at='2026-01-02')]), dict(id='imported-server', components=[dict(
            id='component-server', cpe='cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', source='sbom',
            identification='imported')])])), encoding='utf-8')
        self.panel.inventory_path.set(str(path))
        self.panel.import_button.invoke()
        self.finish()
        self.panel.audit_button.invoke()
        self.finish()
        report = self.panel.result
        self.assertIsNotNone(report)
        rows = [row for row in report['catalog_audit']['results'] if row['cve'] == 'CVE-2026-10001']
        self.assertEqual({(row['asset_id'], row['applicability']) for row in rows},
                         {('declared-laptop', 'true'), ('imported-server', 'unknown')})
        output = self.panel.output.get('1.0', 'end')
        same_cve = [line for line in output.splitlines() if 'CVE-2026-10001' in line]
        self.assertEqual(len(set(same_cve)), 2)
        self.assertTrue(any('资产 declared-laptop' in line and '适用性 true' in line for line in same_cve))
        self.assertTrue(any('资产 imported-server' in line and '适用性 unknown' in line for line in same_cve))
        self.assertIn('组件 component-laptop', output)
        self.assertIn('版本 1.2.3', output)
        self.assertIn('来源 local · 识别 declared · 来源时间 2026-01-02', output)
        self.assertIn('组件 component-server', output)
        self.assertIn('版本 未知（CPE ANY）', output)
        self.assertIn('来源 sbom · 识别 imported · 来源时间 未知（null）', output)
        self.assertIsNone(self.app.controller.report)

    def test_demo_preview_resolves_own_inventory_instead_of_selected_inventory(self):
        self.build()
        self.detail()
        self.panel.identity_choice.current(0)
        self.panel.asset_label.set('Unrelated selected inventory')
        self.panel.version.set('9.9.9')
        self.panel.add_button.invoke()
        self.finish()
        selected = self.panel.inventory
        self.panel.demo_button.invoke()
        self.finish()
        self.assertIs(self.panel.inventory, selected)
        output = self.panel.output.get('1.0', 'end')
        self.assertIn('资产 synthetic-positive', output)
        self.assertIn('组件 synthetic-a', output)
        self.assertIn('版本 1.0.0', output)
        self.assertIn('来源 synthetic · 识别 declared · 来源时间 未知（null）', output)
        self.assertNotIn('Unrelated selected inventory', output)
        self.assertNotIn('9.9.9', output)

    def test_preview_display_limits_are_visible_without_changing_complete_report(self):
        self.build()
        path = self.folder / 'many-components.json'
        path.write_text(json.dumps(dict(schema_version=1, assets=[dict(id='bounded-display-asset-'+str(i),
            components=[dict(id=f'component-{i}-{j}', cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*',
                             source='local', identification='declared') for j in range(8)]) for i in range(8)])), encoding='utf-8')
        self.panel.inventory_path.set(str(path))
        self.panel.import_button.invoke()
        self.finish()
        self.panel.audit_button.invoke()
        self.finish()
        report = self.panel.result
        self.assertEqual(report['catalog_audit']['status'], 'complete')
        self.assertEqual(len(report['catalog_audit']['results']), 200)
        self.assertEqual(len(report['catalog_audit']['inventory']['assets'][0]['components']), 8)
        output = self.panel.output.get('1.0', 'end-1c')
        self.assertLessEqual(len(output), 65536)
        self.assertIn('组件显示 3 / 8', output)
        self.assertIn('显示截断', output)
        self.assertIn('完整报告未截断', output)
        self.assertFalse(report['catalog_audit']['summary']['partial'])


if __name__ == '__main__':
    unittest.main()
