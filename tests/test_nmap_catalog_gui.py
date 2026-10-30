"""Synthetic offline Nmap controls through actual Tk widgets, queues and CLI."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import tkinter as tk
import unittest
from unittest.mock import patch

from wifiscope.catalog_store import build_catalog
from wifiscope.cli import main
from wifiscope.gui import Workstation
from wifiscope.inventory_import import import_inventory


XML = '''<nmaprun start="1700000000"><host endtime="1700000002">
<status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="2001:db8::10" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service method="probed" conf="10"><cpe>cpe:/a:example:app:1.2.3-RC.1</cpe>
</service></port></ports><os><osmatch><osclass accuracy="98">
<cpe>cpe:/o:example:os_one:1</cpe></osclass><osclass accuracy="97">
<cpe>cpe:/o:example:os_two:2</cpe></osclass></osmatch></os></host>
<host><status state="up"/><address addr="198.51.100.20" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service method="table" conf="3"><cpe>cpe:/a:example:app:1.2.3-RC.1</cpe>
</service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''


def feed():
    app = 'cpe:2.3:a:example:app:1.2.3-RC.1:*:*:*:*:*:*:*'
    os_one = 'cpe:2.3:o:example:os_one:1:*:*:*:*:*:*:*'
    os_two = 'cpe:2.3:o:example:os_two:2:*:*:*:*:*:*:*'
    matches = [[dict(criteria=app, vulnerable=True)],
               [dict(criteria=app, vulnerable=True), dict(criteria=os_one, vulnerable=False)],
               [dict(criteria=os_one, vulnerable=True), dict(criteria=os_two, vulnerable=False)],
               [dict(criteria=app.replace(':1.2.3-RC.1:', ':*:'), vulnerable=True,
                     versionEndExcluding='1.2.3-rc.1')]]
    return dict(format='NVD_CVE', version='2.0', totalResults=4, startIndex=0, resultsPerPage=4,
                vulnerabilities=[dict(cve=dict(id=f'CVE-2026-{91001+i}', vulnStatus='Analyzed',
                    configurations=[dict(nodes=[dict(operator='AND', cpeMatch=rows)])]))
                                 for i, rows in enumerate(matches)])


class NmapCatalogCliTests(unittest.TestCase):
    def test_actual_local_nmap_cli_default_hmac_raw_bundle_and_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, xml, db = folder/'feed.json', folder/'source.xml', folder/'index.db'
            source.write_text(json.dumps(feed()), encoding='utf8')
            xml.write_text(XML, encoding='utf8')
            build_catalog([source], db)
            original = xml.read_bytes(), db.read_bytes()
            args = ['catalog', 'audit', '--db', str(db), '--inventory', str(xml),
                    '--inventory-format', 'nmap']
            for raw in (False, True):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = main(args + (['--include-identifiers'] if raw else []))
                self.assertEqual(status, 0)
                report = json.loads(output.getvalue())
                audit = report['catalog_audit']
                self.assertEqual(audit['summary']['assets'], 2)
                self.assertEqual(audit['inventory']['import_context']['scanner_summary']['input_hosts'], 2)
                self.assertEqual('192.0.2.10' in output.getvalue(), raw)
                self.assertEqual('1.2.3-RC.1' in output.getvalue(), raw)
                self.assertNotIn(str(folder), output.getvalue())
                assets = {a['id'] for a in audit['inventory']['assets']}
                self.assertTrue(all(r['asset_id'] in assets for r in audit['results']))
            bundle = folder/'bundle'
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(args + ['--out', str(bundle)]), 0)
            self.assertEqual(json.loads(output.getvalue()), dict(status='complete', bundle_created=True))
            self.assertNotIn('192.0.2.10', (bundle/'report.json').read_text(encoding='utf8'))
            self.assertEqual(xml.read_bytes(), original[0])
            xml.write_text(XML.replace('exit="success"', 'exit="error"'), encoding='utf8')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 1)
            xml.write_text('<nmaprun/>', encoding='utf8')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(db.read_bytes(), original[1])


class NmapCatalogTkTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest('Actual Tk display unavailable.')
        self.app = Workstation(self.root)
        self.addCleanup(self.app.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.xml = self.folder/'source.xml'
        self.xml.write_text(XML, encoding='utf8')
        self.source, self.db = self.folder/'feed.json', self.folder/'catalog.db'
        self.source.write_text(json.dumps(feed()), encoding='utf8')
        build_catalog([self.source], self.db)
        self.app.open_security_tools('catalog')
        self.tools, self.panel = self.app.security_tools, self.app.security_tools.panels['catalog']
        self.root.update()

    def finish(self):
        worker = self.app.controller.worker
        if worker:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.app.pump()
        self.root.update()

    def imported(self):
        self.panel.inventory_path.set(str(self.xml))
        self.panel.inventory_format.set('nmap')
        self.panel.import_button.invoke()
        self.finish()
        self.assertIsNone(self.app.controller.tool_error)
        self.assertIsNotNone(self.panel.inventory)
        return self.panel.inventory

    def open_db(self):
        self.panel.db_path.set(str(self.db))
        self.panel.open_button.invoke()
        self.finish()

    def select(self, index=0):
        self.panel.inventory_rows.selection_set(self.panel.inventory_rows.get_children()[index])

    def test_both_modes_choose_nmap_import_worker_preview_and_no_startup_io(self):
        self.tools.close()
        seen = []
        def tracked(*args, **kwargs):
            seen.append(threading.get_ident())
            return import_inventory(*args, **kwargs)
        with (patch('wifiscope.catalog_view.import_inventory', side_effect=tracked) as importer,
              patch('wifiscope.catalog_view.CatalogIndex') as index,
              patch('wifiscope.catalog_view.build_catalog') as build,
              patch('wifiscope.gui.collect_local') as collector):
            for count, mode in enumerate(('novice', 'professional')):
                self.app.set_mode(mode)
                self.app.open_security_tools('catalog')
                self.tools = self.app.security_tools
                self.panel = self.tools.panels['catalog']
                self.tools.show('capture')
                self.tools.show('catalog')
                self.assertEqual(importer.call_count, count)
                self.assertIn('nmap', self.panel.format_choice['values'])
                with patch('wifiscope.catalog_view.filedialog.askopenfilename', return_value=str(self.xml)):
                    self.panel.choose_inventory_button.invoke()
                self.assertEqual(self.panel.inventory_path.get(), str(self.xml))
                self.assertEqual(importer.call_count, count)
                self.imported()
                output = self.panel.output.get('1.0', 'end')
                for value in ('192.0.2.10', '2001:db8::10', '198.51.100.20', 'probed',
                              'table', 'possible', 'asserted', 'osclass', '置信度 10',
                              '准确度 98', 'tcp', '443', 'host-end', 'uri', '排序 unknown'):
                    self.assertIn(value, output)
                self.tools.close()
            index.assert_not_called()
            build.assert_not_called()
            collector.assert_not_called()
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(identifier != threading.get_ident() for identifier in seen))
        self.assertIsNone(self.app.controller.report)

    def test_ordering_worker_independent_edit_preserves_original_hypotheses_and_semver_case(self):
        before = copy.deepcopy(self.imported())
        self.open_db()
        self.panel.audit_button.invoke()
        self.finish()
        first = before['assets'][0]
        self.assertEqual(next(r['applicability'] for r in self.panel.result['catalog_audit']['results']
                              if r['asset_id'] == first['id'] and r['cve'] == 'CVE-2026-91004'), 'unknown')
        self.select()
        self.panel.component_scheme.set('semver2')
        self.panel.order_button.invoke()
        self.finish()
        after = copy.deepcopy(self.panel.inventory)
        self.assertIsNone(self.panel.result)
        self.assertIsNone(self.app.controller.report)
        self.assertIn(':1.2.3-RC.1:', after['assets'][0]['components'][0]['cpe'])
        after['assets'][0]['components'][0]['version_scheme'] = 'unknown'
        self.assertEqual(after, before)
        self.panel.audit_button.invoke()
        self.finish()
        self.assertEqual(next(r['applicability'] for r in self.panel.result['catalog_audit']['results']
                              if r['asset_id'] == first['id'] and r['cve'] == 'CVE-2026-91004'), 'true')
        self.select(1)
        self.panel.component_scheme.set('numeric')
        self.panel.order_button.invoke()
        self.finish()
        self.assertEqual(self.panel.inventory['assets'][0]['components'][1]['scanner']['presence'], 'possible')
        self.assertEqual(self.panel.inventory['assets'][0]['components'][0]['version_scheme'], 'semver2')

    def test_preview_leads_with_host_and_evidence_without_changing_full_export(self):
        from wifiscope.catalog_view import audit_preview, inventory_preview
        # Repeated addresses still represent distinct source hosts, never a join.
        self.xml.write_text(XML.replace('198.51.100.20', '192.0.2.10'), encoding='utf8')
        prepared = []
        def tracked(renderer, value):
            before = json.dumps(value, sort_keys=True).encode('utf8')
            output = renderer(value)
            self.assertEqual(json.dumps(value, sort_keys=True).encode('utf8'), before)
            prepared.append((threading.get_ident(), before))
            return output
        original = self.xml.read_bytes(), self.db.read_bytes()
        with patch('wifiscope.catalog_view.inventory_preview',
                   side_effect=lambda value: tracked(inventory_preview, value)):
            inventory = self.imported()
        imported_output = self.panel.output.get('1.0', 'end-1c')
        self.assertIn('主机 1 · 地址 192.0.2.10, 2001:db8::10', imported_output)
        self.assertIn('主机 2 · 地址 192.0.2.10 · 资产 ', imported_output)
        self.assertNotIn(inventory['import_context']['source_sha256'], imported_output)
        imported_bytes = json.dumps(inventory, sort_keys=True).encode('utf8')
        self.open_db()
        with patch('wifiscope.catalog_view.audit_preview',
                   side_effect=lambda value: tracked(audit_preview, value)):
            self.panel.audit_button.invoke()
            self.finish()
        report = self.panel.result
        report_bytes = json.dumps(report, sort_keys=True).encode('utf8')
        output = self.panel.output.get('1.0', 'end-1c')
        self.assertLessEqual(len(output), 65536)
        digest = inventory['import_context']['source_sha256']
        self.assertNotIn(digest, output)
        self.assertIn('SHA256', output)
        self.assertIn('[缩略]', output)
        hosts = [line for line in output.splitlines() if line.startswith('主机 ')]
        self.assertEqual(len(hosts), 2)
        self.assertTrue(hosts[0].startswith('主机 1 · 地址 192.0.2.10, 2001:db8::10'))
        self.assertTrue(hosts[1].startswith('主机 2 · 地址 192.0.2.10 · 资产 '))
        for asset in inventory['assets']:
            self.assertNotIn(asset['id'], output)
            for component in asset['components']:
                self.assertNotIn(component['id'], output)
        source_line = next(line for line in output.splitlines() if 'CPE a / example / app' in line)
        for evidence in ('版本 1.2.3-RC.1', '来源 nmap', '来源时间 2023-11-14T22:13:22+00:00',
                         'presence asserted', 'service / probed'):
            self.assertLess(source_line.index(evidence), source_line.index('组件 '))
        result_lines = [line for line in output.splitlines() if line.startswith('CVE-2026-91001')]
        self.assertTrue(any('主机 1 · 地址 192.0.2.10' in line and '适用性 true' in line
                            for line in result_lines))
        self.assertTrue(any('主机 2 · 地址 192.0.2.10 · 资产 ' in line and '适用性 unknown' in line
                            for line in result_lines))
        self.assertEqual(len(prepared), 2)
        self.assertTrue(all(identifier != threading.get_ident() for identifier, _ in prepared))
        self.assertEqual(imported_bytes, json.dumps(inventory, sort_keys=True).encode('utf8'))
        self.tools.export_raw.set(True)
        bundle = self.folder/'readable-raw'
        with patch('wifiscope.security_tools_view.filedialog.asksaveasfilename', return_value=str(bundle)):
            self.tools.export_button.invoke()
        self.finish()
        exported = json.loads((bundle/'report.json').read_text(encoding='utf8'))
        self.assertEqual(exported['catalog_audit'], report['catalog_audit'])
        for filename in ('report.csv', 'report.html'):
            raw = (bundle/filename).read_text(encoding='utf-8-sig')
            self.assertIn(digest, raw)
            for asset in inventory['assets']:
                self.assertIn(asset['id'], raw)
                for component in asset['components']:
                    self.assertIn(component['id'], raw)
        self.assertEqual(report_bytes, json.dumps(report, sort_keys=True).encode('utf8'))
        self.assertEqual((self.xml.read_bytes(), self.db.read_bytes()), original)
        self.assertIsNone(self.app.controller.report)

    def test_ordering_invalid_selection_scheme_and_inventory_refuse_without_mutation(self):
        prior = self.imported()
        self.panel.order_button.invoke()
        self.assertIs(self.panel.inventory, prior)
        self.select()
        self.panel.component_scheme.set('automatic')
        self.panel.order_button.invoke()
        self.finish()
        self.assertIsNotNone(self.app.controller.tool_error)
        self.assertIs(self.panel.inventory, prior)
        self.panel.component_scheme.set('numeric')
        malformed = copy.deepcopy(prior)
        malformed['assets'][0]['components'][0]['scanner']['presence'] = 'confirmed'
        self.panel.inventory = malformed
        self.panel.order_button.invoke()
        self.finish()
        self.assertIsNotNone(self.app.controller.tool_error)
        self.assertIs(self.panel.inventory, malformed)

    def test_remove_retains_source_units_updates_hosts_and_final_empty_scope(self):
        prior = copy.deepcopy(self.imported()['import_context'])
        for _ in range(3):
            self.select()
            self.panel.remove_button.invoke()
            self.finish()
            self.assertIsNone(self.app.controller.tool_error)
        context = self.panel.inventory['import_context']
        self.assertEqual(context['retained_components'], 1)
        self.assertEqual(context['scanner_summary']['retained_hosts'], 1)
        self.assertEqual(context['scanner_summary']['unmapped_hosts'], 1)
        self.assertTrue(context['partial'])
        expected = copy.deepcopy(prior)
        expected.update(retained_components=1, partial=True, gaps=sorted(set(prior['gaps']) | {'input-partial'}))
        expected['scanner_summary'].update(retained_hosts=1, unmapped_hosts=1)
        self.assertEqual(context, expected)
        self.assertIn('移除', self.panel.notice.get())
        self.select()
        self.panel.remove_button.invoke()
        self.finish()
        self.assertIsNone(self.panel.inventory)

    def test_audit_associations_unknowns_default_export_and_explicit_apply(self):
        c = self.app.controller
        c.snapshot_id, c.case_path, c.overlay = 17, 'saved-case', {'f': {'status': 'investigating'}}
        inv = self.imported()
        self.open_db()
        self.tools.replace_current.set(True)
        self.tools.apply_button.invoke()
        self.assertIsNone(c.report)
        self.panel.audit_button.invoke()
        self.finish()
        audit = self.panel.result['catalog_audit']
        asset = inv['assets'][0]
        row = next(r for r in audit['results'] if r['asset_id'] == asset['id'] and r['cve'] == 'CVE-2026-91001')
        self.assertEqual(row['component_ids'], [asset['components'][0]['id']])
        self.assertEqual(row['applicability'], 'true')
        self.assertTrue(all(r['applicability'] == 'unknown' for r in audit['results']
                            if r['cve'] in ('CVE-2026-91002', 'CVE-2026-91003')))
        output = self.panel.output.get('1.0', 'end')
        self.assertIn('主机 1 · 地址 192.0.2.10', output)
        self.assertIn('未知条件', output)
        self.assertIn('presence', output)
        self.assertEqual((c.snapshot_id, c.case_path, c.overlay), (17, 'saved-case', {'f': {'status': 'investigating'}}))
        bundle = self.folder/'bundle'
        with patch('wifiscope.security_tools_view.filedialog.asksaveasfilename', return_value=str(bundle)):
            self.tools.export_button.invoke()
        self.finish()
        self.assertNotIn('192.0.2.10', (bundle/'report.json').read_text(encoding='utf8'))
        self.assertIsNone(c.report)
        self.tools.replace_current.set(True)
        self.tools.apply_button.invoke()
        self.finish()
        self.assertIn('catalog_audit', c.report)
        self.assertIsNone(c.snapshot_id)

    def test_new_synthetic_walkthrough_keeps_selected_inputs_and_existing_demo(self):
        self.imported()
        self.open_db()
        prior = self.panel.inventory, self.panel.loaded_db, self.panel.inventory_path.get()
        from wifiscope.catalog_audit import audit_catalog
        observed = []
        def audited(report, inventory, index, **kwargs):
            observed.append(report.get('synthetic'))
            return audit_catalog(report, inventory, index, **kwargs)
        with (patch('wifiscope.catalog_view.audit_catalog', side_effect=audited),
              patch('socket.socket', side_effect=AssertionError('No network')),
              patch('subprocess.Popen', side_effect=AssertionError('No executable'))):
            self.panel.nmap_demo_button.invoke()
            self.finish()
        self.assertEqual(observed, [True])
        report = self.panel.result
        self.assertTrue(report['synthetic'])
        self.assertEqual(report['catalog_audit']['summary']['assets'], 2)
        self.assertTrue(all(c['source'] == 'nmap' for a in report['catalog_audit']['inventory']['assets'] for c in a['components']))
        self.assertGreater(report['catalog_audit']['summary']['true_pairs'], 0)
        self.assertGreater(report['catalog_audit']['summary']['unknown_pairs'], 0)
        self.assertEqual((self.panel.inventory, self.panel.loaded_db, self.panel.inventory_path.get()), prior)
        self.assertIsNone(self.app.controller.report)
        self.panel.demo_button.invoke()
        self.finish()
        self.assertTrue(self.panel.result['synthetic'])
        self.assertTrue(any(r['model'] == 'cna' for r in self.panel.result['catalog_audit']['results']))

    def test_large_import_prepares_bounded_preview_in_worker_without_losing_hosts(self):
        from wifiscope.catalog_view import inventory_preview
        seen = []
        host = XML[XML.index('<host '):XML.index('</host>')+7]
        self.xml.write_text('<nmaprun start="1700000000">'+host*100+
                            '<runstats><finished exit="success"/></runstats></nmaprun>', encoding='utf8')
        def tracked(value):
            seen.append(threading.get_ident())
            return inventory_preview(value)
        with patch('wifiscope.catalog_view.inventory_preview', side_effect=tracked):
            inventory = self.imported()
        self.assertTrue(seen)
        self.assertTrue(all(i != threading.get_ident() for i in seen))
        self.assertEqual(len(inventory['assets']), 100)
        self.assertEqual(len(self.panel.inventory_rows.get_children()), 300)
        output = self.panel.output.get('1.0', 'end')
        self.assertLessEqual(len(output), 16500)
        self.assertIn('显示截断', output)

    def test_work_limit_preview_preserves_partial_unknown_unexamined_count(self):
        self.imported()
        self.open_db()
        with patch('wifiscope.catalog_audit.MAX_PREDICATES', 1):
            self.panel.audit_button.invoke()
            self.finish()
        audit = self.panel.result['catalog_audit']
        self.assertEqual(audit['status'], 'partial')
        self.assertIsNone(audit['summary']['unexamined_pairs'])
        self.assertIn('未评估 未知（null）', self.panel.output.get('1.0', 'end'))
        self.assertIsNone(self.app.controller.report)

    def test_real_queued_ordering_stale_busy_cancel_closed_owner_and_failure(self):
        # Pause the real normalized edit in its worker; late delivery must not mutate Tk state.
        from wifiscope.inventory import validate_inventory
        for action in ('stale', 'cancel', 'close', 'failure'):
            with self.subTest(action=action):
                if self.app.security_tools is None:
                    self.app.open_security_tools('catalog')
                    self.tools, self.panel = self.app.security_tools, self.app.security_tools.panels['catalog']
                prior = self.imported()
                self.select()
                ready, release = threading.Event(), threading.Event()
                seen = []
                def paused(value):
                    seen.append(threading.get_ident())
                    ready.set()
                    release.wait(5)
                    if action == 'failure':
                        raise ValueError('Controlled synthetic refusal.')
                    return validate_inventory(value)
                with patch('wifiscope.catalog_view.validate_inventory', side_effect=paused):
                    self.panel.component_scheme.set('numeric')
                    self.panel.order_button.invoke()
                    self.assertTrue(ready.wait(3))
                    self.assertTrue(self.app.controller.busy)
                    self.panel.nmap_demo_button.invoke()
                    self.assertIs(self.panel.inventory, prior)
                    if action == 'stale':
                        self.panel.component_scheme.set('semver2')
                    elif action == 'cancel':
                        self.tools.cancel_button.invoke()
                    elif action == 'close':
                        self.tools.close()
                    release.set()
                    self.finish()
                self.assertTrue(all(i != threading.get_ident() for i in seen))
                self.assertIs(self.panel.inventory, prior)
                self.assertIsNone(self.panel.result)
                self.assertIsNone(self.app.controller.report)
                self.assertFalse(self.app.controller.busy)
                if action == 'failure':
                    self.assertIsNotNone(self.app.controller.tool_error)


if __name__ == '__main__':
    unittest.main()
