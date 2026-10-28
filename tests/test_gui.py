import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from wifiscope.demo import demo_report


class ControllerTests(unittest.TestCase):
    def controller(self):
        from wifiscope.gui_controller import Controller
        return Controller()

    def test_all_101_persisted_triage_states_survive_reopen_and_exports(self):
        import subprocess
        import sys
        from wifiscope.cases import CaseStore
        controller = self.controller()
        rows = [dict(id=f'f{index}', code='tls-trust', status='observed', severity='medium', confidence='high') for index in range(101)]
        controller.accept(dict(schema_version=1, investigation=dict(assets=[], findings=rows, coverage=[])), 'synthetic fixture')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db = root / 'case.db'
            controller.save_case(db)
            controller.worker.join(5)
            controller.poll()
            self.assertEqual(controller.snapshot_id, 1)
            stored_ids = [row['id'] for row in controller.report['investigation']['findings']]
            with CaseStore(db) as store:
                for finding_id in stored_ids:
                    store.triage(finding_id, 'investigating', 'LOCAL ONLY NOTE', snapshot_id=1)
            controller.open_case(db, 1)
            controller.worker.join(10)
            controller.poll()
            self.assertEqual(len(controller.overlay), 101)
            self.assertEqual(controller.overlay[stored_ids[0]]['note'], 'LOCAL ONLY NOTE')
            controller.export(root / 'gui-report')
            gui_report = json.loads((root / 'gui-report/report.json').read_text(encoding='utf-8'))
            self.assertTrue(all(row['triage_status'] == 'investigating' for row in gui_report['investigation']['findings']))
            run = subprocess.run([sys.executable, '-m', 'wifiscope', 'case', 'show', '--db', str(db), '--snapshot', '1', '--out', str(root / 'cli-report')], capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            cli_report = json.loads((root / 'cli-report/report.json').read_text(encoding='utf-8'))
            self.assertEqual(len(cli_report['investigation']['findings']), 101)
            self.assertTrue(all(row['triage_status'] == 'investigating' for row in cli_report['investigation']['findings']))
            for directory in ('gui-report', 'cli-report'):
                for suffix in ('json', 'csv', 'html'):
                    self.assertNotIn('LOCAL ONLY NOTE', (root / directory / ('report.' + suffix)).read_text(encoding='utf-8-sig'))

    def test_investigation_shapes_rejected_before_accept_or_case_write(self):
        import copy
        from wifiscope.case_validation import validate_report
        from wifiscope.cases import CaseStore
        from wifiscope.workstation import load_json
        controller = self.controller()
        original = demo_report()
        controller.accept(original, 'original')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for field, bad_value in [('coverage', dict(category='tcp-exposure')), ('coverage', ['PRIVATE']), ('assets', {}), ('findings', [1])]:
                bad = copy.deepcopy(original)
                bad['investigation'][field] = bad_value
                with self.subTest(field=field, value=bad_value):
                    with self.assertRaises(ValueError):
                        validate_report(bad)
                    with self.assertRaises(ValueError):
                        controller.accept(bad, 'bad')
                    self.assertIs(controller.report, original)
                    path = root / 'bad.json'
                    path.write_text(json.dumps(bad), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        load_json(path)
                    with CaseStore(root / 'case.db') as store:
                        with self.assertRaises(ValueError):
                            store.add_snapshot(bad)
                        self.assertEqual(store.snapshots(), [])
            # Genuine source coverage records remain accepted in their context.
            validate_report(original)

    def test_queue_main_thread_delivery_and_cancellation(self):
        controller = self.controller()
        main = threading.get_ident()
        workers = []
        def work(cancel):
            workers.append(threading.get_ident())
            cancel.wait(2)
            return demo_report()
        controller.start('demo', work)
        controller.cancel()
        controller.worker.join(3)
        self.assertIsNone(controller.report)
        controller.poll()
        self.assertEqual(threading.get_ident(), main)
        self.assertNotEqual(workers[0], main)
        self.assertIsNotNone(controller.report)
        self.assertIn('cancel', controller.status)

    def test_multi_source_import_and_case_save_triage_reopen(self):
        controller = self.controller()
        controller.accept(demo_report(), 'Synthetic demo')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            xml = root / 'scan.xml'
            xml.write_text('<nmaprun><host><address addr="192.0.2.199" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>')
            controller.import_evidence(xml, 'nmap', merge=True)
            controller.worker.join(3)
            controller.poll()
            self.assertIn('192.0.2.199', [a['address'] for a in controller.report['investigation']['assets']])
            self.assertTrue(controller.report['investigation']['findings'])
            db = root / 'case.db'
            controller.save_case(db, include_identifiers=False)
            controller.worker.join(3)
            controller.poll()
            self.assertEqual(controller.snapshot_id, 1)
            self.assertFalse(controller.report['identifiers_included'])
            fid = controller.report['investigation']['findings'][0]['id']
            controller.triage(fid, 'investigating', 'LOCAL NOTE')
            controller.worker.join(3)
            controller.poll()
            controller.open_case(db, 1)
            controller.worker.join(3)
            controller.poll()
            self.assertEqual(controller.overlay[fid]['status'], 'investigating')
            self.assertNotEqual(controller.report['investigation']['findings'][0]['status'], 'investigating')
            controller.export(root / 'bundle')
            encoded = (root / 'bundle/report.json').read_text(encoding='utf-8')
            self.assertNotIn('LOCAL NOTE', encoded)
            self.assertNotIn(fid, encoded)
            self.assertEqual(json.loads(encoded)['investigation']['findings'][0]['triage_status'], 'investigating')

    def test_partial_comparison_does_not_invent_remediation(self):
        from wifiscope.comparison import compare_snapshots
        before = demo_report()
        after = dict(identifiers_included=True, run=dict(status='cancelled'), assets=[], connectivity=[])
        before['identifiers_included'] = True
        after['wifi'] = []
        comparison = compare_snapshots(before, after)['comparison']
        self.assertTrue(comparison['partial'])
        self.assertTrue(all(c['status'] == 'not-observed' for c in comparison['asset_changes']))
        self.assertNotIn('resolved', json.dumps(comparison))
        self.assertTrue(comparison['wifi_changes'])
        before['identifiers_included'] = False
        self.assertEqual(compare_snapshots(before, after)['comparison']['mode'], 'counts-only')

    def test_raw_retention_explicit_and_case_work_is_not_on_ui_thread(self):
        controller = self.controller()
        controller.accept(demo_report(), 'synthetic')
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / 'case.db'
            controller.save_case(db, include_identifiers=True)
            controller.worker.join(3)
            controller.poll()
            self.assertTrue(controller.report['identifiers_included'])
            self.assertIn('192.0.2.80', json.dumps(controller.report))
            self.assertEqual(controller.history[0]['id'], 1)
            controller.verify_case()
            controller.worker.join(3)
            controller.poll()
            self.assertTrue(controller.result['ok'])
            self.assertIn('receipt', controller.status)

    def test_model_update_from_worker_rejected_and_error_delivery_actionable(self):
        controller = self.controller()
        failures = []
        def invalid(cancel):
            try:
                controller.accept({}, 'invalid')
            except RuntimeError:
                failures.append(True)
            raise ValueError('SECRET imported text')
        controller.start('test', invalid)
        controller.worker.join(2)
        self.assertEqual(failures, [True])
        self.assertIsNone(controller.report)
        controller.poll()
        self.assertNotIn('SECRET', controller.status)
        self.assertIn('format', controller.status)

    def test_new_netsh_probe_and_batch_reports_can_save_without_reexport(self):
        from wifiscope.batch import audit_scope
        from wifiscope.investigate import build_investigation
        from wifiscope.workstation import open_evidence
        from wifiscope.cases import CaseStore
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'wifi.txt'
            path.write_text('SSID 1 : Lab\n Authentication : Open\n BSSID 1 : 02:00:00:00:00:01\n')
            reports = [open_evidence(path, 'netsh'), build_investigation(dict(connectivity=[])),
                       audit_scope(['192.0.2.1'], [23], authorized=True, probe=lambda *a, **kw: [])]
            for index, report in enumerate(reports):
                self.assertEqual(report.get('schema_version'), 1)
                controller = self.controller()
                controller.accept(report, 'fixture')
                db = root / f'case{index}.db'
                controller.save_case(db)
                controller.worker.join(3)
                controller.poll()
                self.assertEqual(controller.snapshot_id, 1, controller.status)
                with CaseStore(db) as store:
                    self.assertTrue(store.verify()['ok'])
            with self.assertRaises(ValueError):
                build_investigation(dict(schema_version=99))


class GuiDisplayTests(unittest.TestCase):
    def assert_contained(self, widget, geometry):
        self.assertTrue(widget.winfo_ismapped(), (geometry, widget))
        x = widget.winfo_rootx() - self.root.winfo_rootx()
        y = widget.winfo_rooty() - self.root.winfo_rooty()
        self.assertGreaterEqual(x, 0, (geometry, widget))
        self.assertGreaterEqual(y, 0, (geometry, widget))
        self.assertLessEqual(x + widget.winfo_width(), self.root.winfo_width(), (geometry, widget))
        self.assertLessEqual(y + widget.winfo_height(), self.root.winfo_height(), (geometry, widget))

    def setUp(self):
        try:
            import tkinter as tk
            self.root = tk.Tk()
        except Exception as exc:
            self.skipTest('Native Tk display unavailable: ' + type(exc).__name__)

    def tearDown(self):
        if hasattr(self, 'root'):
            for callback in self.root.tk.call('after', 'info'):
                self.root.after_cancel(callback)
            self.root.destroy()


class NativeGuiTests(GuiDisplayTests):

    def test_real_demo_tables_details_import_and_export_privacy(self):
        from wifiscope.gui import Workstation
        app = Workstation(self.root, demo_provider=demo_report)
        app.set_mode('professional')
        app.load_demo()
        for _ in range(80):
            self.root.update()
            if app.controller.report is not None:
                break
            time.sleep(.01)
        self.assertTrue(app.tables['wifi'].get_children())
        self.assertTrue(app.tables['assets'].get_children())
        ids = app.tables['findings'].get_children()
        self.assertTrue(ids)
        app.tables['findings'].selection_set(ids[0])
        app.show_finding()
        self.assertIn('Retest', app.detail.get('1.0', 'end'))
        self.assertIn('Rule code:', app.detail.get('1.0', 'end'))
        self.assertIn('SYNTHETIC', app.source.get())
        self.assertLessEqual(self.root.winfo_width(), 1280)
        self.assertLessEqual(self.root.winfo_height(), 800)
        with tempfile.TemporaryDirectory() as temp:
            app.controller.export(Path(temp) / 'bundle')
            self.assertNotIn('192.0.2.80', (Path(temp) / 'bundle/report.json').read_text())
            xml = Path(temp) / 'new.xml'
            xml.write_text('<nmaprun><host><address addr="192.0.2.199" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>')
            app.controller.import_evidence(xml, 'nmap', merge=True)
            app.controller.worker.join(3)
            app.controller.poll()
            app.render()
            self.assertIn('192.0.2.199', str([app.tables['assets'].item(i, 'values') for i in app.tables['assets'].get_children()]))
            app.search.set('Cleartext')
            self.assertTrue(app.tables['findings'].get_children())
            app.severity.set('critical')
            self.assertFalse(app.tables['findings'].get_children())
            app.search.set('')
            app.severity.set('all')
            app.controller.save_case(Path(temp) / 'case.db', include_identifiers=False)
            app.controller.worker.join(3)
            app.controller.poll()
            app.render()
            self.assertEqual(app.controller.snapshot_id, 1)
            self.assertTrue(app.tables['history'].get_children())
            self.assertEqual(str(app.triage_button.cget('state')), 'normal')
            self.assertFalse(app.controller.report['identifiers_included'])

    def test_footer_and_scrolling_accessible_at_default_and_minimum_size(self):
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        app.set_mode('professional')
        for geometry in ('1180x730', '900x620'):
            self.root.geometry(geometry)
            self.root.update()
            privacy = [w for w in self._descendants(self.root) if w.winfo_class() == 'TCheckbutton' and w.cget('text') == '本次导出包含原始标识符'][0]
            for widget in (privacy, app.mode_switch, app.cancel_button, app.export_button, app.status_label):
                self.assert_contained(widget, geometry)
            app.export_button.invoke()
            self.assertIn('尚无', app.status.get())
        for widget in (app.overview, app.comparison):
            self.assertTrue(widget.cget('yscrollcommand'))

    def test_bad_json_keeps_previous_report_and_pump_delivers_next_demo(self):
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        app.controller.accept(demo_report(), 'previous demo')
        app.render()
        original = app.controller.report
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.json'
            path.write_text('{"schema_version":1,"investigation":{"assets":[],"findings":[],"coverage":{"category":"tcp-exposure"}}}')
            app.controller.import_evidence(path, 'json')
            app.controller.worker.join(3)
            self.root.after_cancel(app.timer)
            app.pump()
            self.assertIs(app.controller.report, original)
            self.assertIn('format', app.status.get())
            self.assertTrue(self.root.tk.call('after', 'info'))
            app.load_demo()
            app.controller.worker.join(3)
            self.root.after_cancel(app.timer)
            app.pump()
            self.assertIsNot(app.controller.report, original)
            self.assertTrue(app.tables['findings'].get_children())
            self.assertIn('SYNTHETIC', app.source.get())

    def test_render_failure_reschedules_pump_and_preserves_previous_model(self):
        from unittest.mock import patch
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        app.controller.accept(demo_report(), 'previous demo')
        app.render()
        original = app.controller.report
        app.controller.start('next', lambda cancel: demo_report())
        app.controller.worker.join(3)
        self.root.after_cancel(app.timer)
        with patch.object(app, 'render', side_effect=AttributeError('PRIVATE unexpected text')):
            app.pump()
        self.assertIs(app.controller.report, original)
        self.assertNotIn('PRIVATE', app.status.get())
        self.assertIn('display', app.status.get())
        self.assertTrue(self.root.tk.call('after', 'info'))
        app.load_demo()
        app.controller.worker.join(3)
        self.root.after_cancel(app.timer)
        app.pump()
        self.assertIsNot(app.controller.report, original)
        self.assertTrue(app.tables['assets'].get_children())

    def test_comparison_has_accurate_synthetic_label_and_side_counts(self):
        import copy
        from wifiscope.gui import Workstation
        from wifiscope.comparison import compare_snapshots
        app = Workstation(self.root)
        left = demo_report()
        right = copy.deepcopy(left)
        right.pop('synthetic')
        right['gaps'].remove('synthetic-demo')
        for source in right['sources']:
            source.pop('synthetic', None)
        app.controller.accept(compare_snapshots(left, right), 'comparison')
        app.render()
        self.assertIn('MIXED SYNTHETIC COMPARISON', app.source.get())
        self.assertIn('混合', app.guided.results.get('1.0', 'end'))
        self.assertIn('Before: synthetic', app.source.get())
        self.assertIn('After: not marked synthetic', app.source.get())
        self.assertEqual([value.get() for value in app.metrics], ['4', '4', '13', '13'])
        self.assertIn('Before', app.metric_labels[0].get())
        app.controller.accept(compare_snapshots(left, left), 'comparison')
        app.render()
        self.assertIn('SYNTHETIC COMPARISON', app.source.get())
        self.assertNotIn('MIXED', app.source.get())
        app.controller.accept(demo_report(), 'demo')
        app.render()
        self.assertEqual(app.metric_labels[0].get(), '候选资产')

    @classmethod
    def _descendants(cls, widget):
        for child in widget.winfo_children():
            yield child
            yield from cls._descendants(child)


class GuidedNativeTests(GuiDisplayTests):
    def test_readonly_button_cancel_busy_and_switch_keep_same_active_worker(self):
        from unittest.mock import patch
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        entered = threading.Event()
        release = threading.Event()
        calls = []
        def local():
            calls.append(threading.get_ident())
            entered.set()
            release.wait(3)
            return dict(wifi=[], gaps=[])
        try:
            with patch('wifiscope.gui.collect_local', side_effect=local), patch('wifiscope.gui.probe_hosts', side_effect=AssertionError('no target IO')):
                app.guided.local_button.invoke()
                self.assertTrue(entered.wait(2))
                worker = app.controller.worker
                app.set_mode('professional')
                app.set_mode('novice')
                app.guided.demo_button.invoke()
                self.assertIn('仍在进行', app.status.get())
                self.assertIs(app.controller.worker, worker)
                app.cancel_button.invoke()
                self.assertTrue(app.controller.stop.is_set())
                release.set()
                worker.join(3)
                app.controller.poll()
                app.render()
                self.assertIn('已取消', app.controller.status)
                self.assertIsNotNone(app.controller.report)
                self.assertNotEqual(calls[0], threading.get_ident())
        finally:
            release.set()


    def test_launch_mode_switch_preserves_evidence_case_overlay_and_starts_no_work(self):
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        self.root.update()
        self.assertEqual(app.mode.get(), 'novice')
        self.assertIsNone(app.controller.worker)
        self.assertFalse(app.notebook.winfo_ismapped())
        app.controller.accept(demo_report(), 'fixture')
        app.controller.case_path = 'LOCAL'
        app.controller.snapshot_id = 7
        app.controller.overlay = {'id': {'status': 'investigating', 'note': 'LOCAL'}}
        report, overlay = app.controller.report, app.controller.overlay
        for mode in ('professional', 'novice'):
            app.set_mode(mode)
            self.root.update()
            self.assertIs(app.controller.report, report)
            self.assertIs(app.controller.overlay, overlay)
            self.assertEqual(app.controller.snapshot_id, 7)
            self.assertEqual(app.controller.case_path, 'LOCAL')
            self.assertIsNone(app.controller.worker)

    def test_demo_button_delivers_explanations_without_active_work(self):
        from unittest.mock import patch
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        with patch('wifiscope.gui.probe_hosts', side_effect=AssertionError('active IO forbidden')):
            app.guided.demo_button.invoke()
            app.controller.worker.join(3)
            app.controller.poll()
            app.render()
        text = app.guided.results.get('1.0', 'end')
        self.assertIn('合成', text)
        self.assertIn('先做什么', text)
        self.assertIn('下一步', text)
        self.assertIn('未知', text)

    def test_target_preview_authorization_invalidation_and_real_worker_delivery(self):
        from unittest.mock import patch
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        app.guided.host.set('127.0.0.1')
        app.guided.preview_button.invoke()
        self.assertIn('80, 443', app.guided.preview.get())
        self.assertIn('3', app.guided.preview.get())
        self.assertIn('0.75', app.guided.preview.get())
        app.guided.start_button.invoke()
        self.assertIsNone(app.controller.worker)
        self.assertIn('授权', app.status.get())
        app.guided.authorized.set(True)
        app.guided.host.set('127.0.0.2')
        self.assertFalse(app.guided.authorized.get())
        app.guided.start_button.invoke()
        self.assertIsNone(app.controller.worker)
        app.guided.preview_button.invoke()
        app.guided.authorized.set(True)
        calls = []
        def fake(hosts, ports, **kwargs):
            calls.append((hosts, ports, kwargs['authorized'], kwargs['urls'], threading.get_ident()))
            return []
        with patch('wifiscope.gui.probe_hosts', side_effect=fake):
            app.guided.start_button.invoke()
            app.controller.worker.join(3)
            self.assertIsNone(app.controller.report)
            app.controller.poll()
            app.render()
        self.assertEqual(calls[0][:4], (['127.0.0.2'], [80, 443], True, []))
        self.assertNotEqual(calls[0][4], threading.get_ident())
        self.assertIsNotNone(app.controller.report)

    def test_minimum_window_has_scroll_and_reachable_mode_start_cancel_export_status(self):
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        for size in ('1180x730', '900x620'):
            self.root.geometry(size)
            self.root.update()
            for widget in (app.mode_switch, app.guided.start_button, app.cancel_button, app.export_button, app.status_label):
                self.assert_contained(widget, size)
            app.guided.start_button.invoke()
            self.assertIsNone(app.controller.worker)
            self.assertIn('单个', app.status.get())
            self.assertTrue(app.guided.canvas.cget('yscrollcommand'))
            app.guided.canvas.yview_moveto(1)
            self.root.update()
            self.assertGreater(app.guided.canvas.yview()[0], 0)

    def test_rate_estimate_preview_and_multirun_scope_are_honest_in_both_modes(self):
        from wifiscope.gui import Workstation
        from wifiscope.investigate import merge_reports
        from tests.test_final_fixes import measured
        app = Workstation(self.root)
        app.guided.host.set('192.0.2.1')
        app.guided.preview_button.invoke()
        self.assertIn('规划估算约 0.75 秒', app.guided.preview.get())
        self.assertNotIn('至少', app.guided.preview.get())
        for inputs in ([measured('complete', 1, '192.0.2.1'), measured('cancelled', 3, '192.0.2.2')],
                       [measured('cancelled', 3, '192.0.2.2'), measured('complete', 1, '192.0.2.1')]):
            app.controller.accept(merge_reports(inputs), 'fixture')
            for mode in ('novice', 'professional'):
                app.set_mode(mode)
                app.render()
                self.assertIn('partial', app.scope_status.get())
                self.assertIn('计划连接 未知', app.scope_status.get())
                self.assertIn('多个执行范围', app.guided.results.get('1.0', 'end'))

    def test_novice_export_ignores_professional_raw_opt_in_and_errors_are_actionable(self):
        from unittest.mock import patch
        from wifiscope.gui import Workstation
        app = Workstation(self.root)
        app.export_raw.set(True)
        app.export_button.invoke()
        self.assertIn('尚无', app.status.get())
        app.controller.accept(demo_report(), 'fixture')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bundle'
            with patch('wifiscope.gui.filedialog.asksaveasfilename', return_value=str(path)):
                app.export_button.invoke()
            app.controller.worker.join(3)
            app.controller.poll()
            self.assertFalse(json.loads((path / 'report.json').read_text(encoding='utf-8'))['identifiers_included'])
        app.guided.host.set('PRIVATE/24')
        app.guided.preview_button.invoke()
        self.assertIn('单个', app.status.get())
        self.assertNotIn('PRIVATE', app.status.get())


if __name__ == '__main__':
    unittest.main()
