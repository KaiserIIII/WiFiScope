"""Real saved-audit Tk workflows against a tiny local catalog."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import tkinter as tk
import unittest
from unittest.mock import patch

from test_catalog_gui import feed
from wifiscope.catalog_store import build_catalog
from wifiscope.gui import Workstation
from wifiscope.inventory import validate_inventory


class CatalogRunTkTests(unittest.TestCase):
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
        source = self.folder/'source.json'
        source.write_text(json.dumps(feed(2)), encoding='utf8')
        self.db = self.folder/'catalog.db'
        build_catalog([source], self.db)
        self.inventory = validate_inventory(dict(schema_version=1, assets=[dict(id='PRIVATE-ASSET', components=[
            dict(id='PRIVATE-COMPONENT', cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*', source='local', identification='declared')])]))

    def panel(self, mode='novice'):
        self.app.set_mode(mode)
        self.app.open_security_tools('catalog')
        self.tools = self.app.security_tools
        self.view = self.tools.panels['catalog']
        self.assertTrue(hasattr(self.view, 'runs'), 'saved-audit controls are missing')
        self.runs = self.view.runs
        self.view.db_path.set(str(self.db))
        self.view.open_button.invoke()
        self.finish()
        self.view.inventory = copy.deepcopy(self.inventory)
        self.runs.run_path.set(str(self.folder/(mode+'.db')))
        self.runs.page_size.set('1')
        return self.runs

    def finish(self):
        worker = self.app.controller.worker
        if worker:
            worker.join(10)
            self.assertFalse(worker.is_alive())
        self.app.pump()
        self.root.update()
        self.assertIsNone(self.app.controller.tool_error)

    def test_saved_pages_reopen_continue_frozen_inventory_and_explicit_apply_both_modes(self):
        for mode in ('novice', 'professional'):
            runs = self.panel(mode)
            before = copy.deepcopy(self.app.controller.report)
            inventory = copy.deepcopy(self.view.inventory)
            runs.new_button.invoke()
            self.assertFalse(Path(runs.run_path.get()).exists())
            self.assertFalse(runs.store_raw.get())
            runs.store_raw.set(True)
            runs.new_button.invoke()
            self.finish()
            self.assertEqual((runs.status['state'], runs.status['page_count']), ('paused', 1))
            self.assertEqual(runs.status['cumulative']['evaluated_pairs'], 1)
            self.assertEqual(self.view.result['catalog_audit']['page']['scope'], 'page')
            self.assertEqual(self.app.controller.report, before)
            self.assertEqual(self.view.inventory, inventory)
            saved = runs.run_path.get()
            self.tools.close()
            self.panel(mode)
            runs = self.runs
            runs.run_path.set(saved)
            runs.open_button.invoke()
            self.finish()
            self.assertEqual(runs.page_number, 1)
            self.view.inventory = None
            runs.continue_button.invoke()
            self.finish()
            self.assertEqual(runs.status['cumulative']['evaluated_pairs'], 2)
            runs.continue_button.invoke()
            self.finish()
            self.assertEqual(runs.status['state'], 'complete')
            self.assertIsNone(self.view.inventory)
            self.assertEqual(self.app.controller.report, before)
            runs.previous_button.invoke()
            self.finish()
            self.assertEqual(runs.page_number, 1)
            self.assertTrue(runs.previous_button.instate(['disabled']))
            runs.next_button.invoke()
            self.finish()
            self.assertEqual(runs.page_number, 2)
            self.assertTrue(runs.next_button.instate(['disabled']))
            self.assertIn('冻结', runs.status_text.get())
            self.assertIn('未应用', runs.status_text.get())
            self.tools.replace_current.set(True)
            self.tools.apply()
            self.finish()
            self.assertEqual(self.app.controller.report['catalog_audit']['page']['page_number'], 2)
            self.tools.close()

    def test_busy_stale_cancel_and_closed_results_do_not_replace_preview(self):
        runs = self.panel()
        runs.store_raw.set(True)
        entered, release = threading.Event(), threading.Event()
        from wifiscope.catalog_runs import advance_run
        def delayed(*args, **kwargs):
            entered.set()
            release.wait(5)
            return advance_run(*args, **kwargs)
        with patch('wifiscope.catalog_run_view.advance_run', side_effect=delayed):
            runs.new_button.invoke()
            self.assertTrue(entered.wait(5))
            with self.assertRaises(ValueError):
                runs.open()
            heartbeat = []
            self.root.after(0, lambda: heartbeat.append(True))
            self.root.update()
            self.assertTrue(heartbeat)
            runs.run_path.set(str(self.folder/'changed.db'))
            self.app.controller.cancel()
            release.set()
            self.finish()
            self.assertIsNone(self.view.result)
            self.assertIsNone(runs.status)
        runs.run_path.set(str(self.folder/'novice.db'))
        runs.open_button.invoke()
        self.tools.close()
        self.finish()
        self.assertIsNone(self.app.controller.tool_result)
        self.assertIsNone(self.app.controller.report)

    def test_open_modes_perform_no_run_io(self):
        with patch('wifiscope.catalog_run_view._RunReader', side_effect=AssertionError('startup read')):
            for mode in ('novice', 'professional'):
                self.app.set_mode(mode)
                self.app.open_security_tools('catalog')
                self.assertTrue(hasattr(self.app.security_tools.panels['catalog'], 'runs'))
                self.app.security_tools.close()

    def test_worker_owns_sqlite_rendering_and_freezes_copies_before_dispatch(self):
        runs = self.panel()
        runs.store_raw.set(True)
        entered, release = threading.Event(), threading.Event()
        from wifiscope import catalog_run_view, catalog_runs
        from wifiscope.catalog_view import audit_preview
        create = catalog_run_view.create_run
        connect = catalog_runs.sqlite3.connect
        main = threading.get_ident()
        threads = []
        def delayed(*args, **kwargs):
            entered.set()
            release.wait(5)
            return create(*args, **kwargs)
        def checked_connect(*args, **kwargs):
            threads.append(threading.get_ident())
            return connect(*args, **kwargs)
        def checked_render(*args):
            self.assertNotEqual(threading.get_ident(), main)
            return audit_preview(*args)
        with (patch.object(catalog_run_view, 'create_run', side_effect=delayed),
              patch.object(catalog_runs.sqlite3, 'connect', side_effect=checked_connect),
              patch('wifiscope.catalog_view.audit_preview', side_effect=checked_render)):
            runs.new_button.invoke()
            self.assertTrue(entered.wait(5))
            self.view.inventory['assets'][0]['id'] = 'EDITED-AFTER-DISPATCH'
            release.set()
            self.finish()
        self.assertTrue(threads)
        self.assertNotIn(main, threads)
        self.assertEqual(self.view.result['catalog_audit']['inventory']['assets'][0]['id'], 'PRIVATE-ASSET')
        self.assertIn('累计谓词', runs.status_text.get())
        self.assertIn('本页', self.view.output.get('1.0', 'end'))

    def test_whole_export_uses_separate_raw_choice_and_preserves_existing_output(self):
        runs = self.panel()
        runs.store_raw.set(True)
        runs.new_button.invoke()
        self.finish()
        runs.continue_button.invoke()
        self.finish()
        runs.previous_button.invoke()
        self.finish()
        destination = self.folder/'export'
        with patch('wifiscope.catalog_run_view.filedialog.asksaveasfilename', return_value=str(destination)):
            runs.export_button.invoke()
            self.finish()
            self.assertEqual(runs.page_number, 1)
            report = (destination/'page-0001/report.json').read_text(encoding='utf8')
            self.assertNotIn('PRIVATE-ASSET', report)
            self.assertFalse(json.loads(report)['identifiers_included'])
            runs.export_button.invoke()
            self.app.controller.worker.join(10)
            self.app.pump()
            self.root.update()
            self.assertIsNotNone(self.app.controller.tool_error)
            self.assertEqual((destination/'page-0001/report.json').read_text(encoding='utf8'), report)
        self.assertIsNone(self.app.controller.report)

    def test_blocked_and_limited_do_not_spin_and_partial_completion_stays_visible(self):
        runs = self.panel()
        runs.store_raw.set(True)
        with patch('wifiscope.catalog_chunks.MAX_PREDICATES', 1):
            runs.new_button.invoke()
            self.finish()
        self.assertEqual(runs.status['state'], 'blocked')
        self.assertTrue(runs.continue_button.instate(['disabled']))
        self.assertIsNone(self.view.result)
        self.assertIn('新建更小', runs.status_text.get())
        runs.run_path.set(str(self.folder/'limited.db'))
        runs.new_button.invoke()
        self.finish()
        with patch('wifiscope.catalog_runs.MAX_PAGES', 1):
            runs.continue_button.invoke()
            self.finish()
        self.assertEqual(runs.status['state'], 'limited')
        self.assertTrue(runs.continue_button.instate(['disabled']))
        partial = feed(2)
        partial['totalResults'] = 5
        source = self.folder/'partial.json'
        source.write_text(json.dumps(partial), encoding='utf8')
        db = self.folder/'partial.db'
        build_catalog([source], db)
        self.view.db_path.set(str(db))
        self.view.open_button.invoke()
        self.finish()
        runs.run_path.set(str(self.folder/'partial-run.db'))
        runs.page_size.set('256')
        runs.new_button.invoke()
        self.finish()
        self.assertEqual(runs.status['state'], 'complete')
        self.assertTrue(runs.status['source_partial'])
        self.assertIsNone(runs.status['unexamined_pairs'])
        self.assertIn('来源有缺口', runs.status_text.get())
        self.assertIn('不是安全证明', runs.status_text.get())
