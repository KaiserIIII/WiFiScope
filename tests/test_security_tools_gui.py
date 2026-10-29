"""Security tools: actual Tk actions, queued workers and offline evidence only."""

import copy
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from wifiscope.demo import demo_report
from wifiscope.gui import Workstation
from wifiscope.gui_controller import Controller


class ToolQueueTests(unittest.TestCase):
    def test_explicit_apply_validates_heavy_report_in_worker_and_assigns_only_on_poll(
        self,
    ):
        from wifiscope.case_validation import validate_report

        c = Controller()
        original, replacement = demo_report(), demo_report()
        c.accept(original, "original")
        c.snapshot_id, c.tool_owner = 8, "panel"
        validation_threads = []

        def validate(report):
            validation_threads.append(threading.get_ident())
            return validate_report(report)

        with patch("wifiscope.gui_controller.validate_report", side_effect=validate):
            c.apply_tool(replacement, "explicit apply", "panel")
            c.worker.join(3)
            self.assertIs(c.report, original)
            c.poll()
        self.assertEqual(len(validation_threads), 1)
        self.assertNotEqual(validation_threads[0], threading.get_ident())
        self.assertIsNot(c.report, original)
        self.assertIsNone(c.snapshot_id)

    def test_progress_rejects_prose_and_ignores_regressing_counters(self):
        c = Controller()
        c.tool_owner = "p"

        def work(cancel, progress):
            progress(
                dict(packets=5, captured_bytes=100, elapsed_ms=400, status="running")
            )
            progress(
                dict(packets=2, captured_bytes=40, elapsed_ms=200, status="running")
            )
            return demo_report()

        c.start_tool("fake capture", work, "p")
        c.worker.join(3)
        c.poll()
        self.assertEqual(c.tool_progress["packets"], 5)
        self.assertEqual(
            set(c.tool_progress), {"packets", "captured_bytes", "elapsed_ms", "status"}
        )

        def invalid(cancel, progress):
            progress(
                dict(packets=0, captured_bytes=0, elapsed_ms=0, status="PRIVATE PROSE")
            )

        c.start_tool("invalid progress", invalid, "p")
        c.worker.join(3)
        c.poll()
        self.assertIsNone(c.tool_result)
        self.assertNotIn("PRIVATE PROSE", c.tool_error)

    def test_invalid_apply_and_closed_apply_keep_current_case(self):
        c = Controller()
        original = demo_report()
        c.accept(original, "original")
        c.snapshot_id, c.tool_owner = 9, "panel"
        c.apply_tool(dict(schema_version=1, wifi_survey={}), "bad apply", "panel")
        c.worker.join(3)
        c.poll()
        self.assertIs(c.report, original)
        self.assertEqual(c.snapshot_id, 9)
        self.assertIsNotNone(c.tool_error)
        c.apply_tool(demo_report(), "closed apply", "panel")
        c.worker.join(3)
        c.tool_owner = None
        c.poll()
        self.assertIs(c.report, original)
        self.assertEqual(c.snapshot_id, 9)

    def test_progress_keeps_shared_busy_and_persisted_model_until_apply(self):
        c = Controller()
        original = demo_report()
        c.accept(original, "original")
        c.snapshot_id, c.case_path, c.overlay = (
            7,
            "case.db",
            {"f": {"status": "investigating"}},
        )
        c.tool_owner = "panel"
        ready, finish = threading.Event(), threading.Event()

        def work(cancel, progress):
            progress(
                dict(packets=2, captured_bytes=80, elapsed_ms=200, status="running")
            )
            ready.set()
            finish.wait(2)
            return demo_report()

        c.start_tool("capture", work, "panel")
        ready.wait(2)
        c.poll()
        self.assertTrue(c.busy)
        self.assertEqual(c.tool_progress["packets"], 2)
        self.assertIs(c.report, original)
        self.assertEqual(c.snapshot_id, 7)
        self.assertEqual(c.overlay["f"]["status"], "investigating")
        finish.set()
        c.worker.join(3)
        c.poll()
        self.assertFalse(c.busy)
        self.assertIs(c.report, original)
        self.assertIsNotNone(c.tool_result)

    def test_closed_owner_ignores_stale_progress_result_and_errors(self):
        c = Controller()
        c.tool_owner = "closed"

        def work(cancel, progress):
            cancel.wait(2)
            progress(
                dict(packets=1, captured_bytes=96, elapsed_ms=201, status="running")
            )
            return demo_report()

        c.start_tool("capture", work, "closed")
        c.tool_owner = None
        c.cancel()
        c.worker.join(3)
        c.poll()
        self.assertIsNone(c.tool_result)
        self.assertIsNone(c.tool_progress)
        self.assertFalse(c.busy)
        self.assertIsNone(c.report)


class SecurityToolsTkTests(unittest.TestCase):
    def action(self, widget, label):
        for child in widget.winfo_children():
            if hasattr(child, "invoke") and child.cget("text") == label:
                return child
            found = self.action(child, label)
            if found is not None:
                return found

    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest(
                "Tk/display unavailable; native UI coverage remains unverified."
            )
        self.app = Workstation(self.root)
        self.root.geometry("900x620+20+20")
        self.root.update()

    def tearDown(self):
        self.app.close()

    def finish(self):
        worker = self.app.controller.worker
        if worker:
            worker.join(5)
        self.app.pump()
        self.root.update()

    def tools(self, name="capture"):
        self.app.open_security_tools(name)
        self.root.update()
        return self.app.security_tools

    def test_open_modes_tabs_and_clicks_do_no_io_and_default_plan(self):
        with (
            patch("wifiscope.capture_view.list_capture_interfaces") as enum,
            patch("wifiscope.capture_view.capture_live") as capture,
            patch("wifiscope.survey_view.collect_local") as collect,
            patch("wifiscope.vulnerability_view.builtin_catalog") as catalog,
        ):
            view = self.tools()
            self.app.set_mode("professional")
            self.app.set_mode("novice")
            view.show("survey")
            survey = view.panels["survey"]
            survey.select_position(type("Click", (), {"x": 140, "y": 110})())
            enum.assert_not_called()
            capture.assert_not_called()
            collect.assert_not_called()
            catalog.assert_not_called()
            panel = view.panels["capture"]
            self.assertEqual(
                [
                    v.get()
                    for v in (
                        panel.duration,
                        panel.max_packets,
                        panel.max_bytes,
                        panel.snaplen,
                    )
                ],
                ["10", "2000", "8388608", "96"],
            )
            self.assertFalse(panel.authorized.get())
            self.assertFalse(panel.raw_optin.get())
            self.assertFalse(panel.promiscuous.get())

    def test_audit_refreshes_current_coverage_and_builtin_pin_is_not_silently_ignored(
        self,
    ):
        v = self.tools("vulnerability")
        self.app.controller.accept(demo_report(), "new current evidence")
        v.show("vulnerability")
        p = v.panels["vulnerability"]
        self.assertIn(
            str(len(self.app.controller.report["sources"])) + " 个来源",
            p.evidence.get(),
        )
        p.expected_sha256.set("0" * 64)
        with patch("wifiscope.vulnerability_view.audit_vulnerabilities") as audit:
            p.audit_button.invoke()
            self.assertFalse(self.app.controller.busy)
            audit.assert_not_called()
        self.assertIn("native", v.status.get())

    def test_capture_buttons_authorization_invalidation_and_separate_raw_optin(self):
        view = self.tools()
        p = view.panels["capture"]
        rows = [
            dict(
                interface="fake-loopback",
                label="Synthetic adapter",
                backend="npcap",
                loopback=True,
                supports_filter=True,
                supports_promiscuous=True,
                linktype=1,
            )
        ]
        with patch("wifiscope.capture_view.list_capture_interfaces", return_value=rows):
            p.enumerate_button.invoke()
            self.finish()
        self.assertEqual(p.interface.get(), "")
        p.interface.set("fake-loopback")
        with patch(
            "wifiscope.capture_view.capture_live", return_value=demo_report()
        ) as capture:
            p.start_button.invoke()
            capture.assert_not_called()
            p.authorized.set(True)
            p.snaplen.set("200")
            self.assertFalse(p.authorized.get())
            p.authorized.set(True)
            p.start_button.invoke()
            capture.assert_not_called()
            p.raw_optin.set(True)
            p.authorized.set(True)
            p.start_button.invoke()
            self.finish()
            self.assertEqual(capture.call_args.kwargs["snaplen"], 200)
            self.assertTrue(capture.call_args.kwargs["retain_packets"])
            self.assertIsNone(capture.call_args.kwargs["raw_path"])

    def test_idle_capture_cancel_actual_queue_and_worker_has_no_tk_reads(self):
        view = self.tools()
        p = view.panels["capture"]
        p.interfaces = [
            dict(interface="fake", supports_filter=True, supports_promiscuous=True)
        ]
        p.interface.set("fake")
        p.authorized.set(True)
        threads = []

        def capture(interface, **kwargs):
            threads.append(threading.get_ident())
            kwargs["progress"](
                dict(packets=0, captured_bytes=0, elapsed_ms=200, status="running")
            )
            kwargs["cancel"].wait(2)
            return demo_report()

        with patch("wifiscope.capture_view.capture_live", side_effect=capture):
            p.start_button.invoke()
            time.sleep(0.02)
            self.app.controller.poll()
            self.assertTrue(self.app.controller.busy)
            view.cancel_button.invoke()
            self.finish()
        self.assertNotEqual(threads[0], threading.get_ident())
        self.assertIn("0", p.progress.get())
        self.assertIsNone(self.app.controller.report)
        self.assertIsNotNone(p.result)

    def test_real_engine_demos_keep_case_until_explicit_apply_and_safe_exports(self):
        original = demo_report()
        self.app.controller.accept(original, "original")
        self.app.controller.snapshot_id = 42
        self.app.controller.overlay = {"f": {"note": "LOCAL NOTE"}}
        view = self.tools("vulnerability")
        p = view.panels["vulnerability"]
        p.demo_button.invoke()
        self.finish()
        self.assertGreaterEqual(len(p.result["vulnerability_audit"]["candidates"]), 3)
        self.assertIs(self.app.controller.report, original)
        self.assertEqual(self.app.controller.snapshot_id, 42)
        view.apply_button.invoke()
        self.assertIs(self.app.controller.report, original)
        view.replace_current.set(True)
        view.apply_button.invoke()
        self.finish()
        self.assertEqual(self.app.controller.report, p.result)
        self.assertIsNone(self.app.controller.snapshot_id)
        view.show("survey")
        s = view.panels["survey"]
        s.demo_button.invoke()
        self.finish()
        self.assertGreater(s.project["grid"]["estimated_count"], 0)
        self.assertGreater(s.project["grid"]["unknown_count"], 0)
        with tempfile.TemporaryDirectory() as temp:
            with patch(
                "wifiscope.security_tools_view.filedialog.asksaveasfilename",
                return_value=str(Path(temp) / "bundle"),
            ):
                view.export_button.invoke()
                self.finish()
            text = (Path(temp) / "bundle" / "report.json").read_text(encoding="utf-8")
            self.assertNotIn("Synthetic Survey SSID", text)
            self.assertNotIn("LOCAL NOTE", text)
            self.assertTrue((Path(temp) / "bundle" / "heatmap.svg").exists())

    def test_geometry_zoom_pan_resize_preserve_normalized_samples_and_no_click_collection(
        self,
    ):
        p = self.tools("survey").panels["survey"]
        p.demo_button.invoke()
        self.finish()
        before = copy.deepcopy(p.project["samples"])
        p.canvas.configure(width=500, height=300)
        self.root.update()
        p.zoom_by(1.5)
        p.pan(25, -10)
        x, y = p.to_canvas(0.3, 0.4)
        self.assertAlmostEqual(p.from_canvas(x, y)[0], 0.3)
        self.assertAlmostEqual(p.from_canvas(x, y)[1], 0.4)
        self.assertEqual(p.project["samples"], before)
        with patch("wifiscope.survey_view.render_heatmap_svg") as render:
            p.draw()
            p.pan(5, 5)
            render.assert_not_called()
        x, y = p.to_canvas(0.3, 0.4)
        _, _, width, height = p.transform()
        with patch("wifiscope.survey_view.collect_local") as collect:
            p.select_position(type("Click", (), {"x": round(x), "y": round(y)})())
            collect.assert_not_called()
        self.assertAlmostEqual(p.position[0], 0.3, delta=1 / width)
        self.assertAlmostEqual(p.position[1], 0.4, delta=1 / height)
        self.assertEqual(p.project["samples"], before)

    def test_literal_ssid_spaces_create_sample_and_reopen_through_real_queue(self):
        from wifiscope.survey import save_project

        p = self.tools('survey').panels['survey']
        rows = [
            dict(ssid='Lab ', bssid='02:00:00:00:00:01', signal_percent=25),
            dict(ssid='Lab', bssid='02:00:00:00:00:02', signal_percent=95),
            dict(ssid=' Lab', bssid='02:00:00:00:00:03', signal_percent=35),
            dict(ssid=' ', bssid='02:00:00:00:00:04', signal_percent=45),
        ]
        for ssid, bssid, value in (
            ('Lab ', '02:00:00:00:00:01', 25),
            ('Lab', '02:00:00:00:00:02', 95),
            (' Lab', '02:00:00:00:00:03', 35),
            (' ', '02:00:00:00:00:04', 45),
        ):
            with self.subTest(ssid=ssid), tempfile.TemporaryDirectory() as temp:
                p.ssid.set(ssid)
                p.bssid.set('')
                self.action(p.frame, '创建新项目（保留主快照）').invoke()
                self.finish()
                self.assertEqual((p.project['ssid'], p.project['bssid']), (ssid, None))
                for phase in ('created', 'reopened'):
                    if phase == 'reopened':
                        path = Path(temp) / 'project.json'
                        original = copy.deepcopy(p.project)
                        save_project(original, path)
                        with patch(
                            'wifiscope.survey_view.filedialog.askopenfilename',
                            return_value=str(path),
                        ):
                            self.action(p.frame, '打开项目 JSON').invoke()
                            self.finish()
                        self.assertEqual(p.project, original)
                    p.position = (0.3, 0.4)
                    stamp = (
                        '2026-10-29T11:22:33+00:00' if phase == 'created'
                        else '2026-10-29T11:23:34+00:00'
                    )
                    with patch(
                        'wifiscope.survey_view.collect_local',
                        return_value=dict(collected_at=stamp, wifi=rows),
                    ):
                        p.sample_button.invoke()
                        self.finish()
                    self.assertEqual(
                        len(p.project['samples']), 1 if phase == 'created' else 2
                    )
                    item = p.project['samples'][-1]
                    self.assertEqual(
                        (p.ssid.get(), p.project['ssid'], p.project['bssid']),
                        (ssid, ssid, bssid),
                    )
                    self.assertEqual(
                        (item['ssid'], item['bssid'], item['value']), (ssid, bssid, value)
                    )
                    self.assertEqual(
                        (item['x'], item['y'], item['observed_at']), (0.3, 0.4, stamp)
                    )
                    self.assertEqual(item['source'], 'measured')
                    self.assertIsNone(item['gap'])
                p.ssid.set('different')
                before = copy.deepcopy(p.project)
                with patch('wifiscope.survey_view.collect_local') as collect:
                    p.sample_button.invoke()
                    self.finish()
                    collect.assert_not_called()
                self.assertEqual(p.project, before)
        p.ssid.set('')
        p.bssid.set(' 02:00:00:00:00:01 ')
        self.action(p.frame, '创建新项目（保留主快照）').invoke()
        self.finish()
        self.assertEqual(
            (p.project['ssid'], p.project['bssid']), (None, '02:00:00:00:00:01')
        )

    def test_floorplan_preallocation_limits_png_gif_and_no_external_reference(self):
        from wifiscope.survey_view import floorplan_bytes

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.png"
            path.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + struct.pack("!I4sII", 13, b"IHDR", 9000, 1)
                + b"0" * 20
            )
            with self.assertRaises(ValueError):
                floorplan_bytes(path)
            path.write_bytes(b"GIF89a" + struct.pack("<HH", 8192, 8192) + b"0" * 20)
            with self.assertRaises(ValueError):
                floorplan_bytes(path)
            path.write_text(
                '<svg><image href="https://example.invalid"/></svg>', encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                floorplan_bytes(path)

    def test_survey_sampling_uses_collector_timestamp_unknown_metric_and_reversible_remove(
        self,
    ):
        p = self.tools("survey").panels["survey"]
        p.ssid.set("Lab")
        p.bssid.set("AP-A")
        p.metric.set("dbm")
        p.new_project()
        p.position = (0.3, 0.4)
        stamp = "2026-10-29T11:22:33+00:00"
        with patch(
            "wifiscope.survey_view.collect_local",
            return_value=dict(
                collected_at=stamp,
                wifi=[dict(ssid="Lab", bssid="AP-A", signal_percent=80)],
            ),
        ) as collect:
            p.sample_button.invoke()
            self.finish()
            self.assertEqual(collect.call_count, 1)
        item = p.project["samples"][0]
        self.assertIsNone(item["value"])
        self.assertEqual(item["gap"], "signal-unavailable")
        self.assertEqual(item["observed_at"], stamp)
        p.table.selection_set(item["id"])
        p.remove_button.invoke()
        self.finish()
        self.assertEqual(p.project["samples"], [])
        p.undo_remove()
        self.finish()
        self.assertEqual(p.project["samples"][0]["id"], item["id"])

    def test_synthetic_project_save_is_controlled_refusal_and_sampling_stays_blocked(
        self,
    ):
        p = self.tools("survey").panels["survey"]
        p.demo_button.invoke()
        self.finish()
        before = copy.deepcopy(p.result)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.json"
            with patch(
                "wifiscope.survey_view.filedialog.asksaveasfilename",
                return_value=str(path),
            ) as dialog:
                self.action(p.frame, "保存本地项目").invoke()
                self.assertFalse(self.app.controller.busy)
                self.assertFalse(path.exists())
                dialog.assert_not_called()
        self.assertIn("合成", self.app.security_tools.status.get())
        self.assertIn("导出", self.app.security_tools.status.get())
        p.position = (0.4, 0.4)
        with patch("wifiscope.survey_view.collect_local") as collector:
            p.sample_button.invoke()
            collector.assert_not_called()
        self.assertTrue(p.synthetic)
        self.assertIn("合成", p.summary.get())
        self.assertEqual(p.result, before)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "synthetic-report"
            with patch(
                "wifiscope.security_tools_view.filedialog.asksaveasfilename",
                return_value=str(directory),
            ):
                self.app.security_tools.export_button.invoke()
                self.finish()
            report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["synthetic"])
            self.assertIn(
                "SYNTHETIC DEMO",
                (directory / "report.html").read_text(encoding="utf-8"),
            )
            self.assertTrue((directory / "heatmap.svg").exists())
            self.assertIn(
                'SYNTHETIC DEMO: illustrative readings; no actual network was sampled.',
                (directory / "heatmap.svg").read_text(encoding="utf-8"),
            )

    def test_ordinary_project_save_open_remains_exclusive_and_live_sampleable(self):
        p = self.tools("survey").panels["survey"]
        p.ssid.set("Ordinary")
        p.bssid.set("AP-A")
        p.new_project()
        original = copy.deepcopy(p.project)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ordinary.json"
            with patch(
                "wifiscope.survey_view.filedialog.asksaveasfilename",
                return_value=str(path),
            ):
                self.action(p.frame, "保存本地项目").invoke()
                self.finish()
                self.assertEqual(
                    json.loads(path.read_text(encoding="utf-8"))["id"], original["id"]
                )
                first = path.read_bytes()
                self.action(p.frame, "保存本地项目").invoke()
                self.finish()
                self.assertEqual(path.read_bytes(), first)
            with patch(
                "wifiscope.survey_view.filedialog.askopenfilename",
                return_value=str(path),
            ):
                self.action(p.frame, "打开项目 JSON").invoke()
                self.finish()
            self.assertFalse(p.synthetic)
            self.assertEqual(p.project["id"], original["id"])
            p.position = (0.2, 0.3)
            stamp = "2026-10-29T12:00:00+00:00"
            with patch(
                "wifiscope.survey_view.collect_local",
                return_value=dict(
                    collected_at=stamp,
                    wifi=[dict(ssid="Ordinary", bssid="AP-A", signal_percent=42)],
                ),
            ) as collect:
                p.sample_button.invoke()
                self.finish()
                self.assertEqual(collect.call_count, 1)
            self.assertEqual(p.project["samples"][0]["value"], 42)
            self.assertEqual(p.project["samples"][0]["observed_at"], stamp)

    def test_project_replacement_json_csv_and_demo_reset_undo_even_same_id(self):
        from wifiscope.survey import save_project

        p = self.tools("survey").panels["survey"]
        stamp = "2026-10-29T12:00:00+00:00"
        with tempfile.TemporaryDirectory() as temp:
            for kind in ("json", "csv", "demo"):
                with self.subTest(kind=kind):
                    self.app.security_tools.close()
                    p = self.tools("survey").panels["survey"]
                    p.demo_button.invoke()
                    self.finish()
                    p.table.selection_set(p.project["samples"][0]["id"])
                    p.remove_button.invoke()
                    self.finish()
                    self.assertEqual(len(p.undo), 1)
                    if kind == "json":
                        # A replacement is still a replacement when all identity fields match.
                        data = copy.deepcopy(p.project)
                        data.pop("grid", None)
                        data["samples"] = []
                        path = Path(temp) / "replacement.json"
                        save_project(data, path)
                        label = "打开项目 JSON"
                    elif kind == "csv":
                        path = Path(temp) / "replacement.csv"
                        path.write_text(
                            "x,y,value,observed_at,ssid,bssid,metric\n"
                            + f".1,.2,25,{stamp},Replacement,AP-B,signal_percent\n",
                            encoding="utf-8",
                        )
                        label = "导入 CSV"
                    if kind == "demo":
                        p.demo_button.invoke()
                        self.finish()
                    else:
                        with patch(
                            "wifiscope.survey_view.filedialog.askopenfilename",
                            return_value=str(path),
                        ):
                            self.action(p.frame, label).invoke()
                            self.finish()
                    self.assertEqual(len(p.undo), 0)
                    before = copy.deepcopy(p.result)
                    self.action(p.frame, "撤销移除").invoke()
                    self.assertFalse(self.app.controller.busy)
                    self.assertEqual(p.result, before)
                    self.assertEqual(p.synthetic, kind == "demo")

    def test_same_project_undo_restores_complete_provenance_and_failed_open_keeps_history(
        self,
    ):
        p = self.tools("survey").panels["survey"]
        p.demo_button.invoke()
        self.finish()
        original = copy.deepcopy(p.result)
        p.table.selection_set(p.project["samples"][0]["id"])
        p.remove_button.invoke()
        self.finish()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text(json.dumps({"invalid": True}), encoding="utf-8")
            with patch(
                "wifiscope.survey_view.filedialog.askopenfilename",
                return_value=str(path),
            ):
                self.action(p.frame, "打开项目 JSON").invoke()
                self.finish()
        self.assertEqual(len(p.undo), 1)
        self.action(p.frame, "撤销移除").invoke()
        self.finish()
        self.assertTrue(
            p.result == original,
            "Undo must restore the complete original report provenance.",
        )
        self.assertTrue(p.synthetic)
        self.assertIn("合成", p.summary.get())

    def test_local_floorplan_button_decodes_safe_gif_and_controls_invalid_png(self):
        import base64

        p = self.tools("survey").panels["survey"]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "local.gif"
            path.write_bytes(
                base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
            )

            def find(widget):
                for child in widget.winfo_children():
                    if (
                        hasattr(child, "invoke")
                        and child.cget("text") == "加载本地 PNG/GIF"
                    ):
                        return child
                    found = find(child)
                    if found:
                        return found

            button = find(p.frame)
            with patch(
                "wifiscope.survey_view.filedialog.askopenfilename",
                return_value=str(path),
            ):
                button.invoke()
                self.finish()
            self.assertEqual((p.image.width(), p.image.height()), (1, 1))
            before = p.image
            path.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + struct.pack("!I4sII", 13, b"IHDR", 9000, 1)
                + b"0" * 20
            )
            with patch(
                "wifiscope.survey_view.filedialog.askopenfilename",
                return_value=str(path),
            ):
                button.invoke()
                self.finish()
            self.assertIs(p.image, before)
            self.assertIsNone(self.app.controller.report)

    def test_capture_unavailable_backend_and_unsupported_filter_are_actionable(self):
        p = self.tools().panels["capture"]
        with patch(
            "wifiscope.capture_view.list_capture_interfaces",
            side_effect=ValueError("PRIVATE PATH / DRIVER ERROR"),
        ):
            p.enumerate_button.invoke()
            self.finish()
        self.assertIn("驱动", self.app.security_tools.status.get())
        self.assertNotIn("PRIVATE PATH", self.app.security_tools.status.get())
        p.interfaces = [
            dict(interface="fake", supports_filter=False, supports_promiscuous=False)
        ]
        p.interface.set("fake")
        p.packet_filter.set("tcp")
        p.authorized.set(True)
        with patch("wifiscope.capture_view.capture_live") as capture:
            p.start_button.invoke()
            capture.assert_not_called()
        self.assertIn("不支持", self.app.security_tools.status.get())

    def test_close_does_not_cancel_unrelated_main_operation_and_no_stale_callbacks(
        self,
    ):
        v = self.tools()
        v.panels["capture"].demo_button.invoke()
        self.finish()
        self.app.controller.start(
            "other", lambda stop: (stop.wait(0.1), demo_report())[1]
        )
        v.close()
        self.assertFalse(self.app.controller.stop.is_set())
        self.finish()

    def test_three_typed_html_sections_shared_privacy_and_case_roundtrip(self):
        from wifiscope.demo import vulnerability_demo, capture_demo, survey_demo
        from wifiscope.reports import export_report
        from wifiscope.cases import CaseStore

        report = vulnerability_demo()
        report["capture_session"] = capture_demo()["capture_session"]
        report["wifi_survey"] = survey_demo()["wifi_survey"]
        report["vulnerability_audit"]["candidates"][0]["notes"] = (
            "PRIVATE IMPORTED PROSE"
        )
        report["wifi_survey"]["floorplan"] = "C:/PRIVATE/FLOOR.png"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            export_report(report, root / "default")
            export_report(report, root / "raw", True)
            for folder in ("default", "raw"):
                text = (root / folder / "report.html").read_text(encoding="utf-8")
                self.assertIn("漏洞审计", text)
                self.assertIn("抓包会话", text)
                self.assertIn("Wi-Fi 调查", text)
                self.assertNotIn("PRIVATE IMPORTED PROSE", text)
                self.assertNotIn("PRIVATE/FLOOR", text)
            self.assertNotIn(
                "Synthetic Survey SSID",
                (root / "default/report.json").read_text(encoding="utf-8"),
            )
            with self.assertRaises(FileExistsError):
                export_report(report, root / "default")
            with CaseStore(root / "case.db") as store:
                identifier = store.add_snapshot(report)
                loaded = store.load_snapshot(identifier)
                self.assertIn("capture_session", loaded)
                self.assertIn("wifi_survey", loaded)
                self.assertIn("vulnerability_audit", loaded)

    def test_viewport_footer_and_header_actions_reachable_both_modes_all_panels(self):
        for mode in ("novice", "professional"):
            self.app.set_mode(mode)
            self.root.update()
            for button in self.app.security_buttons:
                self.assertTrue(button.winfo_ismapped())
                self.assertGreaterEqual(button.winfo_rootx(), self.root.winfo_rootx())
                self.assertLessEqual(
                    button.winfo_rootx() + button.winfo_width(),
                    self.root.winfo_rootx() + 900,
                )
            if mode == "professional":
                for button in self.app.professional.winfo_children()[
                    0
                ].winfo_children():
                    self.assertLessEqual(
                        button.winfo_rootx() + button.winfo_width(),
                        self.root.winfo_rootx() + 900,
                    )
                    self.assertGreaterEqual(
                        button.winfo_width(), button.winfo_reqwidth()
                    )
            view = self.tools()
            view.window.geometry("900x620+20+20")
            for panel in ("capture", "vulnerability", "survey"):
                view.show(panel)
                self.root.update()
                for button in (
                    view.apply_button,
                    view.export_button,
                    view.cancel_button,
                ):
                    self.assertTrue(button.winfo_ismapped())
                    self.assertGreaterEqual(
                        button.winfo_rootx(), view.window.winfo_rootx()
                    )
                    self.assertLessEqual(
                        button.winfo_rootx() + button.winfo_width(),
                        view.window.winfo_rootx() + 900,
                    )
                    self.assertGreaterEqual(
                        button.winfo_rooty(), view.window.winfo_rooty()
                    )
                    self.assertLessEqual(
                        button.winfo_rooty() + button.winfo_height(),
                        view.window.winfo_rooty() + 620,
                    )
            view.close()


class FloorplanSafetyTests(unittest.TestCase):
    def test_gif_subimage_cannot_exceed_declared_safe_canvas(self):
        from wifiscope.survey_view import floorplan_bytes

        # Safe logical dimensions must not hide a larger raster frame allocation.
        data = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0)
        data += (
            b"," + struct.pack("<HHHHB", 0, 0, 65535, 65535, 0) + b"\x02\x01\x00\x00;"
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "frame.gif"
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                floorplan_bytes(path)

    def test_safe_gif_header_and_oversized_input(self):
        from wifiscope.survey_view import floorplan_bytes
        import base64

        data = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "safe.gif"
            path.write_bytes(data)
            self.assertEqual(floorplan_bytes(path)[1:], (1, 1))
            path.write_bytes(b"0" * (8 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                floorplan_bytes(path)
        with patch("pathlib.Path.open") as opened:
            for path in (
                "https://example.invalid/plan.png",
                "//server/share/plan.gif",
                "\\\\server\\share\\plan.gif",
            ):
                with self.assertRaises(ValueError):
                    floorplan_bytes(path)
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
