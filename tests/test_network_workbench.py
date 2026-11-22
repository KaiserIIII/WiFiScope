import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def empty_pcap():
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


class NetworkWorkbenchTests(unittest.TestCase):
    def test_list_protocol_timeline_from_local_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp, "capture.pcap")
            source.write_bytes(empty_pcap())
            process = subprocess.run(
                [sys.executable, "-m", "wifiscope", "network", "timeline", "--input", str(source)],
                capture_output=True, encoding="utf-8", timeout=15, check=False,
            )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["packet_analysis"]["packets"], 0)

    def test_export_escapes_report_markup_and_hides_device_identifiers(self):
        from wifiscope.network_export import export_network
        data = {
            "schema_version": 1,
            "source": {"label": "switch<script>alert(1)</script>"},
            "routes": [{"prefix": "192.168.71.0/24", "next_hop": "192.168.70.73", "metric": 10}],
            "coverage": [{"section": "routes", "by_device": {"sensitive-hq-router": {"status": "observed"}}}],
            "notices": ["unstructured line identifying sensitive-hq-router"],
            "config": {"preview_lines": ["hostname <script>unexpected</script>"]},
        }
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp, "new")
            export_network(data, out)
            for name in ("report.json", "report.html", "report.csv"):
                text = Path(out, name).read_text(encoding="utf-8-sig")
                self.assertNotIn("192.168.70.73", text)
                self.assertNotIn("192.168.71.0", text)
                self.assertNotIn("<script>unexpected</script>", text)
                self.assertNotIn("sensitive-hq-router", text)
            with self.assertRaises(FileExistsError):
                export_network(data, out)

    def test_decoder_consumes_only_typed_display_columns(self):
        from wifiscope.packet_dissect import decode_fields
        body = (b"1\t0.0\t60\teth:ethertype:arp\n"
                b"2\t0.120\t74\teth:ip:tcp:tls\n"
                b"3\tnan\t120\teth:ip\n"
                b"4\t0.1\t88\teth:ip:<injected>\n")
        result = decode_fields(body, limit=10)
        self.assertEqual([r["packet_number"] for r in result["frames"]], [1, 2])
        self.assertEqual(result["frames"][1]["relative_ms"], 120.0)
        self.assertEqual(result["frames"][1]["protocols"], ["eth", "ip", "tcp", "tls"])
        self.assertEqual(result["skipped_rows"], 2)
        self.assertTrue(result["partial"])

    def test_packet_filter_respects_protocol_and_results_page(self):
        from wifiscope.network_present import packet_rows
        rows = [
            {"packet_number": 1, "protocol": "tcp", "event_type": "tcp-syn", "exchange_id": 1},
            {"packet_number": 2, "protocol": "dns", "event_type": "dns-query", "exchange_id": 2},
            {"packet_number": 3, "protocol": "tcp", "event_type": "tcp-handshake-complete", "exchange_id": 1},
        ]
        view = packet_rows(rows, protocol="tcp", query="complete", page=0, size=1)
        self.assertEqual(view["total"], 1)
        self.assertEqual(view["rows"], [rows[2]])


    def test_native_packet_page_filters_and_keeps_evidence(self):
        import tkinter as tk

        from wifiscope.network_workbench_view import NetworkWorkbench
        try:
            root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        self.addCleanup(root.destroy)
        root.withdraw()
        app = NetworkWorkbench(root)
        app.show_packets({"packet_analysis": {"packets": 3, "protocol_counts": {"tcp": 2, "dns": 1},
                         "protocol_timeline": {"events": [
                             {"packet_number": 1, "protocol": "tcp", "event_type": "tcp-syn"},
                             {"packet_number": 2, "protocol": "dns", "event_type": "dns-query"},
                             {"packet_number": 3, "protocol": "tcp", "event_type": "tcp-handshake-complete"},
                         ]}}})
        root.update()
        app.packets.protocol.set("dns")
        self.assertEqual(len(app.packets.table.tree.get_children()), 1)
        self.assertEqual(app.packets.table.selected_data[0]["event_type"], "dns-query")
        self.assertEqual(app.packets.report["packet_analysis"]["packets"], 3)
        app.close()


    def test_topology_and_diagnostics_views_render_real_shapes(self):
        import tkinter as tk

        from wifiscope.network_devices import parse_device_evidence
        from wifiscope.network_workbench_view import NetworkWorkbench

        try:
            root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        self.addCleanup(root.destroy)
        root.withdraw()
        app = NetworkWorkbench(root)
        app.devices.show(parse_device_evidence(
            "R2#show ip ospf neighbor\n"
            "Neighbor ID Pri State Dead Time Address Interface\n"
            "192.0.2.1 0 FULL/- 00:00:37 192.0.2.5 Serial1/0\n"
            "R2#\n"
        ))
        self.assertEqual(app.devices.table.selected_data[0]["target"], "192.0.2.1")
        app.diagnostics.show({"samples": [{"sequence": 1, "stages": {
            "path": {"status": "ok", "checks": [{"hops": [{"hop": 1, "addresses": ["192.0.2.1"]}]}]},
            "local": {"status": "ok", "routes": [{"destination": "192.0.2.0/24"}]},
        }}]})
        app.diagnostics.view.set("路径跳点")
        self.assertEqual(app.diagnostics.table.selected_data[0]["addresses"], ["192.0.2.1"])
        app.diagnostics.view.set("本机路由")
        self.assertEqual(app.diagnostics.table.selected_data[0]["destination"], "192.0.2.0/24")
        app.close()
