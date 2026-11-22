import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from wifiscope.network_export import project_network
from wifiscope.network_map import build_network_map
from wifiscope.zeek_flows import parse_zeek_flows

CONNECTION = {
    "ts": 1700000001.25,
    "uid": "synthetic-private-uid",
    "id.orig_h": "2001:db8::4",
    "id.orig_p": 48123,
    "id.resp_h": "2001:db8::81",
    "id.resp_p": 8080,
    "proto": "tcp",
    "duration": 0.875,
    "service": "http",
    "conn_state": "SF",
    "orig_bytes": 91,
    "resp_bytes": 380,
    "missed_bytes": 0,
}


def jsonl(*rows):
    return "\n".join(json.dumps(row) for row in rows).encode("utf-8")


class ZeekFlowTests(unittest.TestCase):
    def test_jsonl_maps_source_time_direction_and_preserves_unknown(self):
        report = parse_zeek_flows(jsonl(CONNECTION, dict(CONNECTION, service="ssl", resp_bytes=None, duration=None,
                                                        missed_bytes=None)))
        graph = build_network_map(flow_logs=[report])
        self.assertEqual(graph["map_sources"][0]["kind"], "zeek")
        self.assertEqual(graph["map_sources"][0]["observed_at"], "2023-11-14T22:13:21.250000+00:00")
        self.assertEqual(graph["map_sources"][0]["unknown_loss_rows"], 1)
        self.assertEqual([(e["kind"], e["orig_bytes"], e["resp_bytes"], e["duration_ms"], e["source_line"])
                          for e in graph["edges"]], [("zeek-flow", 91, 380, 875.0, 1), ("zeek-flow", 91, None, None, 2)])
        self.assertEqual([row["code"] for row in graph["findings"]], ["zeek-http"])
        self.assertEqual(graph["findings"][0]["node_id"], graph["edges"][0]["to_node"])
        projected = project_network(graph)
        rendered = json.dumps(projected)
        for private in ("2001:db8::81", "2001:db8::4", "synthetic-private-uid"):
            self.assertNotIn(private, rendered)
        self.assertEqual(projected["edges"][0]["service"], ["http"])

    def test_tabular_format_header_columns_and_partial_rows(self):
        data = (
            "#separator \\x09\n#path\tconn\n#unset_field\t-\n"
            "#fields\tid.resp_h\tid.orig_h\tproto\tts\tservice\tmissed_bytes\tduration\n"
            "192.0.2.9\t192.0.2.1\tudp\t1700000000\tdns\t19\t-\n"
            "192.0.2.9\tbad\tudp\t1700000000\tdns\t0\t-\n"
            "#close\t2023-11-14-22-14-00\n"
        ).encode()
        graph = build_network_map(flow_logs=[parse_zeek_flows(data)])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["missed_bytes"], 19)
        self.assertIsNone(graph["edges"][0]["duration_ms"])
        source = graph["map_sources"][0]
        self.assertEqual(source["status"], "partial")
        self.assertEqual(source["skipped_rows"], 1)
        self.assertEqual(source["loss_rows"], 1)
        self.assertEqual(graph["findings"], [])

    def test_service_classification_requires_known_clean_http(self):
        altered = [dict(CONNECTION, service=service) for service in ("-http", "unknown<script>", "ssl,http",
                                                                    "http,-http")]
        altered.append(dict(CONNECTION, service="ssl,http", failed_service=["http"]))
        graph = build_network_map(flow_logs=[parse_zeek_flows(jsonl(*altered))])
        self.assertEqual([row["service"] for row in graph["edges"]], [[], [], ["ssl", "http"], [], ["ssl"]])
        self.assertEqual([row["source_line"] for row in graph["findings"]], [3])

    def test_invalid_or_unrelated_input_is_rejected(self):
        for raw in (b'{"note":"Scan::Port_Scan"}\n', b"junk", b"#separator \\x09\n#path\thttp\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_zeek_flows(raw)

    def test_icmp_type_code_and_same_ip_across_known_vlans(self):
        row = dict(CONNECTION, proto="icmpv6", service="http", vlan=10, inner_vlan=100)
        row.update({"id.orig_h": "2001:db8::a", "id.orig_p": 128, "id.resp_p": 0})
        graph = build_network_map(flow_logs=[parse_zeek_flows(jsonl(row, dict(row, inner_vlan=101)))])
        self.assertEqual({node["context"] for node in graph["nodes"]}, {"VLAN 10 / 100", "VLAN 10 / 101"})
        self.assertEqual(len(graph["nodes"]), 4)
        self.assertEqual([(edge["src_port"], edge["dst_port"], edge["icmp_type"], edge["icmp_code"])
                          for edge in graph["edges"]], [(None, None, 128, 0), (None, None, 128, 0)])
        self.assertFalse(graph["findings"])

    def test_cli_and_native_flow_browser(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "conn.log")
            path.write_bytes(jsonl(CONNECTION))
            run = subprocess.run([sys.executable, "-m", "wifiscope", "network", "map", "--zeek", str(path)],
                                 capture_output=True, text=True, encoding="utf-8", timeout=20, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["edges"][0]["kind"], "zeek-flow")

        import tkinter as tk

        from wifiscope.network_workbench_view import NetworkWorkbench

        try:
            root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        self.addCleanup(root.destroy)
        root.withdraw()
        app = NetworkWorkbench(root)
        self.addCleanup(app.close)
        app.mapping.show(build_network_map(flow_logs=[parse_zeek_flows(jsonl(CONNECTION))]))
        app.mapping.mode.set("流量")
        app.mapping.category.set("HTTP")
        root.update()
        self.assertEqual(len(app.mapping.current), 1)
        self.assertTrue(app.mapping.graph.find_withtag("active-flow"))
        self.assertIn("380", app.mapping.table.details.get("1.0", "end"))
        app.mapping.query.set("192.0.2.20")
        self.assertEqual(len(app.mapping.current), 0)
