import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from wifiscope.network_devices import compare_device_evidence, parse_device_evidence
from wifiscope.network_export import export_network, project_network
from wifiscope.network_map import build_network_map, read_map_evidence

DEVICE_TEXT = (
    "private-router#show ip ospf neighbor\n"
    "Neighbor ID Pri State Dead Time Address Interface\n"
    "192.0.2.1 0 FULL/- 00:00:37 192.0.2.5 Serial1/0\n"
    "private-router#show lldp neighbors\n"
    "Device ID Local Intf Hold-time Capability Port ID\n"
    "private-switch Gi0/1 123 B Gi0/2\n"
    "private-router#\n"
)
CAPTURE = {"packet_analysis": {
    "endpoints": [{"address": "192.0.2.1", "packets": 10}],
    "conversations": [{"src_address": "192.0.2.1", "dst_address": "192.0.2.7",
                       "src_port": 41000, "dst_port": 8080, "protocol": "tcp", "packets": 5}],
    "arp_bindings": [{"address": "192.0.2.1", "mac": "02:00:00:00:00:01"},
                     {"address": "192.0.2.1", "mac": "02:00:00:00:00:02"}],
    "observations": [{"code": "arp-conflict", "address": "192.0.2.1"}],
    "protocol_timeline": {"events": [
        {"protocol": "http", "event_type": "http-request", "packet_number": 7,
         "src_address": "192.0.2.1", "dst_address": "192.0.2.7", "dst_port": 8080},
        {"protocol": "http", "event_type": "http-request", "packet_number": 9,
         "src_address": "192.0.2.1", "dst_address": "192.0.2.7", "dst_port": 8080},
    ]},
}}
DIAGNOSTICS = {"samples": [{"sequence": 2, "stages": {"local": {
    "status": "ok", "interfaces": [{"interface": "private-adapter", "addresses": ["192.0.2.1/24"]}],
    "neighbors": [{"ip": "192.0.2.7", "interface": "private-adapter", "mac": "02:00:00:00:00:02"}],
    "routes": [{"destination": "0.0.0.0/0", "gateway": "192.0.2.7", "interface": "private-adapter",
                "nexthops": [{"gateway": "192.0.2.9", "interface": "private-adapter"}]}],
    "listeners": [
        {"address": "0.0.0.0", "protocol": "tcp", "port": 8080, "bind": "wildcard"},
        {"address": "127.0.0.1", "protocol": "tcp", "port": 8000, "bind": "loopback"},
        {"address": "192.0.2.1", "protocol": "udp", "port": 53, "bind": "specific"},
    ],
}}}]}


class NetworkMapTests(unittest.TestCase):
    def test_relations_and_findings_remain_in_evidence_scopes(self):
        report = build_network_map(captures=[CAPTURE, CAPTURE],
                                   devices=[parse_device_evidence(DEVICE_TEXT)], diagnostics=[DIAGNOSTICS])
        nodes = {node["node_id"]: node for node in report["nodes"]}
        self.assertEqual(len([node for node in nodes.values() if node["label"] == "192.0.2.1"]), 4)
        kinds = {edge["kind"] for edge in report["edges"]}
        self.assertTrue({"observed-traffic", "arp-claim", "ospf-neighbor", "lldp-neighbor",
                         "cached-neighbor", "route-next-hop", "listening-socket"} <= kinds)
        for edge in report["edges"]:
            self.assertEqual(nodes[edge["from_node"]]["source_id"], edge["source_id"])
            self.assertEqual(nodes[edge["to_node"]]["source_id"], edge["source_id"])
        http = [row for row in report["findings"] if row["code"] == "cleartext-http"]
        self.assertEqual([row["packet_number"] for row in http], [7, 7])
        self.assertEqual([row["count"] for row in http], [2, 2])
        self.assertNotIn("arp-claims-differ", {row["code"] for row in report["findings"]})
        self.assertEqual({row["port"] for row in report["findings"] if row["code"] == "listener-wildcard"}, {8080})
        self.assertEqual({row["port"] for row in report["findings"] if row["code"] == "listener-nonloopback"}, {53})
        self.assertTrue(all(row["sample"] == 2 for row in report["findings"] if row["code"].startswith("listener-")))

    def test_same_mac_claim_detection_compares_only_matching_vlan_scope(self):
        from test_packets import arp, ethernet, pcap

        from wifiscope.packets import analyze_capture
        from wifiscope.reports import prepare_export

        first = ethernet(arp(), 0x0806, vlan=1)
        same_vlan = ethernet(arp("66778899aacc"), 0x0806, vlan=1)
        other_vlan = same_vlan[:14] + b"\x00\x02" + same_vlan[16:]
        cross = analyze_capture(pcap([first, other_vlan]))
        self.assertEqual(cross["packet_analysis"]["observations"], [])
        self.assertFalse(build_network_map(captures=[cross])["findings"])
        within = prepare_export(analyze_capture(pcap([first, other_vlan, same_vlan])), True)
        findings = build_network_map(captures=[within])["findings"]
        self.assertEqual([(f["code"], f["packet_number"], f["related_packet_number"]) for f in findings],
                         [("arp-claims-differ", 3, 1)])

    def test_pseudonymized_xml_inventory_is_visible_as_a_redacted_source(self):
        report = {"identifiers_included": False, "sources": [{"type": "nmap", "sha256": "id-123"}],
                  "assets": [{"address": "192.0.2.1", "source": "nmap", "source_sha256": "id-123"}]}
        result = build_network_map(inventories=[report])
        self.assertEqual([row["status"] for row in result["map_sources"]], ["redacted"])
        self.assertFalse(result["nodes"])

    def test_config_only_topology_and_baseline_lines(self):
        prefix = "SW#show running-config\nvlan 20\n name Lab\n!\ninterface GigabitEthernet0/1\n"
        before = parse_device_evidence(prefix + " switchport access vlan 20\n!\nSW#\n")
        current = parse_device_evidence(prefix + " switchport access vlan 21\n!\nSW#\n")
        result = build_network_map(devices=[current], comparisons=[compare_device_evidence(before, current)])
        self.assertEqual({edge["kind"] for edge in result["edges"]},
                         {"configured-interface", "configured-vlan", "configured-access-vlan"})
        self.assertEqual([(row["before_source_line"], row["after_source_line"]) for row in result["findings"]], [(5, 5)])

    def test_local_path_rejected_before_reading_network_share(self):
        with self.assertRaisesRegex(ValueError, "local evidence"):
            read_map_evidence("nmap", "//network-share/scan.xml")

    def test_diagnostic_export_roundtrip_accepts_named_stage_records(self):
        data = dict(copy.deepcopy(DIAGNOSTICS), schema_version=1, kind="network-diagnostics")
        data["samples"][0]["stages"]["gateway"] = {"status": "not-run", "checks": []}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "local.json")
            path.write_text(json.dumps(project_network(data, True)), encoding="utf-8")
            result = build_network_map(diagnostics=[read_map_evidence("diagnostics", path)])
        self.assertIn("listener-wildcard", {row["code"] for row in result["findings"]})

    def test_incomplete_and_pseudonymized_sources_do_not_become_clean_results(self):
        projected = copy.deepcopy(CAPTURE)
        projected["identifiers_included"] = False
        result = build_network_map(captures=[projected], diagnostics=[{"samples": []}])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["findings"], [])
        self.assertEqual({row["status"] for row in result["map_sources"]}, {"redacted", "unavailable"})

    def test_export_retains_link_ids_and_hides_source_and_device_identity(self):
        capture = copy.deepcopy(CAPTURE)
        capture["packet_analysis"]["source_sha256"] = "a" * 64
        report = build_network_map(captures=[capture], devices=[parse_device_evidence(DEVICE_TEXT, "secret-file.txt")],
                                   diagnostics=[DIAGNOSTICS])
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp, "report")
            export_network(report, directory)
            for path in directory.iterdir():
                contents = path.read_text(encoding="utf-8-sig")
                for private in ("192.0.2.1", "private-router", "private-adapter", "secret-file.txt", "a" * 64):
                    self.assertNotIn(private, contents, path)
            exported = json.loads((directory / "report.json").read_text(encoding="utf-8"))
            self.assertIn("明文 HTTP", (directory / "report.html").read_text(encoding="utf-8"))
            ids = {node["node_id"] for node in exported["nodes"]}
            self.assertTrue(all(edge["from_node"] in ids and edge["to_node"] in ids for edge in exported["edges"]))
            self.assertTrue(any(row["code"] == "cleartext-http" for row in exported["findings"]))

    def test_cli_imports_existing_scanner_xml_without_a_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "local.xml")
            path.write_text(
                '<nmaprun><host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="443"><state state="open"/></port>'
                '<port protocol="tcp" portid="80"><state state="filtered"/></port></ports>'
                '</host></nmaprun>', encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-m", "wifiscope", "network", "map", "--nmap", str(path)],
                capture_output=True, text=True, encoding="utf-8", check=False, timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["map_sources"][0]["kind"], "nmap")
        self.assertEqual([(row["kind"], row["port"]) for row in report["edges"]], [("reported-service", 443)])

    def test_desktop_clickable_graph_and_findings_filter(self):
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
        self.assertEqual(app.tabs.tab(app.tabs.select(), "text"), "安全与测绘")
        app.mapping.show(build_network_map(captures=[CAPTURE], diagnostics=[DIAGNOSTICS]))
        app.mapping.mode.set("安全发现")
        app.mapping.category.set("中")
        app.mapping.query.set("HTTP")
        root.update()
        self.assertEqual(len(app.mapping.table.tree.get_children()), 1)
        self.assertIn("7", app.mapping.table.details.get("1.0", "end"))
        finding = app.mapping.current[0]
        self.assertTrue(app.mapping.graph.find_withtag(f'map-node-{finding["related_node"]}'))
        app.mapping.focus_node(finding["related_node"])
        self.assertIn("明文 HTTP", app.mapping.table.details.get("1.0", "end"))


if __name__ == "__main__":
    unittest.main()
