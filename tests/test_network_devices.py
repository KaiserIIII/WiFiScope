import json
import tempfile
import unittest
from pathlib import Path

from wifiscope.network_devices import (
    MAX_EVIDENCE_BYTES,
    compare_device_evidence,
    parse_device_evidence,
    read_device_evidence,
)

_CAPTURE = """lab-switch#show vlan brief
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/1, Gi0/2
                                                Gi0/3
20   office                           active    Fa0/1
lab-switch#show interfaces trunk
Port        Mode             Encapsulation  Status        Native vlan
Gi0/4       on               802.1q         trunking      1

Port        Vlans allowed on trunk
Gi0/4       20,10-12,13

Port        Vlans allowed and active in management domain
Gi0/4       20

Port        Vlans in spanning tree forwarding state and not pruned
Gi0/4       20
lab-switch#show ip route
Codes: L - local, C - connected, S - static, O - OSPF
Gateway of last resort is 192.0.2.1 to network 0.0.0.0
S*    0.0.0.0/0 [1/0] via 192.0.2.1
      192.0.2.0/24 is variably subnetted, 2 subnets, 2 masks
C        192.0.2.0/24 is directly connected, GigabitEthernet0/1
L        192.0.2.10/32 is directly connected, GigabitEthernet0/1
O IA  198.51.100.0/24 [110/20] via 192.0.2.2, 00:00:29, Gi0/1
                      [110/20] via 192.0.2.3, 00:00:29, Gi0/2
lab-switch#show ip ospf neighbor
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.0.2.100       1   FULL/-          00:00:37    192.0.2.2       Gi0/1
lab-switch#show ip ospf interface
GigabitEthernet0/1 is up, line protocol is up
  Internet Address 192.0.2.10/24, Area 0, Attached via Network Statement
  Process ID 10, Router ID 192.0.2.10, Network Type POINT_TO_POINT, Cost: 10
  Transmit Delay is 1 sec, State POINT_TO_POINT
  Timer intervals configured, Hello 10, Dead 40, Wait 40, Retransmit 5
lab-switch#show ip ospf database
            OSPF Router with ID (192.0.2.10) (Process ID 10)

                Router Link States (Area 0)

Link ID         ADV Router      Age         Seq#       Checksum Link count
192.0.2.100     192.0.2.100     155         0x80000007 0x00F400  2
lab-switch#show lldp neighbors
Capability codes:
    (R) Router, (B) Bridge
Device ID           Local Intf     Hold-time  Capability      Port ID
lab-router          Gi0/1          120        R               Gi0/0
Total entries displayed: 1
lab-switch#
"""


class DeviceEvidenceTests(unittest.TestCase):
    def test_normalizes_cisco_tables_with_provenance(self):
        capture = parse_device_evidence(_CAPTURE, 'snapshot')
        self.assertEqual(capture['source']['devices'], ['lab-switch'])
        self.assertEqual(capture['source']['label'], 'snapshot')
        self.assertEqual(capture['ports'][2]['interface'], 'GigabitEthernet0/3')
        self.assertEqual(capture['ports'][2]['source_line'], 5)
        self.assertEqual(capture['ports'][2]['source_device'], 'lab-switch')
        self.assertEqual(capture['trunks'][0]['allowed_vlans'], '10-13,20')
        self.assertEqual(capture['routes'][1]['interface'], 'GigabitEthernet0/1')
        self.assertEqual([row['next_hop'] for row in capture['routes'][3:]],
                         ['192.0.2.2', '192.0.2.3'])
        self.assertEqual(capture['ospf_neighbors'][0]['state'], 'FULL')
        self.assertEqual(capture['ospf_neighbors'][0]['role'], '-')
        self.assertEqual(capture['ospf_interfaces'][0]['cost'], 10)
        self.assertEqual(capture['ospf_interfaces'][0]['router_id'], '192.0.2.10')
        self.assertEqual(capture['ospf_lsdb'][0]['lsa_type'], 'router')
        self.assertEqual(capture['lldp_neighbors'][0]['device'], 'lab-router')
        self.assertEqual(capture['lldp_neighbors'][0]['remote_interface'], 'GigabitEthernet0/0')
        self.assertEqual({row['status'] for row in capture['coverage'] if row['section'] != 'config'},
                         {'observed'})
        self.assertEqual(capture, json.loads(json.dumps(capture)))

    def test_reports_only_material_changes_for_multipath_ports_and_ospf(self):
        revised = (_CAPTURE.replace('Gi0/1, Gi0/2', 'Gi0/2')
                   .replace('active    Fa0/1', 'active    Fa0/1, Gi0/1')
                   .replace('[110/20]', '[110/30]').replace('via 192.0.2.3', 'via 192.0.2.4')
                   .replace('Cost: 10', 'Cost: 15').replace('FULL/-', 'INIT/DROTHER')
                   .replace('00:00:29', '00:00:11').replace('00:00:37', '00:00:09'))
        result = compare_device_evidence(parse_device_evidence(_CAPTURE), parse_device_evidence(revised))
        changes = {item['section']: item for item in result['changes']}
        self.assertEqual(result['count'], 4)
        self.assertEqual(changes['ports']['change'], 'changed')
        self.assertEqual(changes['ports']['after']['vlan_id'], 20)
        self.assertEqual(set(changes['routes']['fields']), {'metric', 'next_hop'})
        self.assertEqual(changes['routes']['after']['next_hop'], ['192.0.2.2', '192.0.2.4'])
        self.assertEqual(changes['ospf_interfaces']['fields'], ['cost'])
        self.assertEqual(changes['ospf_neighbors']['fields'], ['role', 'state'])

    def test_missing_filtered_or_unparsed_sections_do_not_prove_removal(self):
        original = parse_device_evidence('R1#show ip route\nO 198.51.100.0/24 [110/2] via 192.0.2.1')
        for capture in (
            'R1#show vlan brief\nVLAN Name Status Ports',
            'R1#show ip route | include 203.0.113\nCodes: O - OSPF',
            'R1#show ip route\nCodes: O - OSPF\nO 198.51.100.0 broken route syntax',
            'R1#show ip route\n% Invalid input detected at marker.',
            'R1#show ip route\nCodes: O - OSPF\n--More--',
        ):
            with self.subTest(capture=capture):
                result = compare_device_evidence(original, parse_device_evidence(capture))
                self.assertEqual(result['changes'], [])
                route_coverage = next(row for row in result['coverage'] if row['section'] == 'routes')
                self.assertFalse(route_coverage['comparable'])
        result = compare_device_evidence(original, parse_device_evidence('R1#show ip route\nCodes: O - OSPF'))
        self.assertEqual(result['changes'][0]['change'], 'removed')

    def test_compares_matching_rows_when_newer_capture_is_filtered(self):
        original = parse_device_evidence('R1#show ip route\nO 198.51.100.0/24 [110/2] via 192.0.2.1')
        revised = parse_device_evidence('R1#show ip route | include 198\nO 198.51.100.0/24 [110/6] via 192.0.2.1')
        result = compare_device_evidence(original, revised)
        self.assertEqual(result['changes'][0]['fields'], ['metric'])

    def test_parses_promptless_vrf_and_ospf_brief_output(self):
        route = parse_device_evidence('Routing Table: BLUE\nCodes: O - OSPF\n'
                                      '     198.51.100.0/24 is subnetted, 2 subnets\n'
                                      'O    198.51.100.0 [110/2] via 192.0.2.1')
        self.assertEqual(route['routes'][0]['prefix'], '198.51.100.0/24')
        self.assertEqual(route['routes'][0]['vrf'], 'BLUE')
        brief = parse_device_evidence('Interface PID Area IP Address/Mask Cost State Nbrs F/C\n'
                                      'Gi0/1 10 0 192.0.2.10/24 15 P2P 1/1')
        self.assertEqual(brief['ospf_interfaces'][0]['cost'], 15)
        self.assertEqual(brief['ospf_interfaces'][0]['address'], '192.0.2.10/24')

    def test_uses_device_identity_for_multi_device_evidence(self):
        capture = 'R1#show ip route\nO 198.51.100.0/24 [110/2] via 192.0.2.1\n' \
                  'R2#show ip route\nO 198.51.100.0/24 [110/6] via 192.0.2.2'
        after = capture.replace('[110/6]', '[110/7]')
        result = compare_device_evidence(parse_device_evidence(capture), parse_device_evidence(after))
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['changes'][0]['after']['source_device'], 'R2')

    def test_config_preview_and_diff_only_include_allowlisted_declarations(self):
        raw = '''R1#show running-config
Building configuration...
Current configuration : 800 bytes
!
hostname R1
enable secret 0 CREDENTIAL_TOKEN
banner motd ^C
interface GigabitEthernet1/7
 switchport access vlan 1234
CREDENTIAL_TOKEN
^C
vlan 20
 name Lab Clients
!
interface GigabitEthernet0/1
 description CREDENTIAL_TOKEN
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet0/2
 no switchport
 ip address 192.0.2.10 255.255.255.0
 ip ospf 10 area 0
 ip ospf cost 10
 ip ospf authentication-key CREDENTIAL_TOKEN
!
router ospf 10
 router-id 192.0.2.10
 network 192.0.2.0 0.0.0.255 area 0
 passive-interface GigabitEthernet0/2
!
line vty 0 4
 password CREDENTIAL_TOKEN
end
R1#
'''
        before = parse_device_evidence(raw)
        config = before['config']
        self.assertEqual(config['vlans'][0]['name'], 'Lab Clients')
        self.assertEqual([row['interface'] for row in config['interfaces']],
                         ['GigabitEthernet0/1', 'GigabitEthernet0/2'])
        self.assertEqual(config['interfaces'][1]['addresses'], ['192.0.2.10/24'])
        self.assertEqual(config['ospf'][0]['networks'][0]['wildcard'], '0.0.0.255')
        self.assertEqual(config['ospf'][0]['passive_interfaces'], ['GigabitEthernet0/2'])
        self.assertTrue(config['preview_lines'])
        diff = compare_device_evidence(before, parse_device_evidence(raw.replace('ip ospf cost 10', 'ip ospf cost 11')))
        self.assertEqual(diff['changes'][0]['section'], 'config')
        self.assertEqual(diff['changes'][0]['fields'], ['ospf_cost'])
        self.assertNotIn('CREDENTIAL_TOKEN', json.dumps([before, diff]))

    def test_banner_content_cannot_masquerade_as_new_command_output(self):
        capture = parse_device_evidence(
            'R1#show running-config\nbanner motd ^C\n'
            'R2#show lldp neighbors\n'
            'Device ID Local Intf Hold-time Capability Port ID\n'
            'BANNER_SECRET Gi0/1 120 B Gi0/2\n^C\n'
            'vlan 20\n name Lab\nend\nR1#')
        self.assertEqual(capture['source']['devices'], ['R1'])
        self.assertEqual(capture['lldp_neighbors'], [])
        self.assertEqual(capture['config']['vlans'][0]['vlan_id'], 20)
        self.assertNotIn('BANNER_SECRET', json.dumps(capture))

    def test_accepts_ospf_external_default_route_flags(self):
        capture = parse_device_evidence(
            'R1#show ip route\nO*E2 0.0.0.0/0 [110/1] via 192.0.2.1, 00:00:18, Gi0/1')
        self.assertEqual([(row['protocol'], row['prefix'], row['metric']) for row in capture['routes']],
                         [('O E2', '0.0.0.0/0', 1)])

    def test_route_comparison_detects_metrics_exchange_between_paths(self):
        raw = ('R1#show ip route\nD 198.51.100.0/24 [90/20] via 192.0.2.1\n'
               '                       [90/40] via 192.0.2.2')
        revised = raw.replace('[90/20]', '[90/40]', 1).replace('[90/40] via 192.0.2.2',
                                                               '[90/20] via 192.0.2.2')
        result = compare_device_evidence(parse_device_evidence(raw), parse_device_evidence(revised))
        self.assertEqual(result['changes'][0]['fields'], ['metric'])

    def test_multiple_devices_with_a_missing_command_are_not_globally_comparable(self):
        raw = ('R1#show ip route\nO 198.51.100.0/24 [110/2] via 192.0.2.1\n'
               'R2#show ip route\nO 198.51.100.0/24 [110/6] via 192.0.2.2')
        revised = ('R1#show ip route\nO 198.51.100.0/24 [110/3] via 192.0.2.1\n'
                   'R2#show vlan brief\nVLAN Name Status Ports')
        result = compare_device_evidence(parse_device_evidence(raw), parse_device_evidence(revised))
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['changes'][0]['after']['source_device'], 'R1')
        self.assertFalse(next(row for row in result['coverage'] if row['section'] == 'routes')['comparable'])

    def test_reads_local_unicode_filenames_and_gbk_and_blocks_nonlocal_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / '\u6837\u672c [1].txt'
            path.write_bytes('VLAN Name Status Ports\r\n20 \u529e\u516c active Gi0/1\r\n'.encode('gbk'))
            result = read_device_evidence(path)
            self.assertEqual(result['source']['encoding'], 'gbk')
            self.assertEqual(result['source']['label'], path.name)
            self.assertEqual(result['vlans'][0]['name'], '\u529e\u516c')
            self.assertNotIn(str(path.parent), json.dumps(result))
        for path in ('//example.invalid/folder/file.txt', r'\\?\C:\file.txt'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                read_device_evidence(path)

    def test_rejects_oversized_or_binary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'snapshot.txt'
            path.write_bytes(b' ' * (MAX_EVIDENCE_BYTES + 1))
            with self.assertRaises(ValueError):
                read_device_evidence(path)
            path.write_bytes(b'VLAN\x00 Name Status Ports')
            with self.assertRaises(ValueError):
                read_device_evidence(path)


if __name__ == '__main__':
    unittest.main()


class PacketTracerTranscriptTests(unittest.TestCase):
    def test_scoped_ospf_interface_command_captures_actual_packet_tracer_format(self):
        prefix = """R1#show ip ospf interface serial 1/0
Serial1/0 is up, line protocol is up
  Internet address is 192.0.2.1/30, Area 0
  Process ID 1, Router ID 192.0.2.1, Network Type POINT-TO-POINT, Cost: 781
  Transmit Delay is 1 sec, State POINT-TO-POINT, Priority 0
R1#
"""
        before = parse_device_evidence(prefix)
        row = before["ospf_interfaces"][0] if before["ospf_interfaces"] else {}
        self.assertEqual((row.get("interface"), row.get("address"), row.get("cost")),
                         ("Serial1/0", "192.0.2.1/30", 781))
        after = parse_device_evidence(prefix.replace("Cost: 781", "Cost: 10"))
        comparison = compare_device_evidence(before, after)
        self.assertEqual(comparison["changes"][0]["fields"], ["cost"])
        self.assertEqual(comparison["changes"][0]["after"]["cost"], 10)
