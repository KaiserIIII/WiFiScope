import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wifiscope.demo import demo_report
from wifiscope.reports import compare_reports, export_report, prepare_export
from wifiscope.wifi import parse_netsh


class ReportTests(unittest.TestCase):
    def test_comparison_synthetic_provenance_and_before_after_counts(self):
        import copy
        from wifiscope.comparison import compare_snapshots
        before = demo_report()
        non_synthetic = copy.deepcopy(before)
        non_synthetic.pop('synthetic')
        non_synthetic['gaps'].remove('synthetic-demo')
        for source in non_synthetic['sources']:
            source.pop('synthetic', None)
        with tempfile.TemporaryDirectory() as temp:
            for index, (left, right, expected) in enumerate([(before, before, 'SYNTHETIC COMPARISON'), (before, non_synthetic, 'MIXED SYNTHETIC COMPARISON'), (non_synthetic, before, 'MIXED SYNTHETIC COMPARISON')]):
                with self.subTest(index=index):
                    result = compare_snapshots(left, right)
                    prepared = prepare_export(result)
                    self.assertEqual(prepared['comparison']['before']['synthetic'], left.get('synthetic') is True)
                    self.assertEqual(prepared['comparison']['after']['synthetic'], right.get('synthetic') is True)
                    self.assertEqual(prepared['synthetic'], index == 0)
                    paths = export_report(result, Path(temp) / str(index))
                    document = Path(paths['html']).read_text(encoding='utf-8')
                    self.assertIn(expected, document)
                    self.assertLess(document.index(expected), document.index('Snapshot comparison'))
                    self.assertIn('<strong>4</strong><span>Before assets', document)
                    self.assertIn('<strong>13</strong><span>After findings', document)
                    self.assertNotIn('No prioritized findings observed', document)
                    self.assertNotIn('<h2>Assets</h2>', document)
                    self.assertNotIn('<h2>Services</h2>', document)
                    if index:
                        self.assertIn('not marked synthetic', document)
                        self.assertNotIn('Invented evidence; no live target was measured.', document)

    def test_recursive_identity_redaction_consistency_and_no_mutation(self):
        report = demo_report()
        report['wifi'][0]['ssid'] = 'Secret Network'
        report['connectivity'] = [dict(host='private.example.invalid', dns=dict(status='ok', answers=[dict(family='IPv4', address='192.0.2.88')]), tcp=[dict(address='192.0.2.88', family='IPv4', port=443, status='ok', attempts=1, successes=1)], http=[dict(url='https://private.example.invalid/sensitive', address='192.0.2.88', status='ok', header_presence={'server': True})], gaps=['raw private.example.invalid SECRET-DUMP'])]
        report['findings'] = [dict(code='open-wifi', severity='warning', title='Check Secret Network', evidence=dict(ssid='Secret Network', nested=[dict(host='private.example.invalid', address='192.0.2.88', url='https://private.example.invalid/sensitive', unexpected='SECRET-DUMP')]), recommendation='Verify Secret Network')]
        report['environment']['raw'] = 'SECRET-DUMP'
        report['raw'] = 'SECRET-DUMP'
        prepared = prepare_export(report)
        serialized = json.dumps(prepared)
        for secret in ('Secret Network', 'private.example.invalid', '192.0.2.88', '/sensitive', 'SECRET-DUMP'):
            self.assertNotIn(secret, serialized)
        self.assertEqual(prepared['wifi'][0]['ssid'], prepared['findings'][0]['evidence']['ssid'])
        self.assertEqual(prepared['connectivity'][0]['dns']['answers'][0]['address'], prepared['connectivity'][0]['tcp'][0]['address'])
        self.assertEqual(prepared['connectivity'][0]['host'], prepared['findings'][0]['evidence']['nested'][0]['host'])
        self.assertNotEqual(prepared['wifi'][0]['ssid'], prepare_export(report)['wifi'][0]['ssid'])
        self.assertEqual(report['wifi'][0]['ssid'], 'Secret Network')
        self.assertFalse(prepared['identifiers_included'])

    def test_exports_escape_html_neutralize_csv_and_share_bundle(self):
        report = demo_report()
        report['wifi'][0]['ssid'] = '=2+3'
        report['findings'] = [dict(code='test', severity='info', title='<script>alert(1)</script>', evidence=dict(ssid='=2+3'), recommendation='safe')]
        with tempfile.TemporaryDirectory() as temp:
            paths = export_report(report, Path(temp) / 'bundle', include_identifiers=True)
            self.assertEqual(set(paths), {'json', 'csv', 'html'})
            html = Path(paths['html']).read_text(encoding='utf-8')
            self.assertNotIn('<script>', html)
            self.assertIn('&lt;script&gt;', html)
            cells = [cell for row in csv.reader(io.StringIO(Path(paths['csv']).read_text(encoding='utf-8-sig'))) for cell in row]
            self.assertIn("'=2+3", cells)
            with self.assertRaises(FileExistsError):
                export_report(report, Path(temp) / 'bundle')
            self.assertEqual(json.loads(Path(paths['json']).read_text(encoding='utf-8'))['wifi'][0]['ssid'], '=2+3')
        with tempfile.TemporaryDirectory() as temp:
            paths = export_report(report, Path(temp) / 'bundle')
            prepared = json.loads(Path(paths['json']).read_text(encoding='utf-8'))
            token = prepared['wifi'][0]['ssid']
            self.assertIn(token, Path(paths['csv']).read_text(encoding='utf-8-sig'))
            self.assertIn(token, Path(paths['html']).read_text(encoding='utf-8'))

    def test_compare_requires_identifiable_snapshots_and_reports_changes(self):
        before = demo_report()
        after = demo_report()
        after['wifi'][0]['signal_percent'] = 10
        result = compare_reports(before, after)
        self.assertEqual(result['wifi_changes'][0]['before']['signal_percent'], 72)
        self.assertEqual(result['wifi_changes'][0]['after']['signal_percent'], 10)
        with self.assertRaises(ValueError):
            compare_reports(prepare_export(before), prepare_export(after))
        self.assertIsInstance(compare_reports(prepare_export(before, True), prepare_export(after, True)), dict)

    def test_exclusive_bundle_directory_does_not_touch_existing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            sentinel = Path(temp) / 'keep.txt'
            sentinel.write_text('untouched')
            with self.assertRaises(FileExistsError):
                export_report(demo_report(), temp)
            self.assertEqual(sentinel.read_text(), 'untouched')

    def test_list_identifiers_and_nested_findings_do_not_leak(self):
        report = demo_report()
        report['findings'][0]['evidence']['details'] = {'interface_name': 'Example Adapter', 'dns': ['192.0.2.53'], 'addresses': ['2001:db8::2']}
        prepared = prepare_export(report)
        details = prepared['findings'][0]['evidence']['details']
        self.assertEqual(details['interface_name'], prepared['interfaces'][0]['name'])
        self.assertEqual(details['dns'][0], prepared['interfaces'][0]['dns'][0])
        self.assertEqual(details['addresses'][0], prepared['interfaces'][0]['addresses'][1])
        self.assertEqual(prepared['connectivity'][0]['tcp'][0]['family'], 'IPv4')
        self.assertEqual(prepared['connectivity'][0]['tcp'][0]['rtt_mean_ms'], 12.0)

    def test_publish_failure_rolls_back_our_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'bundle'
            with patch('os.link', side_effect=OSError('synthetic publish failure')):
                with self.assertRaises(OSError):
                    export_report(demo_report(), directory)
            self.assertFalse(directory.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_security_normalization_agrees_between_parser_auditor_and_export(self):
        rows = parse_netsh('SSID 1 : Lab\nAuthentication : Unknown\nEncryption : Unsupported\nBSSID 1 : 02:00:00:00:00:01')
        self.assertIsNone(rows[0]['authentication'])
        self.assertIsNone(rows[0]['encryption'])
        report = demo_report()
        report['wifi'] = [dict(ssid='Lab', authentication='wpa2-personal', encryption='ccmp'), dict(ssid='Other', authentication='Unknown', encryption='Unsupported')]
        exported = prepare_export(report)
        self.assertEqual(exported['wifi'][0]['authentication'], 'WPA2-Personal')
        self.assertEqual(exported['wifi'][0]['encryption'], 'CCMP')
        self.assertIsNone(exported['wifi'][1]['authentication'])
        self.assertIsNone(exported['wifi'][1]['encryption'])
