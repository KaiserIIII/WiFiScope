"""Offline regressions for the final review's bounded-model defects."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wifiscope import cli, importers
from wifiscope.case_validation import validate_report
from wifiscope.cases import CaseStore
from wifiscope.explanations import summarize_report
from wifiscope.investigate import build_investigation, merge_reports
from wifiscope.reports import export_report, prepare_export
from wifiscope.workstation import load_json


def scan(addresses=4, ports=3, names=0, prior=''):
    host = ('<host>' + ''.join(f'<address addr="192.0.2.{n}" addrtype="ipv4"/>' for n in range(1, addresses + 1))
            + '<hostnames>' + '<hostname name="private.example"/>' * names + '</hostnames><ports>'
            + ''.join(f'<port protocol="tcp" portid="{n}"/>' for n in range(1, ports + 1)) + '</ports></host>')
    return ('<nmaprun>' + prior + host + '</nmaprun>').encode()


def measured(status, planned, address):
    return dict(schema_version=1, identifiers_included=True, collected_at='2026-01-01T00:00:00+00:00',
        run=dict(status=status, planned_hosts=planned, attempted_hosts=1, planned_connections=planned,
                 attempted_connections=1, unattempted_endpoints=planned - 1),
        sources=[dict(type='measured', sha256=address, observed_at='2026-01-01T00:00:00+00:00')],
        connectivity=[dict(host=address, dns=dict(status='ok', answers=[]), tcp=[dict(address=address,
            family='IPv4', port=80, status='ok', attempts=1, successes=1)], tls=[], http=[], gaps=[])])


class NmapExpansionTests(unittest.TestCase):
    def test_expansion_and_prior_hosts_rejected_before_asset_allocation(self):
        prior = '<host><address addr="198.51.100.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"/></ports></host>'
        for data, row_limit, asset_limit, allocated in [(scan(), 11, 100, 0),
                (scan(), 100, 3, 0), (scan(prior=prior), 12, 100, 1)]:
            with self.subTest(row_limit=row_limit, asset_limit=asset_limit), patch.object(importers, 'MAX_ROWS', row_limit), patch.object(importers, 'MAX_ASSETS', asset_limit), patch.object(importers, '_asset', wraps=importers._asset) as factory:
                with self.assertRaisesRegex(ValueError, 'budget'):
                    importers.import_nmap(data)
                self.assertEqual(factory.call_count, allocated)

    def test_exact_expansion_boundary_preserves_multi_address_semantics(self):
        with patch.object(importers, 'MAX_ROWS', 12), patch.object(importers, 'MAX_ASSETS', 4):
            report = importers.import_nmap(scan(names=2))
        self.assertEqual(len(report['assets']), 4)
        self.assertEqual(sum(len(a['services']) for a in report['assets']), 12)
        self.assertTrue(all(len(a['hostnames']) == 2 for a in report['assets']))
        self.assertIsNot(report['assets'][0]['services'][0], report['assets'][1]['services'][0])

    def test_hostname_replication_is_bounded_before_asset_allocation(self):
        data = scan(addresses=8, ports=0, names=16)
        self.assertLess(len(data), 2000)
        with patch.object(importers, 'MAX_BYTES', 3000), patch.object(importers, '_asset', wraps=importers._asset) as factory:
            with self.assertRaisesRegex(ValueError, 'budget'):
                importers.import_nmap(data)
            self.assertEqual(factory.call_count, 0)

    def test_scoped_ipv6_identity_length_counts_toward_retained_model(self):
        address = 'fe80::1%' + 'z' * 800
        data = ('<nmaprun><host>' + f'<address addr="{address}" addrtype="ipv6"/>' * 8 + '</host></nmaprun>').encode()
        self.assertLess(len(data), 7500)
        with patch.object(importers, 'MAX_BYTES', 7500), patch.object(importers, '_asset', wraps=importers._asset) as factory:
            with self.assertRaisesRegex(ValueError, 'budget'):
                importers.import_nmap(data)
            self.assertEqual(factory.call_count, 0)
        with patch.object(importers, 'MAX_MODEL_ITEMS', 100), patch.object(importers, '_asset', wraps=importers._asset) as factory:
            with self.assertRaisesRegex(ValueError, 'budget'):
                importers.import_nmap(data)
            self.assertEqual(factory.call_count, 0)


class MergedRunTests(unittest.TestCase):
    def test_unknown_partial_deadline_and_legacy_headlines_never_imply_complete(self):
        for status in ('partial', 'deadline', 'unknown'):
            a, b = measured('complete', 1, '192.0.2.1'), measured(status, 3, '192.0.2.2')
            b['run'].pop('attempted_connections')
            for inputs in ([a, b], [b, a]):
                result = merge_reports(inputs)
                result['run'] = copy.deepcopy(result['run_contexts'][0])  # prior-version saved merge
                for report in (result, merge_reports([result]), prepare_export(result)):
                    self.assertIn('计划连接 未知', summarize_report(report)['coverage'])
                    self.assertIn('实际连接 未知', summarize_report(report)['coverage'])
                    self.assertEqual(len(report['run_contexts']), 2)
                    self.assertEqual(sum('attempted_connections' not in row for row in report['run_contexts']), 1)

    def test_distinct_current_run_is_not_lost_when_prior_contexts_exist(self):
        report = measured('complete', 1, '192.0.2.1')
        report['run_contexts'] = [dict(status='deadline', planned_connections=3, attempted_connections=None)]
        merged = merge_reports([report])
        self.assertEqual(len(merged['run_contexts']), 2)
        self.assertEqual([row['status'] for row in merged['run_contexts']], ['complete', 'deadline'])
        for result in (build_investigation(report), prepare_export(report)):
            self.assertEqual([row['status'] for row in result['run_contexts']], ['complete', 'deadline'])
            self.assertNotIn('run', result)

    def test_both_orders_remerge_projection_case_and_consumers_keep_contexts(self):
        a, b = measured('complete', 1, '192.0.2.1'), measured('cancelled', 3, '192.0.2.2')
        for inputs in ([a, b], [b, a], [a, a]):
            with self.subTest(order=[r['run']['status'] for r in inputs]), tempfile.TemporaryDirectory() as temp:
                merged = merge_reports(inputs)
                with CaseStore(Path(temp) / 'case.db') as store:
                    identifier = store.add_snapshot(merged, include_identifiers=True)
                    stored = store.load_snapshot(identifier)
                for report in (merged, merge_reports([merged]), stored, build_investigation(stored), prepare_export(merged, True)):
                    self.assertNotIn('run', report)
                    self.assertEqual([r['planned_connections'] for r in report['run_contexts']], [r['run']['planned_connections'] for r in inputs])
                    self.assertEqual([r['sha256'] for r in report['sources'] if 'sha256' in r], [r['sources'][0]['sha256'] for r in inputs] if inputs[0] != inputs[1] else [a['sources'][0]['sha256']])
                    summary = summarize_report(report)['coverage']
                    self.assertIn('多个执行范围', summary)
                    self.assertIn('计划连接 未知', summary)
                    self.assertIn('实际连接 未知', summary)
                    self.assertIn('未检查端点 未知', summary)
                    self.assertIn('范围 2', summary)
                paths = export_report(merged, Path(temp) / 'bundle')
                html = Path(paths['html']).read_text(encoding='utf-8')
                self.assertIn('Scope / 执行状态: partial', html)
                self.assertIn('Planned connections: Unknown', html)
                self.assertIn('Original run contexts', html)
                self.assertIn('cancelled' if inputs[0] != inputs[1] else 'complete', html)
                with patch.object(cli, 'load_json', side_effect=copy.deepcopy(inputs)), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(['merge', '--input', 'a.json', '--input', 'b.json']), 0)


class NumericBoundaryTests(unittest.TestCase):
    def test_extreme_typed_numbers_rejected_consistently(self):
        records = [dict(run=dict(planned_connections=10**400)),
            dict(connectivity=[dict(tcp=[dict(rtt_mean_ms=10**400)])]),
            dict(packet_analysis=dict(protocol_counts=dict(tcp=10**400))),
            dict(imported_findings=[dict(confidence=10**400)]),
            dict(run=dict(deadline_seconds=float('inf'))), dict(run=dict(planned_connections=True))]
        for fields in records:
            report = dict(schema_version=1, **fields)
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    validate_report(report)
                if fields != records[-1]:
                    with self.assertRaises(ValueError):
                        prepare_export(report)
                    with self.assertRaises(ValueError):
                        build_investigation(report)

    def test_real_json_and_cli_reject_without_partial_bundle_or_private_text(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'PRIVATE.json'
            source.write_text(json.dumps(dict(schema_version=1, run=dict(planned_connections=10**400))))
            with self.assertRaises(ValueError):
                load_json(source)
            for extra in ([], ['--out', str(Path(temp) / 'bundle')]):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(cli.main(['merge', '--input', str(source), *extra]), 2)
                self.assertEqual(out.getvalue(), '')
                self.assertNotIn('Traceback', err.getvalue())
                self.assertNotIn('PRIVATE', err.getvalue())
                self.assertFalse((Path(temp) / 'bundle').exists())

    def test_supported_numbers_and_unknowns_remain_useful(self):
        report = dict(schema_version=1, run=dict(planned_connections=2**64, attempted_connections=0,
                     unattempted_endpoints=None), connectivity=[dict(tls=[dict(days_remaining=-1, elapsed_ms=0.25)])])
        validate_report(report)
        self.assertEqual(prepare_export(report)['run'], report['run'])
        for value in (float('nan'), float('inf'), -float('inf')):
            with self.assertRaises(ValueError):
                validate_report(dict(schema_version=1, run=dict(deadline_seconds=value)))

    def test_worker_rejects_extreme_numeric_import_and_preserves_previous_model(self):
        from wifiscope.gui_controller import Controller
        controller = Controller()
        controller.accept(dict(schema_version=1, assets=[]), 'previous')
        previous = controller.report
        payload = json.dumps(dict(schema_version=1, run=dict(planned_connections=10**400))).encode()
        with patch('wifiscope.workstation.read_bounded', return_value=payload):
            controller.import_evidence('PRIVATE.json', 'json')
            controller.worker.join(3)
            controller.poll()
        self.assertIs(controller.report, previous)
        self.assertNotIn('PRIVATE', controller.status)


class TimingLabelTests(unittest.TestCase):
    def test_cli_audit_labels_rate_estimate_without_changing_planned_count(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as temp, patch.object(cli, 'audit_scope', return_value=dict(schema_version=1)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = cli.main(['audit', '--scope', '192.0.2.1', '--port', '80', '--out', str(Path(temp) / 'bundle'), '--authorized'])
        self.assertEqual(result, 0)
        self.assertIn('planning estimate 0.25s', err.getvalue())
        self.assertNotIn('minimum', err.getvalue())
