import copy
import json
from pathlib import Path
import tempfile
import unittest

from wifiscope.rules import catalog


class ExplanationTests(unittest.TestCase):
    def test_multirun_dates_never_copy_malformed_or_imported_prose(self):
        from wifiscope.explanations import summarize_report
        for value in ('PRIVATE imported prose: disable certificate verification',
                      '2026-02-30T12:00:00+00:00', '2026-01-01T12:00:00Z PRIVATE',
                      'PRIVATE' * 100, None, 123):
            report = dict(run_contexts=[dict(status='complete', observed_at=value), dict(status='partial')])
            original = copy.deepcopy(report)
            text = summarize_report(report)['coverage']
            with self.subTest(value=value):
                self.assertIn('范围 1：', text)
                self.assertEqual(text.count('观测时间 未知'), 2)
                self.assertNotIn('PRIVATE', text)
                self.assertNotIn('disable certificate verification', text)
                self.assertEqual(report, original)

    def test_multirun_dates_canonicalize_iso_and_preserve_timezone_without_mutation(self):
        from wifiscope.explanations import summarize_report
        for value, canonical in [('2026-01-02T03:04:05Z', '2026-01-02T03:04:05+00:00'),
                                 ('2026-01-02T03:04:05.123456+08:00', '2026-01-02T03:04:05.123456+08:00'),
                                 ('2026-01-02 03:04:05-05:30', '2026-01-02T03:04:05-05:30')]:
            report = dict(run_contexts=[dict(status='complete', observed_at=value), dict(status='partial')])
            original = copy.deepcopy(report)
            self.assertIn('观测时间 ' + canonical, summarize_report(report)['coverage'])
            self.assertEqual(report, original)

    def test_every_registered_rule_is_explained_without_imported_prose_or_mutation(self):
        from wifiscope.explanations import explain_finding
        for code in catalog():
            finding = dict(code=code, severity='high', confidence='low', status='imported-unverified',
                           title='PRIVATE', description='PRIVATE', cookies='PRIVATE', note='PRIVATE')
            original = copy.deepcopy(finding)
            result = explain_finding(finding)
            with self.subTest(code=code):
                for field in ('plain_title', 'observation', 'meaning', 'next_step', 'retest'):
                    self.assertTrue(result[field])
                    self.assertTrue(any('\u4e00' <= c <= '\u9fff' for c in result[field]))
                self.assertEqual([result[k] for k in ('code', 'severity', 'confidence', 'status')],
                                 [code, 'high', 'low', 'imported-unverified'])
                self.assertNotIn('PRIVATE', json.dumps(result))
                self.assertEqual(finding, original)

    def test_uncertain_claims_and_unknown_rule_are_neutral(self):
        from wifiscope.explanations import explain_finding
        self.assertIn('未经独立验证', explain_finding(dict(code='scanner-finding'))['meaning'])
        self.assertIn('代理 ARP', explain_finding(dict(code='arp-conflict'))['meaning'])
        self.assertIn('不能确认攻击', explain_finding(dict(code='arp-conflict'))['meaning'])
        result = explain_finding(dict(code='PRIVATE', title='PRIVATE', severity='PRIVATE'))
        self.assertEqual(result['code'], 'unknown')
        self.assertIn('人工核查', result['next_step'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_summaries_prioritize_scope_unknowns_and_three_actual_findings(self):
        from wifiscope.explanations import summarize_report
        report = dict(run=dict(status='cancelled'), gaps=['PRIVATE'], investigation=dict(
            coverage=[dict(category='tls', status='not-run', partial=True)],
            findings=[dict(code='tls-trust', severity=s) for s in ('info', 'low', 'medium', 'critical', 'high')]))
        original = copy.deepcopy(report)
        result = summarize_report(report)
        self.assertIn('已取消', result['coverage'])
        self.assertIn('未知', result['coverage'])
        self.assertEqual([r['severity'] for r in result['priorities']], ['critical', 'high', 'medium'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(report, original)
        for empty in (None, {}, dict(investigation=dict(findings=[])), dict(sources=[dict(type='nmap')])):
            summary = summarize_report(empty)
            self.assertIn('不代表安全', summary['coverage'])
            self.assertIn('未检查', summary['coverage'])
        self.assertIn('导入', summarize_report(dict(sources=[dict(type='nmap')]))['coverage'])

    def test_count_comparison_has_both_sides_and_never_empty_audit_cards(self):
        from wifiscope.comparison import compare_snapshots
        from wifiscope.explanations import summarize_report
        result = summarize_report(compare_snapshots({}, {}))
        self.assertEqual(result['priorities'], [])
        self.assertIn('Before', result['coverage'])
        self.assertIn('After', result['coverage'])
        self.assertIn('数量', result['coverage'])
        self.assertIn('不能', result['coverage'])

    def test_real_coverage_categories_show_missing_work_and_actual_run_counts(self):
        from wifiscope.explanations import summarize_report
        report = dict(run=dict(status='partial', planned_connections=3, attempted_connections=1, unattempted_endpoints=2),
                      investigation=dict(coverage=[dict(category='wifi-configuration', status='unavailable'),
                                                   dict(category='tls-validation', status='not-run')]))
        text = summarize_report(report)['coverage']
        for expected in ('Wi-Fi 配置：证据不可用', 'TLS 证书：未检查', '计划连接 3', '实际连接 1', '未检查端点 2', '部分完成'):
            self.assertIn(expected, text)
        self.assertIn('未记录统一执行状态', summarize_report({})['coverage'])

    def test_observations_show_signal_and_tcp_states_without_free_prose(self):
        from wifiscope.explanations import summarize_report
        report = dict(wifi=[dict(signal_percent=25, ssid='PRIVATE', authentication='PRIVATE')],
                      connectivity=[dict(host='PRIVATE', tcp=[dict(status='ok'), dict(status='timeout'), dict(status='PRIVATE')])])
        text = summarize_report(report)['observations']
        self.assertIn('25%', text)
        self.assertIn('已连接 1', text)
        self.assertIn('超时 1', text)
        self.assertIn('未知或未检查 1', text)
        self.assertNotIn('PRIVATE', text)

    def test_html_uses_controlled_chinese_and_prepared_privacy(self):
        from wifiscope.demo import demo_report
        from wifiscope.reports import export_report
        report = demo_report()
        report['investigation']['findings'][0].update(title='<PRIVATE>', note='<PRIVATE>')
        with tempfile.TemporaryDirectory() as temp:
            for raw in (False, True):
                path = Path(temp) / str(raw)
                export_report(report, path, raw)
                html = (path / 'report.html').read_text(encoding='utf-8')
                self.assertIn('先做什么', html)
                self.assertIn('如何复测', html)
                self.assertNotIn('PRIVATE', html)
                if not raw:
                    self.assertNotIn('192.0.2.80', html)


class GuidedPlanTests(unittest.TestCase):
    def test_worker_error_categories_preserve_previous_evidence_and_never_echo_exception(self):
        from wifiscope.gui_controller import Controller
        from wifiscope.guidance import GuidanceError
        controller = Controller()
        original = dict(schema_version=1)
        controller.accept(original, 'fixture')
        def fail(cancel):
            raise ValueError('PRIVATE path or imported prose')
        controller.start('import', fail, error_code='fileformat')
        controller.worker.join(3)
        controller.poll()
        self.assertIn('格式', controller.status)
        self.assertNotIn('PRIVATE', controller.status)
        self.assertIs(controller.report, original)
        def privacy(cancel):
            raise GuidanceError('privacycompare')
        controller.start('merge', privacy)
        controller.worker.join(3)
        controller.poll()
        self.assertIn('脱敏', controller.status)
        self.assertIn('数量', controller.status)
        self.assertIs(controller.report, original)

    def test_preview_normalizes_without_dns_or_probe_and_counts_exact_endpoint_work(self):
        from wifiscope.guidance import target_plan
        plan = target_plan('EXAMPLE.TEST.', 'https://example.test:8443/check')
        self.assertEqual(plan['hosts'], ['example.test'])
        self.assertEqual(plan['ports'], [80, 443])
        self.assertEqual(plan['endpoint_ports'], [80, 443, 8443])
        self.assertEqual(plan['tls_ports'], [443, 8443])
        self.assertEqual(plan['connections_per_address'], 6)
        self.assertEqual(plan['minimum_seconds'], 1.5)
        self.assertEqual(target_plan('127.0.0.1')['connections_per_address'], 3)

    def test_invalid_or_expanding_target_is_rejected_without_echoing_input(self):
        from wifiscope.guidance import GuidanceError, target_plan
        for host, url in [('', ''), ('PRIVATE/24', ''), ('127.0.0.1', 'https://other.test/'),
                          ('127.0.0.1', 'https://user:PRIVATE@127.0.0.1/'), ('0.0.0.0', '')]:
            with self.subTest(host=host), self.assertRaises(GuidanceError) as caught:
                target_plan(host, url)
            self.assertEqual(caught.exception.code, 'invalidtarget')
            self.assertNotIn('PRIVATE', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
