"""Static, self-contained investigation presentation; all content is escaped."""
import html
import json

from .comparison import comparison_notice
from .explanations import CONFIDENCE, SEVERITY, STATUS, explain_finding, summarize_report
from .investigate import _run_contexts, run_summary


def esc(value):
    return html.escape('Unknown' if value is None else str(value), quote=True)


def table(title, fields, rows):
    head = ''.join('<th>' + esc(f.replace('_', ' ').title()) + '</th>' for f in fields)
    body = ''.join('<tr>' + ''.join('<td>' + esc(row.get(f)) + '</td>' for f in fields) + '</tr>' for row in rows if isinstance(row, dict))
    return '<h2>' + esc(title) + '</h2><div class="scroll"><table><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>'


def render(prepared, typed_rows, packets_html):
    if 'comparison' in prepared:
        from .case_validation import validate_comparison
        validate_comparison(prepared['comparison'])
    is_comparison = 'comparison' in prepared
    investigation = prepared.get('investigation', {})
    findings = investigation.get('findings', [])
    assets = investigation.get('assets', [])
    coverage = investigation.get('coverage', [])
    banner = '<aside class="synthetic">SYNTHETIC DEMO · 合成演示 · Invented evidence; no live target was measured.</aside>' if prepared.get('synthetic') or 'synthetic-demo' in prepared.get('gaps', []) else ''
    notice = comparison_notice(prepared)
    if notice:
        banner = '<aside class="synthetic">' + esc(notice) + '</aside>'
    run = run_summary(prepared)
    source = ', '.join(sorted({str(s.get('type', 'unknown')) for s in prepared.get('sources', [])})) or 'unknown'
    cards = ''.join('<div class="metric"><strong>' + esc(value) + '</strong><span>' + label + '</span></div>' for label, value in [('Assets / 资产', len(assets)), ('Prioritized findings / 发现', len(findings)), ('Evidence sources / 来源', len(prepared.get('sources', []))), ('Coverage gaps / 缺口', len(prepared.get('gaps', [])))])
    if is_comparison:
        cards = ''.join('<div class="metric"><strong>' + esc(prepared['comparison'][side]['summary'][field]) + '</strong><span>' + side.title() + ' ' + field + '</span></div>' for field in ('assets', 'findings') for side in ('before', 'after'))
    scope = '<section class="scope"><b>Scope / 执行状态: ' + esc(run.get('status', 'unknown')) + '</b><p>Planned connections: ' + esc(run.get('planned_connections')) + ' · Actual: ' + esc(run.get('attempted_connections')) + ' · Remaining endpoints: ' + esc(run.get('unattempted_endpoints')) + '</p><p>Unknown or partial coverage is never a pass. Partial or differently scoped retests cannot establish removal or resolution.</p></section>'
    if is_comparison:
        scope = '<section class="scope"><b>Comparison scope / 比较范围</b><p>Check both original times, coverage and gaps below. Partial or differently scoped retests cannot establish removal or resolution.</p></section>'
    elif len(_run_contexts(prepared)) > 1:
        scope += table('Original run contexts / 原始执行范围', ('status', 'observed_at', 'planned_hosts',
            'attempted_hosts', 'planned_connections', 'attempted_connections', 'unattempted_endpoints'), _run_contexts(prepared))
    finding_cards = []
    for f in findings:
        plain = explain_finding(f)
        badges = ''.join('<span class="badge">' + esc(f.get(k)) + '</span>' for k in ('severity', 'confidence', 'status', 'triage_status') if f.get(k) is not None)
        labels = '优先级：' + SEVERITY[plain['severity']] + ' · 置信：' + CONFIDENCE[plain['confidence']] + ' · 检测状态：' + STATUS[plain['status']]
        finding_cards.append('<article class="finding"><div>' + badges + '</div><h3>' + esc(plain['plain_title']) + '</h3><p>' + esc(labels) + '</p><p>' + esc(plain['observation']) + ' ' + esc(plain['meaning']) + '</p><p><b>下一步</b><br>' + esc(plain['next_step']) + '</p><p><b>如何复测</b><br>' + esc(plain['retest']) + '</p><details><summary>Structured evidence / 结构化证据 · ' + esc(plain['code']) + '</summary><p>' + esc(f.get('title')) + '</p><p><b>Recommendation / 建议</b> ' + esc(f.get('recommendation')) + '</p><p><b>Retest / 复测</b> ' + esc(f.get('retest')) + '</p><pre>' + esc(json.dumps(f.get('evidence', {}), ensure_ascii=False, indent=2)) + '</pre></details></article>')
    plain_summary = summarize_report(prepared)
    guidance = '<section class="scope"><h2>先看覆盖范围</h2><p>' + esc(plain_summary['coverage']).replace('\n', '<br>') + '</p><p>' + esc(plain_summary['observations']) + '</p><h3>先做什么</h3>'
    for item in plain_summary['priorities']:
        guidance += '<p><b>' + esc(item['plain_title']) + '</b> · ' + esc(item['next_step']) + '</p>'
    guidance += '</section>'
    services = [dict(address=a.get('address'), **{k: s.get(k) for k in ('port', 'protocol', 'state', 'service', 'source', 'observed_at')}) for a in assets for s in a.get('services', [])]
    sources = table('Evidence sources and original times', ('type', 'observed_at', 'imported_at', 'sha256'), prepared.get('sources', []))
    comparison = ''
    if 'comparison' in prepared:
        comp = prepared['comparison']
        comparison = '<h2>Snapshot comparison</h2><p>Mode: ' + esc(comp.get('mode')) + '. Absence means not observed; scope differences prevent automatic remediation claims.</p>'
        for key in ('before', 'after'):
            side = comp.get(key, {})
            comparison += '<h3>' + key.title() + '</h3><pre>' + esc(json.dumps(side.get('summary', {}), ensure_ascii=False, indent=2)) + '</pre>'
            comparison += '<p>Persisted snapshot ID: ' + esc(side.get('snapshot_id')) + ' · Original collection time: ' + esc(side.get('collected_at')) + '</p>'
            comparison += table(key.title() + ' coverage', ('category', 'status', 'partial', 'planned', 'evaluated', 'unattempted'), side.get('coverage', []))
            comparison += '<details><summary>Assets, source times and gaps</summary><pre>' + esc(json.dumps(side, ensure_ascii=False, indent=2)) + '</pre></details>'
    content = guidance + (comparison if is_comparison else '<h2>Prioritized findings</h2>' + (''.join(finding_cards) or '<p>No prioritized findings observed; missing evidence does not establish security.</p>') + table('Assets', ('id', 'address', 'family', 'status'), assets) + table('Services', ('address', 'port', 'protocol', 'state', 'service', 'source', 'observed_at'), services) + table('Coverage', ('category', 'status', 'reason', 'count_unit', 'planned', 'attempted', 'evaluated', 'unattempted', 'partial'), coverage) + sources + packets_html)
    css = """*{box-sizing:border-box}body{font:15px/1.55 system-ui,'Microsoft YaHei',sans-serif;background:#eef2f7;color:#17263d;margin:0}main{max-width:1220px;margin:auto;padding:28px}header{background:#142941;color:#f6f9ff;padding:25px;border-radius:12px}header h1{margin:0 0 8px;font-size:30px}header p{margin:5px 0;color:#d5e2f1}.synthetic{padding:14px 18px;margin:18px 0;background:#fff0c2;border-left:5px solid #ae6d00;font-weight:650}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:20px 0}.metric{padding:17px;background:white;border:1px solid #d5deea;border-radius:10px}.metric strong{display:block;font-size:28px}.metric span{color:#4f627a}.scope{background:#e1eaf7;border-radius:10px;padding:16px 20px}.scope p{margin:6px 0}h2{margin-top:30px;font-size:22px}h3{font-size:18px}.finding{background:white;border:1px solid #d5deea;border-left:4px solid #bc6c20;border-radius:8px;padding:18px 22px;margin:14px 0}.finding p{max-width:100ch}.badge{display:inline-block;white-space:nowrap;padding:3px 10px;margin:0 7px 5px 0;border-radius:5px;background:#e6edf5;font-size:13px;font-weight:650}table{border-collapse:collapse;background:white;width:100%;font-size:14px}th{white-space:nowrap;background:#dae4f0}th,td{border:1px solid #cdd8e5;padding:10px 12px;text-align:left;vertical-align:top}td{overflow-wrap:anywhere;min-width:90px}tr:nth-child(even){background:#f7f9fc}.scroll{overflow:auto}details{padding:12px;background:#f4f7fb;border:1px solid #d7e1ed;border-radius:6px;margin:10px 0}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace}footer{margin-top:25px;color:#52657e}@media(max-width:700px){main{padding:14px}.metrics{grid-template-columns:repeat(2,1fr)}.finding{padding:14px}}"""
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;"><title>WiFiScope report</title><style>' + css + '</style></head><body><main><header><h1>WiFiScope · Evidence report</h1><p>Security investigation / 安全调查</p><p>Sources: ' + esc(source) + ' · Collected: ' + esc(prepared.get('collected_at')) + '</p></header>' + banner + scope + '<div class="metrics">' + cards + '</div>' + content + '<h2>Typed evidence</h2><details><summary>Inspect all allowlisted measurements</summary><div class="scroll"><table><tr><th>Field</th><th>Value</th></tr>' + typed_rows + '</table></div></details><footer>Observations are limited evidence; absence of findings does not establish security. TCP timings do not measure throughput. Pseudonymization minimizes identifiers but does not guarantee anonymity.</footer></main></body></html>'
