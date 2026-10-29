"""Deterministic Chinese presentation, never templates from imported prose.

These functions return new dictionaries and never alter evidence or identities.
"""
from datetime import datetime

from .rules import catalog
from .investigate import _run_contexts, run_summary


SEVERITY = dict(critical='严重', high='高', medium='中', low='低', info='提示', warning='警示', unknown='未知')
CONFIDENCE = dict(high='高', medium='中', low='低', unknown='未知')
STATUS = {'observed': '已观察', 'needs-review': '待核查', 'imported-unverified': '导入 · 未验证', 'unknown': '未知'}
RUN = dict(complete='已完成限定检查', partial='部分完成', cancelled='已取消', deadline='已到截止时间', unknown='未知')
COVERAGE = {'wifi-configuration': 'Wi-Fi 配置', 'local-firewall': '本机防火墙', 'tcp-exposure': 'TCP 连接',
            'dns-resolution': '地址解析', 'ipv4': 'IPv4 连接', 'ipv6': 'IPv6 连接',
            'tls-validation': 'TLS 证书', 'http-posture': 'HTTP 响应策略', 'tls': 'TLS 证书',
            'offline-packets': '离线抓包元数据', 'external-vulnerability-scan': '外部扫描', 'environment-context': '本机环境',
            'local-vulnerability-audit': '本地版本漏洞候选核查'}
# title, observation, implication, safe next action; each key is a shipped rule.
_ZH = {
    'cve-version-match': ('软件版本匹配公告范围', '明确的软件产品和版本匹配本地公告目录。', '配置、平台条件和发行版回补尚未核实，版本匹配不能证明可利用性。', '向负责人核对安装包、厂商公告及回补状态，补充相同授权范围的证据。'),
    'packet-http': ('抓包中有明文 HTTP 请求', '离线抓包记录了 HTTP 请求元数据。', '可能需要加密；元数据不能证明密码泄漏。', '向应用负责人确认是否应使用 HTTPS。'),
    'arp-conflict': ('地址对应关系需要核查', '同一 IP 出现不同 MAC 对应关系。', '高可用、代理 ARP 或地址复用都可能造成差异，不能确认攻击。', '与网络管理员核对 ARP 和高可用配置。'),
    'cleartext-exposure': ('可能开放了明文服务', '观察到可能用于明文协议的开放端口。', '端口号只是线索，不能证明协议或漏洞。', '确认实际应用协议和加密要求。'),
    'management-exposure': ('管理或文件共享端口可连接', '观察到管理或共享端口开放。', '开放端口不等于漏洞，应结合允许的访问范围理解。', '与负责人核对允许的客户端和访问控制。'),
    'tls-trust': ('证书验证未通过', '正常 TLS 证书验证失败。', '证书链、主机名、本机时间或信任库都可能影响结果。', '核对时间、主机名和证书链，不要关闭验证。'),
    'tls-expired': ('证书已过期', '证书有效期已结束。', '需结合观测时间和本机时钟核实。', '联系负责人更新证书并检查证书链。'),
    'tls-expiring': ('证书即将到期', '观察到证书将在 30 天内到期。', '证书需要及时续期，避免之后验证失败。', '安排续期并核对替换证书有效期。'),
    'tls-legacy': ('协商使用了旧版 TLS', '一次正常握手协商了旧版 TLS。', '此检查没有枚举服务支持的全部版本。', '与负责人审查服务的协议配置。'),
    'tls-weak-cipher': ('协商使用了弱密码套件', '一次握手观察到弱密码套件。', '只说明本次协商结果，不能概括所有客户端。', '与服务负责人审查密码套件配置。'),
    'http-transport': ('地址使用了 HTTP', '显式 URL 的请求使用明文 HTTP。', 'HTTP 不等于已经泄漏密码，应结合用途判断。', '确认此地址是否应迁移到 HTTPS。'),
    'http-hsts': ('HTTPS 强制策略需要核查', '成功的 HTTPS 响应缺少有效的 HSTS 有效期策略。', '浏览器后续访问的传输保护可能需要配置。', '与网站负责人审查 HSTS 的适用范围。'),
    'http-csp': ('网页内容策略需要核查', '成功的 HTML 响应未观察到内容安全策略。', '响应头缺失是配置线索，不证明可利用漏洞。', '为应用评估合适的 CSP 策略。'),
    'http-frame': ('网页嵌入保护需要核查', 'HTML 响应未观察到可判定的限制嵌入策略。', '需结合应用是否允许被嵌入判断。', '审查 frame-ancestors 或框架保护响应头。'),
    'http-nosniff': ('网页类型保护需要核查', 'HTML 响应未观察到 nosniff 策略。', '浏览器内容类型处理可能需要加强。', '与网站负责人核对 nosniff 配置。'),
    'cookie-secure': ('Cookie 传输标记需要核查', '观察到 Cookie 缺少 Secure 标记，未保留其值。', '需结合用途评估是否只允许加密传输。', '审查相应 Cookie 的 Secure 标记。'),
    'cookie-httponly': ('Cookie 脚本访问标记需要核查', '观察到 Cookie 缺少 HttpOnly 标记，未保留其值。', '是否允许脚本读取需结合应用用途评估。', '审查相应 Cookie 是否应设置 HttpOnly。'),
    'family-reachability': ('IPv4 与 IPv6 连接结果不同', '两种地址族的连接结果存在差异。', '解析的地址可能对应不同系统，不能据此确认策略失效。', '在相同授权范围内核对等价端点和预期策略。'),
    'scanner-finding': ('扫描器导入的待验证发现', '外部扫描报告包含一条发现。', '这是未经独立验证的扫描器主张，不能当作已确认漏洞。', '在原扫描工具中核查适用性并独立验证。'),
    'wifi-unavailable': ('尚无 Wi-Fi 证据', '本次没有可用 Wi-Fi 观测。', '无法据此判断无线配置。', '选择本机只读检查或导入 Wi-Fi 文本。'),
    'open-wifi': ('观察到开放 Wi-Fi', '观测中的无线网络未要求认证。', '应核对是否为预期网络，不能据此判断攻击。', '确认网络归属并评估认证加密配置。'),
    'weak-encryption': ('观察到旧式无线加密', '观测中包含 WEP 或 TKIP。', '旧式算法需要结合设备兼容性审查。', '与管理员评估现代认证加密方案。'),
    'security-unavailable': ('无线安全配置未知', '缺少认证或加密方式信息。', '缺少信息不表示配置安全。', '补充认证和加密方式的观测。'),
    'weak-signal': ('观察到较弱信号', '信号百分比低于本工具提示阈值。', '信号强度不能单独证明连接质量或带宽。', '在接近接入点的位置重复观测。'),
    'mixed-security': ('同名 Wi-Fi 的安全配置不同', '同一 Wi-Fi 名称下出现不同认证或加密方式。', '同名差异不能证明存在攻击。', '向管理员确认各接入点的预期配置。'),
    'firewall-unavailable': ('本机防火墙状态未知', '缺少可靠的防火墙启用状态。', '不能据此判断主机的防护情况。', '使用系统管理工具核查防火墙状态。'),
    'firewall-disabled': ('本机防火墙配置未启用', '观察到防火墙配置文件处于关闭状态。', '应结合主机的预期策略理解。', '与管理员核对预期策略后再调整设置。'),
}
_UNKNOWN = ('未识别规则的证据', '存在一项无法按已知规则解释的记录。', '当前无法判断含义，不作安全或漏洞结论。', '在专业工作台人工核查结构化证据和来源。')


def _controlled(value, labels):
    return value if isinstance(value, str) and value in labels else 'unknown'


def _display_time(value):
    """Render only a bounded canonical date, never imported free-form prose."""
    if not isinstance(value, str) or len(value) > 64:
        return '未知'
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).isoformat()
    except ValueError:
        return '未知'


def explain_finding(finding):
    """Return controlled prose plus canonical code/severity/confidence/status."""
    code = finding.get('code')
    code = code if isinstance(code, str) and code in catalog() and code in _ZH else 'unknown'
    title, observation, meaning, next_step = _ZH.get(code, _UNKNOWN)
    return dict(code=code, severity=_controlled(finding.get('severity'), SEVERITY),
                confidence=_controlled(finding.get('confidence'), CONFIDENCE),
                status=_controlled(finding.get('status'), STATUS), plain_title=title,
                observation=observation, meaning=meaning, next_step=next_step,
                retest='在相同授权范围和相同条件下重复对应观测；核对证据与时间，缺失或部分结果不能证明已修复。')


def summarize_report(report):
    """Return coverage-first text and at most three actual finding explanations."""
    report = report or {}
    comparison = report.get('comparison')
    warning = '未知、未检查或部分覆盖不代表安全；缺少观测不能证明已修复。'
    if comparison:
        lines = ['快照比较 · ' + ('仅数量比较，不能关联身份。' if comparison.get('mode') == 'counts-only' else '身份关联仍受范围限制。')]
        for side in ('before', 'after'):
            row = comparison.get(side, {})
            counts = row.get('summary', {})
            lines.append(f"{side.title()}: 资产 {counts.get('assets', 0)} · 发现 {counts.get('findings', 0)} · 覆盖项 {len(row.get('coverage', []))} · 缺口 {len(row.get('gaps', []))}")
        return dict(coverage='\n'.join(lines + [warning, '请在专业工作台核对双方原始时间和范围；数量为 0 不能视为干净审计。']), priorities=[], observations='')
    inv = report.get('investigation', {})
    contexts = _run_contexts(report)
    run = run_summary(report)
    state = '多个执行范围 · 部分或未知覆盖' if len(contexts) > 1 else RUN.get(run.get('status'), '未记录统一执行状态（覆盖范围未知）')
    coverage = inv.get('coverage', [])
    lines = ['执行状态：' + state + '。' + warning,
             f"本次记录 {len(coverage)} 个覆盖项、{len(report.get('gaps', []))} 个缺口；未列出缺口不表示完整覆盖。"]
    counts = [str(run[key]) if type(run.get(key)) is int and run[key] >= 0 else '未知'
              for key in ('planned_connections', 'attempted_connections', 'unattempted_endpoints')]
    lines.append(f'计划连接 {counts[0]} · 实际连接 {counts[1]} · 未检查端点 {counts[2]}。')
    if len(contexts) > 1:
        for index, context in enumerate(contexts, 1):
            values = [str(context[key]) if type(context.get(key)) is int and context[key] >= 0 else '未知'
                      for key in ('planned_connections', 'attempted_connections', 'unattempted_endpoints')]
            lines.append(f"范围 {index}：{RUN.get(context.get('status'), '未知')} · 计划连接 {values[0]} · 实际连接 {values[1]} · 未检查端点 {values[2]} · 观测时间 {_display_time(context.get('observed_at'))}")
    for row in coverage:
        category = COVERAGE.get(row.get('category'), '其他检查')
        status = {'observed': '已观察', 'imported': '导入证据', 'unavailable': '证据不可用', 'not-run': '未检查', 'not_run': '未检查', 'unknown': '未知'}.get(row.get('status'), '待核查')
        lines.append(category + '：' + status + (' · 部分覆盖' if row.get('partial') else ''))
    lines.append('未检查或未知的项目需到专业工作台“覆盖与缺口”核查；本工具不提供完整漏洞扫描或带宽测速。')
    if report.get('sources') and not report.get('connectivity'):
        lines.append('已有来源可能仅为导入或本机只读证据；导入主张未经独立验证，不能证明当前可连接。')
    findings = inv.get('findings', [])
    if not findings:
        lines.append('本次已检查的项目未发现需提示的问题；尚无证据时也不代表已完成检查。')
    order = dict(critical=0, high=1, medium=2, warning=2, low=3, info=4)
    top = sorted(findings, key=lambda f: order.get(f.get('severity'), 5))[:3]
    signals = [row['signal_percent'] for row in report.get('wifi', [])
               if type(row.get('signal_percent')) in (int, float) and 0 <= row['signal_percent'] <= 100]
    signal_text = f'已记录信号 {min(signals):g}% 至 {max(signals):g}%。' if signals else '信号强度未知。'
    tcp = [row for target in report.get('connectivity', []) for row in target.get('tcp', [])]
    connected = sum(row.get('status') == 'ok' for row in tcp)
    refused = sum(row.get('status') == 'refused' for row in tcp)
    timeout = sum(row.get('status') == 'timeout' for row in tcp)
    observations = (f"Wi-Fi 配置观测 {len(report.get('wifi', []))} 条；{signal_text}连接证据目标 {len(report.get('connectivity', []))} 个。"
                    f'TCP 记录：已连接 {connected} · 拒绝 {refused} · 超时 {timeout} · 未知或未检查 {len(tcp) - connected - refused - timeout}。'
                    '这些是已有观测，不代表当前持续可连接。本机只读检查读取配置，不证明互联网可用；TCP 耗时不是带宽或丢包率。')
    return dict(coverage='\n'.join(lines), priorities=[explain_finding(f) for f in top], observations=observations)
