"""Beginner workflow for local and authorized campus evidence."""
import tkinter as tk
from tkinter import ttk

from .field_audit import run_field

_ISOLATION = {
    'not-tested': '未执行对端抽测',
    'inconclusive': '所测对端未回应，隔离状态未定',
    'icmp-only': '发现 Ping 回包，所测 TCP 互通未证实',
    'tcp-reachable': '所测目标至少一个 TCP 端口可连接',
    'tcp-reachable-with-shared-mac': 'TCP 可连接的地址中有与网关共用 MAC 的条目',
}
_STATUS = {
    'ok': '成功', 'redirect': '重定向', 'http_error': 'HTTP 错误',
    'tls_error': 'TLS 握手失败', 'certificate_error': '证书验证失败',
    'timeout': '超时', 'refused': '拒绝连接', 'reachable': '可连接',
    'cancelled': '已取消', 'error': '连接错误', 'dns_error': '解析失败',
    'not-run': '未执行', 'no-compatible-address': '没有与源地址匹配的地址',
}


def _status(value):
    return _STATUS.get(value, value)


def _label(value):
    return str(value) if value is not None else '未知'


def describe(report):
    link = report['link']
    lines = [
        '执行状态：' + ('已取消，保留已有观测' if report['status'] == 'cancelled' else '已完成所选检查'),
        f"当前无线：{_label(link.get('ssid'))}   加密：{_label(link.get('cipher'))}",
        '本机地址：' + ('、'.join(link.get('addresses', [])) or '未知'),
        '默认网关：' + ('、'.join(link.get('gateways', [])) or '未知'),
        'DNS：' + ('、'.join(link.get('dns', [])) or '未知'),
        'DHCP 租期（秒）：' + _label(link.get('lease_seconds')),
    ]
    if report['plan']['source_status'] == 'system-selected' and (
            report['plan']['gateway'] or report['plan']['portals'] or report['plan']['peers']):
        lines.append('主动检查由系统选择路由。指定本机源地址请使用 CLI。')
    if report['gateway']:
        lines.append('网关端口与协议')
        for row in report['gateway']['ports']:
            protocol = row['protocol']
            detail = ''
            if protocol == 'ssh':
                detail = ' · SSH ' + row['ssh_version']
                if row['product_hint']:
                    detail += ' · ' + row['product_hint']
            elif protocol == 'telnet':
                detail = ' · Telnet' + (' · 收到登录提示' if row['login_prompt'] else '')
            lines.append(f"  TCP {row['port']} · {_status(row['status'])}{detail}")
    if report['portal']:
        lines.append('门户时间线')
        for row in report['portal']:
            code = row['http_status'] if row['http_status'] is not None else _status(row['status'])
            redirect = ' · 有重定向头' if row['has_location'] else ''
            lines.append(f"  第 {row['sample']} 次 · {row['transport'].upper()} · {code}{redirect} · {row['observed_at']}")
    lines.append('对端结果：' + _ISOLATION[report['isolation']])
    if report['peer_sample']:
        tested = sum(len(row['tcp']) for row in report['peer_sample'])
        replies = sum(row['icmp']['status'] == 'reply' for row in report['peer_sample'])
        lines.append(f"  {len(report['peer_sample'])} 个地址 · {tested} 次 TCP 检查 · {replies} 个地址回 Ping")
        shared = sum(row.get('class') == 'shared_gateway_mac'
                     for row in (report['neighbor'] or {}).get('rows', []))
        lines.append(f'  {shared} 个地址与网关共用邻居 MAC。可用配对测试确认对端身份。')
    if link.get('gaps'):
        lines.append('有些本机信息无法读取，具体项目见导出的 JSON。')
    return '\n'.join(lines)


class FieldView:
    standalone = True
    error_help = ' 请核对网关和对端 IP、门户 URL、授权选择及输出路径。'

    def __init__(self, tools, parent):
        self.tools = tools
        self.result = None
        self.gateway = tk.StringVar(master=parent)
        self.portal = tk.StringVar(master=parent)
        self.peers = tk.StringVar(master=parent)
        self.authorized = tk.BooleanVar(master=parent)
        tools.text(parent, '先读取当前连接。需要复测时，核对指定的网关、门户和对端，再授权开始。')
        controls = ttk.Frame(parent)
        controls.pack(fill='x')
        controls.columnconfigure(1, weight=1)
        for index, (label, value) in enumerate((
            ('网关 IP', self.gateway), ('门户 HTTP(S) 地址', self.portal),
            ('对端 IP（逗号分隔，可选）', self.peers),
        )):
            ttk.Label(controls, text=label).grid(row=index, column=0, sticky='w', pady=2)
            ttk.Entry(controls, textvariable=value).grid(row=index, column=1, sticky='ew', padx=8)
            value.trace_add('write', self._clear_authorization)
        buttons = ttk.Frame(parent)
        buttons.pack(fill='x', pady=4)
        ttk.Button(buttons, text='读取当前连接', command=lambda: tools.guard(self.inspect)).pack(side='left')
        ttk.Checkbutton(buttons, text='我已获授权检查以上目标', variable=self.authorized).pack(side='left', padx=8)
        ttk.Button(buttons, text='开始复测', command=lambda: tools.guard(self.audit)).pack(side='left')
        tools.text(parent, '随机地址超时可能来自离线或防火墙。用两台设备运行 field listen / field check 可校验对端。')
        self.output = tools.output(parent, height=12)
        self.output.configure(state='disabled')

    def _clear_authorization(self, *_):
        self.authorized.set(False)

    def inspect(self):
        self.tools.start(self, '读取当前连接',
                         lambda cancel, progress: run_field(cancel=cancel),
                         progress_kind='catalog-local')

    def audit(self):
        gateway = self.gateway.get().strip() or None
        url = self.portal.get().strip()
        peers = tuple(p.strip() for p in self.peers.get().split(',') if p.strip())
        if not (gateway or url or peers) or not self.authorized.get():
            raise ValueError('Enter and authorize the field targets.')
        self.tools.start(self, '校园网定点复测',
                         lambda cancel, progress: run_field(
                             gateway=gateway, portals=(url,) if url else (),
                             peers=peers, authorized=True, cancel=cancel),
                         progress_kind='catalog-local')

    def on_result(self, result):
        if 'exported' in result:
            return
        self.result = result
        link = result['link']
        if not self.gateway.get() and result['status'] == 'complete':
            ipv4 = next((g for g in link.get('gateways', []) if ':' not in g), None)
            if ipv4:
                self.gateway.set(ipv4)
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', describe(result))
        self.output.configure(state='disabled')
