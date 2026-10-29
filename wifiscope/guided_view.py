"""Scrollable novice presentation; no collection or controller ownership here."""
import tkinter as tk
from tkinter import ttk

from .comparison import comparison_notice
from .explanations import CONFIDENCE, SEVERITY, STATUS, summarize_report
from .guidance import GuidanceError, target_plan


class GuidedView:
    def __init__(self, app, parent, footer):
        self.app = app
        self.frame = ttk.Frame(parent, padding=(14, 6))
        self.canvas = tk.Canvas(self.frame, bg='#edf2f8', highlightthickness=0, takefocus=True)
        scroll = ttk.Scrollbar(self.frame, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.canvas.pack(fill='both', expand=True)
        inner = ttk.Frame(self.canvas, padding=(8, 4, 18, 20))
        window = self.canvas.create_window((0, 0), window=inner, anchor='nw')
        inner.bind('<Configure>', lambda event: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda event: self.canvas.itemconfigure(window, width=event.width))
        self.canvas.bind('<Next>', lambda event: self.canvas.yview_scroll(1, 'pages'))
        self.canvas.bind('<Prior>', lambda event: self.canvas.yview_scroll(-1, 'pages'))
        app.root.bind('<MouseWheel>', self._wheel, add='+')
        self.host = tk.StringVar()
        self.url = tk.StringVar()
        self.authorized = tk.BooleanVar(value=False)
        self.preview = tk.StringVar(value='尚未预览。填写单个目标后点击“预览检查计划”，不会发送网络请求。')
        self.plan = None
        self.host.trace_add('write', self.invalidate)
        self.url.trace_add('write', self.invalidate)
        ttk.Label(inner, text='先选一件要做的事', font=('Microsoft YaHei UI', 17, 'bold')).pack(anchor='w', pady=(0, 5))
        self._label(inner, '1 选择任务 → 2 先看覆盖与未知 → 3 查看下一步并导出。启动、切换模式和离线演示都不会主动检查网络。')
        actions = ttk.Frame(inner)
        actions.pack(fill='x', pady=8)
        self.local_button = ttk.Button(actions, text='① 了解这台电脑', command=lambda: app.guard(app.collect))
        self.local_button.pack(side='left', padx=(0, 8))
        ttk.Button(actions, text='② 检查指定设备 / 服务', command=self.focus_target).pack(side='left', padx=(0, 8))
        ttk.Button(actions, text='③ 读懂已有证据文件', command=lambda: app.guard(app.open_evidence)).pack(side='left')
        self._label(inner, '本机检查只读取 Wi-Fi、网卡、路由和防火墙配置，不发送目标探测，也不证明互联网可用。文件导入只解释已有证据，不会自动复测。')
        self.demo_button = ttk.Button(inner, text='先试离线演示 · 全部为合成证据', command=lambda: app.guard(app.load_demo))
        self.demo_button.pack(anchor='w', pady=8)
        deep = ttk.Frame(inner)
        deep.pack(fill='x', pady=5)
        for key, label in [('catalog', '漏洞库与清单'), ('vulnerability', '漏洞审计 · 已有证据'), ('capture', '实时抓包 · 先授权'), ('survey', 'Wi-Fi 热力图 · 定点采样')]:
            ttk.Button(deep, text=label, command=lambda k=key: app.open_security_tools(k)).pack(side='left', padx=(0, 6))
        target = ttk.LabelFrame(inner, text='指定设备 / 服务 · 默认只检查端口 80、443', padding=10)
        target.pack(fill='x', pady=8)
        target.columnconfigure(1, weight=1)
        ttk.Label(target, text='单个主机名 / IP').grid(row=0, column=0, sticky='w', pady=4)
        self.host_entry = ttk.Entry(target, textvariable=self.host)
        self.host_entry.grid(row=0, column=1, sticky='ew', padx=8)
        ttk.Label(target, text='可选 HTTP(S) URL').grid(row=1, column=0, sticky='w', pady=4)
        ttk.Entry(target, textvariable=self.url).grid(row=1, column=1, sticky='ew', padx=8)
        self.preview_button = ttk.Button(target, text='预览检查计划（只验证输入）', command=lambda: app.guard(self.preview_target))
        self.preview_button.grid(row=2, column=0, columnspan=2, sticky='w', pady=6)
        ttk.Label(target, textvariable=self.preview, wraplength=740, justify='left').grid(row=3, column=0, columnspan=2, sticky='ew')
        self._label(inner, 'URL 仅允许同一主机；不会跟随重定向或读取正文。TLS 正常验证；开放端口不是漏洞。预览后在底部确认授权并开始，修改目标会清除授权。')
        ttk.Label(inner, text='先看覆盖，再看发现', font=('Microsoft YaHei UI', 14, 'bold')).pack(anchor='w', pady=(12, 6))
        results_box = ttk.Frame(inner)
        results_box.pack(fill='both', expand=True)
        self.results = tk.Text(results_box, height=24, wrap='word', bg='white', relief='flat', padx=14, pady=10, font=('Microsoft YaHei UI', 10))
        results_scroll = ttk.Scrollbar(results_box, command=self.results.yview)
        self.results.configure(yscrollcommand=results_scroll.set)
        results_scroll.pack(side='right', fill='y')
        self.results.pack(fill='both', expand=True)
        ttk.Button(inner, text='查看全部发现、来源与选中证据 → 专业工作台', command=lambda: app.set_mode('professional')).pack(anchor='w', pady=10)
        self._label(inner, '小词典：Wi-Fi 名称（SSID）是网络显示名；信号是当前位置的无线强度，不能代表带宽。设备地址（IP）用于定位端点；端口表示某项服务入口。证书帮助核验加密连接的身份。覆盖缺口表示没检查到或证据不足；没有发现不表示安全。置信表示证据把握程度，与优先级及检测状态分开。')
        self._label(inner, '隐私：底部“导出脱敏报告”默认替换地址等标识符，本地备注不导出。专业工作台提供原始标识符导出和案件保留两项独立选择；脱敏不保证匿名，独立脱敏文件只能比较数量。')
        self.start_bar = ttk.Frame(footer)
        self.start_bar.pack(fill='x', pady=(0, 4))
        ttk.Checkbutton(self.start_bar, text='我已获授权检查预览中的目标与端口', variable=self.authorized).pack(side='left')
        self.start_button = ttk.Button(self.start_bar, text='开始预览的目标检查', command=lambda: app.guard(app.guided_probe))
        self.start_button.pack(side='left', padx=8)
        self.render(None)

    @staticmethod
    def _label(parent, text):
        ttk.Label(parent, text=text, wraplength=760, justify='left').pack(fill='x', pady=3)

    def _wheel(self, event):
        if self.frame.winfo_ismapped() and not isinstance(event.widget, tk.Text):
            self.canvas.yview_scroll(-int(event.delta / 120), 'units')

    def focus_target(self):
        self.canvas.yview_moveto(.15)
        self.host_entry.focus_set()

    def invalidate(self, *_):
        self.plan = None
        self.authorized.set(False)
        self.preview.set('目标已修改；请重新预览，核对后再确认授权。')

    def preview_target(self):
        self.plan = target_plan(self.host.get(), self.url.get())
        self.authorized.set(False)
        p = self.plan
        count = p['connections_per_address']
        self.preview.set(f"目标：{', '.join(p['hosts'])}\nTCP 端口：{', '.join(map(str, p['endpoint_ports']))}；TLS：{', '.join(map(str, p['tls_ports']))}；HEAD URL：{', '.join(p['urls']) or '无'}\n每个解析地址 {count} 次连接（TCP {len(p['endpoint_ports'])} + TLS {len(p['tls_ports'])} + HEAD {len(p['urls'])}）；限速 4 次/秒，规划估算约 {p['minimum_seconds']:.2f} 秒/地址（首次可立即开始）。\n解析前地址数量未知，最多 {p['max_addresses']} 个地址、{count * p['max_addresses']} 次连接；解析失败可为 0 次。每项超时 0.5 秒，实际耗时可能更短或更长。")

    def checked_plan(self):
        if self.plan is None:
            raise GuidanceError('invalidtarget')
        if not self.authorized.get():
            raise GuidanceError('authorization')
        return self.plan

    def render(self, report):
        summary = summarize_report(report)
        lines = ['合成离线演示 · 这些数据不是在线实测。'] if report and (report.get('synthetic') or 'synthetic-demo' in report.get('gaps', [])) else []
        notice = comparison_notice(report or {})
        if notice:
            lines = [notice]
        lines += [summary['coverage'], '', summary['observations'], '', '先做什么（最多 3 条当前发现）']
        if report and 'catalog_audit' in report:
            audit = report['catalog_audit']
            counts = audit['summary']
            lines += [f"漏洞库收录 {audit['catalog']['records']}；已评估资产-CVE 对 {counts['evaluated_pairs']}；模型匹配 {counts['true_pairs']}；未知条件 {counts['unknown_pairs']}；不匹配 {counts['not_matched_pairs']}；未评估 {counts['unexamined_pairs']}。",
                      '未知条件需要补充证据；来源 CVE 严重度不证明资产受影响。声明/导入身份不是安装确认，无匹配不是安全证明。']
        for item in summary['priorities']:
            lines += ['', item['plain_title'], '优先级：' + SEVERITY[item['severity']] + ' · 置信：' + CONFIDENCE[item['confidence']] + ' · 状态：' + STATUS[item['status']], item['observation'], item['meaning'], '下一步：' + item['next_step'], '如何复测：' + item['retest']]
        self.app._text(self.results, '\n'.join(lines))
