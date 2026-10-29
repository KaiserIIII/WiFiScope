"""Tk security workstation. All widgets and queue delivery live on the Tk thread."""
import copy
import json
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .batch import audit_scope, plan_scope
from .collect import collect_local
from .comparison import compare_snapshots, comparison_notice
from .demo import demo_report
from .gui_controller import Controller
from .guidance import ERRORS, GuidanceError
from .guided_view import GuidedView
from .investigate import build_investigation, _run_contexts, run_summary
from .probe import probe_hosts
from .scope import QUICK_PORTS
from .workstation import existing_case, load_json


class Workstation:
    def __init__(self, root, demo_provider=demo_report):
        self.root = root
        self.demo_provider = demo_provider
        self.controller = Controller()
        self.security_tools = None
        self.tables = {}
        self.finding_rows = {}
        self.history_offset = 0
        self.root.title('WiFiScope · 安全证据工作台')
        width = min(1180, max(900, root.winfo_screenwidth() - 70))
        height = min(740, max(620, root.winfo_screenheight() - 70))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(900, 620)
        self.root.configure(bg='#edf2f8')
        self.style = ttk.Style(root)
        self.style.theme_use('clam')
        self.style.configure('.', font=('Microsoft YaHei UI', 10), background='#edf2f8', foreground='#192d46')
        self.style.configure('TButton', padding=(10, 5))
        self.style.configure('Treeview', background='white', fieldbackground='white', rowheight=29)
        self.style.configure('Treeview.Heading', background='#dce6f2', font=('Microsoft YaHei UI', 10, 'bold'))
        self.style.configure('TNotebook.Tab', padding=(13, 6))
        self.style.map('Treeview', background=[('selected', '#254e79')], foreground=[('selected', 'white')])
        self.source = tk.StringVar(value='尚无证据 · 使用离线演示开始，或明确选择证据格式。')
        self.status = tk.StringVar(value=self.controller.status)
        self.scope = tk.StringVar()
        self.host = tk.StringVar()
        self.ports = tk.StringVar(value=','.join(map(str, QUICK_PORTS)))
        self.authorized = tk.BooleanVar(value=False)
        self.export_raw = tk.BooleanVar(value=False)
        self.retain_raw = tk.BooleanVar(value=False)
        self.search = tk.StringVar()
        self.severity = tk.StringVar(value='all')
        self.mode = tk.StringVar(value='novice')
        self._build()
        root.bind('<Control-o>', lambda event: self.guard(self.open_evidence))
        root.bind('<Control-e>', lambda event: self.guard(self.export))
        root.protocol('WM_DELETE_WINDOW', self.close)
        self.timer = root.after(50, self.pump)

    def _build(self):
        header = tk.Frame(self.root, bg='#142941', padx=20, pady=12)
        header.pack(fill='x')
        tk.Label(header, text='WiFiScope', font=('Segoe UI', 22, 'bold'), fg='white', bg='#142941').pack(side='left')
        self.mode_switch = ttk.Frame(header)
        self.mode_switch.pack(side='right')
        for value, text in [('novice', '新手引导'), ('professional', '专业工作台')]:
            ttk.Radiobutton(self.mode_switch, text=text, variable=self.mode, value=value, command=lambda: self.set_mode(self.mode.get())).pack(side='left')
        security_bar = ttk.Frame(self.root, padding=(16, 3))
        security_bar.pack(fill='x')
        self.security_buttons = []
        for key, label in [('vulnerability', '漏洞审计'), ('capture', '实时抓包'), ('survey', 'Wi-Fi 热力图')]:
            button = ttk.Button(security_bar, text=label, command=lambda k=key: self.open_security_tools(k))
            button.pack(side='left', padx=(0, 8))
            self.security_buttons.append(button)
        ttk.Label(security_bar, text='独立工具结果 · 明确应用才替换快照').pack(side='left')
        persistent_footer = ttk.Frame(self.root, padding=(16, 6))
        persistent_footer.pack(side='bottom', fill='x')
        self.guided = GuidedView(self, self.root, persistent_footer)
        controls = ttk.Frame(persistent_footer)
        controls.pack(fill='x')
        self.cancel_button = ttk.Button(controls, text='取消当前操作', command=self.controller.cancel)
        self.cancel_button.pack(side='left')
        self.export_button = ttk.Button(controls, text='导出脱敏报告 Ctrl+E', command=lambda: self.guard(self.export))
        self.export_button.pack(side='right')
        self.status_label = ttk.Label(persistent_footer, textvariable=self.status, wraplength=840, foreground='#3b5674')
        self.status_label.pack(fill='x', pady=(4, 0))
        body = ttk.Frame(self.root, padding=(14, 8))
        self.professional = body
        body.pack(fill='both', expand=True)
        tools = ttk.Frame(body)
        tools.pack(fill='x')
        for text, command in [('离线演示', self.load_demo), ('本机采集', self.collect), ('打开证据 Ctrl+O', self.open_evidence), ('保存快照', self.save_case), ('打开案件', self.open_case), ('验证案件', self.verify_case), ('比较快照', self.compare)]:
            ttk.Button(tools, text=text, command=lambda c=command: self.guard(c)).pack(side='left', padx=(0, 5))
        ttk.Label(body, textvariable=self.source, wraplength=1100, foreground='#425e7e').pack(fill='x', pady=(7, 4))
        active = ttk.LabelFrame(body, text='主动检查 · 仅限明确授权的目标（TCP 暴露检查，不是全面漏洞扫描）', padding=(8, 5))
        active.pack(fill='x')
        active.columnconfigure(1, weight=1)
        ttk.Label(active, text='IP / CIDR 范围').grid(row=0, column=0, sticky='w')
        ttk.Entry(active, textvariable=self.scope, width=27).grid(row=0, column=1, sticky='ew', padx=8)
        ttk.Button(active, text='Quick Audit', command=lambda: self.guard(self.quick_audit)).grid(row=0, column=2, padx=5)
        ttk.Checkbutton(active, text='我已获授权检查以上目标', variable=self.authorized).grid(row=0, column=3, sticky='w')
        ttk.Button(active, text='取消', command=self.controller.cancel).grid(row=0, column=4, padx=5)
        ttk.Label(active, text='单主机 / 端口').grid(row=1, column=0, sticky='w', pady=4)
        ttk.Entry(active, textvariable=self.host).grid(row=1, column=1, sticky='ew', padx=8)
        ttk.Button(active, text='Run 单主机', command=lambda: self.guard(self.run_probe)).grid(row=1, column=2, padx=5)
        ttk.Entry(active, textvariable=self.ports, width=37).grid(row=1, column=3, sticky='ew')
        ttk.Button(active, text='快速端口配置', command=lambda: self.ports.set(','.join(map(str, QUICK_PORTS)))).grid(row=1, column=4, padx=5)
        self.scope_status = tk.StringVar(value='Quick profile: 22, 80, 443, 445, 3389, 5900, 8080, 8443 · 最多 64 IP；每批最多 4 主机。')
        ttk.Label(body, textvariable=self.scope_status, wraplength=1100).pack(fill='x', pady=(5, 4))
        cards = ttk.Frame(body)
        cards.pack(fill='x', pady=(0, 7))
        self.metrics = []
        self.metric_labels = []
        for index, label in enumerate(('候选资产', '优先发现', '证据来源', '覆盖缺口')):
            cards.columnconfigure(index, weight=1)
            card = tk.Frame(cards, bg='white', highlightbackground='#d5deea', highlightthickness=1, padx=13, pady=5)
            card.grid(row=0, column=index, sticky='ew', padx=(0, 8 if index < 3 else 0))
            value = tk.StringVar(value='—')
            self.metrics.append(value)
            tk.Label(card, textvariable=value, font=('Segoe UI', 19, 'bold'), fg='#142941', bg='white').pack(side='left')
            metric_label = tk.StringVar(value=label)
            self.metric_labels.append(metric_label)
            tk.Label(card, textvariable=metric_label, fg='#526881', bg='white').pack(side='right')
        # Reserve the footer before the expanding notebook so it stays reachable
        # even when the notebook's natural size exceeds the available height.
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', pady=(7, 0))
        ttk.Checkbutton(footer, text='本次导出包含原始标识符', variable=self.export_raw).pack(side='right')
        ttk.Label(footer, textvariable=self.status, wraplength=650, foreground='#3b5674').pack(side='left', fill='x', expand=True)
        self.notebook = ttk.Notebook(body)
        self.notebook.pack(fill='both', expand=True)
        overview = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(overview, text='概览')
        self.overview = tk.Text(overview, wrap='word', bg='white', fg='#263b55', relief='flat', padx=15, pady=12, font=('Microsoft YaHei UI', 11))
        overview_scroll = ttk.Scrollbar(overview, command=self.overview.yview)
        self.overview.configure(yscrollcommand=overview_scroll.set)
        overview_scroll.pack(side='right', fill='y')
        self.overview.pack(fill='both', expand=True)
        self._text(self.overview, '从“离线演示”开始。所有示例均为合成证据，不会访问网络。\n\n工作流：采集或导入 → 核查范围与缺口 → 查看发现证据 → 保存案件 → 本地处置 → 同范围复测 → 导出。\n\n未观察到问题不等于安全；导入扫描结果仍需独立验证。')
        findings = ttk.Frame(self.notebook)
        self.notebook.add(findings, text='优先发现')
        filters = ttk.Frame(findings, padding=5)
        filters.pack(fill='x')
        ttk.Label(filters, text='搜索').pack(side='left')
        ttk.Entry(filters, textvariable=self.search, width=28).pack(side='left', padx=6)
        ttk.Combobox(filters, textvariable=self.severity, values=['all', 'critical', 'high', 'medium', 'low', 'info', 'warning'], state='readonly', width=10).pack(side='left')
        self.triage_button = ttk.Button(filters, text='处置选中发现', command=lambda: self.guard(self.triage), state='disabled')
        self.triage_button.pack(side='right')
        panes = ttk.Panedwindow(findings, orient='horizontal')
        panes.pack(fill='both', expand=True)
        left, right = ttk.Frame(panes), ttk.Frame(panes)
        panes.add(left, weight=3)
        panes.add(right, weight=2)
        self._table(left, 'findings', [('severity', '优先级', 75), ('title', '发现', 240), ('confidence', '置信', 65), ('status', '检测状态', 115), ('triage_status', '本地处置', 100)])
        self.detail = tk.Text(right, wrap='word', bg='white', relief='flat', padx=12, pady=8, font=('Microsoft YaHei UI', 10))
        detail_scroll = ttk.Scrollbar(right, command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side='right', fill='y')
        self.detail.pack(fill='both', expand=True)
        self._text(self.detail, '选择发现以查看证据、建议和复测条件。')
        self.tables['findings'].bind('<<TreeviewSelect>>', lambda event: self.show_finding())
        self.search.trace_add('write', lambda *_: self.render_findings())
        self.severity.trace_add('write', lambda *_: self.render_findings())
        tabs = [
            ('assets', '资产 / 服务', [('address', '地址', 180), ('family', '协议族', 70), ('status', '状态', 110), ('services', '服务 / 端口 / 来源', 550)]),
            ('wifi', 'Wi-Fi', [('ssid', 'SSID', 180), ('bssid', 'BSSID', 180), ('authentication', '认证', 130), ('encryption', '加密', 100), ('signal_percent', '信号 %', 90), ('channel', '信道', 70)]),
            ('connectivity', '连通性', [('host', '目标', 180), ('address', '地址', 180), ('port', '端口', 75), ('status', 'TCP 状态', 100), ('successes', '成功次数', 90), ('rtt_mean_ms', 'TCP 连接均值 ms', 145)]),
            ('coverage', '覆盖与缺口', [('category', '类别', 180), ('status', '状态', 110), ('source', '来源', 110), ('planned', '计划', 75), ('attempted', '尝试', 75), ('evaluated', '评估', 75), ('unattempted', '未检查', 75), ('partial', '部分', 70)]),
            ('history', '案件历史', [('id', '快照 ID', 90), ('timestamp', '保存时间', 250), ('identifiers_included', '保留标识符', 110), ('summary', '摘要', 400)]),
        ]
        for key, label, columns in tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=label)
            if key == 'history':
                bar = ttk.Frame(frame)
                bar.pack(fill='x')
                ttk.Button(bar, text='上一页', command=lambda: self.guard(lambda: self.history_page(-100))).pack(side='left')
                ttk.Button(bar, text='下一页（100 条）', command=lambda: self.guard(lambda: self.history_page(100))).pack(side='left')
                ttk.Button(bar, text='打开选中快照', command=lambda: self.guard(self.open_history)).pack(side='left')
                ttk.Checkbutton(bar, text='保存案件时保留原始标识符（独立于导出）', variable=self.retain_raw).pack(side='left', padx=8)
            self._table(frame, key, columns)
        comparison = ttk.Frame(self.notebook)
        self.notebook.add(comparison, text='快照比较')
        self.comparison = tk.Text(comparison, wrap='word', bg='white', relief='flat', padx=15, pady=10)
        comparison_scroll = ttk.Scrollbar(comparison, command=self.comparison.yview)
        self.comparison.configure(yscrollcommand=comparison_scroll.set)
        comparison_scroll.pack(side='right', fill='y')
        self.comparison.pack(fill='both', expand=True)
        self.set_mode('novice')

    def set_mode(self, mode):
        if mode not in ('novice', 'professional'):
            raise ValueError('Unknown presentation mode.')
        self.mode.set(mode)
        self.professional.pack_forget()
        self.guided.frame.pack_forget()
        self.guided.start_bar.pack_forget()
        if mode == 'novice':
            self.guided.frame.pack(fill='both', expand=True)
            self.guided.start_bar.pack(before=self.cancel_button.master, fill='x', pady=(0, 4))
        else:
            self.professional.pack(fill='both', expand=True)
        self.export_button.configure(text='导出脱敏报告 Ctrl+E' if mode == 'novice' else '导出（按专业隐私选择）Ctrl+E')
        self.guided.render(self.controller.report)

    def open_security_tools(self, key='vulnerability'):
        if self.security_tools is None:
            from .security_tools_view import SecurityToolsView
            self.security_tools = SecurityToolsView(self)
        self.security_tools.show(key)

    def _table(self, frame, key, columns):
        box = ttk.Frame(frame)
        box.pack(fill='both', expand=True)
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        tree = ttk.Treeview(box, columns=[c[0] for c in columns], show='headings', selectmode='browse')
        for name, label, width in columns:
            tree.heading(name, text=label)
            tree.column(name, width=width, minwidth=65, stretch=True)
        y, x = ttk.Scrollbar(box, orient='vertical', command=tree.yview), ttk.Scrollbar(box, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky='nsew')
        y.grid(row=0, column=1, sticky='ns')
        x.grid(row=1, column=0, sticky='ew')
        for tag, color in [('high', '#9c351c'), ('critical', '#9c351c'), ('medium', '#855000'), ('low', '#315b7d')]:
            tree.tag_configure(tag, foreground=color)
        self.tables[key] = tree

    @staticmethod
    def _text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def guard(self, work):
        try:
            if self.controller.busy:
                raise GuidanceError('busy')
            work()
        except GuidanceError as error:
            self.controller.status = ERRORS[error.code]
            self.status.set(self.controller.status)
        except (ValueError, OSError, TypeError):
            self.controller.status = ERRORS['unknown']
            self.status.set(self.controller.status)
            if self.mode.get() == 'professional':
                messagebox.showerror('WiFiScope', self.controller.status, parent=self.root)

    def pump(self):
        # Also safe for an explicit test/accessibility pump: keep one timer.
        if getattr(self, 'timer', None) is not None:
            self.root.after_cancel(self.timer)
            self.timer = None
        fields = ('report', 'overlay', 'snapshot_id', 'case_path', 'history', 'source', 'result')
        previous = {field: getattr(self.controller, field) for field in fields}
        try:
            if self.controller.poll() and any(previous[field] is not getattr(self.controller, field)
                                               for field in ('report', 'overlay', 'history', 'source')):
                self.render()
            if self.security_tools is not None:
                self.security_tools.deliver()
        except Exception:
            # A presentation failure must not replace the prior usable model
            # or permanently disable future worker delivery. Never echo input.
            for field, value in previous.items():
                setattr(self.controller, field, value)
            self.controller.status = 'Cannot display evidence / 无法显示证据；已保留上一快照。Check input format or reload the demo.'
            try:
                self.render()
            except Exception:
                pass
        finally:
            self.status.set(self.controller.status)
            self.timer = self.root.after(50, self.pump)

    def load_demo(self):
        self.controller.start('SYNTHETIC DEMO / 合成离线演示', lambda cancel: self.demo_provider())

    def collect(self):
        self.controller.start('Local collection / 本机只读采集', lambda cancel: build_investigation(collect_local()))

    def _ports(self):
        return [int(p.strip()) for p in self.ports.get().split(',') if p.strip()]

    def quick_audit(self):
        scope, ports = self.scope.get().replace(',', ' ').split(), self._ports()
        plan = plan_scope(scope, ports)
        self.scope_status.set(f"计划 {len(plan['hosts'])} 主机 × {len(ports)} 端口；含 TLS 共 {plan['planned_connections']} 次连接，按限速规划估算约 {plan['minimum_seconds']:.2f} 秒（首次可立即开始）；截止 300 秒。端口 {ports}")
        if not self.authorized.get():
            raise ValueError('Check authorization before running.')
        self.controller.start('Authorized Quick Audit / 已授权 TCP 检查', lambda cancel: audit_scope(scope, ports, authorized=True, cancel=cancel))

    def run_probe(self):
        host, ports, authorized = self.host.get().strip(), self._ports(), self.authorized.get()
        if not authorized:
            raise ValueError('Check authorization before running.')
        self.scope_status.set(f'单主机：{host} · 端口 {ports} · 每端口 1 次 TCP；443 附加正常 TLS 诊断。')
        self.controller.start('Authorized host / 已授权单主机', lambda cancel: build_investigation(dict(connectivity=probe_hosts([host], ports, authorized=True, attempts=1, timeout=.5, cancel=cancel))))

    def guided_probe(self):
        plan = self.guided.checked_plan()
        self.controller.start('指定目标 TCP/TLS/HEAD 检查', lambda cancel: build_investigation(dict(connectivity=probe_hosts(plan['hosts'], plan['ports'], urls=plan['urls'], authorized=True, attempts=1, timeout=.5, cancel=cancel))))

    def open_evidence(self):
        dialog = tk.Toplevel(self.root)
        dialog.title('明确选择证据类型')
        dialog.transient(self.root)
        ttk.Label(dialog, text='选择格式，再选择文件。XML 不会自动猜测类型。', padding=12).pack()
        ttk.Label(dialog, text='nmap：主机 / 端口 XML；greenbone：扫描器发现 XML\npcap / pcapng：离线抓包元数据；netsh / nmcli：Wi-Fi 文本\njson：WiFiScope 快照。导入不会访问目标；扫描器主张待验证。', padding=12, justify='left').pack()
        kind = tk.StringVar(value='nmap')
        ttk.Combobox(dialog, textvariable=kind, values=['nmap', 'greenbone', 'pcap', 'pcapng', 'netsh', 'nmcli', 'json'], state='readonly').pack(padx=12, pady=5)
        merge = tk.BooleanVar(value=False)
        ttk.Checkbutton(dialog, text='合并到当前调查（默认替换当前快照）', variable=merge).pack(padx=12, pady=8)
        def choose():
            selected, merging = kind.get(), merge.get()
            path = filedialog.askopenfilename(parent=dialog, title='打开 ' + selected + ' 证据（最多 16 MiB）')
            if path:
                dialog.destroy()
                self.guard(lambda: self.controller.import_evidence(path, selected, merge=merging))
        ttk.Button(dialog, text='选择文件…', command=choose).pack(pady=12)

    def export(self):
        if self.controller.report is None:
            raise GuidanceError('noevidence')
        path = filedialog.asksaveasfilename(parent=self.root, title='选择新的报告目录名称（不可已存在）', initialfile='wifiscope-report')
        if path:
            raw = self.mode.get() == 'professional' and self.export_raw.get()
            report, overlay = copy.deepcopy(self.controller.report), copy.deepcopy(self.controller.overlay)
            from .reports import export_report
            from .workstation import controlled_report, with_triage
            if report is None:
                raise ValueError('Load evidence first.')
            self.controller.start('Report export / 报告导出', lambda cancel: export_report(controlled_report(with_triage(report, overlay)), path, raw), 'export', error_code='export')

    def save_case(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='新建或选择本地案件数据库', defaultextension='.db', filetypes=[('SQLite case', '*.db')])
        if path:
            self.controller.save_case(path, include_identifiers=self.retain_raw.get())

    def open_case(self):
        path = filedialog.askopenfilename(parent=self.root, title='打开本地案件数据库', filetypes=[('SQLite case', '*.db'), ('All', '*')])
        if path:
            identifier = simpledialog.askinteger('快照 ID', '输入已保存的快照 ID（从 1 开始）', initialvalue=1, minvalue=1, parent=self.root)
            if identifier is not None:
                self.controller.open_case(path, identifier)

    def verify_case(self):
        receipt = simpledialog.askstring('可信回执', '可选：粘贴此前独立保存的 SHA256 head；留空仅验证本地链。', parent=self.root)
        if receipt is not None:
            self.controller.verify_case(receipt or None)

    def triage(self):
        selection = self.tables['findings'].selection()
        if not selection:
            return
        finding = self.finding_rows[selection[0]]
        state = simpledialog.askstring('本地处置状态', 'open / investigating / accepted-risk / resolved\n检测状态不会更改。', initialvalue='investigating', parent=self.root)
        if state:
            note = simpledialog.askstring('本地备注', '仅保存在本地案件，不随报告导出（最多 2000 字符）。', parent=self.root)
            if note is not None:
                self.controller.triage(finding['id'], state, note)

    def history_page(self, delta):
        self.history_offset = max(0, self.history_offset + delta)
        self.controller.history_page(self.history_offset)

    def open_history(self):
        selection = self.tables['history'].selection()
        if selection:
            identifier = int(self.tables['history'].item(selection[0], 'values')[0])
            self.controller.open_case(self.controller.case_path, identifier)

    def compare(self):
        if self.controller.case_path:
            before = simpledialog.askinteger('比较案件快照', 'Before：持久化快照 ID', minvalue=1, parent=self.root)
            after = simpledialog.askinteger('比较案件快照', 'After：持久化快照 ID', minvalue=1, parent=self.root)
            if before is None or after is None:
                return
            path = self.controller.case_path
            def work(cancel):
                from .cases import CaseStore
                with CaseStore(existing_case(path)) as store:
                    return compare_snapshots(store.load_snapshot(before), store.load_snapshot(after), before_id=before, after_id=after)
        else:
            before = filedialog.askopenfilename(parent=self.root, title='Before：WiFiScope JSON')
            if not before:
                return
            after = filedialog.askopenfilename(parent=self.root, title='After：WiFiScope JSON')
            if not after:
                return
            def work(cancel):
                return compare_snapshots(load_json(before), load_json(after))
        self.controller.start('Snapshot comparison / 快照比较（新视图）', work)
        self.notebook.select(self.comparison.master)

    def _rows(self, key, rows):
        tree = self.tables[key]
        tree.delete(*tree.get_children())
        for index, row in enumerate(rows):
            values = [row.get(name, '—') for name in tree['columns']]
            tree.insert('', 'end', iid=str(index), values=['—' if v is None else str(v) for v in values], tags=(row.get('severity', ''),))

    def render_findings(self):
        report = self.controller.report or {}
        rows = []
        for f in report.get('investigation', {}).get('findings', []):
            if self.severity.get() != 'all' and f.get('severity') != self.severity.get():
                continue
            if self.search.get().casefold() not in (str(f.get('title', '')) + ' ' + str(f.get('code', ''))).casefold():
                continue
            row = dict(f)
            row['triage_status'] = self.controller.overlay.get(f.get('id'), {}).get('status', f.get('triage_status', '—'))
            rows.append(row)
        self._rows('findings', rows)
        self.finding_rows = {str(i): row for i, row in enumerate(rows)}
        self._text(self.detail, '选择发现以查看结构化证据、建议和复测条件。')
        self.triage_button.configure(state='normal' if self.controller.snapshot_id is not None and rows else 'disabled')

    def show_finding(self):
        selected = self.tables['findings'].selection()
        if not selected or selected[0] not in self.finding_rows:
            return
        f = self.finding_rows[selected[0]]
        text = f"{f.get('title')}\nRule code: {f.get('code')}\n\nSeverity: {f.get('severity')} · Confidence: {f.get('confidence')}\nDetection status: {f.get('status')}\nLocal triage_status: {f.get('triage_status')}\nPersisted snapshot: {self.controller.snapshot_id or '尚未保存'}\nFinding ID: {f.get('id')}\n\nEvidence / 证据\n{json.dumps(f.get('evidence', {}), ensure_ascii=False, indent=2)}\n\nRecommendation / 建议\n{f.get('recommendation')}\n\nRetest / 复测\n{f.get('retest')}"
        if f.get('id') in self.controller.overlay:
            text += '\n\nLocal note / 本地备注\n' + self.controller.overlay[f['id']].get('note', '')
        self._text(self.detail, text)

    def render(self):
        report = self.controller.report or {}
        self.guided.render(self.controller.report)
        investigation = report.get('investigation', {})
        sources = report.get('sources', [])
        synthetic = report.get('synthetic') or 'synthetic-demo' in report.get('gaps', [])
        notice = comparison_notice(report)
        prefix = notice + ' | ' if notice else 'SYNTHETIC DEMO · 合成证据 | ' if synthetic else ''
        self.source.set(prefix + self.controller.source + ' | 原始采集时间: ' + str(report.get('collected_at') or '未知') + ' | 来源: ' + ', '.join(sorted({s.get('type', 'unknown') for s in sources})))
        run = run_summary(report)
        self.scope_status.set(f"执行状态 {run.get('status', 'unknown / 未知范围')} · 计划连接 {run.get('planned_connections') if run.get('planned_connections') is not None else '未知'} · 实际 {run.get('attempted_connections') if run.get('attempted_connections') is not None else '未知'} · 剩余端点 {run.get('unattempted_endpoints') if run.get('unattempted_endpoints') is not None else '未知'} · 部分覆盖不能推断已修复。")
        labels = ['候选资产', '优先发现', '证据来源', '覆盖缺口']
        values = [len(investigation.get('assets', [])), len(investigation.get('findings', [])), len(sources), len(report.get('gaps', []))]
        if 'comparison' in report:
            comparison = report['comparison']
            labels = ['Before 资产', 'After 资产', 'Before 发现', 'After 发现']
            values = [comparison[side]['summary'][count] for count in ('assets', 'findings') for side in ('before', 'after')]
            self.scope_status.set('比较视图 · 先核查双方原始时间、覆盖范围与缺口；未观察到不能推断移除或修复。')
        for variable, value, label_variable, label in zip(self.metrics, values, self.metric_labels, labels):
            variable.set(str(value))
            label_variable.set(label)
        summary = ['范围与覆盖优先于风险数量。未知、未检查和失败必须分别理解。', '', '工作流：证据 → 范围核查 → 发现详情 → 案件快照 → 本地处置 → 同范围复测。', '', '数据源和时间（原始观测 / 导入时间；未知保持未知）：']
        summary.extend(f"• {s.get('type')}  |  {s.get('observed_at') or '未知'}  /  {s.get('imported_at') or '未知'}" for s in sources)
        if len(_run_contexts(report)) > 1:
            summary.extend(['', '多个执行范围 · 计数不可合并；逐项核查：'])
            summary.extend(json.dumps(context, ensure_ascii=False, sort_keys=True) for context in _run_contexts(report))
        summary.extend(['', '覆盖缺口：', ', '.join(report.get('gaps', [])) or '未列出；这不代表完整覆盖。', '', 'TCP RTT 是连接耗时，不是吞吐测速。离线抓包仅分析元数据。扫描器结果保持 imported-unverified。', '案件 hash 链可被重算；独立保存验证回执才能帮助发现后缀删除或历史替换。'])
        if 'vulnerability_audit' in report:
            audit = report['vulnerability_audit']
            summary += ['', '漏洞审计 · 本地版本候选，非利用确认',
                        f"目录 {audit['catalog']['catalog_version']} · 规则 {audit['catalog']['rule_count']} · 复核 {audit['catalog']['reviewed_at']} · 来源 {audit['catalog']['source']}",
                        f"已评估服务 {audit['summary']['evaluated_services']} · 未知 {audit['summary']['unknown_services']} · 候选 {audit['summary']['candidates']}",
                        '需核查回补与配置适用性；无匹配不表示安全。']
        if 'capture_session' in report:
            session = report['capture_session']
            summary += ['', '抓包会话 · 元数据', f"{session['status']} / {session['stop_reason']} · {session['duration_ms']} ms · {session['packets']} 包 / 分析 {session['analyzed_packets']} 包",
                        f"捕获 {session['captured_bytes']} 字节 / 线上长度 {session['wire_bytes']}；快照 {session['limits']['snaplen']} 字节；丢包未知保持未知。"]
        if 'wifi_survey' in report:
            survey = report['wifi_survey']
            summary += ['', 'Wi-Fi 调查 · 读数与插值估计分开', f"指标 {survey['metric']} · 测点 {len(survey['samples'])} · 未知 {sum(s['value'] is None for s in survey['samples'])}",
                        '估计仅覆盖凸包内且具有三个局部贡献点的区域；信号不证明吞吐、干扰或安全。打开 Wi-Fi 热力图查看独立工具结果。']
        self._text(self.overview, '\n'.join(summary))
        self._rows('wifi', report.get('wifi', []))
        assets = []
        for a in investigation.get('assets', []):
            row = dict(a)
            row['services'] = '; '.join(f"{s.get('port')}/{s.get('protocol')} {s.get('state')} {s.get('service') or ''} [{s.get('source') or 'unknown'}]" for s in a.get('services', [])) or '未观察到服务'
            assets.append(row)
        self._rows('assets', assets)
        self._rows('connectivity', [dict(row, host=r.get('host')) for r in report.get('connectivity', []) for row in r.get('tcp', [])])
        self._rows('coverage', investigation.get('coverage', []))
        self._rows('history', [dict(row, summary=', '.join(f'{k}: {v}' for k, v in row.get('summary', {}).items() if not isinstance(v, (dict, list)))) for row in self.controller.history])
        self.render_findings()
        comparison = report.get('comparison')
        if comparison:
            lines = ['快照比较 · ' + comparison.get('mode', 'unknown'), '仅双份保留标识符的快照可进行身份关联。缺失代表未观察到，不自动判定移除或修复。']
            for key in ('before', 'after'):
                side = comparison.get(key, {})
                lines += ['', key.upper(), '持久化快照 ID: ' + str(side.get('snapshot_id', '文件输入 / 未知')), '原始采集时间: ' + str(side.get('collected_at')), '数量: ' + json.dumps(side.get('summary', {})), '覆盖: ' + json.dumps(side.get('coverage', []), ensure_ascii=False, indent=2), '缺口: ' + ', '.join(side.get('gaps', [])), '来源原始时间: ' + json.dumps(side.get('sources', []), ensure_ascii=False, indent=2)]
            lines += ['', '资产观测变化: ' + json.dumps(comparison.get('asset_changes', []), ensure_ascii=False, indent=2), '', 'Wi-Fi 观测变化: ' + json.dumps(comparison.get('wifi_changes', []), ensure_ascii=False, indent=2)]
            self._text(self.comparison, '\n'.join(lines))

    def close(self):
        if self.security_tools is not None:
            self.security_tools.close()
        self.controller.cancel()
        self.root.after_cancel(self.timer)
        self.root.destroy()


def launch():
    try:
        root = tk.Tk()
    except tk.TclError:
        print('WiFiScope: Tk display unavailable. Use python -m wifiscope demo --out NEW_DIR or install/enable your OS Python Tk display support.', file=sys.stderr)
        return 2
    Workstation(root)
    root.mainloop()
    return 0
