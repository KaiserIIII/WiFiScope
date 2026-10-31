"""Focused saved-run controls; all persistence and rendering stays in workers."""
import copy
import tkinter as tk
from tkinter import filedialog, ttk

from .catalog_runs import _RunReader, advance_run, create_run, export_run
from .case_validation import validate_report


def status_text(status, page_number):
    totals = status['cumulative']
    state = {'ready': '已保存，尚未评估', 'paused': '已暂停，可继续一批', 'complete': '所选范围计算完成',
             'blocked': '受阻，不能继续推进', 'limited': '达到整次运行限额'}[status['state']]
    reason = {'ready': '尚未开始评估', 'page-limit': '达到本批候选结果或输出大小限额',
              'work-limit': '达到本批条件检查限额', 'pair-limit': '达到本批资产-CVE 对评估限额',
              'cancelled': '已取消本批评估', 'exhausted': '已评估完所选范围',
              'blocked-predicate': '单个资产-CVE 对所需的条件检查超过本批限额',
              'blocked-output': '单个资产-CVE 对的结果超过本批输出限额',
              'blocked-index': '相关记录索引查询无法在限额内完成',
              'run-page-limit': '达到整次运行的保存页数限额',
              'run-pair-limit': '达到整次运行的资产-CVE 对评估限额',
              'run-byte-limit': '达到整次运行的保存数据大小限额'}[status['stop_reason']]
    source = '来源有缺口' if status['source_partial'] else '来源未声明缺口'
    return (f"{state} · 原因 {reason} · {source}\n"
            f"结果页 {page_number or 0} / {status['page_count']}（仅此页预览，未应用）；累计已评估资产-CVE 对 {totals['evaluated_pairs']}；"
            f"模型匹配 {totals['true_pairs']}；未知条件 {totals['unknown_pairs']}；不匹配 {totals['not_matched_pairs']}；"
            f"保留候选 {totals['retained_results']}；未评估 {status['unexamined_pairs'] if status['unexamined_pairs'] is not None else '未知'}。\n"
            f"累计谓词 {totals['predicates']}；身份查询 {totals['identity_queries']}；索引命中 {totals['index_hits']}；相关去重 CVE 记录 {totals['relevant_records']}。\n"
            '继续使用已保存的冻结清单，不替换面板清单。来源缺口与计算完成分别显示；完成不是安全证明。'
            + (' 受阻/限额不能自动跳过；请新建更小清单/目录范围的审计。' if status['state'] in ('blocked', 'limited') else ''))


class CatalogRunView:
    def __init__(self, catalog_view, parent):
        self.catalog = catalog_view
        self.owner = catalog_view.owner
        self.status = None
        self.page_number = 0
        self.run_path = tk.StringVar()
        self.store_raw = tk.BooleanVar(value=False)
        self.page_size = tk.StringVar(value='256')
        self.status_text = tk.StringVar(value='尚未打开保存审计。默认每批保留 256 个候选结果；继续一批保留之前的页。')
        frame = catalog_view.section(parent, '④ 保存审计 · 可关闭后继续')
        catalog_view.entry(frame, '本地保存审计文件', self.run_path, 0)
        paths = ttk.Frame(frame)
        paths.grid(row=1, column=0, columnspan=2, sticky='w')
        catalog_view.button(paths, '选择新保存文件', self.choose_new, side='left')
        catalog_view.button(paths, '选择已有审计文件', self.choose_existing, side='left')
        ttk.Checkbutton(frame, text='我明确同意在本机保存原始标识符与证据（与脱敏导出分开）',
                        variable=self.store_raw).grid(row=2, column=0, columnspan=2, sticky='w')
        catalog_view.entry(catalog_view.detail_settings, '保存审计每批候选结果数（1..4096；默认256）', self.page_size, 4)
        actions = ttk.Frame(frame)
        actions.grid(row=3, column=0, columnspan=2, sticky='w')
        self.new_button = catalog_view.button(actions, '新建保存审计', self.new, side='left')
        self.continue_button = catalog_view.button(actions, '继续一批', self.continue_run, side='left')
        self.open_button = catalog_view.button(actions, '打开保存审计', self.open, side='left')
        pages = ttk.Frame(frame)
        pages.grid(row=4, column=0, columnspan=2, sticky='w')
        self.previous_button = catalog_view.button(pages, '上一结果页', lambda: self.page(-1), side='left')
        self.next_button = catalog_view.button(pages, '下一结果页', lambda: self.page(1), side='left')
        self.export_button = catalog_view.button(pages, '导出整次审计', self.export, side='left')
        ttk.Label(frame, textvariable=self.status_text, wraplength=730).grid(row=5, column=0, columnspan=2, sticky='w')
        ttk.Label(frame, text='所有文件仅在点击后读取；停止使用窗口原有取消按钮。保存文件含原始证据，请自行保护。选定结果页须明确应用才替换当前报告。',
                  wraplength=730).grid(row=6, column=0, columnspan=2, sticky='w')
        for variable in (self.run_path, self.store_raw, self.page_size):
            variable.trace_add('write', self.changed)
        self.boundaries()

    def changed(self, *_):
        self.catalog.invalidate()
        self.status = None
        self.page_number = 0
        self.status_text.set('选择已改变；请明确打开或新建审计。继续使用保存文件中的冻结清单。')
        self.boundaries()

    def boundaries(self):
        count = self.status['page_count'] if self.status else 0
        self.previous_button.configure(state='normal' if self.page_number > 1 else 'disabled')
        self.next_button.configure(state='normal' if self.page_number < count else 'disabled')
        self.continue_button.configure(state='disabled' if self.status and self.status['state'] in ('complete', 'blocked', 'limited') else 'normal')

    def idle(self):
        if self.owner.app.controller.busy:
            raise ValueError('Wait for current worker.')

    def choose_new(self):
        self.idle()
        path = filedialog.asksaveasfilename(parent=self.owner.window, title='新保存审计文件（不得已存在）')
        if path:
            self.run_path.set(path)

    def choose_existing(self):
        self.idle()
        path = filedialog.askopenfilename(parent=self.owner.window, title='选择本地保存审计文件')
        if path:
            self.run_path.set(path)

    @staticmethod
    def prepared(path, number=None):
        # One validated snapshot for both cumulative state and selected page.
        with _RunReader(path) as reader:
            status = reader.status()
            number = min(number or status['page_count'], status['page_count'])
            report = reader.read_page(number) if number else None
        return dict(operation='run', status=status, page_number=number, report=report)

    @staticmethod
    def prepare_result(value):
        from .catalog_view import audit_preview
        if value.get('report') is not None:
            validate_report(value['report'])
            value['preview_text'] = '仅此结果页；下列结果与评估计数为本页，不代表整次运行。\n'+audit_preview(value['report'])
        value['status_text'] = status_text(value['status'], value['page_number'])
        return value

    @staticmethod
    def activity(progress):
        # Chunk counters differ from legacy distinct-record progress. Do not
        # relabel them. The committed cumulative counts arrive with the result.
        return lambda value: progress(dict(status='running'))

    def new(self):
        self.idle()
        if not self.store_raw.get():
            self.status_text.set('新建前须明确勾选本机保存原始标识符与证据；脱敏导出不代表存储同意。')
            return
        path, pin = self.catalog._database()
        destination = self.run_path.get()
        page_size = int(self.page_size.get())
        inventory = copy.deepcopy(self.catalog.inventory)
        report = copy.deepcopy(self.owner.app.controller.report if self.catalog.audit_source.get() == '当前原始本地报告'
                               else dict(schema_version=1))
        if inventory is None or report is None:
            raise ValueError('Select explicit inventory and original evidence.')
        def work(cancel, progress):
            create_run(destination, report, inventory, path, expected_sha256=pin,
                       store_raw_identifiers=True, page_size=page_size, cancel=cancel)
            advance_run(destination, path, cancel=cancel, progress=self.activity(progress))
            return self.prepared(destination)
        self.catalog.begin('新建保存审计 · 仅一批', work)

    def continue_run(self):
        self.idle()
        destination, path = self.run_path.get(), self.catalog.db_path.get()
        def work(cancel, progress):
            advance_run(destination, path, cancel=cancel, progress=self.activity(progress))
            return self.prepared(destination)
        self.catalog.begin('继续一批 · 使用保存的冻结清单', work)

    def open(self):
        self.idle()
        destination = self.run_path.get()
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            return self.prepared(destination)
        self.catalog.begin('打开保存审计 · 仅预览', work)

    def page(self, step):
        self.idle()
        if self.status is None or not 1 <= self.page_number+step <= self.status['page_count']:
            raise ValueError('Select an available result page.')
        destination, number = self.run_path.get(), self.page_number+step
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            return self.prepared(destination, number)
        self.catalog.begin('读取保存结果页 · 仅预览', work)

    def export(self):
        self.idle()
        destination = filedialog.asksaveasfilename(parent=self.owner.window, title='新建整次审计导出目录（不得已存在）')
        if not destination:
            return
        path, raw, number = self.run_path.get(), self.owner.export_raw.get(), self.page_number
        def work(cancel, progress):
            receipt = export_run(path, destination, include_identifiers=raw, cancel=cancel)
            value = self.prepared(path, number)
            value['run_exported'] = receipt
            return value
        self.catalog.begin('导出整次保存审计', work)

    def on_progress(self, value):
        self.status_text.set('保存审计工作进行中；可停止。累计计数在本批保存后显示；当前报告未应用。')

    def on_result(self, value):
        self.status, self.page_number = value['status'], value['page_number']
        self.status_text.set(value['status_text'] + (' 整次审计已导出（默认 HMAC 脱敏；原始导出需单独勾选）。' if 'run_exported' in value else ''))
        self.catalog.result = value['report']
        self.owner.app._text(self.catalog.output, value.get('preview_text', '尚无保存结果页；没有可应用的报告。'))
        self.boundaries()
