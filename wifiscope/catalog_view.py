"""Explicit offline indexed catalog workflow; SQLite belongs to workers only."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import tkinter as tk
from tkinter import filedialog, ttk

from .catalog_audit import audit_catalog
from .catalog_store import CatalogIndex, build_catalog
from .case_validation import validate_report
from .cpe_names import parse_cpe
from .inventory import SCHEMES, text, validate_inventory
from .inventory_import import import_inventory


def identity_choices(record):
    """Extract only literal identities, never advisory versions or conditions."""
    choices, seen = [], set()
    pending = list(record['configurations'])
    while pending:
        node = pending.pop()
        pending.extend(node['nodes'])
        for match in node['cpeMatch']:
            try:
                name = parse_cpe(match.get('criteria'))
            except ValueError:
                continue
            if any(name.field(k).kind != 'literal' for k in ('part', 'vendor', 'product')):
                continue
            if name.field('part').original_text not in ('a', 'o', 'h'):
                continue
            row = {k: name.field(k).original_text for k in ('part', 'vendor', 'product')}
            row['kind'] = 'cpe'
            key = tuple(row.items())
            if key not in seen:
                seen.add(key)
                choices.append(row)
    for container in record['affected']:
        for affected in container['affectedData']:
            if not affected['vendor'] or not affected['product']:
                continue
            row = dict(kind='cna', vendor=affected['vendor'], product=affected['product'])
            key = tuple(row.items())
            if key not in seen:
                seen.add(key)
                choices.append(row)
    return choices


def _encoded(value):
    # Preserve the user's literal including colons, wildcards and backslashes.
    return ''.join('\\'+c if c in '\\:*?' or value == '-' else c for c in value)


def manual_inventory(previous, label, identity, version, scheme):
    """Append a declared component selected explicitly from typed detail."""
    text(label, 249)
    text(version, 1024)
    if scheme not in SCHEMES or not isinstance(identity, dict):
        raise ValueError('Select a literal catalog identity and an ordering scheme.')
    if set(identity) != ({'kind', 'part', 'vendor', 'product'} if identity.get('kind') == 'cpe'
                         else {'kind', 'vendor', 'product'}) or identity.get('kind') not in ('cpe', 'cna'):
        raise ValueError('Select a literal catalog identity.')
    for key in ('vendor', 'product'):
        text(identity[key])
    result = validate_inventory(previous) if previous is not None else dict(schema_version=1, assets=[])
    if 'import_context' in result:
        raise ValueError('Create an explicit new manual inventory before adding to an imported document scope.')
    identifier = 'manual:'+label
    asset = next((a for a in result['assets'] if a['id'] == identifier), None)
    if asset is None:
        asset = dict(id=identifier, components=[], complete_parts=[])
        result['assets'].append(asset)
    existing = {c['id'] for a in result['assets'] for c in a['components']}
    ordinal = 0
    while True:
        key = hashlib.sha256(json.dumps([identifier, identity, version, scheme, ordinal],
                                        ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()
        if 'manual-component-'+key not in existing:
            break
        ordinal += 1
    row = dict(id='manual-component-'+key, source='local', identification='declared',
               observed_at=None, version_scheme=scheme)
    if identity['kind'] == 'cpe':
        if identity['part'] not in ('a', 'o', 'h'):
            raise ValueError('Select a literal CPE part.')
        row['cpe'] = 'cpe:2.3:'+':'.join([identity['part'], _encoded(identity['vendor']),
                    _encoded(identity['product']), _encoded(version)] + ['*'] * 7)
    else:
        row.update(vendor=identity['vendor'], product=identity['product'], version=version)
    asset['components'].append(row)
    return validate_inventory(result)


def catalog_demo(cancel=None, progress=None):
    """Explicit ephemeral synthetic walkthrough. Nothing is measured/discovered."""
    cpe = 'cpe:2.3:a:example_vendor:example_app:1.0.0:*:*:*:*:*:*:*'
    rows = [dict(cve=dict(id='CVE-2026-90001', vulnStatus='Analyzed', configurations=[dict(
        nodes=[dict(operator='OR', cpeMatch=[dict(criteria=cpe, vulnerable=True)])])])),
        dict(cve=dict(id='CVE-2026-90002', vulnStatus='Analyzed', affected=[dict(affectedData=[dict(vendor='Sample Labs',
            product='CNA Example', versions=[dict(version='3.4.5', status='affected')])])])),
        dict(cve=dict(id='CVE-2026-90003', vulnStatus='Analyzed', configurations=[dict(nodes=[dict(
            operator='AND', cpeMatch=[dict(criteria=cpe, vulnerable=True), dict(vulnerable=False,
            criteria='cpe:2.3:o:example_os:environment:2.0:*:*:*:*:*:*:*')])])]))]
    inventory = validate_inventory(dict(schema_version=1, assets=[dict(id='synthetic-positive', components=[
        dict(id='synthetic-a', cpe=cpe, source='synthetic', identification='declared'),
        dict(id='synthetic-b', vendor='Sample Labs', product='CNA Example', version='3.4.5',
             source='synthetic', identification='declared')]),
        dict(id='synthetic-negative', complete_parts=['a', 'o', 'h'], components=[dict(id='synthetic-fixed',
            cpe=cpe.replace(':1.0.0:', ':2.0.0:'), source='synthetic', identification='declared')])]))
    with tempfile.TemporaryDirectory(prefix='wifiscope-synthetic-') as directory:
        path = Path(directory)
        source, db = path / 'invented.json', path / 'catalog.sqlite'
        source.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=3, startIndex=0, resultsPerPage=3,
                                          vulnerabilities=rows)), encoding='utf-8')
        build_catalog([source], db, cancel=cancel)
        with CatalogIndex(db) as index:
            report = audit_catalog(dict(schema_version=1), inventory, index, cancel=cancel, progress=progress)
    return report


PREVIEW_MAX_CHARS = 65536
PREVIEW_COMPONENTS = 3
PREVIEW_FIELD_CHARS = 160


def _preview_field(value):
    if len(value) <= PREVIEW_FIELD_CHARS:
        return value
    return value[:PREVIEW_FIELD_CHARS]+'…[显示截断]'


def _component_preview(component):
    """Display source literals without replacing unknown source times or facts."""
    if 'cpe' in component and component['cpe'].startswith('cpe:2.3:'):
        # The report was validated already. Decode the original escaped fields
        # for presentation, preserving original version case (parse_cpe folds
        # matching text). Never borrow fields from an advisory or panel state.
        fields, chars, quoted = [], [], False
        for char in component['cpe'][8:]:
            if quoted:
                chars.append(char)
                quoted = False
            elif char == '\\':
                quoted = True
            elif char == ':':
                fields.append(''.join(chars))
                chars = []
            else:
                chars.append(char)
        fields.append(''.join(chars))
        version_kind = parse_cpe(component['cpe']).field('version').kind
        version = ('未知（CPE ANY）' if version_kind == 'any' else '不适用（CPE NA）'
                   if version_kind == 'na' else _preview_field(fields[3]))
        identity = 'CPE '+ ' / '.join(_preview_field(field) for field in fields[:3])
    elif 'cpe' in component:
        identity, version = 'CPE '+_preview_field(component['cpe']), '未知（身份已脱敏）'
    else:
        identity = 'CNA '+_preview_field(component['vendor'])+' / '+_preview_field(component['product'])
        version = _preview_field(component['version']) if component['version'] is not None else '未知（null）'
    return (f"  组件 {component['id']} · {identity} · 版本 {version} · 排序 {component['version_scheme']}"
            f" · 来源 {component['source']} · 识别 {component['identification']}"
            f" · 来源时间 {component['observed_at'] or '未知（null）'}")


def audit_preview(report):
    """Bounded local display joined solely to this validated preview's inventory.

    At most 65536 characters, three components/result and 160 characters per
    identity/version field. Presentation omissions are explicit; report/audit
    completeness and the full result/inventory data are never changed.
    """
    audit, summary = report['catalog_audit'], report['catalog_audit']['summary']
    assets = {asset['id']: asset for asset in audit['inventory']['assets']}
    components = {row['id']: row for asset in assets.values() for row in asset['components']}
    lines = ['合成演练 · 非实测' if report.get('synthetic') else '声明/导入身份的本地审核预览',
        f"状态 {audit['status']}；目录收录 {audit['catalog']['records']}；资产 {summary['assets']} / 组件 {summary['components']}",
        f"已评估资产-CVE 对 {summary['evaluated_pairs']}；模型匹配 {summary['true_pairs']}；未知条件 {summary['unknown_pairs']}；不匹配 {summary['not_matched_pairs']}；未评估 {summary['unexamined_pairs']}",
        '模型匹配仍需核查安装、配置、环境和回补；未知项不是正面漏洞。无匹配不是安全证明。',
        '下一步：先确认身份/声明版本，再补充环境/供应商证据，修复后在相同范围复测。',
        '下列身份来自本预览自己的清单；每项最多显示 3 个组件、身份/版本字段最多 160 字符。']
    # Reserve bounded footer space; each outcome receives its own allowance so
    # a large true group cannot hide every unknown row (or the reverse).
    group_limit = (PREVIEW_MAX_CHARS-len('\n'.join(lines))-1024)//2
    for outcome, label in [('true', '模型匹配候选（非确认）'), ('unknown', '未知条件（需补充证据）')]:
        lines.append('\n'+label)
        total = sum(row['applicability'] == outcome for row in audit['results'])
        used, shown = 0, 0
        for row in audit['results']:
            if row['applicability'] != outcome:
                continue
            chunk = [f"{row['cve']} · 资产 {row['asset_id']} · 适用性 {outcome} · {row['model']} · {row['status']}",
                     '  待核查：'+', '.join(row['reasons']+row['gaps'])]
            identifiers = row['component_ids']
            if identifiers:
                selected = [components[key] for key in identifiers[:PREVIEW_COMPONENTS]]
                count = len(identifiers)
            else:
                asset_components = assets[row['asset_id']]['components']
                selected, count = asset_components[:PREVIEW_COMPONENTS], len(asset_components)
                chunk.append('  未归属具体组件；以下仅为同资产上下文，不是组件匹配证据。')
            chunk.append(f'  组件显示 {len(selected)} / {count}'+
                         ('（显示截断；完整报告保留全部关联）' if count > len(selected) else ''))
            chunk.extend(_component_preview(component) for component in selected)
            rendered = '\n'.join(chunk)
            if used+len(rendered)+1 > group_limit:
                break
            lines.append(rendered)
            used += len(rendered)+1
            shown += 1
        if shown < total:
            lines.append(f'显示截断：本组显示 {shown} / {total} 条；完整报告未截断，可导出查看全部。审计状态仍为 {audit["status"]}。')
    return '\n'.join(lines)


class CatalogView:
    error_help = ('目录操作未完成；原快照保留。检查明确选择的格式/新目标/哈希/字面身份与限制。'
                  'SBOM 需显式 CPE 2.3；脱敏报告请改选“新空白本地报告”，或重新载入原始本地证据。')

    def __init__(self, owner, parent):
        self.owner, self.result = owner, None
        self.catalog_info = self.inventory = self.loaded_db = None
        self.feed_paths, self.choices = (), []
        self.offset = 0
        self.revision = 0
        self.db_path, self.db_pin, self.feed_pins = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.cve, self.vendor, self.product = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.inventory_path = tk.StringVar()
        self.inventory_format = tk.StringVar(value='native')
        self.asset_label, self.version = tk.StringVar(), tk.StringVar()
        self.scheme = tk.StringVar(value='unknown')
        self.audit_source = tk.StringVar(value='新空白本地报告')
        self.details_visible = tk.BooleanVar(value=False)
        self.notice = tk.StringVar(value='尚未打开目录或清单。所有操作都需要明确点击；不会下载、扫描或采集。')
        owner.text(parent, '三步开始：① 准备/打开本地目录 → ② 选择产品并填写自己的版本，或导入清单 → ③ 运行预览，核查未知条件后明确应用/导出。')
        self.demo_button = self.button(parent, '完整合成演练 · 两个供应商 / CNA / 正反对照', self.demo)
        owner.text(parent, '合成示例非实测；清单是声明/导入身份，不证明软件已安装。目录收录数 ≠ 已评估资产-CVE 对 ≠ 候选；无匹配不是安全证明。')
        catalog = self.section(parent, '① 本地漏洞库')
        self.entry(catalog, '数据库', self.db_path, 0)
        actions = ttk.Frame(catalog)
        actions.grid(row=1, column=0, columnspan=2, sticky='ew')
        self.button(actions, '选择数据库', self.choose_db, side='left')
        self.open_button = self.button(actions, '明确打开', self.open, side='left')
        ttk.Checkbutton(catalog, text='专业详细设置：本地源文件 / 哈希 / 新建索引 / 工作预算',
                        variable=self.details_visible, command=self.toggle_details).grid(row=2, column=0, columnspan=2, sticky='w')
        self.detail_settings = ttk.Frame(catalog)
        self.entry(self.detail_settings, '数据库 SHA256（可选）', self.db_pin, 0)
        self.entry(self.detail_settings, '按选择顺序的展开 SHA256（空格分隔）', self.feed_pins, 1)
        detail_actions = ttk.Frame(self.detail_settings)
        detail_actions.grid(row=2, column=0, columnspan=2, sticky='ew')
        self.button(detail_actions, '选择 1..64 个本地 NVD 文件', self.choose_feeds, side='left')
        self.button(detail_actions, '选择新数据库目标', self.choose_destination, side='left')
        self.build_button = self.button(detail_actions, '明确新建索引', self.build, side='left')
        ttk.Label(self.detail_settings, text='只写新文件；不覆盖。源 ≤256 MiB / 展开 ≤2 GiB；SQL 查询 2000 万指令。审计 ≤50000 对 / 4096 结果 / 500000 谓词。哈希校验不证明来源权威。', wraplength=730).grid(row=3, column=0, columnspan=2, sticky='w')
        search = self.section(parent, '查找身份 · 精确 CVE 或供应商+产品；均空则分页浏览')
        self.entry(search, 'CVE', self.cve, 0)
        self.entry(search, '供应商', self.vendor, 1)
        self.entry(search, '产品', self.product, 2)
        bar = ttk.Frame(search)
        bar.grid(row=3, column=0, columnspan=2, sticky='ew')
        self.search_button = self.button(bar, '明确查询', self.search, side='left')
        self.previous_button = self.button(bar, '上一页', lambda: self.search(-20), side='left')
        self.next_button = self.button(bar, '下一页', lambda: self.search(20), side='left')
        self.detail_button = self.button(bar, '查看所选记录详情/身份', self.detail, side='left')
        self.rows = ttk.Treeview(parent, columns=('cve', 'status'), show='headings', height=4, selectmode='browse')
        self.rows.heading('cve', text='CVE · 本页最多 20 条')
        self.rows.heading('status', text='来源状态（Rejected/无模型不代表可评估）')
        self.rows.pack(fill='x')
        self.output = owner.output(parent, 7)
        form = self.section(parent, '② 自己的本地声明清单 · 从所选详情提取字面身份')
        ttk.Label(form, text='已选身份').grid(row=0, column=0, sticky='w')
        self.identity_choice = ttk.Combobox(form, values=(), state='readonly')
        self.identity_choice.grid(row=0, column=1, sticky='ew')
        self.entry(form, '资产标签（相同标签加入同一资产）', self.asset_label, 1)
        self.entry(form, '你实际观察/声明的版本（不会复制公告版本）', self.version, 2)
        ttk.Label(form, text='版本排序（不确定选 unknown）').grid(row=3, column=0, sticky='w')
        ttk.Combobox(form, textvariable=self.scheme, values=SCHEMES, state='readonly').grid(row=3, column=1, sticky='ew')
        self.add_button = self.button(form, '明确加入清单', self.add, grid_row=4)
        self.new_inventory_button = self.button(form, '新建空白声明清单（替换面板清单）', self.new_inventory, grid_row=5)
        ttk.Label(form, text='导入文档与手工声明分别保留来源；给导入文档添加手工项前，明确新建声明清单。', wraplength=730).grid(row=6, column=0, columnspan=2, sticky='w')
        imports = self.section(parent, '或导入本地清单 · SBOM 不等于安装/环境验证')
        self.entry(imports, '清单文件', self.inventory_path, 0)
        ttk.Combobox(imports, textvariable=self.inventory_format, values=('native', 'cyclonedx', 'spdx'), state='readonly').grid(row=1, column=0, sticky='w')
        bar = ttk.Frame(imports)
        bar.grid(row=1, column=1, sticky='ew')
        self.button(bar, '选择清单文件', self.choose_inventory, side='left')
        self.import_button = self.button(bar, '明确导入', self.import_file, side='left')
        ttk.Label(imports, text='支持 schema1 / CycloneDX JSON 1.6、1.7 / SPDX JSON SPDX-2.3；≤16 MiB、1024 资产、8192 组件。Nmap 服务 CPE 转换暂不支持。', wraplength=730).grid(row=2, column=0, columnspan=2, sticky='w')
        self.inventory_rows = ttk.Treeview(parent, columns=('asset', 'identity'), show='headings', height=4, selectmode='browse')
        self.inventory_rows.heading('asset', text='清单资产（本地标识符）')
        self.inventory_rows.heading('identity', text='组件身份 / 声明版本')
        self.inventory_rows.pack(fill='x')
        self.remove_button = self.button(parent, '明确移除所选组件', self.remove)
        audit = self.section(parent, '③ 运行并检查报告预览')
        ttk.Combobox(audit, textvariable=self.audit_source, values=('新空白本地报告', '当前原始本地报告'), state='readonly').grid(row=0, column=0, sticky='ew')
        self.audit_button = self.button(audit, '运行索引审计预览', self.audit, grid_row=1)
        ttk.Label(parent, textvariable=self.notice, wraplength=760, foreground='#3b5674').pack(fill='x', pady=5)
        for variable in (self.cve, self.vendor, self.product):
            variable.trace_add('write', self.query_changed)
        for variable in (self.db_path, self.db_pin, self.inventory_path, self.inventory_format,
                         self.asset_label, self.version, self.scheme, self.audit_source):
            variable.trace_add('write', lambda *_: self.invalidate())

    def button(self, parent, label, action, *, side=None, grid_row=None):
        button = ttk.Button(parent, text=label, command=lambda: self.owner.guard(action))
        if grid_row is not None:
            button.grid(row=grid_row, column=0, columnspan=2, sticky='w', pady=4)
        else:
            button.pack(side=side or 'top', anchor='w', padx=2, pady=3)
        return button

    @staticmethod
    def section(parent, label):
        frame = ttk.LabelFrame(parent, text=label, padding=6)
        frame.pack(fill='x', pady=5)
        frame.columnconfigure(1, weight=1)
        return frame

    @staticmethod
    def entry(parent, label, variable, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', padx=3, pady=2)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky='ew', pady=2)
        parent.columnconfigure(1, weight=1)

    def toggle_details(self):
        if self.details_visible.get():
            self.detail_settings.grid(row=3, column=0, columnspan=2, sticky='ew')
        else:
            self.detail_settings.grid_remove()

    def invalidate(self):
        self.result = None
        self.revision += 1

    def query_changed(self, *_):
        self.offset = 0
        self.rows.delete(*self.rows.get_children())
        self.choices = []
        self.identity_choice.configure(values=())
        self.identity_choice.set('')
        self.invalidate()

    def choose_db(self):
        path = filedialog.askopenfilename(parent=self.owner.window, title='选择本地只读索引')
        if path:
            self.db_path.set(path)

    def choose_destination(self):
        path = filedialog.asksaveasfilename(parent=self.owner.window, title='新数据库文件（不得已存在）')
        if path:
            self.db_path.set(path)

    def choose_feeds(self):
        paths = filedialog.askopenfilenames(parent=self.owner.window, title='按顺序选择本地 NVD JSON/gzip 源')
        if paths:
            self.feed_paths = tuple(paths)
            self.notice.set(f'已选择 {len(paths)} 个源；尚未读取。展开哈希按选择顺序填写。')
            self.invalidate()

    def choose_inventory(self):
        path = filedialog.askopenfilename(parent=self.owner.window, title='选择本地显式身份清单')
        if path:
            self.inventory_path.set(path)

    def begin(self, operation, work, *, progress_kind='catalog-local'):
        if self.owner.app.controller.busy:
            raise ValueError('Wait for current worker.')
        self.invalidate()
        revision = self.revision
        def versioned(cancel, progress):
            value = work(cancel, progress)
            value['_revision'] = revision
            return value
        self.owner.start(self, operation, versioned, progress_kind=progress_kind)

    @staticmethod
    def prepare_result(value):
        if value.get('operation') == 'audit':
            validate_report(value['report'])
            value['preview_text'] = audit_preview(value['report'])
        return value

    def open(self):
        path, pin = self.db_path.get(), self.db_pin.get().strip() or None
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            with CatalogIndex(path, expected_sha256=pin) as index:
                return dict(operation='open', info=index.info(), loaded_db=(path, pin))
        self.begin('明确打开本地目录', work)

    def build(self):
        paths, destination = tuple(self.feed_paths), self.db_path.get()
        pins = self.feed_pins.get().split() or None
        def work(cancel, progress):
            info = build_catalog(paths, destination, expected_sha256=pins, cancel=cancel, progress=progress)
            return dict(operation='open', info=info, loaded_db=(destination, None))
        self.begin('明确新建本地目录', work, progress_kind='catalog-build')

    def _database(self):
        if self.loaded_db is None:
            raise ValueError('Explicitly open or build a catalog first.')
        if (self.db_path.get(), self.db_pin.get().strip() or None) != self.loaded_db:
            raise ValueError('Explicitly open the changed database selection first.')
        return self.loaded_db

    def query(self):
        return (self.cve.get().strip() or None, self.vendor.get().strip() or None, self.product.get().strip() or None)

    def search(self, step=0):
        path, pin = self._database()
        query, offset = self.query(), max(0, self.offset+step)
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            with CatalogIndex(path, expected_sha256=pin) as index:
                rows = index.search(cve=query[0], vendor=query[1], product=query[2], offset=offset, limit=20)
            return dict(operation='search', rows=rows, query=query, offset=offset)
        self.begin('明确查询目录', work)

    def detail(self):
        path, pin = self._database()
        selected = self.rows.selection()
        if not selected:
            raise ValueError('Select one typed record.')
        cve, query = selected[0], self.query()
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            with CatalogIndex(path, expected_sha256=pin) as index:
                record = index.get(cve)
            return dict(operation='detail', record=record, choices=identity_choices(record), query=query)
        self.begin('明确查看记录详情', work)

    def import_file(self):
        path, kind = self.inventory_path.get(), self.inventory_format.get()
        self.begin('明确导入本地清单', lambda cancel, progress: dict(operation='inventory',
            inventory=import_inventory(path, format=kind, cancel=cancel)))

    def add(self):
        selection = self.identity_choice.current()
        if not 0 <= selection < len(self.choices):
            raise ValueError('Select a supported literal identity from detail first.')
        identity, previous = dict(self.choices[selection]), self.inventory
        label, version, scheme = self.asset_label.get(), self.version.get(), self.scheme.get()
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            return dict(operation='inventory', inventory=manual_inventory(previous, label, identity, version, scheme))
        self.begin('明确添加本地声明组件', work)

    def remove(self):
        selection = self.inventory_rows.selection()
        if not selection or self.inventory is None:
            raise ValueError('Select a component to remove.')
        previous, identifier = self.inventory, selection[0]
        def work(cancel, progress):
            if cancel.is_set():
                raise ValueError('Cancelled.')
            value = copy.deepcopy(previous)
            for asset in value['assets']:
                asset['components'] = [c for c in asset['components'] if c['id'] != identifier]
            value['assets'] = [a for a in value['assets'] if a['components']]
            if 'import_context' in value:
                context = value['import_context']
                context['retained_components'] = sum(len(a['components']) for a in value['assets'])
                context['partial'] = True
                context['gaps'] = sorted(set(context['gaps']) | {'input-partial'})
            return dict(operation='inventory', inventory=validate_inventory(value) if value['assets'] else None)
        self.begin('明确移除本地声明组件', work)

    def new_inventory(self):
        self.begin('明确新建空白声明清单', lambda cancel, progress: dict(operation='inventory', inventory=None))

    def audit(self):
        path, pin = self._database()
        inventory = self.inventory
        if inventory is None:
            raise ValueError('Select an explicit inventory first.')
        report = (self.owner.app.controller.report if self.audit_source.get() == '当前原始本地报告'
                  else dict(schema_version=1))
        if report is None:
            raise ValueError('Load original local evidence or select an empty local report.')
        def work(cancel, progress):
            with CatalogIndex(path, expected_sha256=pin) as index:
                value = audit_catalog(report, inventory, index, cancel=cancel, progress=progress)
            return dict(operation='audit', report=value)
        self.begin('索引清单适用性预览', work, progress_kind='catalog-audit')

    def demo(self):
        self.begin('完整合成演练（非实测；临时目录自动清理）', lambda cancel, progress:
                   dict(operation='audit', report=catalog_demo(cancel, progress)), progress_kind='catalog-audit')

    def on_progress(self, value):
        self.notice.set('工作进度（单位保持独立）：'+json.dumps(value, ensure_ascii=False))

    def on_result(self, value):
        if 'exported' in value:
            self.owner.status.set('工具报告已写入新目录；默认共享 HMAC 脱敏。')
            return
        if value.get('_revision') != self.revision:
            self.notice.set('输入已改变；过期工具结果未应用。请按当前选择重新运行预览。')
            return
        operation = value['operation']
        if operation == 'open':
            self.catalog_info, self.loaded_db = value['info'], tuple(value['loaded_db'])
            self.query_changed()
            self.notice.set(f"收录 {self.catalog_info['records']} 条；Rejected {self.catalog_info['rejected_records']}；无模型 {self.catalog_info['without_applicability']}；有缺口 {self.catalog_info['unsupported_records']}。尚未评估任何资产。")
        elif operation == 'search':
            if value['query'] != self.query():
                return
            self.rows.delete(*self.rows.get_children())
            self.offset = value['offset']
            for row in value['rows']:
                self.rows.insert('', 'end', iid=row['cve'], values=(row['cve'], row['status']))
            self.notice.set(f"目录浏览偏移 {self.offset}；本页 {len(value['rows'])} 条。请选择一条查看类型化模型。")
        elif operation == 'detail':
            if value['query'] != self.query():
                return
            self.choices = value['choices']
            self.identity_choice.configure(values=[f"{r['kind'].upper()} · {r['vendor']} / {r['product']}" for r in self.choices])
            self.identity_choice.set('')
            record = value['record']
            self.owner.app._text(self.output, json.dumps(record, ensure_ascii=False, indent=2))
            self.notice.set('明确选择一个身份，再填写自己的版本。公告范围/环境不会填入清单。' if self.choices
                            else '此记录没有可用的字面身份（模式/未知/仅元数据）；已有清单保留。请选择其他记录或导入显式清单。')
        elif operation == 'inventory':
            self.inventory = value['inventory']
            self.render_inventory()
        elif operation == 'audit':
            self.result = value['report']
            self.owner.app._text(self.output, value['preview_text'])
            self.notice.set('预览已就绪，尚未应用。完整状态/取消/工作限额保留在报告；可明确应用或默认脱敏导出。')

    def render_inventory(self):
        self.inventory_rows.delete(*self.inventory_rows.get_children())
        if self.inventory is None:
            self.notice.set('清单为空；不能运行空白清洁审计。')
            return
        for asset in self.inventory['assets']:
            for row in asset['components']:
                label = row.get('cpe') or f"{row['vendor']} / {row['product']} · {row['version']}"
                self.inventory_rows.insert('', 'end', iid=row['id'], values=(asset['id'], label))
        context = self.inventory.get('import_context')
        self.notice.set((f"清单来源 {context['format']}：输入条目 {context['input_entries']}；显式 CPE {context['input_cpe_identifiers']}；保留组件 {context['retained_components']}；无映射条目 {context['unmapped_entries']}；不支持标识符 {context['unsupported_identifiers']}；重复标识符 {context['duplicate_identifiers']}。环境/安装未验证。缺口：{', '.join(context['gaps'])}"
                         if context else f"{len(self.inventory['assets'])} 个声明资产；无隐含地址合并、无安装确认、来源时间可未知。"))
