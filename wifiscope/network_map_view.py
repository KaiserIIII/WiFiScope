"""Interactive security findings and source-scoped topology in the Tk workbench."""
import math
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from .network_map import FINDING_TEXT, build_network_map, read_map_evidence
from .network_widgets import BG, BORDER, INK, MUTED, EvidenceTable, canvas, text_set
from .zeek_flows import SERVICES

_SOURCES = {"pcap": "抓包", "device": "设备记录", "local": "本机快照", "baseline": "设备基线",
            "nmap": "Nmap XML", "greenbone": "Greenbone XML", "zeek": "Zeek 会话日志"}
_NODES = {"ip": "IP", "configured-ip": "配置 IP", "mac": "MAC", "special-address": "特殊地址", "local-socket": "本机套接字",
          "local-host": "本机", "device": "设备", "interface": "接口", "vlan": "VLAN", "prefix": "网段",
          "lldp-device": "LLDP 设备", "ospf-router-id": "OSPF Router ID", "reported-service": "导入服务"}
_EDGES = {
    "observed-traffic": ("观测流量", "#315ca8"), "arp-claim": ("ARP 声明", "#856226"),
    "zeek-flow": ("Zeek 会话", "#008085"),
    "device-interface": ("设备接口", "#4e6481"), "interface-address": ("接口地址", "#4e6481"),
    "configured-interface": ("配置接口", "#6a66a0"), "configured-address": ("配置地址", "#6a66a0"),
    "configured-vlan": ("配置 VLAN", "#6a66a0"), "configured-access-vlan": ("配置接入 VLAN", "#6a66a0"),
    "vlan-member": ("VLAN 成员", "#784e98"), "native-vlan": ("Trunk Native VLAN", "#784e98"),
    "lldp-neighbor": ("LLDP 邻接", "#137266"), "ospf-neighbor": ("OSPF 邻居", "#137266"),
    "route-prefix": ("路由前缀", "#305496"), "route-next-hop": ("路由下一跳", "#305496"),
    "cached-neighbor": ("缓存邻居", "#856226"), "cached-link-address": ("缓存 MAC", "#856226"),
    "listening-socket": ("本机绑定", "#a0522b"), "reported-service": ("导入开放服务", "#a0522b"),
}
_LEVELS = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息"}
_COVERAGE = {"observed": "有观测", "partial": "部分覆盖", "unavailable": "缺失", "redacted": "标识符已脱敏",
             "missing": "未提供", "imported-unverified": "导入待复核"}
_PAGE_SIZE = 90
_MAX_IMPORTED = 8
_VIEWS = {"资产": "nodes", "关系": "edges", "流量": "flows", "安全发现": "findings", "证据覆盖": "map_sources"}
_COLUMNS = {
    "nodes": (("label", "资产或对象", 176), ("kind", "类型", 103), ("source_id", "来源", 70),
              ("context", "范围", 120)),
    "edges": (("origin", "起点", 137), ("target", "终点", 137), ("kind", "关系", 115),
              ("source_id", "来源", 65)),
    "flows": (("origin", "发起端", 101), ("target", "响应端", 102), ("service", "应用", 69),
              ("dst_port", "响应端口", 62), ("orig_bytes", "发起 B", 65), ("resp_bytes", "响应 B", 65),
              ("duration_ms", "耗时 ms", 64), ("observed_at", "时间 UTC", 130), ("source_line", "源日志行", 66)),
    "findings": (("code", "安全发现", 149), ("severity", "级别", 53), ("label", "关联节点", 133),
                 ("source_id", "来源", 65), ("count", "条数", 55)),
    "map_sources": (("source_id", "来源", 65), ("kind", "来源类型", 100), ("label", "标识", 155),
                    ("status", "覆盖", 110)),
}


def _packet_inputs(report, path):
    if not report:
        return ()
    label = Path(path).name if path else "当前抓包"
    contexts = report.get("packet_analysis_contexts")
    if isinstance(contexts, list) and contexts:
        metadata = {key: report[key] for key in ("identifiers_included", "synthetic") if key in report}
        return tuple(dict(metadata, packet_analysis=context, map_label=f"{label} {index}")
                     for index, context in enumerate(contexts, 1) if isinstance(context, dict))
    return (dict(report, map_label=label),)


class MapView:
    def __init__(self, owner, parent):
        self.owner = owner
        self.report, self.imported = {}, []
        self.nodes, self.links, self.findings = {}, {}, {}
        self.page, self.matches = 0, 0
        self.focus = None
        self.current = []
        self.summary = tk.StringVar(parent, value="导入已有证据，或读取本机接口、邻居缓存、路由和监听。")
        self.mode = tk.StringVar(parent, value="资产")
        self.query = tk.StringVar(parent)
        self.source = tk.StringVar(parent, value="全部来源")
        self.category = tk.StringVar(parent, value="全部类型")
        self.sources, self.categories = {}, {}
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(0, 5))
        ttk.Button(top, text="汇总工作台证据", command=lambda: owner.guard(self.rebuild)).pack(side="left")
        ttk.Button(top, text="读取本机并更新", command=self.collect_local).pack(side="left", padx=6)
        button = ttk.Menubutton(top, text="导入已有证据…")
        menu = tk.Menu(button, tearoff=False)
        for label, kind, pattern in (("报文 PCAP/PCAPNG", "pcap", "*.pcap *.pcapng"),
                                     ("设备命令文本", "device", "*.txt *.log"),
                                     ("诊断或监测 JSON", "diagnostics", "*.json"),
                                     ("Zeek conn.log", "zeek", "*.log *.jsonl *.ndjson *.tsv"),
                                     ("Nmap XML", "nmap", "*.xml"), ("Greenbone XML", "greenbone", "*.xml")):
            menu.add_command(label=label, command=lambda k=kind, p=pattern, name=label: self.open(k, p, name))
        menu.add_separator()
        menu.add_command(label="清空本页导入", command=lambda: owner.guard(self.clear_imports))
        button.configure(menu=menu)
        button.pack(side="left")
        ttk.Label(parent, textvariable=self.summary, wraplength=810).pack(fill="x", pady=(0, 4))
        filters = ttk.Frame(parent)
        filters.pack(fill="x", pady=(0, 5))
        ttk.Combobox(filters, textvariable=self.mode, values=tuple(_VIEWS), state="readonly",
                     width=9).pack(side="left")
        self.source_picker = ttk.Combobox(filters, textvariable=self.source, values=("全部来源",),
                                         state="readonly", width=20)
        self.source_picker.pack(side="left", padx=5)
        self.category_picker = ttk.Combobox(filters, textvariable=self.category, values=("全部类型",),
                                           state="readonly", width=14)
        self.category_picker.pack(side="left")
        ttk.Label(filters, text="筛选").pack(side="left", padx=(10, 4))
        ttk.Entry(filters, textvariable=self.query, width=18).pack(side="left", fill="x", expand=True)
        ttk.Button(filters, text="‹", width=3, command=lambda: self.move(-1)).pack(side="left", padx=(5, 0))
        self.page_label = ttk.Label(filters, text="1 / 1", width=10, anchor="center")
        self.page_label.pack(side="left")
        ttk.Button(filters, text="›", width=3, command=lambda: self.move(1)).pack(side="left")
        panes = ttk.Panedwindow(parent, orient="vertical")
        panes.pack(fill="both", expand=True)
        graph_frame = ttk.Frame(panes)
        panes.add(graph_frame, weight=1)
        self.graph = canvas(graph_frame, 155)
        self.graph.pack(fill="both", expand=True)
        self.graph.bind("<Configure>", lambda _event: self.draw())
        self.table = EvidenceTable(panes, _COLUMNS["nodes"])
        panes.add(self.table, weight=2)
        self.table.tree.bind("<<TreeviewSelect>>", self.select)
        for value in (self.query, self.source, self.category):
            value.trace_add("write", self.reset)
        self.mode.trace_add("write", self.change_mode)
        self.change_mode()

    def result(self):
        return self.report

    def rebuild(self):
        owner = self.owner
        if owner.busy:
            owner.status.set("当前任务仍在运行。")
            return
        main = owner.main_report() or {}
        packet = owner.packets.report or (main if "packet_analysis" in main else None)
        batches = {
            "captures": _packet_inputs(packet, owner.packets.path),
            "devices": (dict(owner.devices.current, map_label=owner.devices.current_name),) if owner.devices.current else (),
            "diagnostics": (dict(owner.diagnostics.report, map_label="工作台诊断"),) if owner.diagnostics.report else (),
            "comparisons": (owner.devices.comparison,) if owner.devices.comparison else (),
            "inventories": (dict(main, map_label="主界面报告"),) if main.get("assets") or main.get("imported_findings") else (),
            "flow_logs": (),
        }
        slots = {"pcap": "captures", "device": "devices", "diagnostics": "diagnostics",
                 "nmap": "inventories", "greenbone": "inventories", "zeek": "flow_logs"}
        for kind, evidence in self.imported:
            slot = slots[kind]
            batches[slot] += (evidence,)
        owner.start("正在汇总证据…", lambda _stop: build_network_map(**batches), self.show)

    def open(self, kind, pattern, label):
        if len(self.imported) == _MAX_IMPORTED:
            self.owner.status.set(f"本页已导入 {_MAX_IMPORTED} 份证据，请先清空本页导入。")
            return
        path = filedialog.askopenfilename(parent=self.owner.window, title=f"选择{label}",
                                         filetypes=((label, pattern), ("所有文件", "*")))
        if path:
            self.owner.start("正在读取本地证据…", lambda _stop: read_map_evidence(kind, path),
                             lambda report: self.accept(kind, report))

    def accept(self, kind, report):
        if self.owner.stop.is_set():
            return
        self.imported.append((kind, report))
        if kind == "zeek":
            self.mode.set("流量")
        self.rebuild()

    def clear_imports(self):
        self.imported.clear()
        self.rebuild()

    def collect_local(self):
        from .network_diagnostics import diagnose_network

        def apply(report):
            self.owner.diagnostics.show(report)
            if report["status"] != "cancelled":
                self.rebuild()

        self.owner.start("正在读取本机网络状态…", lambda stop: diagnose_network(cancel=stop), apply)

    def show(self, report):
        self.report = report if report["map_sources"] else {}
        self.nodes = {node["node_id"]: node for node in report["nodes"]}
        self.links = {}
        for edge in report["edges"]:
            origin, target = edge["from_node"], edge["to_node"]
            for node in {origin, target}:
                self.links.setdefault(node, []).append(edge)
        self.findings = {}
        for finding in report["findings"]:
            for node in {finding["node_id"], finding.get("related_node")} - {None}:
                self.findings.setdefault(node, []).append(finding)
        self.sources = {
            f'{row["source_id"]} · {_SOURCES[row["kind"]]} · {row.get("label", "")}'
            + ("（合成）" if row.get("synthetic") else ""): row["source_id"] for row in report["map_sources"]
        }
        self.source_picker.configure(values=("全部来源", *self.sources))
        self.source.set("全部来源")
        incomplete = sum(row["status"] != "observed" for row in report["map_sources"])
        limitation = " · 已达到展示上限" if report["gaps"] else ""
        capture_scope = " · 抓包地址按文件汇总" if any(row["kind"] == "pcap" for row in report["map_sources"]) else ""
        self.summary.set(
            f'{len(self.sources)} 个来源 · {len(self.nodes)} 个节点 · {len(report["edges"])} 条关系 · '
            f'{len(report["findings"])} 项安全发现 · {incomplete} 个来源覆盖待核对{limitation}{capture_scope}'
            if self.report else "尚无证据。导入已有文件，或读取本机网络状态。"
        )

    def change_mode(self, *_args):
        view = _VIEWS[self.mode.get()]
        choices = {"nodes": _NODES, "edges": {k: v[0] for k, v in _EDGES.items()}, "findings": _LEVELS,
                   "flows": {service: service.upper() for service in SERVICES}, "map_sources": _SOURCES}[view]
        self.categories = {value: key for key, value in choices.items()}
        self.category_picker.configure(values=("全部类型", *self.categories))
        self.table.set_columns(_COLUMNS[view])
        self.category.set("全部类型")

    def reset(self, *_args):
        self.page = 0
        self.refresh()

    def move(self, step):
        self.page = min(max(0, self.page + step), max(0, (self.matches - 1) // _PAGE_SIZE))
        self.refresh()

    def refresh(self):
        view = _VIEWS[self.mode.get()]
        source = self.sources.get(self.source.get())
        category = self.categories.get(self.category.get())
        query = self.query.get().strip().casefold()
        rows = []
        for row in self.report.get("edges" if view == "flows" else view, []):
            if view == "flows" and row["kind"] != "zeek-flow":
                continue
            if source is not None and row["source_id"] != source:
                continue
            if category is not None:
                matches = category in row["service"] if view == "flows" else row.get(
                    "severity" if view == "findings" else "kind") == category
                if not matches:
                    continue
            data = self.describe(row, view)
            if not query or any(query in str(value).casefold() for value in data.values()):
                rows.append((row, data))
        if view == "findings":
            priority = {level: index for index, level in enumerate(_LEVELS)}
            rows.sort(key=lambda pair: priority[pair[0]["severity"]])
        self.matches = len(rows)
        start = self.page * _PAGE_SIZE
        page = rows[start:start + _PAGE_SIZE]
        self.current = [row for row, _ in page]
        self.focus = None
        self.page_label.configure(text=f"{self.page + 1} / {max(1, math.ceil(self.matches / _PAGE_SIZE))}")
        self.table.set_rows([data for _, data in page])
        self.select()

    def describe(self, row, view):
        data = dict(row)
        if view in ("edges", "flows"):
            data.update(kind=_EDGES[row["kind"]][0], origin=self.nodes[row["from_node"]]["label"],
                        target=self.nodes[row["to_node"]]["label"])
        elif view == "findings":
            title, action = FINDING_TEXT[row["code"]]
            data.update(code=title, severity=_LEVELS[row["severity"]], label=self.nodes[row["node_id"]]["label"],
                        next_action=action)
        else:
            data["kind"] = (_NODES if view == "nodes" else _SOURCES)[row["kind"]]
        if row.get("status") in _COVERAGE:
            data["status"] = _COVERAGE[row["status"]]
        if row.get("scope_status") == "capture-address-aggregate":
            data["scope_status"] = "按抓包文件汇总地址。文件内可能含多个 VLAN 或接口。"
        return data

    def select(self, _event=None):
        selected = self.table.tree.selection()
        if not selected:
            self.draw()
            return
        index = int(selected[0])
        if index >= len(self.current):
            return
        row = self.current[index]
        self.focus = row.get("node_id", row.get("from_node"))
        view = _VIEWS[self.mode.get()]
        self.table.show_row(self.describe(row, view))
        if view == "nodes":
            self.node_detail(self.focus)
        self.draw()

    def node_detail(self, node_id):
        node = self.nodes[node_id]
        lines = [f'{_NODES[node["kind"]]} · {node["label"]}', f'节点 {node_id} · 来源 {node["source_id"]}']
        if "context" in node:
            lines.append(f'范围　{node["context"]}')
        lines.extend(("", f"关系 {len(self.links.get(node_id, ()))} · 关联发现 {len(self.findings.get(node_id, ()))}"))
        for row in self.findings.get(node_id, [])[:12]:
            title, action = FINDING_TEXT[row["code"]]
            locator = f'帧 {row["packet_number"]}' if row.get("packet_number") else f'记录 {row["row"]}'
            lines.extend(("", f'{_LEVELS[row["severity"]]} · {title} · {locator}', action))
        text_set(self.table.details, "\n".join(lines))

    def focus_node(self, node_id):
        if self.mode.get() == "资产":
            index = next((i for i, row in enumerate(self.current) if row["node_id"] == node_id), None)
            if index is not None:
                self.table.select(index)
                self.select()
                return
        self.table.tree.selection_remove(*self.table.tree.selection())
        self.focus = node_id
        self.node_detail(node_id)
        self.draw()

    def draw(self):
        chart = self.graph
        chart.delete("all")
        if self.focus not in self.nodes:
            chart.create_text(12, 11, text="选择资产、关系或安全发现以查看邻近证据。", anchor="nw", fill=MUTED)
            return
        width, height = max(chart.winfo_width(), 480), max(chart.winfo_height(), 130)
        center = width / 2, height / 2 + 6
        neighbors = {}
        selected = self.table.tree.selection()
        active_flow = None
        if self.mode.get() == "流量" and selected and int(selected[0]) < len(self.current):
            active_flow = self.current[int(selected[0])]
            if active_flow["from_node"] == self.focus and active_flow["to_node"] != self.focus:
                neighbors[active_flow["to_node"]] = "zeek-flow"
        for edge in self.links.get(self.focus, ()):
            other = edge["to_node"] if edge["from_node"] == self.focus else edge["from_node"]
            if other != self.focus:
                neighbors.setdefault(other, edge["kind"])
        visible = list(neighbors.items())[:12]
        positions = {self.focus: center}
        for index, (node_id, kind) in enumerate(visible):
            angle = 2 * math.pi * index / len(visible)
            x = center[0] + (width / 2 - 98) * math.cos(angle)
            y = center[1] + max(25, height / 2 - 36) * math.sin(angle)
            positions[node_id] = x, y
            selected_flow = active_flow is not None and node_id == active_flow["to_node"]
            if selected_flow:
                dx, dy = x - center[0], y - center[1]
                distance = math.hypot(dx, dy)
                padding = min(64, distance * 0.4) / distance
                chart.create_line(*center, x - dx * padding, y - dy * padding, fill=_EDGES[kind][1],
                                  width=3, arrow=tk.LAST, tags="active-flow")
            else:
                chart.create_line(*center, x, y, fill=_EDGES[kind][1], width=2)
        chart.create_text(10, 8, text=f"邻近节点 {len(visible)} / {len(neighbors)}　·　连线类型见关系表",
                          anchor="nw", fill=MUTED)
        for node_id, (x, y) in positions.items():
            node = self.nodes[node_id]
            label = node["label"][:24]
            if self.findings.get(node_id):
                label += f' · {len(self.findings[node_id])}'
            tag = f"map-node-{node_id}"
            text = chart.create_text(x, y, text=label, fill="white" if node_id == self.focus else INK, tags=tag)
            left, top, right, bottom = chart.bbox(text)
            background = chart.create_rectangle(left - 6, top - 3, right + 6, bottom + 3,
                                                fill=INK if node_id == self.focus else BG, outline=BORDER, tags=tag)
            chart.tag_lower(background, text)
            chart.tag_bind(tag, "<Button-1>", lambda _event, selected=node_id: self.focus_node(selected))
        if active_flow is not None:
            self.draw_bytes(active_flow, width)

    def draw_bytes(self, flow, width):
        left, right = flow["orig_bytes"], flow["resp_bytes"]
        values = ("未记录" if value is None else f"{value:,} B" for value in (left, right))
        label = "  /  ".join(values)
        self.graph.create_text(width - 12, 8, text=f"发起 / 响应　{label}", anchor="ne", fill=MUTED)
        if left is None or right is None or left + right == 0:
            return
        base = width - 164
        pivot = base + 152 * left / (left + right)
        self.graph.create_rectangle(base, 27, pivot, 33, fill="#008085", width=0)
        self.graph.create_rectangle(pivot, 27, width - 12, 33, fill="#315ca8", width=0)
