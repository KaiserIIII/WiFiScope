"""Browse locally imported switch and router evidence."""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from .network_present import topology_links
from .network_widgets import INK, MUTED, PALETTE, EvidenceTable, canvas, chart_title

PAGE = 100
SECTIONS = {
    "拓扑关系": (
        ("kind", "类型", 62), ("source", "来源", 138), ("target", "邻居 / 端口", 152),
        ("label", "关系 / 状态", 104), ("note", "接口", 120),
    ),
    "VLAN": (("vlan_id", "VLAN", 64), ("name", "名称", 130), ("status", "状态", 90), ("ports", "端口", 275)),
    "端口": (("interface", "接口", 180), ("vlan_id", "VLAN", 65), ("source_device", "设备", 145)),
    "Trunk": (("interface", "接口", 128), ("native_vlan", "Native VLAN", 92),
              ("allowed_vlans", "允许 VLAN", 160), ("status", "状态", 110)),
    "路由表": (
        ("prefix", "目标网段", 133), ("next_hop", "下一跳", 135), ("protocol", "协议", 84),
        ("metric", "开销", 58), ("interface", "接口", 126),
    ),
    "OSPF 邻居": (
        ("neighbor_id", "Router ID", 120), ("state", "状态", 90), ("role", "角色", 80),
        ("address", "对端地址", 135), ("interface", "本地接口", 120),
    ),
    "OSPF 接口": (
        ("interface", "接口", 128), ("area", "区域", 94), ("cost", "Cost", 70),
        ("state", "状态", 94), ("address", "地址", 140),
    ),
    "OSPF 链路库": (
        ("lsa_type", "LSA", 88), ("link_id", "Link ID", 130),
        ("advertising_router", "通告路由器", 148), ("area", "区域", 120),
    ),
    "LLDP": (("device", "邻居", 180), ("local_interface", "本地端口", 150),
             ("remote_interface", "邻居端口", 150)),
    "配置预览": (("line", "行", 52), ("command", "受支持配置摘要", 490)),
    "基线差异": (("section", "类别", 130), ("identity", "对象", 162), ("change", "变化", 80),
                 ("fields", "字段", 143)),
    "覆盖情况": (("section", "类别", 145), ("status", "状态", 100), ("rows", "记录", 65),
                 ("unknown_lines", "未知行", 75), ("command", "命令", 150)),
}
KEYS = {
    "VLAN": "vlans", "端口": "ports", "Trunk": "trunks", "路由表": "routes",
    "OSPF 邻居": "ospf_neighbors", "OSPF 接口": "ospf_interfaces", "OSPF 链路库": "ospf_lsdb",
    "LLDP": "lldp_neighbors", "覆盖情况": "coverage",
}


class DeviceView:
    def __init__(self, owner, parent):
        self.owner = owner
        self.current, self.baseline, self.comparison = {}, {}, {}
        self.current_name = self.baseline_name = "未导入"
        self.section = tk.StringVar(master=parent, value="拓扑关系")
        self.summary = tk.StringVar(master=parent, value="导入交换机或路由器命令输出文本。")
        self.query = tk.StringVar(master=parent)
        self.page_label = tk.StringVar(master=parent)
        self.page = 0
        self.links_on_page = []
        tools = ttk.Frame(parent)
        tools.pack(fill="x")
        for label, action in (
            ("打开设备输出…", lambda: self.open_file(False)),
            ("打开基线…", lambda: self.open_file(True)),
            ("比较基线", self.compare),
        ):
            ttk.Button(tools, text=label, command=action).pack(side="left", padx=(0, 6))
        ttk.Label(parent, textvariable=self.summary, wraplength=880).pack(fill="x", pady=7)
        filters = ttk.Frame(parent)
        filters.pack(fill="x")
        ttk.Combobox(filters, textvariable=self.section, values=tuple(SECTIONS), state="readonly",
                     width=15).pack(side="left", padx=(0, 8))
        ttk.Label(filters, text="筛选").pack(side="left")
        ttk.Entry(filters, textvariable=self.query, width=25).pack(side="left", padx=4)
        self.next = ttk.Button(filters, text="下一页", command=lambda: self.move(1))
        self.previous = ttk.Button(filters, text="上一页", command=lambda: self.move(-1))
        self.next.pack(side="right", padx=(5, 0))
        self.previous.pack(side="right", padx=(5, 0))
        ttk.Label(filters, textvariable=self.page_label).pack(side="right")
        self.chart = canvas(parent, 187)
        self.chart.pack(fill="x", pady=7)
        self.chart.bind("<Configure>", self.draw)
        self.table = EvidenceTable(parent, SECTIONS["拓扑关系"])
        self.table.pack(fill="both", expand=True)
        self.section.trace_add("write", lambda *_: self.reset())
        self.query.trace_add("write", lambda *_: self.reset())
        self.render()

    def open_file(self, baseline):
        from .network_devices import read_device_evidence
        path = filedialog.askopenfilename(parent=self.owner.window, title="导入设备命令输出",
                                          filetypes=[("文本或日志", "*.txt *.log *.cfg *.conf"), ("所有文件", "*.*")])
        if path:
            self.owner.start("正在解析设备证据", lambda _stop: read_device_evidence(path),
                             lambda value: self.show(value, baseline, Path(path).name))

    def show(self, value, baseline=False, name="当前证据"):
        if baseline:
            self.baseline, self.baseline_name = value, name
        else:
            self.current, self.current_name = value, name
            self.section.set("拓扑关系")
        self.comparison = {}
        self.render()

    def compare(self):
        from .network_devices import compare_device_evidence
        if not self.baseline or not self.current:
            self.owner.status.set("先导入基线和当前两份设备输出。")
            return
        before, after = self.baseline, self.current
        self.owner.start("正在比较设备基线", lambda _stop: compare_device_evidence(before, after), self.show_comparison)

    def show_comparison(self, value):
        self.comparison = value
        self.section.set("基线差异")
        self.render()

    def result(self):
        return self.comparison if self.section.get() == "基线差异" else self.current

    def rows(self):
        section = self.section.get()
        if section == "拓扑关系":
            return topology_links(self.current)
        if section == "基线差异":
            return self.comparison.get("changes", [])
        if section == "配置预览":
            return [{"line": i, "command": line} for i, line in
                    enumerate(self.current.get("config", {}).get("preview_lines", []), 1)]
        return self.current.get(KEYS[section], [])

    def reset(self):
        self.page = 0
        self.render()

    def move(self, delta):
        self.page = max(self.page + delta, 0)
        self.render()

    def render(self):
        if self.current or self.baseline:
            count = len(topology_links(self.current))
            diffs = len(self.comparison.get("changes", []))
            self.summary.set(f"当前 {self.current_name}  ·  基线 {self.baseline_name}"
                             f"  ·  {count} 条观测关系  ·  {diffs} 条已比较变更")
        data = self.rows()
        query = self.query.get().casefold().strip()
        if query:
            data = [row for row in data if any(query in str(value).casefold() for value in row.values())]
        total = len(data)
        size = 6 if self.section.get() == "拓扑关系" else PAGE
        self.page = min(self.page, max(0, (total - 1) // size))
        rows = data[self.page * size:(self.page + 1) * size]
        self.page_label.set(f"{total} 条 · 第 {self.page + 1}/{max(1, (total + size - 1) // size)} 页")
        self.previous.configure(state="normal" if self.page else "disabled")
        self.next.configure(state="normal" if (self.page + 1) * size < total else "disabled")
        self.table.set_columns(SECTIONS[self.section.get()])
        self.table.set_rows(rows)
        self.links_on_page = rows if self.section.get() == "拓扑关系" else []
        self.draw()

    def draw(self, _event=None):
        chart = self.chart
        chart.delete("all")
        width, height = max(430, chart.winfo_width()), max(180, chart.winfo_height())
        rows = self.links_on_page
        if self.section.get() == "拓扑关系":
            chart_title(chart, "从设备证据观察到的连接和 VLAN 成员")
            if not rows:
                chart.create_text(width / 2, height / 2, text="导入带邻接或 VLAN 端口的设备输出", fill=MUTED)
            for i, row in enumerate(rows):
                y = 46 + i * min(23, (height - 49) / len(rows))
                left, right, edge = min(width * .29, 250), width - min(width * .29, 250), f"edge-{i}"
                color = PALETTE.get(row["kind"], INK)
                chart.create_line(left, y, right, y, fill=color, width=2, arrow="last", tags=(edge,))
                chart.create_oval(left - 4, y - 4, left + 4, y + 4, fill=color, width=0, tags=(edge,))
                chart.create_text(left - 9, y, text=self.short(row["source"]), anchor="e", fill=INK, tags=(edge,))
                chart.create_text(right + 9, y, text=self.short(row["target"]), anchor="w", fill=INK, tags=(edge,))
                label = row["kind"] + " · " + self.short(row["label"])
                label_x = (left + right) / 2
                chart.create_rectangle(label_x - 69, y - 9, label_x + 69, y + 9, width=0, fill="#eef4fa", tags=(edge,))
                chart.create_text(label_x, y, text=label, fill=color, tags=(edge,), font=("Microsoft YaHei UI", 8))
                chart.tag_bind(edge, "<Button-1>", lambda _, ix=i: self.table.select(ix))
        else:
            chart_title(chart, self.section.get())
            stats = [("VLAN", "vlans"), ("路由", "routes"), ("OSPF 邻居", "ospf_neighbors"),
                     ("LLDP 邻居", "lldp_neighbors"), ("基线变更", "changes")]
            for i, (label, key) in enumerate(stats):
                data = self.comparison if key == "changes" else self.current
                px = width * (i + .5) / len(stats)
                chart.create_text(px, 77, text=str(len(data.get(key, []))), fill=INK,
                                  font=("Segoe UI", 22, "bold"))
                chart.create_text(px, 111, text=label, fill=MUTED)

    @staticmethod
    def short(value):
        value = str(value)
        return value if len(value) <= 23 else value[:20] + "…"
