"""Shared desktop widgets for inspecting local network evidence."""
import json
import tkinter as tk
from tkinter import ttk

INK = "#18324b"
MUTED = "#48617a"
BG = "#f1f5fa"
WHITE = "#ffffff"
BORDER = "#d2deeb"
PALETTE = {
    "arp": "#137268", "icmp": "#2876a0", "icmpv6": "#2876a0", "tcp": "#30589b",
    "dhcp": "#915a19", "dns": "#7551a0", "http": "#147989", "tls": "#393e8e",
    "OSPF": "#356498", "LLDP": "#167869", "VLAN": "#925723",
}


def show(value):
    if value is None or value == "":
        return "—"
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ", ".join(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return str(value)


def text_set(widget, content):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.configure(state="disabled")


def entry(parent, title, value, column, row=0, width=15):
    frame = ttk.Frame(parent)
    frame.grid(row=row, column=column, sticky="ew", padx=(0, 9), pady=(0, 6))
    ttk.Label(frame, text=title).pack(anchor="w")
    control = ttk.Entry(frame, textvariable=value, width=width)
    control.pack(fill="x")
    return control


class EvidenceTable(ttk.Frame):
    """Scrollable data table with a separate, copyable selected record."""
    def __init__(self, parent, columns):
        super().__init__(parent)
        self.panes = ttk.Panedwindow(self, orient="horizontal")
        self.panes.pack(fill="both", expand=True)
        grid, detail = ttk.Frame(self.panes), ttk.Frame(self.panes, padding=(9, 0, 0, 0))
        self.panes.add(grid, weight=5)
        self.panes.add(detail, weight=2)
        self.grid_frame = grid
        grid.columnconfigure(0, weight=1)
        grid.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(grid, show="headings", selectmode="browse", height=8)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar = ttk.Scrollbar(grid, orient="vertical", command=self.tree.yview)
        xbar = ttk.Scrollbar(grid, orient="horizontal", command=self.tree.xview)
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        ttk.Label(detail, text="选中记录", style="NetworkTitle.TLabel").pack(anchor="w", pady=(0, 4))
        self.details = tk.Text(detail, width=27, height=7, bg=WHITE, fg=INK, relief="flat",
                               padx=8, pady=7, wrap="word", font=("Microsoft YaHei UI", 9))
        scroll = ttk.Scrollbar(detail, command=self.details.yview)
        self.details.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.details.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._selection)
        self.selected_data = []
        self.formatters = {}
        self.set_columns(columns)
        self.clear()

    def set_columns(self, columns):
        self.columns = [field for field, _, _ in columns]
        self.labels = {field: label for field, label, _ in columns}
        self.tree.configure(columns=self.columns)
        for field, label, width in columns:
            self.tree.heading(field, text=label)
            self.tree.column(field, width=width, minwidth=min(width, 48), stretch=width >= 110)

    def clear(self):
        self.set_rows([], placeholder="选择一行后可查看完整字段。")

    def set_rows(self, rows, *, placeholder="当前筛选没有匹配记录。"):
        self.selected_data = list(rows)
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(self.selected_data):
            self.tree.insert("", "end", iid=str(index),
                             values=[self.formatters.get(k, show)(row.get(k)) for k in self.columns])
        if self.selected_data:
            self.select(0)
        else:
            text_set(self.details, placeholder)

    def show_row(self, row):
        lines = [f"{self.labels.get(k, k)}　{show(v)}" for k, v in row.items() if not isinstance(v, dict)]
        for k, value in row.items():
            if isinstance(value, dict):
                lines.extend(("", self.labels.get(k, k), json.dumps(value, ensure_ascii=False, indent=2)))
        text_set(self.details, "\n".join(lines))

    def select(self, index):
        self.tree.selection_set(str(index))
        self.tree.focus(str(index))
        self.tree.see(str(index))
        self.show_row(self.selected_data[index])

    def _selection(self, _event=None):
        selected = self.tree.selection()
        if selected:
            index = int(selected[0])
            if index < len(self.selected_data):
                self.show_row(self.selected_data[index])


def canvas(parent, height):
    return tk.Canvas(parent, height=height, bg=WHITE, highlightbackground=BORDER, highlightthickness=1)


def chart_title(chart, text):
    chart.create_text(11, 12, text=text, anchor="nw", fill=INK, font=("Microsoft YaHei UI", 9, "bold"))
