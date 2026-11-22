"""Filter and inspect local capture timelines and optional TShark frames."""
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk

from .network_present import packet_rows
from .network_widgets import (
    INK,
    MUTED,
    PALETTE,
    EvidenceTable,
    canvas,
    chart_title,
    show,
)
from .packet_dissect import dissect_capture, open_in_wireshark
from .packets import analyze_capture
from .workstation import read_bounded

ALL_PROTOCOLS = "全部"
PACKET_FILE = [("抓包文件", "*.pcap *.pcapng *.cap"), ("所有文件", "*.*")]
COLUMNS = [
    ("packet_number", "帧", 47), ("protocol", "协议", 65), ("event_type", "事件", 175),
    ("exchange_id", "交互", 55), ("rtt_ms", "RTT ms", 70), ("src_address", "来源", 115),
    ("dst_address", "目标", 115),
]
FRAME_COLUMNS = [
    ("packet_number", "帧", 62), ("relative_ms", "相对时间 ms", 115),
    ("wire_bytes", "字节", 80), ("protocols", "协议栈", 360),
]
EVENT_TEXT = {
    "arp-request": "ARP 请求", "arp-reply": "ARP 应答",
    "echo-request": "回送请求", "echo-reply": "回送应答",
    "tcp-syn": "SYN", "tcp-syn-retransmission": "SYN 重传", "tcp-syn-ack": "SYN + ACK",
    "tcp-handshake-complete": "握手完成", "dhcp-discover": "发现 Discover",
    "dhcp-offer": "提供 Offer", "dhcp-request": "请求 Request", "dhcp-ack": "确认 ACK",
    "dhcp-nak": "拒绝 NAK", "dns-query": "DNS 查询", "dns-response": "DNS 应答",
    "http-request": "HTTP 请求", "http-response": "HTTP 响应", "tls-client-hello": "Client Hello",
    "tls-server-hello": "Server Hello", "tls-application-data": "TLS 应用数据",
}


class PacketView:
    def __init__(self, owner, parent):
        self.owner = owner
        self.report, self.decoded, self.path = {}, {}, None
        self.page = 0
        self.current = []
        self.protocol = tk.StringVar(master=parent, value=ALL_PROTOCOLS)
        self.search = tk.StringVar(master=parent)
        self.mode = tk.StringVar(master=parent, value="timeline")
        self.summary = tk.StringVar(master=parent, value="打开 PCAP 或 PCAPNG 文件以查看报文交互。")
        self.page_label = tk.StringVar(master=parent)
        tools = ttk.Frame(parent)
        tools.pack(fill="x", pady=(0, 5))
        ttk.Button(tools, text="打开抓包…", command=self.open_file).pack(side="left")
        ttk.Button(tools, text="TShark 解码…", command=lambda: owner.guard(self.open_decoder)).pack(side="left", padx=7)
        ttk.Button(tools, text="Wireshark 查看…", command=lambda: owner.guard(self.open_wireshark)).pack(side="left", padx=(0, 7))
        ttk.Button(tools, text="离线示例", command=self.demo).pack(side="left", padx=(0, 7))
        for title, value in (("协议时间线", "timeline"), ("解码帧", "frames")):
            ttk.Radiobutton(tools, text=title, value=value, variable=self.mode).pack(side="left", padx=(3, 0))
        ttk.Label(parent, textvariable=self.summary, wraplength=880).pack(anchor="w", fill="x", pady=(0, 8))
        filters = ttk.Frame(parent)
        filters.pack(fill="x")
        ttk.Label(filters, text="协议").pack(side="left")
        self.protocol_box = ttk.Combobox(filters, width=10, state="readonly", values=(ALL_PROTOCOLS,), textvariable=self.protocol)
        self.protocol_box.pack(side="left", padx=(4, 12))
        ttk.Label(filters, text="搜索").pack(side="left")
        ttk.Entry(filters, textvariable=self.search, width=24).pack(side="left", padx=4)
        self.previous = ttk.Button(filters, text="上一页", command=lambda: self.move_page(-1))
        self.next = ttk.Button(filters, text="下一页", command=lambda: self.move_page(1))
        self.next.pack(side="right", padx=(4, 0))
        self.previous.pack(side="right", padx=(4, 0))
        ttk.Label(filters, textvariable=self.page_label).pack(side="right")
        self.chart = canvas(parent, 154)
        self.chart.pack(fill="x", pady=7)
        self.chart.bind("<Configure>", self.draw)
        self.table = EvidenceTable(parent, COLUMNS)
        self.table.formatters["event_type"] = lambda value: EVENT_TEXT.get(value, show(value))
        self.table.pack(fill="both", expand=True)
        for field in (self.protocol, self.search, self.mode):
            field.trace_add("write", lambda *_: self.reset_filter())
        self.render()

    def open_file(self):
        path = filedialog.askopenfilename(parent=self.owner.window, title="打开抓包文件", filetypes=PACKET_FILE)
        if path:
            self.owner.start("正在读取抓包", lambda _stop: analyze_capture(read_bounded(path)),
                             lambda result: self.show(result, path))

    def open_decoder(self):
        path = self.path or filedialog.askopenfilename(
            parent=self.owner.window, title="选择要解码的抓包", filetypes=PACKET_FILE,
        )
        if not path:
            return
        executable = filedialog.askopenfilename(parent=self.owner.window, title="选择本机 TShark 可执行文件")
        if executable:
            self.owner.start("正在离线解码", lambda stop: dissect_capture(path, executable=executable, cancel=stop),
                             self.show_decoded)

    def open_wireshark(self):
        path = self.path or filedialog.askopenfilename(
            parent=self.owner.window, title="选择 Wireshark 要查看的抓包", filetypes=PACKET_FILE,
        )
        if path:
            executable = filedialog.askopenfilename(parent=self.owner.window, title="选择本机 Wireshark 可执行文件")
            if executable:
                open_in_wireshark(path, executable)
                self.owner.status.set("已在本机 Wireshark 中打开抓包。")

    def demo(self):
        from .demo import capture_demo
        self.show(capture_demo())

    def show(self, report, path=None):
        self.report = report
        self.path = path
        self.decoded = {}
        self.protocol.set(ALL_PROTOCOLS)
        self.search.set("")
        self.mode.set("timeline")

    def show_decoded(self, report):
        self.decoded = report
        self.protocol.set(ALL_PROTOCOLS)
        self.search.set("")
        self.mode.set("frames")

    def result(self):
        return self.decoded if self.mode.get() == "frames" else self.report

    def reset_filter(self):
        self.page = 0
        self.render()

    def move_page(self, amount):
        self.page = max(0, self.page + amount)
        self.render()

    def render(self):
        capture = self.report.get("packet_analysis", {})
        timeline = capture.get("protocol_timeline", {})
        selection = self.protocol.get()
        if selection == ALL_PROTOCOLS:
            selection = ""
        if self.mode.get() == "frames":
            source = self.decoded.get("frames", [])
            protocols = sorted({p for row in source for p in row.get("protocols", [])})
            query = self.search.get().strip().casefold()
            filtered = [row for row in source if not selection or selection in row.get("protocols", [])]
            filtered = [row for row in filtered if not query or query in
                        f"{row['packet_number']} {' '.join(row['protocols'])}".casefold()]
            total = len(filtered)
            self.page = min(self.page, max(0, (total - 1) // 120))
            self.current = filtered[self.page * 120:(self.page + 1) * 120]
            self.table.set_columns(FRAME_COLUMNS)
            self.summary.set(f"TShark 已解码 {len(source)} 帧 · {self.decoded.get('status', '尚无解码结果')}")
        else:
            source = timeline.get("events", [])
            protocols = sorted({row["protocol"] for row in source if row.get("protocol")})
            view = packet_rows(source, protocol=selection, query=self.search.get(), page=self.page)
            self.page, total, self.current = view["page"], view["total"], view["rows"]
            self.table.set_columns(COLUMNS)
            if capture:
                origin = Path(self.path).name if self.path else "已载入证据"
                if self.report.get("synthetic"):
                    origin = "合成示例"
                status = "部分证据" if capture.get("partial") or timeline.get("partial") else "已读取"
                self.summary.set(f"{origin}  ·  {capture.get('packets', 0)} 帧  ·  {len(source)} 个事件"
                                 f"  ·  省略 {timeline.get('dropped_events', 0)}  ·  {status}")
        self.protocol_box.configure(values=(ALL_PROTOCOLS, *protocols))
        self.page_label.set(f"{total} 条 · 第 {self.page + 1}/{max(1, (total + 119) // 120)} 页")
        self.previous.configure(state="normal" if self.page else "disabled")
        self.next.configure(state="normal" if (self.page + 1) * 120 < total else "disabled")
        self.table.set_rows(self.current)
        self.draw()

    def draw(self, _event=None):
        chart = self.chart
        chart.delete("all")

        width = max(chart.winfo_width(), 420)
        height = max(chart.winfo_height(), 150)
        if not self.current:
            chart_title(chart, "协议时间线")
            chart.create_text(width / 2, height / 2, fill=MUTED, text="等待报文证据")
            return
        rows = self.current
        protocols = sorted({self._protocol(row) for row in rows})
        top, bottom, left, right = 37, height - 23, 77, width - 25
        times = self.times(rows)
        horizontal = times if times is not None else [row["packet_number"] for row in rows]
        start, end = min(horizontal), max(horizontal)
        chart_title(chart, "相对时间 · 点击标记" if times is not None else "帧序号 · 点击标记")
        for n, protocol in enumerate(protocols):
            y = top + (bottom - top - 8) * (n + 0.5) / len(protocols)
            chart.create_line(left, y, right, y, fill="#dbe6f0")
            chart.create_text(11, y, text=protocol.upper(), anchor="w", fill=MUTED, font=("Segoe UI", 8))
        for i, row in enumerate(rows):
            column = (horizontal[i] - start) / (end - start) if end > start else 0.5
            x = left + 6 + (right - left - 12) * column
            protocol = self._protocol(row)
            n = protocols.index(protocol)
            y = top + (bottom - top - 8) * (n + 0.5) / len(protocols)
            key = f"packet-{i}"
            color = PALETTE.get(protocol, INK)
            chart.create_oval(x - 4, y - 4, x + 4, y + 4, fill=color, width=0, tags=(key,))
            chart.tag_bind(key, "<Button-1>", lambda _, ix=i: self.table.select(ix))
        start_label, end_label = (f"{start:g} ms", f"{end:g} ms") if times is not None else (str(start), str(end))
        chart.create_text(left, height - 11, fill=MUTED, text=start_label, anchor="w")
        if end != start:
            chart.create_text(right, height - 11, fill=MUTED, text=end_label, anchor="e")

    def times(self, rows):
        if self.mode.get() == "frames":
            return [row["relative_ms"] for row in rows]
        try:
            baseline = datetime.fromisoformat(self.report["packet_analysis"]["observed_at"])
            return [round((datetime.fromisoformat(row["observed_at"]) - baseline).total_seconds() * 1000, 3)
                    for row in rows]
        except (KeyError, ValueError, TypeError):
            return None

    @staticmethod
    def _protocol(row):
        if row.get("protocol"):
            return row["protocol"]
        stack = row.get("protocols", ())
        return stack[-1] if stack else "unknown"
