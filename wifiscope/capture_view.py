"""Explicit read-only capture plan, independent raw consent and real progress."""

import math
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

from .live_capture import capture_live, list_capture_interfaces
from .demo import capture_demo


class CaptureView:
    def __init__(self, owner, parent):
        self.owner, self.result, self.interfaces = owner, None, []
        self.interface = tk.StringVar()
        self.duration, self.max_packets = (
            tk.StringVar(value="10"),
            tk.StringVar(value="2000"),
        )
        self.max_bytes, self.snaplen = (
            tk.StringVar(value="8388608"),
            tk.StringVar(value="96"),
        )
        self.packet_filter, self.raw_path = tk.StringVar(), tk.StringVar()
        self.promiscuous, self.raw_optin, self.authorized = (
            tk.BooleanVar(),
            tk.BooleanVar(),
            tk.BooleanVar(),
        )
        self.progress = tk.StringVar(
            value="尚未采集 · 包数/捕获字节/时间来自实际回调；不是带宽或互联网测速。"
        )
        self.capability = tk.StringVar(
            value="未枚举。Windows 需要已安装 Npcap 及权限；Linux 需要 AF_PACKET 权限或已安装 libpcap。不会自动安装。"
        )
        owner.text(
            parent,
            "实时抓包 · 只读取明确选择的本地接口，不发送/注入数据。先枚举，再核对精确计划与授权。普通报告仅含元数据。",
        )
        self.enumerate_button = ttk.Button(
            parent,
            text="枚举可用接口（只读）",
            command=lambda: owner.guard(self.enumerate),
        )
        self.enumerate_button.pack(anchor="w")
        self.interface_box = ttk.Combobox(
            parent, textvariable=self.interface, values=(), state="readonly"
        )
        self.interface_box.pack(fill="x", pady=5)
        ttk.Label(parent, textvariable=self.capability, wraplength=790).pack(fill="x")
        plan = ttk.LabelFrame(
            parent, text="本次精确计划 · 修改任何字段都会清除授权", padding=8
        )
        plan.pack(fill="x", pady=8)
        for row, (label, variable) in enumerate(
            [
                ("时长秒 0.2–120", self.duration),
                ("包数上限 1–20000", self.max_packets),
                ("捕获字节 4096–16777216", self.max_bytes),
                ("每包快照字节 64–65535", self.snaplen),
                ("过滤表达式（后端必须支持）", self.packet_filter),
                ("原始文件（留空不写文件）", self.raw_path),
            ]
        ):
            ttk.Label(plan, text=label).grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(plan, textvariable=variable).grid(
                row=row, column=1, sticky="ew", padx=8
            )
        ttk.Button(
            plan,
            text="选择新的原始文件路径",
            command=lambda: owner.guard(self.choose_raw),
        ).grid(row=5, column=2)
        plan.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            plan,
            text="混杂模式（默认关闭；后端不支持时拒绝）",
            variable=self.promiscuous,
        ).grid(row=6, column=0, columnspan=3, sticky="w")
        ttk.Checkbutton(
            plan,
            text="独立同意：>96 字节或原始留存；包前缀/完整包可能含私人应用数据",
            variable=self.raw_optin,
        ).grid(row=7, column=0, columnspan=3, sticky="w")
        ttk.Checkbutton(
            plan,
            text="我已获授权读取所选接口，确认以上全部限额、过滤及留存计划",
            variable=self.authorized,
        ).grid(row=8, column=0, columnspan=3, sticky="w", pady=5)
        actions = ttk.Frame(parent)
        actions.pack(fill="x")
        self.start_button = ttk.Button(
            actions, text="开始授权抓包", command=lambda: owner.guard(self.start)
        )
        self.start_button.pack(side="left")
        self.demo_button = ttk.Button(
            actions,
            text="合成离线抓包示例 · 不打开接口",
            command=lambda: owner.guard(self.demo),
        )
        self.demo_button.pack(side="left", padx=8)
        ttk.Label(parent, textvariable=self.progress, wraplength=790).pack(
            fill="x", pady=5
        )
        self.output = owner.output(parent, 8)
        for variable in (
            self.interface,
            self.duration,
            self.max_packets,
            self.max_bytes,
            self.snaplen,
            self.packet_filter,
            self.raw_path,
            self.promiscuous,
            self.raw_optin,
        ):
            variable.trace_add("write", lambda *_: self.authorized.set(False))

    def enumerate(self):
        self.owner.start(
            self,
            "只读枚举抓包接口",
            lambda cancel, progress: {"interface_catalog": list_capture_interfaces()},
        )

    def choose_raw(self):
        path = filedialog.asksaveasfilename(
            parent=self.owner.window,
            title="原始抓包新文件（禁止覆盖）",
            defaultextension=".pcap",
        )
        if path:
            self.raw_path.set(path)

    def checked_plan(self):
        interface = self.interface.get()
        row = next((r for r in self.interfaces if r["interface"] == interface), None)
        if row is None:
            self.owner.status.set("先枚举，并明确选择一个接口；不会自动选择。")
            return None
        if not self.authorized.get():
            self.owner.status.set("请核对精确抓包计划，并勾选相邻授权。")
            return None
        duration = float(self.duration.get())
        packets, size, snaplen = (
            int(self.max_packets.get()),
            int(self.max_bytes.get()),
            int(self.snaplen.get()),
        )
        packet_filter, raw_path = (
            self.packet_filter.get(),
            self.raw_path.get().strip() or None,
        )
        raw, promisc = self.raw_optin.get(), self.promiscuous.get()
        if (
            not math.isfinite(duration)
            or not 0.2 <= duration <= 120
            or not 1 <= packets <= 20000
            or not 4096 <= size <= 16777216
            or not 64 <= snaplen <= 65535
            or len(packet_filter) > 512
            or any(not 32 <= ord(c) <= 126 for c in packet_filter)
        ):
            raise ValueError("Invalid capture limits.")
        if (snaplen > 96 or raw_path) and not raw:
            self.owner.status.set("较大快照/原始文件需要独立勾选私人应用数据留存同意。")
            return None
        if (
            packet_filter
            and not row["supports_filter"]
            or promisc
            and not row["supports_promiscuous"]
        ):
            self.owner.status.set(
                "所选后端不支持此过滤/混杂模式；修改计划或明确选择已安装的兼容后端。"
            )
            return None
        if raw_path and (
            Path(raw_path).exists()
            or Path(raw_path).is_symlink()
            or not Path(raw_path).parent.is_dir()
        ):
            raise ValueError("Raw path must be new and exclusive.")
        return interface, dict(
            duration=duration,
            max_packets=packets,
            max_bytes=size,
            snaplen=snaplen,
            packet_filter=packet_filter,
            raw_path=raw_path,
            retain_packets=raw,
            promiscuous=promisc,
            authorized=True,
        )

    def start(self):
        plan = self.checked_plan()
        if plan is None:
            return
        interface, options = plan
        self.authorized.set(False)
        self.owner.start(
            self,
            "授权本地接口抓包",
            lambda cancel, progress: capture_live(
                interface, **options, cancel=cancel, progress=progress
            ),
        )

    def demo(self):
        self.owner.start(
            self, "合成离线抓包示例（非实时）", lambda cancel, progress: capture_demo()
        )

    def on_progress(self, value):
        self.progress.set(
            f"实际抓包：{value['packets']} 包 · {value['captured_bytes']} 捕获字节 · {value['elapsed_ms'] / 1000:.1f} 秒 · {value['status']}"
        )

    def on_result(self, value):
        if "interface_catalog" in value:
            self.interfaces = value["interface_catalog"]
            self.interface_box.configure(
                values=[r["interface"] for r in self.interfaces]
            )
            self.interface.set("")
            self.capability.set(
                "\n".join(
                    f"{r['interface']} · {r['label']} · {r['backend']} · 过滤={r['supports_filter']} · 混杂={r['supports_promiscuous']}"
                    for r in self.interfaces
                )
                or "未发现接口；核查已安装驱动、服务及本地权限。"
            )
            return
        if "exported" in value:
            self.owner.status.set(
                "元数据报告已导出；不包含原始包文件、路径或过滤表达式。"
            )
            return
        self.result = value
        session = value.get("capture_session")
        if not session:
            self.owner.app._text(self.output, "部分元数据已返回；未提供抓包会话。")
            return
        lines = [
            "合成离线示例 · 非实时抓包" if value.get("synthetic") else "实际抓包已结束",
            f"状态 {session['status']} · 停止原因 {session['stop_reason']} · 实际时长 {session['duration_ms']} ms",
            f"采集 {session['packets']} 包；分析 {session['analyzed_packets']} 包；捕获 {session['captured_bytes']} 字节；线上长度 {session['wire_bytes']} 字节",
            f"快照 {session['limits']['snaplen']} 字节；仅捕获前缀可能截断。丢包统计 {session['pcap_stats']}（None=未知）",
            "部分覆盖始终保留；没有观测到流量不能证明无通信。报告不保留应用正文、原始文件路径或任意导入描述。",
        ]
        self.owner.app._text(self.output, "\n".join(lines))
