"""Plan, run and inspect bounded, explicitly scoped network diagnostics."""
import tkinter as tk
from tkinter import ttk

from .network_present import diagnostic_rows, latency_points
from .network_widgets import INK, MUTED, EvidenceTable, canvas, entry

STAGES = {
    "link": "网卡 / Wi-Fi", "local": "地址 / 路由", "gateway": "网关", "peer": "指定对端",
    "dns": "DNS", "path": "路径跟踪", "application": "应用",
}
STATUS = {
    "ok": ("已观测", "#136e58"), "failed": ("失败", "#a23037"), "partial": ("部分", "#875711"),
    "unknown": ("未知", "#4f5d74"), "not_requested": ("未请求", "#596a79"),
    "cancelled": ("取消", "#596a79"),
}
SERIES = {"gateway": "#3167a4", "dns": "#0d7969", "application": "#8b4f21"}
RUN_STATUS = {"complete": "已完成", "partial": "部分结果", "cancelled": "已取消", "running": "监测中"}
LOCAL_VIEWS = {
    "本机路由": ("routes", (("destination", "目的网段", 155), ("gateway", "下一跳", 143),
                          ("interface", "接口", 125), ("metric", "度量", 72))),
    "本机邻居": ("neighbors", (("ip", "地址", 155), ("mac", "物理地址", 145),
                              ("interface", "接口", 125), ("state", "状态", 105))),
    "本机监听": ("listeners", (("protocol", "协议", 66), ("address", "绑定地址", 133),
                              ("port", "端口", 67), ("bind", "绑定范围", 108), ("pid", "PID", 75))),
}


class DiagnosticView:
    def __init__(self, owner, parent):
        self.owner = owner
        self.report = {}
        self.preview = None
        self.authorized = tk.BooleanVar(master=parent, value=False)
        self.summary = tk.StringVar(master=parent, value="读取本机配置可直接开始。主动诊断需指定目标并核对计划。")
        self.view = tk.StringVar(master=parent, value="分层结果")
        self.fields = {}
        form = ttk.Frame(parent)
        form.pack(fill="x")
        for n, (key, label, default) in enumerate((
            ("interface", "网卡", ""), ("source", "源 IP", ""), ("gateway", "网关 IP", ""),
            ("peers", "对端 IP（逗号分隔）", ""), ("trace", "跟踪目的 IP", ""),
            ("dns", "DNS 服务器 IP", ""), ("application", "HTTP(S) URL", ""),
            ("ntp", "NTP 服务器 IP", ""), ("doh", "DoH URL", ""),
            ("samples", "监测次数", "5"), ("interval", "间隔秒", "2"), ("failure_threshold", "告警连续失败次数", "2"),
        )):
            row, col = divmod(n, 6)
            variable = tk.StringVar(master=parent, value=default)
            self.fields[key] = variable
            form.columnconfigure(col, weight=1)
            entry(form, label, variable, col, row)
            variable.trace_add("write", self.invalidate)
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(2, 4))
        for label, action in (
            ("仅看本机", self.passive), ("预览计划", self.show_plan),
            ("开始诊断", lambda: self.run(False)), ("开始监测", lambda: self.run(True)),
        ):
            ttk.Button(bar, text=label, command=lambda fn=action: owner.guard(fn)).pack(side="left", padx=(0, 5))
        ttk.Checkbutton(bar, text="授权检查已预览目标", variable=self.authorized).pack(side="left", padx=4)
        self.view_box = ttk.Combobox(bar, textvariable=self.view, values=("分层结果", "路径跳点", "监测告警", *LOCAL_VIEWS), state="readonly", width=10)
        self.view_box.pack(side="right")
        ttk.Label(parent, textvariable=self.summary, wraplength=875).pack(fill="x", pady=(3, 4))
        self.chart = canvas(parent, 150)
        self.chart.pack(fill="x", pady=(0, 7))
        self.chart.bind("<Configure>", self.draw)
        self.table = EvidenceTable(parent, ())
        self.table.formatters["stage"] = lambda value: STAGES.get(value, str(value or "—"))
        self.table.formatters["status"] = lambda value: STATUS.get(value, (str(value or "—"), MUTED))[0]
        self.table.pack(fill="both", expand=True)
        self.view.trace_add("write", lambda *_: self.render())
        self.render()

    def invalidate(self, *_):
        self.preview = None
        self.authorized.set(False)

    def options(self):
        values = {key: var.get().strip() for key, var in self.fields.items()}
        for key in ("samples", "failure_threshold"):
            if not values[key].isdecimal():
                raise ValueError("监测次数和告警阈值须为整数。")
            values[key] = int(values[key])
        try:
            values["interval"] = float(values["interval"])
        except ValueError:
            raise ValueError("监测间隔须为秒数。") from None
        values["peers"] = tuple(item.strip() for item in values["peers"].split(",") if item.strip())
        return {key: value if value != "" else None for key, value in values.items()}

    def show_plan(self):
        from .network_diagnostics import diagnostic_plan
        options = self.options()
        plan = diagnostic_plan(**options)
        self.preview = options
        self.authorized.set(False)
        checks = plan.get("active_checks", [])
        self.table.set_columns((("stage", "环节", 118), ("method", "方法", 150), ("target", "目标", 255)))
        self.table.set_rows(checks, placeholder="本计划只有本机只读检查。")
        self.summary.set(f"预览 {len(checks)} 项主动检查。诊断 1 轮，监测 {options['samples']} 轮，"
                         f"间隔 {options['interval']:g} 秒；勾选授权后开始。")
        self.owner.status.set("计划已校验")

    def passive(self):
        from .network_diagnostics import diagnose_network
        interface = self.fields["interface"].get().strip() or None
        self.owner.start("正在读取本机", lambda stop: diagnose_network(interface=interface, cancel=stop), self.show)

    def run(self, monitoring):
        from .network_diagnostics import (
            diagnose_network,
            diagnostic_plan,
            monitor_network,
        )
        if self.owner.busy:
            raise ValueError("当前任务仍在运行。")
        options = self.options()
        plan = diagnostic_plan(**options)
        if plan.get("requires_authorization") and (options != self.preview or not self.authorized.get()):
            raise ValueError("请预览当前计划并勾选目标授权。")
        confirmed = self.authorized.get()
        if not monitoring:
            options["samples"] = 1
        function = monitor_network if monitoring else diagnose_network

        if monitoring:
            self.show({"kind": "network-monitor", "status": "running", "samples": [], "alerts": [], "plan": plan})

        def task(stop):
            if monitoring:
                return function(authorized=confirmed, cancel=stop,
                                on_sample=lambda sample: self.owner.messages.put(("sample", sample)), **options)
            return function(authorized=confirmed, cancel=stop, **options)

        self.owner.start("正在监测" if monitoring else "正在诊断", task, self.show)

    def record_sample(self, sample):
        self.report["samples"].append(sample)
        self.report["alerts"].extend(sample.get("alerts", []))
        self.owner.status.set(f"已记录 {sample['sequence']} / {self.report['plan']['samples']} 轮监测")
        self.render()

    def show(self, report):
        self.report = report
        self.render()

    def result(self):
        return self.report

    def render(self):
        report = self.report
        if report:
            status = RUN_STATUS.get(report.get("status"), "结果")
            self.summary.set(f"{status}  ·  {len(report.get('samples', []))} 轮样本"
                             f"  ·  {len(report.get('alerts', []))} 条告警或恢复")
        rows = diagnostic_rows(report)
        selected = self.view.get()
        if selected == "分层结果":
            fields = (("sequence", "轮次", 55), ("stage", "环节", 128),
                      ("status", "状态", 107), ("observed_at", "观测时间", 220))
        elif selected == "监测告警":
            rows = report.get("alerts", [])
            fields = (("sequence", "轮次", 60), ("stage", "环节", 125),
                      ("type", "变化", 115), ("target", "目标", 220))
        elif selected == "路径跳点":
            fields = (("sequence", "轮次", 58), ("hop", "跳", 55), ("addresses", "地址", 180),
                      ("rtt_ms", "时延 ms", 100), ("status", "状态", 103))
            rows = [dict(item, sequence=row["sequence"]) for row in rows if row["stage"] == "path"
                    for item in self._collection(row["evidence"], "hops")]
        else:
            collection, fields = LOCAL_VIEWS[selected]
            latest_local = next((row["evidence"] for row in reversed(rows) if row["stage"] == "local"), {})
            rows = self._collection(latest_local, collection)
        self.table.set_columns(fields)
        self.table.set_rows(rows)
        self.draw()

    @staticmethod
    def _collection(evidence, key):
        value = evidence.get("evidence", evidence)
        if not isinstance(value, dict):
            return []
        if key in value:
            return value[key] if isinstance(value[key], list) else []
        for check in value.get("checks", []):
            if isinstance(check.get(key), list):
                return check[key]
        for child in value.values():
            if isinstance(child, dict) and isinstance(child.get(key), list):
                return child[key]
        return []

    def draw(self, _event=None):
        chart = self.chart
        chart.delete("all")
        width, height = max(chart.winfo_width(), 420), max(chart.winfo_height(), 147)
        samples = self.report.get("samples", [])
        last = samples[-1].get("stages", {}) if samples else {}
        for i, stage in enumerate(STAGES):
            label, color = STATUS.get(last.get(stage, {}).get("status"), ("未测", MUTED))
            left, right = width * i / len(STAGES) + 5, width * (i + 1) / len(STAGES) - 5
            chart.create_rectangle(left, 8, right, 49, fill="#eef4fa", width=0)
            chart.create_text((left + right) / 2, 21, text=STAGES[stage], fill=INK)
            chart.create_text((left + right) / 2, 38, text=label, fill=color, font=("Microsoft YaHei UI", 8, "bold"))
        series = latency_points(self.report)
        if not series:
            chart.create_text(width / 2, 96, text="有时延样本后显示趋势", fill=MUTED)
            return
        maximum = max(1, max(v for points in series.values() for _, v in points if v is not None))
        first = min(n for points in series.values() for n, _ in points)
        last_seq = max(n for points in series.values() for n, _ in points)
        floor, top, left, right = height - 28, 74, 73, width - 18
        chart.create_line(left, floor, right, floor, fill="#dce6f0")
        chart.create_text(8, top, text=f"{maximum:g} ms", anchor="w", fill=MUTED, font=("Segoe UI", 8))
        for index, (stage, points) in enumerate(series.items()):
            color = SERIES[stage]
            chart.create_text(left + 75 * index, height - 10, text=STAGES[stage], anchor="w", fill=color)
            previous = None
            for sequence, value in points:
                if value is None:
                    previous = None
                    continue
                x = left + (right - left) * (sequence - first) / max(1, last_seq - first)
                y = floor - (floor - top) * value / maximum
                if previous:
                    chart.create_line(*previous, x, y, fill=color, width=2)
                chart.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, width=0)
                previous = (x, y)
