"""Interactive local network workbench built on the shared evidence engines."""
import tkinter as tk
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from tkinter import filedialog, ttk

from .network_device_view import DeviceView
from .network_diagnostic_view import DiagnosticView
from .network_export import export_network
from .network_packets_view import PacketView
from .network_widgets import BG, INK


class NetworkWorkbench:
    """A modeless tool window. Its worker never calls Tk or changes the main report."""
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("WiFiScope · 网络工作台")
        screen_width, screen_height = parent.winfo_screenwidth(), parent.winfo_screenheight()
        self.window.geometry(f"{min(1100, screen_width - 55)}x{min(735, screen_height - 70)}")
        self.window.minsize(870, 585)
        self.window.configure(background=BG)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.status = tk.StringVar(master=self.window, value="就绪")
        self.include_identifiers = tk.BooleanVar(master=self.window, value=False)
        self.messages = Queue()
        self.stop = Event()
        self.busy = False
        self.timer = None
        style = ttk.Style(self.window)
        style.configure("NetworkTitle.TLabel", font=("Microsoft YaHei UI", 10, "bold"), foreground=INK)
        header = tk.Frame(self.window, bg=INK, padx=15, pady=9)
        header.pack(fill="x")
        tk.Label(header, text="网络工作台", bg=INK, fg="white", font=("Microsoft YaHei UI", 16, "bold")).pack(side="left")
        footer = ttk.Frame(self.window, padding=(12, 6))
        footer.pack(side="bottom", fill="x")
        self.cancel_button = ttk.Button(footer, text="取消", command=self.cancel, state="disabled")
        self.cancel_button.pack(side="left")
        ttk.Label(footer, textvariable=self.status, wraplength=455).pack(side="left", padx=9, fill="x", expand=True)
        ttk.Button(footer, text="导出当前结果…", command=lambda: self.guard(self.export)).pack(side="right")
        ttk.Checkbutton(footer, text="导出保留标识符", variable=self.include_identifiers).pack(side="right", padx=7)
        self.tabs = ttk.Notebook(self.window, padding=(8, 5))
        self.tabs.pack(fill="both", expand=True)
        self.tabs.enable_traversal()
        self.packet_tab, self.diagnostic_tab, self.device_tab = [
            ttk.Frame(self.tabs, padding=9) for _ in range(3)
        ]
        for tab, text in ((self.packet_tab, "报文分析"), (self.diagnostic_tab, "分层诊断与监测"),
                          (self.device_tab, "设备与拓扑")):
            self.tabs.add(tab, text=text)
        self.packets = PacketView(self, self.packet_tab)
        self.diagnostics = DiagnosticView(self, self.diagnostic_tab)
        self.devices = DeviceView(self, self.device_tab)
        self.views = {str(self.packet_tab): self.packets, str(self.diagnostic_tab): self.diagnostics,
                      str(self.device_tab): self.devices}
        self.window.bind("<Control-e>", lambda _event: self.guard(self.export))
        self.timer = self.window.after(60, self.poll)

    def show_packets(self, report, path=None):
        self.packets.show(report, path)
        self.tabs.select(self.packet_tab)

    def guard(self, action):
        try:
            action()
        except (ValueError, TypeError) as error:
            self.status.set(str(error))
        except OSError:
            self.status.set("操作未完成，请检查文件和输出目录权限。")

    def start(self, label, work, apply):
        if self.busy:
            self.status.set("当前任务仍在运行。")
            return
        self.stop = Event()
        self.busy = True
        self.status.set(label)
        self.cancel_button.configure(state="normal")
        stop = self.stop

        def execute():
            try:
                result = work(stop)
            except (FileExistsError, OSError):
                self.messages.put(("error", "无法读取证据或创建输出。导出需要使用新的目录。"))
            except (ValueError, TypeError) as error:
                self.messages.put(("error", str(error)[:260]))
            except Exception:  # noqa: BLE001 - keep unexpected worker failures on the UI channel.
                self.messages.put(("error", "操作未完成。请检查输入格式和本机工具。"))
            else:
                self.messages.put(("result", (result, apply)))

        Thread(target=execute, name="wifiscope-network", daemon=True).start()

    def poll(self):
        while True:
            try:
                kind, value = self.messages.get_nowait()
            except Empty:
                break
            if kind == "sample":
                self.diagnostics.record_sample(value)
                continue
            self.busy = False
            self.cancel_button.configure(state="disabled")
            if kind == "error":
                self.status.set(value)
                continue
            result, apply = value
            cancelled = self.stop.is_set() or isinstance(result, dict) and result.get("status") == "cancelled"
            self.status.set("已取消，保留已获得的结果。" if cancelled else "已完成")
            self.guard(lambda callback=apply, evidence=result: callback(evidence))
        self.timer = self.window.after(60, self.poll)

    def cancel(self):
        self.stop.set()
        self.status.set("正在取消…")

    def close(self):
        self.stop.set()
        if self.timer is not None:
            self.window.after_cancel(self.timer)
            self.timer = None
        self.window.destroy()

    def export(self):
        report = self.views[self.tabs.select()].result()
        if not report:
            raise ValueError("先打开证据或运行一次诊断。")
        directory = filedialog.asksaveasfilename(parent=self.window, title="为报告选择一个尚不存在的新目录名称")
        if directory:
            include = self.include_identifiers.get()
            self.start("正在导出本地报告", lambda _stop: export_network(report, directory, include),
                       lambda value: self.status.set(f"报告已保存到 {Path(value['html']).parent}"))
