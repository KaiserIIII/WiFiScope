"""Dedicated security tool window; all lifecycle delivery remains on Tk thread."""

import tkinter as tk
from tkinter import filedialog, ttk
import uuid

from .reports import export_report
from .workstation import controlled_report


class SecurityToolsView:
    def __init__(self, app):
        self.app = app
        self.token = uuid.uuid4().hex
        self.window = tk.Toplevel(app.root)
        self.window.title("WiFiScope · 安全工具")
        self.window.transient(app.root)
        self.window.geometry("900x620")
        self.window.minsize(760, 540)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.app.controller.tool_owner = self.token
        self.active_panel = None
        self.seen_result = None
        self.seen_progress = None
        self.replace_current = tk.BooleanVar(value=False)
        self.export_raw = tk.BooleanVar(value=False)
        self.status = tk.StringVar(
            value="工具只生成预览；明确应用才替换当前快照。打开或切换工具不会采集。"
        )
        top = ttk.Frame(self.window, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="安全工具", font=("Microsoft YaHei UI", 15, "bold")).pack(
            side="left"
        )
        ttk.Label(top, text="本地证据 · 授权抓包 · 定点采样", padding=(16, 0)).pack(
            side="left"
        )
        footer = ttk.Frame(self.window, padding=8)
        footer.pack(side="bottom", fill="x")
        ttk.Label(
            footer,
            text="应用将替换当前快照并重置未保存的处置关联；先保存案件。",
            wraplength=820,
        ).pack(anchor="w")
        ttk.Checkbutton(
            footer, text="我选择替换当前快照（应用按钮）", variable=self.replace_current
        ).pack(anchor="w")
        controls = ttk.Frame(footer)
        controls.pack(fill="x", pady=3)
        self.apply_button = ttk.Button(
            controls, text="应用工具结果", command=lambda: self.guard(self.apply)
        )
        self.apply_button.pack(side="left")
        self.cancel_button = ttk.Button(
            controls, text="取消当前操作", command=app.controller.cancel
        )
        self.cancel_button.pack(side="left", padx=8)
        self.export_button = ttk.Button(
            controls, text="导出工具结果", command=lambda: self.guard(self.export)
        )
        self.export_button.pack(side="right")
        ttk.Checkbutton(
            controls, text="本次导出原始标识符", variable=self.export_raw
        ).pack(side="right", padx=8)
        ttk.Label(
            footer, textvariable=self.status, wraplength=820, foreground="#3b5674"
        ).pack(fill="x")
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=4)
        from .vulnerability_view import VulnerabilityView
        from .capture_view import CaptureView
        from .survey_view import SurveyView
        from .catalog_view import CatalogView

        self.panels = {}
        self.scroll_pages = {}
        for key, label, cls in [
            ("catalog", "漏洞库与资产清单", CatalogView),
            ("vulnerability", "漏洞审计", VulnerabilityView),
            ("capture", "实时抓包", CaptureView),
            ("survey", "Wi-Fi 热力图", SurveyView),
        ]:
            frame, inner = self.page()
            panel = cls(self, inner)
            panel.frame = frame
            self.panels[key] = panel
            self.notebook.add(frame, text=label)
        self.window.bind("<MouseWheel>", self.wheel)

    def page(self):
        frame = ttk.Frame(self.notebook)
        canvas = tk.Canvas(frame, highlightthickness=0, bg="#edf2f8")
        scrollbar = ttk.Scrollbar(frame, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        inner = ttk.Frame(canvas, padding=10)
        item = canvas.create_window(0, 0, window=inner, anchor="nw")
        inner.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(item, width=e.width))
        canvas.bind(
            "<MouseWheel>", lambda e: canvas.yview_scroll(-int(e.delta / 120), "units")
        )
        canvas.bind("<Next>", lambda e: canvas.yview_scroll(1, "pages"))
        canvas.bind("<Prior>", lambda e: canvas.yview_scroll(-1, "pages"))
        self.scroll_pages[str(frame)] = canvas
        return frame, inner

    def wheel(self, event):
        if isinstance(event.widget, (tk.Text, ttk.Treeview)):
            return
        canvas = self.scroll_pages.get(self.notebook.select())
        if canvas:
            canvas.yview_scroll(-int(event.delta / 120), "units")

    @staticmethod
    def text(parent, text):
        ttk.Label(parent, text=text, wraplength=790, justify="left").pack(
            fill="x", pady=4
        )

    @staticmethod
    def output(parent, height=10):
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True, pady=5)
        text = tk.Text(box, height=height, wrap="word", bg="white", padx=9, pady=6)
        scroll = ttk.Scrollbar(box, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        return text

    def guard(self, work):
        try:
            work()
        except (ValueError, OSError, TypeError, tk.TclError):
            self.status.set(
                "输入或操作不可用：检查文件格式/大小、数值范围、明确选择及授权。已有快照保留。"
            )
        except Exception as error:
            from .guidance import GuidanceError, ERRORS

            if isinstance(error, GuidanceError):
                self.status.set(ERRORS[error.code])
            else:
                raise

    def show(self, key):
        refresh = getattr(self.panels[key], "refresh_evidence", None)
        if refresh is not None:
            refresh()
        self.notebook.select(self.panels[key].frame)
        self.window.deiconify()
        self.window.lift()

    def start(self, panel, label, work, *, progress_kind='capture'):
        prepare = getattr(panel, "prepare_result", lambda value: value)
        self.app.controller.start_tool(
            label, lambda cancel, progress: prepare(work(cancel, progress)), self.token,
            progress_kind=progress_kind
        )
        self.active_panel = panel
        self.seen_result = self.seen_progress = None
        self.replace_current.set(False)
        self.status.set("正在执行：" + label + "；可取消，当前快照保留。")

    def deliver(self):
        c = self.app.controller
        if c.tool_owner != self.token or self.active_panel is None:
            return
        if not c.busy and c.status.startswith("工具结果已明确应用"):
            self.status.set(c.status)
        if c.tool_progress is not None and c.tool_progress is not self.seen_progress:
            self.seen_progress = c.tool_progress
            if hasattr(self.active_panel, "on_progress"):
                self.active_panel.on_progress(c.tool_progress)
        if c.tool_error:
            self.status.set(
                c.tool_error
                + getattr(self.active_panel, 'error_help', " 检查文件/目录、驱动、权限及后端过滤能力；不会自动安装。")
            )
        if c.tool_result is not None and c.tool_result is not self.seen_result:
            self.seen_result = c.tool_result
            try:
                self.active_panel.on_result(c.tool_result)
                self.status.set(c.status)
            except (ValueError, TypeError, KeyError, tk.TclError):
                self.status.set(
                    "无法显示工具结果：检查图片编码/类型化格式，或重载合成示例。上一工具结果及主快照保留。"
                )

    def selected(self):
        return next(
            p for p in self.panels.values() if str(p.frame) == self.notebook.select()
        )

    def apply(self):
        if self.app.controller.busy:
            raise ValueError("Wait for the current operation.")
        result = self.selected().result
        if result is None or not self.replace_current.get():
            self.status.set("先生成结果，再勾选相邻的替换选择；当前案件及处置保留。")
            return
        self.app.controller.apply_tool(result, "安全工具 · 明确应用的结果", self.token)
        self.replace_current.set(False)
        self.status.set("正在验证并应用工具结果；验证失败将保留当前快照。")

    def export(self):
        result = self.selected().result
        if result is None:
            raise ValueError("Generate a result first.")
        directory = filedialog.asksaveasfilename(
            parent=self.window, title="新建工具报告目录（不得已存在）"
        )
        if directory:
            raw = self.export_raw.get()
            from copy import deepcopy

            report = deepcopy(result)
            self.start(
                self.selected(),
                "导出工具报告",
                lambda cancel, progress: {
                    "exported": export_report(controlled_report(report), directory, raw)
                },
            )

    def close(self):
        c = self.app.controller
        if c.tool_owner == self.token:
            c.tool_owner = None
            if c.busy and c.active_tool_owner == self.token:
                c.cancel()
            c.tool_result = c.tool_progress = c.tool_error = None
        self.window.destroy()
        self.app.security_tools = None
