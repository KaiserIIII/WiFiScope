"""Normalized survey canvas, bounded local floorplan and explicit sampling."""

import base64
import copy
import math
from pathlib import Path
import struct
import tkinter as tk
from tkinter import filedialog, ttk
import uuid
import xml.etree.ElementTree as ET

from .collect import collect_local
from .demo import survey_demo
from .heatmap import interpolate_survey, render_heatmap_svg
from .investigate import build_investigation
from .survey import add_sample, import_survey, load_project, save_project
from .survey_schema import MAX_BYTES, validate_survey


def _gif_dimensions(data):
    width, height, packed = struct.unpack("<HHB", data[6:11])
    index = 13 + (3 * 2 ** ((packed & 7) + 1) if packed & 128 else 0)
    frames, pixels = 0, 0

    def blocks(offset):
        while offset < len(data):
            size = data[offset]
            offset += 1
            if size == 0:
                return offset
            offset += size
        raise ValueError("Truncated GIF data blocks.")

    while index < len(data):
        code = data[index]
        index += 1
        if code == 0x3B:
            if frames == 0 or index != len(data):
                raise ValueError("Invalid GIF trailer.")
            return width, height
        if code == 0x21:
            if index >= len(data):
                break
            index = blocks(index + 1)
        elif code == 0x2C and index + 9 <= len(data):
            left, top, frame_width, frame_height, flags = struct.unpack(
                "<HHHHB", data[index : index + 9]
            )
            frames += 1
            pixels += frame_width * frame_height
            if (
                not frame_width
                or not frame_height
                or left + frame_width > width
                or top + frame_height > height
                or frames > 256
                or pixels > 32000000
            ):
                raise ValueError("GIF frame exceeds safe local canvas bounds.")
            index += 9 + (3 * 2 ** ((flags & 7) + 1) if flags & 128 else 0)
            if index >= len(data) or not 2 <= data[index] <= 8:
                break
            index = blocks(index + 1)
        else:
            break
    raise ValueError("Invalid bounded GIF structure.")


def floorplan_bytes(path):
    """Read local PNG/GIF header and bounds before creating any Tk image."""
    location = str(path)
    if location.startswith(("\\\\", "//")) or "://" in location:
        raise ValueError("Use a local floorplan file, not a network reference.")
    with Path(path).open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Floorplan exceeds 8 MiB.")
    if (
        data.startswith(b"\x89PNG\r\n\x1a\n")
        and len(data) >= 33
        and data[8:16] == b"\x00\x00\x00\rIHDR"
    ):
        width, height = struct.unpack("!II", data[16:24])
    elif data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 13:
        width, height = _gif_dimensions(data)
    else:
        raise ValueError("Use a local PNG or GIF floorplan.")
    if not 1 <= width <= 8192 or not 1 <= height <= 8192 or width * height > 32000000:
        raise ValueError("Floorplan dimensions exceed 8192 axes or 32 Mpixels.")
    return data, width, height


class SurveyView:
    def __init__(self, owner, parent):
        self.owner, self.result, self.project = owner, None, None
        self.position, self.zoom, self.offset = None, 1.0, (0.0, 0.0)
        self.image = self.display_image = None
        self.undo = []
        self.project_generation = uuid.uuid4().hex
        self.synthetic = False
        self.tiles = []
        self.ssid, self.bssid = tk.StringVar(), tk.StringVar()
        self.metric = tk.StringVar(value="signal_percent")
        self.grid_size, self.radius, self.power = (
            tk.StringVar(value="40"),
            tk.StringVar(value="0.35"),
            tk.StringVar(value="2"),
        )
        self.position_label = tk.StringVar(value="未选择位置；点击只定位，不采集。")
        self.summary = tk.StringVar(
            value="空白画布可直接使用。先明确选择 SSID/BSSID 和指标，再创建新项目。"
        )
        owner.text(
            parent,
            "Wi-Fi 热力图 · 实测点与 IDW 估计分开显示。优先指定 BSSID；同名多 AP 不会自动合并。信号 % 与实测 dBm 不互相换算；信号不代表带宽/干扰或安全。",
        )
        form = ttk.Frame(parent)
        form.pack(fill="x")
        for row, (label, variable) in enumerate(
            [("SSID（可选）", self.ssid), ("BSSID（优先选择）", self.bssid)]
        ):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w")
            ttk.Entry(form, textvariable=variable).grid(
                row=row, column=1, sticky="ew", padx=8, pady=2
            )
        ttk.Label(form, text="指标 / 单位").grid(row=2, column=0, sticky="w")
        ttk.Combobox(
            form,
            textvariable=self.metric,
            values=("signal_percent", "dbm"),
            state="readonly",
        ).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(
            form,
            text="创建新项目（保留主快照）",
            command=lambda: owner.guard(self.new_project),
        ).grid(row=0, column=2, rowspan=2, padx=6)
        form.columnconfigure(1, weight=1)
        files = ttk.Frame(parent)
        files.pack(fill="x", pady=5)
        for label, command in [
            ("打开项目 JSON", self.open_project),
            ("导入 CSV", self.open_csv),
            ("保存本地项目", self.save),
            ("加载本地 PNG/GIF", self.load_floorplan),
        ]:
            ttk.Button(
                files, text=label, command=lambda c=command: owner.guard(c)
            ).pack(side="left", padx=(0, 5))
        owner.text(
            parent,
            "非合成项目可保存到新文件（保留本地标识符，禁止覆盖）。合成示例请导出带合成标记的工具报告；不能保存为缺少该标记的本地项目。导出默认 HMAC。背景 ≤8 MiB、每轴 ≤8192、≤32 Mpixels；仅本地显示，导入项目不自动加载背景。",
        )
        settings = ttk.Frame(parent)
        settings.pack(fill="x", pady=4)
        for label, variable in [
            ("网格 10–100", self.grid_size),
            ("支持半径 .05–1.5", self.radius),
            ("IDW 幂 1–4", self.power),
        ]:
            ttk.Label(settings, text=label).pack(side="left")
            ttk.Entry(settings, textvariable=variable, width=6).pack(
                side="left", padx=4
            )
        ttk.Button(
            settings, text="重新估计", command=lambda: owner.guard(self.estimate)
        ).pack(side="left", padx=5)
        self.demo_button = ttk.Button(
            parent,
            text="合成离线测点示例 · 有限覆盖与遮罩",
            command=lambda: owner.guard(self.demo),
        )
        self.demo_button.pack(anchor="w", pady=5)
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x")
        for label, command in [
            ("放大", lambda: self.zoom_by(1.5)),
            ("缩小", lambda: self.zoom_by(1 / 1.5)),
            ("←", lambda: self.pan(-30, 0)),
            ("→", lambda: self.pan(30, 0)),
            ("↑", lambda: self.pan(0, -30)),
            ("↓", lambda: self.pan(0, 30)),
            ("复位视图", self.reset_view),
        ]:
            ttk.Button(toolbar, text=label, command=command).pack(
                side="left", padx=(0, 3)
            )
        self.canvas = tk.Canvas(
            parent,
            height=320,
            width=700,
            bg="#e5e7eb",
            highlightthickness=1,
            highlightbackground="#9aa9bb",
        )
        self.canvas.pack(fill="x", pady=5)
        self.canvas.bind("<Button-1>", self.select_position)
        self.canvas.bind("<Configure>", lambda e: self.draw())
        ttk.Label(parent, textvariable=self.position_label, wraplength=780).pack(
            fill="x"
        )
        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=4)
        self.sample_button = ttk.Button(
            actions,
            text="采样此位置（本地只读一次）",
            command=lambda: owner.guard(self.sample),
        )
        self.sample_button.pack(side="left")
        self.remove_button = ttk.Button(
            actions, text="移除选中本地点", command=lambda: owner.guard(self.remove)
        )
        self.remove_button.pack(side="left", padx=6)
        ttk.Button(
            actions, text="撤销移除", command=lambda: owner.guard(self.undo_remove)
        ).pack(side="left")
        ttk.Label(parent, textvariable=self.summary, wraplength=780).pack(
            fill="x", pady=4
        )
        owner.text(
            parent,
            "图例：有边实心点=读数，空心点=未知；半透明红→绿=低→高的估计。灰色遮罩=缺少支持。至少 3 个非共线位置建立凸包，每个估计区域还需 3 个半径内贡献点（精确点除外）。",
        )
        box = ttk.Frame(parent)
        box.pack(fill="x")
        self.table = ttk.Treeview(
            box, columns=("x", "y", "value", "time", "gap"), show="headings", height=6
        )
        for key, label, width in [
            ("x", "归一化 x", 85),
            ("y", "归一化 y", 85),
            ("value", "实测值", 75),
            ("time", "观测时间", 250),
            ("gap", "缺口", 170),
        ]:
            self.table.heading(key, text=label)
            self.table.column(key, width=width, minwidth=50)
        scrollbar = ttk.Scrollbar(box, command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(fill="x", expand=True)

    def config(self):
        return dict(
            grid_size=int(self.grid_size.get()),
            radius=float(self.radius.get()),
            power=float(self.power.get()),
        )

    def new_project(self):
        if self.owner.app.controller.busy:
            raise ValueError("Wait for worker.")
        data = validate_survey(
            dict(
                schema_version=1,
                id=uuid.uuid4().hex,
                ssid=self.ssid.get() or None,
                bssid=self.bssid.get().strip() or None,
                metric=self.metric.get(),
                samples=[],
            )
        )
        self.undo = []
        self.synthetic = False
        self.on_result(build_investigation(dict(schema_version=1, wifi_survey=data)))

    def estimate(self):
        if self.project is None:
            raise ValueError("Create a project first.")
        project, config, synthetic = (
            copy.deepcopy(self.project),
            self.config(),
            self.synthetic,
        )
        self.owner.start(
            self,
            "本地信号插值",
            lambda cancel, progress: build_investigation(
                dict(
                    schema_version=1,
                    synthetic=synthetic,
                    wifi_survey=interpolate_survey(project, **config),
                )
            ),
        )

    def sample(self):
        if self.project is None or self.position is None:
            self.owner.status.set("先创建项目，再在画布中明确选择采样位置。")
            return
        if self.synthetic:
            self.owner.status.set("合成项目不可混入实测；请先创建新的明确网络项目。")
            return
        # Editing entry fields never silently changes a project's AP or metric.
        if (
            self.ssid.get() or None,
            self.bssid.get().strip() or None,
            self.metric.get(),
        ) != (self.project["ssid"], self.project["bssid"], self.project["metric"]):
            self.owner.status.set(
                "网络/指标输入已改变；请恢复当前选择或明确创建新项目，不能混合采样。"
            )
            return
        project, position, config = (
            copy.deepcopy(self.project),
            self.position,
            self.config(),
        )

        def work(cancel, progress):
            local = collect_local()
            data = add_sample(
                project, *position, local.get("wifi", []), local.get("collected_at")
            )
            return build_investigation(
                dict(schema_version=1, wifi_survey=interpolate_survey(data, **config))
            )

        self.owner.start(self, "此位置一次本地 Wi-Fi 采样", work)

    def demo(self):
        self.owner.start(
            self,
            "合成离线 Wi-Fi 测点（非实测）",
            lambda cancel, progress: {"replace_project": survey_demo()},
        )

    def open_project(self):
        path = filedialog.askopenfilename(
            parent=self.owner.window,
            title="本地项目 JSON",
            filetypes=[("JSON", "*.json")],
        )
        if path:
            self.owner.start(
                self,
                "打开本地调查项目",
                lambda cancel, progress: {
                    "replace_project": build_investigation(
                        dict(schema_version=1, wifi_survey=load_project(path))
                    )
                },
            )

    def open_csv(self):
        path = filedialog.askopenfilename(
            parent=self.owner.window,
            title="明确导入调查 CSV",
            filetypes=[("CSV", "*.csv")],
        )
        if path:

            def work(cancel, progress):
                with Path(path).open("rb") as stream:
                    data = stream.read(MAX_BYTES + 1)
                return {
                    "replace_project": build_investigation(
                        dict(schema_version=1, wifi_survey=import_survey(data, "csv"))
                    )
                }

            self.owner.start(self, "离线导入调查 CSV", work)

    def save(self):
        if self.project is None:
            raise ValueError("No project.")
        if self.synthetic:
            self.owner.status.set(
                "合成项目不能保存为缺少合成标记的本地项目；请使用底部“导出工具结果”，保留合成标记。"
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self.owner.window,
            title="本地项目新文件（保留原始标识符）",
            defaultextension=".json",
        )
        if path:
            data = copy.deepcopy(self.project)

            def work(cancel, progress):
                save_project(data, path)
                return {"saved": True}

            self.owner.start(self, "保存本地调查项目", work)

    def load_floorplan(self):
        path = filedialog.askopenfilename(
            parent=self.owner.window,
            title="本地 PNG/GIF（背景不进入导出）",
            filetypes=[("PNG/GIF", "*.png *.gif")],
        )
        if path:
            self.owner.start(
                self,
                "检查本地背景尺寸",
                lambda cancel, progress: {"floorplan": floorplan_bytes(path)},
            )

    def remove(self):
        if self.owner.app.controller.busy or self.project is None:
            raise ValueError("Wait for worker.")
        selection = self.table.selection()
        if not selection:
            return
        report = copy.deepcopy(self.result)
        self.undo.append(
            dict(
                project_generation=self.project_generation,
                project_identity=self.project_identity(report),
                report=report,
            )
        )
        data = copy.deepcopy(self.project)
        data.pop("grid", None)
        data["samples"] = [s for s in data["samples"] if s["id"] != selection[0]]
        config = self.config()
        report = copy.deepcopy(report)

        def work(cancel, progress):
            report["wifi_survey"] = interpolate_survey(data, **config)
            return build_investigation(report)

        self.owner.start(
            self,
            "移除本地测点并重算",
            work,
        )

    def undo_remove(self):
        if self.owner.app.controller.busy:
            raise ValueError("Wait for worker.")
        if self.undo:
            entry = self.undo[-1]
            if entry["project_generation"] != self.project_generation or entry[
                "project_identity"
            ] != self.project_identity(self.result):
                self.undo.clear()
                self.owner.status.set(
                    "撤销历史不属于当前项目，已清除；当前项目保持不变。"
                )
                return
            report = copy.deepcopy(entry["report"])
            self.undo.pop()
            self.owner.start(
                self,
                "撤销本地移除",
                lambda cancel, progress: report,
            )

    def transform(self):
        width, height = (
            max(100, self.canvas.winfo_width() - 40),
            max(100, self.canvas.winfo_height() - 40),
        )
        if self.display_image is not None:
            width, height = self.display_image.width(), self.display_image.height()
        else:
            width, height = width * self.zoom, height * self.zoom
        return (
            (self.canvas.winfo_width() - width) / 2 + self.offset[0],
            (self.canvas.winfo_height() - height) / 2 + self.offset[1],
            width,
            height,
        )

    def to_canvas(self, x, y):
        left, top, width, height = self.transform()
        return left + x * width, top + y * height

    def from_canvas(self, x, y):
        left, top, width, height = self.transform()
        return (x - left) / width, (y - top) / height

    def select_position(self, event):
        x, y = self.from_canvas(
            self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        )
        if 0 <= x <= 1 and 0 <= y <= 1:
            self.position = (x, y)
            self.position_label.set(
                f"已选择 x={x:.4f}, y={y:.4f}；点击下方采样按钮才读取一次。"
            )
            self.draw()

    def zoom_by(self, factor):
        self.zoom = min(4.0, max(0.5, self.zoom * factor))
        self.draw()

    def pan(self, x, y):
        self.offset = (self.offset[0] + x, self.offset[1] + y)
        self.draw()

    def reset_view(self):
        self.zoom, self.offset = 1.0, (0.0, 0.0)
        self.draw()

    def draw(self):
        self.canvas.delete("all")
        if self.image:
            # Integer Tk scaling bounds temporary allocations to the canvas view.
            ratio = max(
                self.image.width() / max(100, self.canvas.winfo_width() - 40),
                self.image.height() / max(100, self.canvas.winfo_height() - 40),
            )
            reduction = max(1, math.ceil(ratio / self.zoom))
            self.display_image = self.image.subsample(reduction, reduction)
        left, top, width, height = self.transform()
        self.canvas.create_rectangle(
            left, top, left + width, top + height, fill="#eeeeee", outline="#7b8794"
        )
        if self.display_image:
            self.canvas.create_image(left, top, image=self.display_image, anchor="nw")
        if self.project:
            # Already prepared safe engine footprints, never regenerate on paint.
            for x, y, w, h, color in self.tiles:
                x1, y1 = self.to_canvas(x, y)
                x2, y2 = self.to_canvas(x + w, y + h)
                self.canvas.create_rectangle(
                    x1, y1, x2, y2, fill=color, outline="", stipple="gray50"
                )
            for sample in self.project["samples"]:
                x, y = self.to_canvas(sample["x"], sample["y"])
                self.canvas.create_oval(
                    x - 5,
                    y - 5,
                    x + 5,
                    y + 5,
                    outline="#17263d",
                    width=2,
                    fill="" if sample["value"] is None else "#176eb5",
                )
        if self.position:
            x, y = self.to_canvas(*self.position)
            self.canvas.create_line(x - 8, y, x + 8, y, fill="#a02020", width=2)
            self.canvas.create_line(x, y - 8, x, y + 8, fill="#a02020", width=2)

    @staticmethod
    def project_identity(report):
        if report is None:
            return None
        data = report["wifi_survey"]
        return (
            data["id"],
            data["ssid"],
            data["bssid"],
            data["metric"],
            bool(report.get("synthetic") or "synthetic-demo" in report.get("gaps", [])),
        )

    @staticmethod
    def prepare_result(value):
        """Worker-only geometry preparation; no Tk or mutable view reads."""
        replace_project = "replace_project" in value
        if replace_project:
            value = value["replace_project"]
        if "wifi_survey" not in value:
            return value
        data = value["wifi_survey"]
        if "grid" not in data:
            value = dict(value, wifi_survey=interpolate_survey(data))
        tiles = []
        for item in ET.fromstring(render_heatmap_svg(value["wifi_survey"])):
            if item.tag.endswith("rect") and item.get("opacity"):
                tiles.append(
                    (
                        (float(item.get("x")) - 10) / 700,
                        (float(item.get("y")) - 10) / 700,
                        float(item.get("width")) / 700,
                        float(item.get("height")) / 700,
                        item.get("fill"),
                    )
                )
        return {
            "survey_report": value,
            "tiles": tiles,
            "replace_project": replace_project,
        }

    def on_result(self, value):
        if "exported" in value or "saved" in value:
            self.owner.status.set(
                "已写入新目录/文件。项目保留本地标识符；普通报告默认脱敏。"
            )
            return
        if "floorplan" in value:
            data, width, height = value["floorplan"]
            image = tk.PhotoImage(master=self.canvas, data=base64.b64encode(data))
            if (image.width(), image.height()) != (width, height):
                raise ValueError("Decoded image dimensions disagree.")
            self.image, self.display_image = image, None
            self.reset_view()
            return
        self.tiles = value.get("tiles", [])
        replace_project = value.get("replace_project", False)
        value = value.get("survey_report", value)
        if replace_project or self.project_identity(value) != self.project_identity(
            self.result
        ):
            self.undo.clear()
            self.project_generation = uuid.uuid4().hex
        self.result, self.project = value, value["wifi_survey"]
        self.synthetic = bool(
            value.get("synthetic") or "synthetic-demo" in value.get("gaps", [])
        )
        self.ssid.set(self.project["ssid"] or "")
        self.bssid.set(self.project["bssid"] or "")
        self.metric.set(self.project["metric"])
        grid = self.project.get("grid", {})
        if grid:
            self.grid_size.set(str(grid["size"]))
            self.radius.set(str(grid["radius"]))
            self.power.set(str(grid["power"]))
        self.table.delete(*self.table.get_children())
        for item in self.project["samples"]:
            self.table.insert(
                "",
                "end",
                iid=item["id"],
                values=(
                    round(item["x"], 4),
                    round(item["y"], 4),
                    item["value"] if item["value"] is not None else "未知",
                    item["observed_at"],
                    item["gap"] or "",
                ),
            )
        self.summary.set(
            ("合成离线示例 · 非实测。" if self.synthetic else "")
            + f"{self.project['metric']} · 读数 {sum(s['value'] is not None for s in self.project['samples'])} · 未知 {sum(s['value'] is None for s in self.project['samples'])} · 估计格 {grid.get('estimated_count', 0)} · {grid.get('notice', '尚未估计')}；覆盖有限，灰色区域保持未知。"
        )
        self.draw()
