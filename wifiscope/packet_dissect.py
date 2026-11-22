"""Read a fixed set of frame metadata with a user-selected local TShark."""
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .workstation import read_bounded

FIELDS = ("frame.number", "frame.time_relative", "frame.len", "frame.protocols")
MAX_FRAMES = 2000
MAX_OUTPUT = 1024 * 1024
TIMEOUT = 20.0
_PROTOCOL = re.compile(r"[a-zA-Z0-9_.-]{1,40}\Z")
_CAPTURE_MAGIC = {
    b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
}


def decode_fields(body, limit=MAX_FRAMES):
    """Accept numeric frame metadata and dissector abbreviations only."""
    frames = []
    skipped = 0
    limited = False
    last_number = 0
    for line in body.splitlines():
        if len(frames) >= limit:
            limited = True
            break
        fields = line.decode("ascii", errors="replace").split("\t")
        if len(fields) != len(FIELDS) or len(line) > 1024:
            skipped += 1
            continue
        try:
            number = int(fields[0])
            relative_ms = float(fields[1]) * 1000
            size = int(fields[2])
        except ValueError:
            skipped += 1
            continue
        protocols = fields[3].split(":") if fields[3] else []
        if (
            not last_number < number <= MAX_FRAMES + 1
            or not math.isfinite(relative_ms)
            or abs(relative_ms) > 1e15
            or not 0 <= size <= 2**32 - 1
            or len(protocols) > 40
            or not all(_PROTOCOL.fullmatch(p) for p in protocols)
        ):
            skipped += 1
            continue
        last_number = number
        frames.append({"packet_number": number, "relative_ms": relative_ms, "wire_bytes": size, "protocols": protocols})
    return {
        "kind": "tshark-frames", "status": "partial" if limited or skipped else "complete",
        "frames": frames, "skipped_rows": skipped, "partial": bool(skipped or limited), "limit": limit,
    }


def get_tshark_path(executable=None):
    if executable:
        path = Path(executable)
        if not path.is_absolute():
            raise ValueError("Choose the absolute path of a local TShark executable.")
    else:
        found = shutil.which("tshark")
        if not found and os.name == "nt":
            found = next((
                candidate for folder in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"))
                if folder and (candidate := Path(folder, "Wireshark", "tshark.exe")).is_file()
            ), None)
        if not found:
            raise ValueError("TShark was not found. Select an already available local executable.")
        path = Path(found)
    names = ("tshark.exe",) if os.name == "nt" else ("tshark",)
    if path.name.lower() not in names or not path.is_file():
        raise ValueError("Choose a local TShark executable.")
    return path.resolve()


def dissect_capture(capture_path, *, executable=None, limit=MAX_FRAMES, cancel=None):
    """Use the selected local decoder on a bounded private copy of a capture."""
    if type(limit) is not int or not 1 <= limit <= MAX_FRAMES:
        raise ValueError("Frame limit must be between 1 and 2000.")
    capture = Path(capture_path)
    if not capture.is_file():
        raise ValueError("Select an existing capture file.")
    if cancel is not None and cancel.is_set():
        return dict(decode_fields(b"", limit), status="cancelled", partial=True)
    data = read_bounded(capture)
    if data[:4] not in _CAPTURE_MAGIC:
        raise ValueError("Select a classic PCAP or PCAPNG file.")
    program = get_tshark_path(executable)
    with tempfile.TemporaryDirectory(prefix="wifiscope-dissect-") as directory:
        source = Path(directory, "capture.pcap")
        source.write_bytes(data)
        # Limit intermediate growth and keep third-party error text out of the report.
        with tempfile.TemporaryFile() as output:
            command = [str(program), "-n", "-r", str(source), "-c", str(limit + 1), "-T", "fields"]
            for field in FIELDS:
                command.extend(("-e", field))
            with subprocess.Popen(
                command, stdout=output, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                cwd=directory, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ) as process:
                stop_reason = None
                deadline = time.monotonic() + TIMEOUT
                try:
                    while process.poll() is None:
                        if cancel is not None and cancel.is_set():
                            stop_reason = "cancelled"
                        elif time.monotonic() >= deadline:
                            stop_reason = "timeout"
                        elif os.fstat(output.fileno()).st_size > MAX_OUTPUT:
                            stop_reason = "output-limit"
                        if stop_reason:
                            break
                        time.sleep(0.04)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                if process.returncode and stop_reason is None:
                    raise ValueError("TShark could not decode this capture; check the selected executable and file.")
            output.seek(0)
            body = output.read(MAX_OUTPUT + 1)
    if len(body) > MAX_OUTPUT:
        stop_reason = stop_reason or "output-limit"
        body = body[:MAX_OUTPUT].rpartition(b"\n")[0]
    result = decode_fields(body, limit)
    if stop_reason:
        result.update(status="cancelled" if stop_reason == "cancelled" else "partial",
                      partial=True, stop_reason=stop_reason)
    return result



def open_in_wireshark(capture_path, executable):
    """Open a user-selected local capture in the explicit Wireshark GUI."""
    capture = Path(capture_path).resolve()
    app = Path(executable)
    names = ("wireshark.exe",) if os.name == "nt" else ("wireshark",)
    if not app.is_absolute() or app.name.lower() not in names or not app.is_file():
        raise ValueError("请选择本机 Wireshark 可执行文件。")
    if not capture.is_file():
        raise ValueError("请选择已有抓包文件。")
    with capture.open("rb") as stream:
        if stream.read(4) not in _CAPTURE_MAGIC:
            raise ValueError("请选择 PCAP 或 PCAPNG 抓包文件。")
    subprocess.Popen([str(app.resolve()), "-n", "-r", str(capture)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
