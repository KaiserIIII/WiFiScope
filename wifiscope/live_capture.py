"""Bounded read-only live capture, final metadata analysis and explicit retention."""

from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import struct
import time
import uuid

from .pcap_native import CaptureError, SUPPORTED_LINKS, default_backend

MAX_STORAGE_BYTES = 16 * 1024 * 1024
_monotonic = time.monotonic
_sleep = time.sleep
_default_backend = default_backend


def _catalog(backend):
    rows = backend.enumerate()
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError("Capture interface enumeration exceeds its bounded catalog.")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid capture interface catalog.")
        name = row.get("interface")
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 1024
            or name == "any"
            or "://" in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or name in seen
            or row.get("backend") != backend.name
            or any(
                type(row.get(key)) is not bool
                for key in ("loopback", "supports_filter", "supports_promiscuous")
            )
            or not isinstance(row.get("label"), str)
            or len(row["label"]) > 1024
        ):
            raise ValueError("Invalid concrete capture interface catalog.")
        seen.add(name)
    return rows


def list_capture_interfaces() -> list[dict]:
    """Read-only local operational labels; report exports pseudonymize identities."""
    return [
        {
            key: row.get(key)
            for key in (
                "interface",
                "label",
                "backend",
                "linktype",
                "loopback",
                "supports_filter",
                "supports_promiscuous",
            )
        }
        for row in _catalog(_default_backend())
    ]


def _validate(
    interface,
    duration,
    max_packets,
    max_bytes,
    snaplen,
    authorized,
    promiscuous,
    packet_filter,
    cancel,
    raw_path,
    retain_packets,
    progress,
):
    if authorized is not True:
        raise ValueError(
            "Live capture requires explicit authorization for the selected interface."
        )
    if (
        not isinstance(interface, str)
        or not interface.strip()
        or len(interface) > 1024
        or interface == "any"
    ):
        raise ValueError("Select one explicit currently listed capture interface.")
    if (
        type(duration) not in (int, float)
        or not 0.2 <= duration <= 120
        or not math.isfinite(duration)
    ):
        raise ValueError(
            "Capture duration must be a finite number in 0.2..120 seconds."
        )
    for value, low, high, name in (
        (max_packets, 1, 20000, "packets"),
        (max_bytes, 4096, 16777216, "bytes"),
        (snaplen, 64, 65535, "snaplen"),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(
                "Capture "
                + name
                + " must be an integer in "
                + str(low)
                + ".."
                + str(high)
                + "."
            )
    if any(
        type(value) is not bool for value in (authorized, promiscuous, retain_packets)
    ):
        raise ValueError(
            "Capture authorization, promiscuous and retention options must be booleans."
        )
    if (snaplen > 96 or raw_path is not None) and not retain_packets:
        raise ValueError(
            "Larger snapshots or raw output require the separate retain-packets opt-in."
        )
    if (
        not isinstance(packet_filter, str)
        or len(packet_filter) > 512
        or any(not 32 <= ord(c) <= 126 for c in packet_filter)
    ):
        raise ValueError(
            "Capture filter must contain at most 512 printable ASCII bytes."
        )
    if (
        cancel is not None
        and not callable(cancel)
        and not callable(getattr(cancel, "is_set", None))
    ):
        raise ValueError("Capture cancellation must be a local callable or event.")
    if progress is not None and not callable(progress):
        raise ValueError("Capture progress must be a local callable.")
    if raw_path is not None:
        if (
            not isinstance(raw_path, (str, Path))
            or not str(raw_path).strip()
            or Path(raw_path).name in ("", ".", "..")
        ):
            raise ValueError("Raw retention requires an explicitly named new file.")
        if Path(raw_path).exists() or Path(raw_path).is_symlink():
            raise ValueError(
                "Raw retention requires a new exclusive file; existing paths are refused."
            )
        if not Path(raw_path).parent.is_dir():
            raise ValueError("Raw retention requires an existing parent directory.")


def _analyze(data, offsets, session):
    """Analyze once normally; on aggregate excess find a valid bounded prefix.

    The strict offline parser remains strict. Final-only logarithmic fallback
    also respects investigation's lower asset/JSON-element budgets.
    """
    from .packets import analyze_capture
    from .investigate import build_investigation, _check_budget

    digest = hashlib.sha256(data).hexdigest()
    session["source_sha256"] = digest

    def analyze(count):
        report = analyze_capture(bytes(data[: offsets[count]]))
        report["packet_analysis"].update(source="measured", source_sha256=digest)
        report["sources"][0].update(type="measured", sha256=digest, imported_at=None)
        report["collected_at"] = session["started_at"]
        report["capture_session"] = dict(
            session, analyzed_packets=count, analysis_limited=count < session["packets"]
        )
        if count < session["packets"]:
            report["gaps"].append("capture-analysis-limit")
        model = build_investigation(report)
        _check_budget(model)
        return model

    try:
        report = analyze(len(offsets) - 1)
    except ValueError as error:
        if not any(
            word in str(error)
            for word in (
                "aggregate limit",
                "4096 assets",
                "element budget",
                "16 MiB",
                "observation/result",
            )
        ):
            raise
        low, high = 0, len(offsets) - 1
        report = analyze(0)
        while low < high:
            middle = (low + high + 1) // 2
            try:
                candidate = analyze(middle)
            except ValueError:
                high = middle - 1
            else:
                low, report = middle, candidate
    return report


def capture_live(
    interface: str,
    *,
    duration=10,
    max_packets=2000,
    max_bytes=8388608,
    snaplen=96,
    authorized=False,
    promiscuous=False,
    packet_filter="",
    cancel=None,
    raw_path=None,
    retain_packets=False,
    backend=None,
    progress=None,
) -> dict:
    """Capture from one explicitly chosen local interface; never transmit packets.

    max_bytes limits frame-prefix bytes. An independent 16 MiB total PCAP cap
    includes the global and per-frame headers. Progress is metadata-only <=5 Hz
    plus final; callback failure stops with partial evidence and no traceback.
    """
    _validate(
        interface,
        duration,
        max_packets,
        max_bytes,
        snaplen,
        authorized,
        promiscuous,
        packet_filter,
        cancel,
        raw_path,
        retain_packets,
        progress,
    )
    adapter = backend if backend is not None else _default_backend()
    rows = _catalog(adapter)
    selected = next((row for row in rows if row["interface"] == interface), None)
    if selected is None:
        raise ValueError("Select one explicit currently listed capture interface.")
    if packet_filter and not selected["supports_filter"]:
        raise ValueError(
            "This backend requires installed libpcap for BPF filters; no capture was started."
        )
    if promiscuous and not selected["supports_promiscuous"]:
        raise ValueError(
            "This backend does not support promiscuous capture; select installed libpcap."
        )
    start = _monotonic()
    started = datetime.now(timezone.utc).isoformat()
    session = dict(
        schema_version=1,
        id="capture-" + uuid.uuid4().hex,
        interface=interface,
        backend=adapter.name,
        source_sha256="pending",
        source="measured",
        timestamp_source="native-unspecified",
        started_at=started,
        ended_at=started,
        duration_ms=0,
        status="complete",
        stop_reason="duration",
        packets=0,
        analyzed_packets=0,
        captured_bytes=0,
        wire_bytes=0,
        storage_bytes=24,
        raw_packets=0,
        raw_retained=False,
        retain_packets=retain_packets,
        promiscuous=promiscuous,
        filter_applied=False,
        filter_requested=bool(packet_filter),
        linktype=1,
        partial=True,
        analysis_limited=False,
        limits=dict(
            duration_seconds=duration,
            max_packets=max_packets,
            max_bytes=max_bytes,
            snaplen=snaplen,
            max_storage_bytes=MAX_STORAGE_BYTES,
        ),
        pcap_stats=dict(received=None, dropped=None, interface_dropped=None),
    )
    handle = None
    stream = None
    raw_end = 24
    data = bytearray()
    offsets = [24]
    last_progress = start - 0.2
    callback = progress

    def notify(final=False):
        nonlocal last_progress, callback
        now = _monotonic()
        if callback is not None and (final or now - last_progress >= 0.2 - 1e-9):
            last_progress = now
            try:
                callback(
                    dict(
                        packets=session["packets"],
                        captured_bytes=session["captured_bytes"],
                        elapsed_ms=max(0, round((now - start) * 1000)),
                        status=session["status"] if final else "running",
                    )
                )
            except Exception:
                callback = None
                session.update(status="partial", stop_reason="progress-error")
                return False
        return True

    try:
        handle = adapter.open(
            interface,
            snaplen=snaplen,
            promiscuous=promiscuous,
            packet_filter=packet_filter,
        )
        if handle.linktype not in SUPPORTED_LINKS:
            raise CaptureError("unsupported-link")
        if bool(handle.filter_applied) != bool(packet_filter):
            raise CaptureError("filter-error")
        session.update(
            linktype=handle.linktype,
            timestamp_source=handle.timestamp_source,
            filter_applied=bool(handle.filter_applied),
        )
        data.extend(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, handle.linktype)
        )
        if raw_path is not None:
            # Exclusive creation is also enforced at the actual write boundary.
            try:
                stream = Path(raw_path).open("xb", buffering=0)
                if stream.write(data) != len(data):
                    raise OSError("short capture header write")
                session["raw_retained"] = True
            except OSError:
                raise ValueError(
                    "Cannot create new exclusive raw capture; check the new filename and permissions."
                ) from None
        while True:
            if not notify():
                break
            if cancel is not None and (
                cancel() if callable(cancel) else cancel.is_set()
            ):
                session.update(status="cancelled", stop_reason="cancelled")
                break
            if _monotonic() >= start + duration:
                session["stop_reason"] = "duration"
                break
            if session["packets"] >= max_packets:
                session["stop_reason"] = "packet-limit"
                break
            remaining_payload = max_bytes - session["captured_bytes"]
            remaining_storage = MAX_STORAGE_BYTES - len(data) - 16
            if remaining_payload <= 0 or remaining_storage < 0:
                session["stop_reason"] = (
                    "byte-limit" if remaining_payload <= 0 else "storage-limit"
                )
                break
            try:
                status, item = handle.read(min(remaining_payload, remaining_storage))
            except CaptureError as error:
                reason = (
                    "storage-limit"
                    if error.code == "byte-limit"
                    and remaining_storage < remaining_payload
                    else error.code
                )
                session.update(
                    status="complete"
                    if reason in ("byte-limit", "storage-limit")
                    else "partial",
                    stop_reason=reason
                    if reason in ("byte-limit", "storage-limit", "invalid-packet")
                    else "native-error",
                )
                break
            if status == 0:
                _sleep(min(0.02, max(0, start + duration - _monotonic())))
                continue
            if status == -2:
                session["stop_reason"] = "eof"
                break
            if status != 1 or not isinstance(item, tuple) or len(item) != 4:
                session.update(status="partial", stop_reason="native-error")
                break
            sec, usec, frame, wirelen = item
            if (
                type(sec) is not int
                or not 0 <= sec <= 0xFFFFFFFF
                or type(usec) is not int
                or not 0 <= usec < 1000000
                or not isinstance(frame, bytes)
                or len(frame) > snaplen
                or type(wirelen) is not int
                or not len(frame) <= wirelen <= 0xFFFFFFFF
            ):
                session.update(status="partial", stop_reason="invalid-packet")
                break
            if len(frame) > min(remaining_payload, remaining_storage):
                session["stop_reason"] = (
                    "byte-limit"
                    if remaining_payload <= remaining_storage
                    else "storage-limit"
                )
                break
            record = struct.pack("<IIII", sec, usec, len(frame), wirelen) + frame
            data.extend(record)
            offsets.append(len(data))
            session["packets"] += 1
            session["captured_bytes"] += len(frame)
            session["wire_bytes"] += wirelen
            session["storage_bytes"] = len(data)
            if stream is not None:
                previous = len(data) - len(record)
                try:
                    if stream.write(record) != len(record):
                        raise OSError("short write")
                    session["raw_packets"] += 1
                    raw_end += len(record)
                except OSError:
                    # Keep the last fully committed PCAP record if storage permits.
                    try:
                        stream.truncate(previous)
                    except OSError:
                        session["raw_retained"] = False
                    session.update(status="partial", stop_reason="raw-write-error")
                    break
    except KeyboardInterrupt:
        if not data:
            raise
        session.update(status="cancelled", stop_reason="cancelled")
        if stream is not None and session["raw_retained"]:
            try:
                stream.truncate(raw_end)
            except OSError:
                session["raw_retained"] = False
    except CaptureError:
        if not data:
            raise
        session.update(status="partial", stop_reason="native-error")
    except OSError:
        if not data:
            raise CaptureError("open-error") from None
        session.update(status="partial", stop_reason="native-error")
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                session.update(status="partial", stop_reason="raw-write-error")
        if handle is not None:
            try:
                session["pcap_stats"] = handle.stats()
            except Exception:
                pass
            try:
                handle.close()
            except Exception:
                session.update(status="partial", stop_reason="close-error")
    session["ended_at"] = max(started, datetime.now(timezone.utc).isoformat())
    session["duration_ms"] = max(0, round((_monotonic() - start) * 1000))
    notify(final=True)
    report = _analyze(data, offsets, session)
    data.clear()
    return report
