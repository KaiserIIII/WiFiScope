"""Synthetic/fake-only capture boundaries; never open a physical interface."""

import contextlib
import ctypes as C
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_packets import ethernet, ipv4, tcp, pcap
from wifiscope import cli
from wifiscope.cases import CaseStore
from wifiscope.packets import analyze_capture
from wifiscope.reports import prepare_export, export_report


class Clock:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class FakeHandle:
    linktype = 1
    timestamp_source = "native-unspecified"
    filter_applied = False

    def __init__(self, packets=(), terminal=-2):
        self.packets = iter(packets)
        self.terminal = terminal
        self.closed = 0
        self.reads = 0

    def read(self, remaining):
        from wifiscope.pcap_native import CaptureError

        self.reads += 1
        item = next(self.packets, None)
        if isinstance(item, Exception):
            raise item
        if item is None:
            return self.terminal, None
        sec, usec, frame, wire = item
        if len(frame) > remaining:
            raise CaptureError("byte-limit")
        return 1, item

    def stats(self):
        return dict(received=15, dropped=2, interface_dropped=None)

    def close(self):
        self.closed += 1


class FakeBackend:
    name = "npcap"

    def __init__(self, packets=(), terminal=-2):
        self.handle = FakeHandle(packets, terminal)
        self.opens = []

    def enumerate(self):
        return [
            dict(
                interface="owned-test",
                label="Owned synthetic adapter",
                backend=self.name,
                linktype=None,
                loopback=True,
                supports_filter=True,
                supports_promiscuous=True,
            )
        ]

    def open(self, interface, *, snaplen, promiscuous, packet_filter):
        self.opens.append((interface, snaplen, promiscuous, packet_filter))
        self.handle.filter_applied = bool(packet_filter)
        return self.handle


def packet(frame=None, wire=None):
    frame = ethernet(ipv4(tcp())) if frame is None else frame
    return 1700000000, 123456, frame, len(frame) if wire is None else wire


class LiveTests(unittest.TestCase):
    def capture(self, backend=None, **kwargs):
        from wifiscope.live_capture import capture_live

        clock = Clock()
        with (
            patch("wifiscope.live_capture._monotonic", clock.now),
            patch("wifiscope.live_capture._sleep", clock.sleep),
        ):
            return capture_live(
                "owned-test",
                backend=backend or FakeBackend([packet()]),
                authorized=True,
                **kwargs,
            )

    def test_prevalidation_has_zero_open_or_file_side_effects(self):
        from wifiscope.live_capture import capture_live

        invalid = [
            dict(authorized=False),
            dict(duration=True),
            dict(duration=float("nan")),
            dict(duration=float("inf")),
            dict(duration=0.19),
            dict(duration=121),
            dict(max_packets=0),
            dict(max_packets=True),
            dict(max_packets=20001),
            dict(max_bytes=4095),
            dict(max_bytes=16777217),
            dict(max_bytes=8192.0),
            dict(snaplen=63),
            dict(snaplen=65536),
            dict(snaplen=97),
            dict(promiscuous=1),
            dict(retain_packets=1),
            dict(packet_filter="x\n"),
            dict(packet_filter="é"),
            dict(packet_filter="x" * 513),
            dict(packet_filter="a\0b"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for options in invalid:
                adapter = FakeBackend()
                options = (
                    dict(
                        authorized=True,
                        raw_path=Path(directory) / "new.pcap",
                        retain_packets=True,
                    )
                    | options
                )
                # The distinct snapshot opt-in case must be tested without the baseline opt-in.
                if options.get("snaplen") == 97:
                    options["retain_packets"] = False
                with self.subTest(options=options), self.assertRaises(ValueError):
                    capture_live("owned-test", backend=adapter, **options)
                self.assertEqual(adapter.opens, [])
                self.assertEqual(list(Path(directory).iterdir()), [])
            adapter = FakeBackend()
            for interface in ("", "any", "unknown", None):
                with self.assertRaises(ValueError):
                    capture_live(interface, authorized=True, backend=adapter)
            self.assertEqual(adapter.opens, [])

    def test_limits_real_counts_stats_and_no_default_retention(self):
        backend = FakeBackend([packet(wire=200)] * 5)
        report = self.capture(backend, max_packets=2)
        session = report["capture_session"]
        self.assertEqual(
            (session["packets"], session["captured_bytes"], session["wire_bytes"]),
            (2, 108, 400),
        )
        self.assertEqual(
            (session["status"], session["stop_reason"]), ("complete", "packet-limit")
        )
        self.assertEqual(
            session["pcap_stats"], dict(received=15, dropped=2, interface_dropped=None)
        )
        self.assertFalse(session["raw_retained"])
        self.assertEqual(session["storage_bytes"], 164)
        self.assertEqual(backend.opens, [("owned-test", 96, False, "")])
        self.assertEqual((backend.handle.reads, backend.handle.closed), (2, 1))
        self.assertEqual(report["packet_analysis"]["packets"], 2)
        self.assertEqual(report["packet_analysis"]["endpoints"][0]["bytes"], 108)
        coverage = next(
            c
            for c in report["investigation"]["coverage"]
            if c["category"] == "live-capture"
        )
        self.assertEqual((coverage["status"], coverage["evaluated"]), ("observed", 2))
        self.assertTrue(coverage["partial"])

    def test_idle_deadline_cancel_and_progress_throttle(self):
        backend = FakeBackend(terminal=0)
        events = []
        report = self.capture(
            backend, duration=1.05, progress=lambda row: events.append(row)
        )
        self.assertEqual(report["capture_session"]["stop_reason"], "duration")
        self.assertLess(backend.handle.reads, 100)
        self.assertTrue(4 <= len(events) <= 7)
        for row in events:
            self.assertEqual(
                set(row), {"packets", "captured_bytes", "elapsed_ms", "status"}
            )
        for a, b in zip(events[:-2], events[1:-1]):
            self.assertGreaterEqual(b["elapsed_ms"] - a["elapsed_ms"], 200)
        self.assertEqual(events[-1]["status"], "complete")
        backend = FakeBackend([packet()], terminal=0)
        report = self.capture(backend, cancel=lambda: backend.handle.reads >= 2)
        self.assertEqual(
            (report["capture_session"]["status"], report["capture_session"]["packets"]),
            ("cancelled", 1),
        )
        self.assertEqual(backend.handle.closed, 1)

    def test_progress_failure_and_native_failure_preserve_partial(self):
        from wifiscope.pcap_native import CaptureError

        for failure, reason in (
            (CaptureError("native-error"), "native-error"),
            (CaptureError("invalid-packet"), "invalid-packet"),
        ):
            backend = FakeBackend([packet(), failure])
            report = self.capture(backend)
            self.assertEqual(
                (
                    report["capture_session"]["status"],
                    report["capture_session"]["stop_reason"],
                ),
                ("partial", reason),
            )
            self.assertEqual(report["packet_analysis"]["packets"], 1)
            self.assertEqual(backend.handle.closed, 1)

        def fail(row):
            if row["status"] == "complete":
                raise RuntimeError("PRIVATE EXCEPTION")

        backend = FakeBackend([packet()])
        report = self.capture(backend, progress=fail)
        self.assertEqual(report["capture_session"]["stop_reason"], "progress-error")
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertEqual(backend.handle.closed, 1)

    def test_raw_exclusive_cancel_and_byte_envelope_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "retained.pcap"
            backend = FakeBackend([packet()], terminal=0)
            report = self.capture(
                backend,
                raw_path=raw,
                retain_packets=True,
                cancel=lambda: backend.handle.reads > 1,
            )
            self.assertTrue(report["capture_session"]["raw_retained"])
            self.assertEqual(
                analyze_capture(raw.read_bytes())["packet_analysis"]["packets"], 1
            )
            self.assertEqual(report["capture_session"]["status"], "cancelled")
            backend = FakeBackend()
            with self.assertRaises(ValueError):
                self.capture(backend, raw_path=raw, retain_packets=True)
            self.assertEqual(backend.opens, [])
            self.assertNotIn(str(raw), json.dumps(report))
        backend = FakeBackend([packet(b"x" * 96)] * 100)
        report = self.capture(backend, max_bytes=4096)
        self.assertEqual(
            (
                report["capture_session"]["packets"],
                report["capture_session"]["stop_reason"],
            ),
            (42, "byte-limit"),
        )
        with patch("wifiscope.live_capture.MAX_STORAGE_BYTES", 200):
            report = self.capture(FakeBackend([packet()] * 10))
        self.assertEqual(
            (
                report["capture_session"]["packets"],
                report["capture_session"]["stop_reason"],
            ),
            (2, "storage-limit"),
        )
        self.assertLessEqual(report["capture_session"]["storage_bytes"], 200)

    def test_aggregate_limit_keeps_valid_prefix_and_original_source(self):
        frames = [
            packet(ethernet(ipv4(tcp(), src=src)))
            for src in ("192.0.2.1", "192.0.2.3", "192.0.2.4")
        ]
        with patch.dict("wifiscope.packets.CAPS", {"endpoints": 2}):
            report = self.capture(FakeBackend(frames))
        session = report["capture_session"]
        self.assertEqual((session["packets"], session["analyzed_packets"]), (3, 1))
        self.assertEqual(report["packet_analysis"]["packets"], 1)
        self.assertIn("capture-analysis-limit", report["gaps"])
        self.assertEqual(
            session["source_sha256"], report["packet_analysis"]["source_sha256"]
        )
        self.assertEqual(report["sources"][0]["type"], "measured")
        self.assertTrue(session["partial"])

    def test_link_formats_keep_true_frame_and_wire_lengths(self):
        ip = ipv4(tcp())
        variants = [
            (0, struct.pack("<I", 2) + ip),
            (0, struct.pack(">I", 2) + ip),
            (101, ip),
            (113, struct.pack("!HHH8sH", 0, 1, 6, b"\0" * 8, 0x800) + ip),
            (276, struct.pack("!HHIHBB8s", 0x800, 0, 1, 1, 0, 6, b"\0" * 8) + ip),
        ]
        for link, frame in variants:
            with self.subTest(link=link):
                backend = FakeBackend([packet(frame, wire=120)])
                backend.handle.linktype = link
                report = self.capture(backend)
                summary = report["packet_analysis"]
                self.assertEqual(summary["protocol_counts"]["tcp"], 1)
                self.assertEqual(summary["captured_bytes"], len(frame))
                self.assertEqual(summary["wire_bytes"], 120)
                self.assertEqual(summary["endpoints"][0]["bytes"], len(frame))
                self.assertNotIn("packet-linktype-unsupported", report["gaps"])

    def test_privacy_cases_reexport_and_audit_preservation(self):
        from wifiscope.investigate import merge_reports
        from wifiscope.vulnerabilities import audit_vulnerabilities

        report = audit_vulnerabilities(
            self.capture(
                FakeBackend([packet(ethernet(ipv4(tcp(b"GET /PRIVATE HTTP/1.1\r\n"))))])
            )
        )
        report["capture_session"]["private_note"] = "SECRET_PATH"
        prepared = prepare_export(report)
        session = prepared["capture_session"]
        self.assertEqual(
            session["source_sha256"], prepared["packet_analysis"]["source_sha256"]
        )
        for marker in ("owned-test", "192.0.2.1", "PRIVATE", "SECRET_PATH"):
            self.assertNotIn(marker, json.dumps(prepared))
        self.assertEqual(
            prepared["investigation"]["findings"][0]["category"], "live-capture"
        )
        with self.assertRaises(ValueError):
            merge_reports([report, report])
        with tempfile.TemporaryDirectory() as directory:
            with CaseStore(Path(directory) / "case.db") as store:
                sid = store.add_snapshot(report)
                reopened = store.load_snapshot(sid)
            self.assertIn("capture_session", prepare_export(reopened, True))
            self.assertIn("vulnerability_audit", reopened)
            paths = export_report(report, Path(directory) / "bundle")
            for path in paths.values():
                text = Path(path).read_text(encoding="utf-8-sig")
                for marker in ("owned-test", "PRIVATE", "SECRET_PATH"):
                    self.assertNotIn(marker, text)
        bad = dict(
            report, capture_session=dict(report["capture_session"], packets=True)
        )
        with self.assertRaises(ValueError):
            prepare_export(bad)

    def test_cli_list_capture_errors_and_cancel_exit(self):
        backend = FakeBackend([packet()])
        output = io.StringIO()
        with (
            patch("wifiscope.live_capture._default_backend", return_value=backend),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["capture", "--list-interfaces"]), 0)
        self.assertIn("owned-test", output.getvalue())
        self.assertEqual(backend.opens, [])
        output = io.StringIO()
        with (
            patch("wifiscope.live_capture._default_backend", return_value=backend),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                cli.main(["capture", "--interface", "owned-test", "--authorized"]), 0
            )
        self.assertNotIn("owned-test", output.getvalue())
        self.assertIn("capture_session", json.loads(output.getvalue()))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["capture", "--interface", "owned-test"]), 2)
        backend = FakeBackend([KeyboardInterrupt()])
        # KeyboardInterrupt is deliberately handled by engine after opening.
        backend.handle.read = lambda remaining: (_ for _ in ()).throw(
            KeyboardInterrupt()
        )
        with (
            patch("wifiscope.live_capture._default_backend", return_value=backend),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cli.main(["capture", "--interface", "owned-test", "--authorized"]), 130
            )
        self.assertEqual(backend.handle.closed, 1)


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class NativeLibrary:
    def __init__(self):
        from wifiscope.pcap_native import header_type, PcapDevice

        self.header = header_type("Windows")()
        self.frame = C.create_string_buffer(ethernet(ipv4(tcp())))
        self.header.ts.tv_sec = 1700000000
        self.header.ts.tv_usec = 123456
        self.header.caplen = 54
        self.header.len = 200
        self.device = PcapDevice()
        self.name = C.create_string_buffer(b"owned-test")
        self.label = C.create_string_buffer(b"Owned test")
        self.device.name = C.cast(self.name, C.c_void_p)
        self.device.description = C.cast(self.label, C.c_void_p)
        self.closed = self.freed = self.freefilters = self.reads = 0
        self.status = 1
        self.fail = ""
        for name in (
            "pcap_findalldevs",
            "pcap_freealldevs",
            "pcap_open_live",
            "pcap_datalink",
            "pcap_setnonblock",
            "pcap_next_ex",
            "pcap_compile",
            "pcap_setfilter",
            "pcap_freecode",
            "pcap_stats",
            "pcap_close",
        ):
            setattr(self, name, Function(getattr(self, "_" + name)))

    def _pcap_findalldevs(self, out, error):
        from wifiscope.pcap_native import PcapDevice

        C.cast(out, C.POINTER(C.POINTER(PcapDevice)))[0] = C.pointer(self.device)
        return 0

    def _pcap_freealldevs(self, devices):
        self.freed += 1

    def _pcap_open_live(self, *args):
        return None if self.fail == "open" else 1234

    def _pcap_datalink(self, handle):
        return 12

    def _pcap_setnonblock(self, *args):
        return -1 if self.fail == "nonblock" else 0

    def _pcap_next_ex(self, handle, header, data):
        from wifiscope.pcap_native import header_type

        self.reads += 1
        Header = header_type("Windows")
        C.cast(header, C.POINTER(C.POINTER(Header)))[0] = C.cast(
            C.pointer(self.header), C.POINTER(Header)
        )
        C.cast(data, C.POINTER(C.c_void_p))[0] = C.cast(self.frame, C.c_void_p)
        return self.status

    def _pcap_compile(self, *args):
        return -1 if self.fail == "compile" else 0

    def _pcap_setfilter(self, *args):
        return -1 if self.fail == "filter" else 0

    def _pcap_freecode(self, *args):
        self.freefilters += 1

    def _pcap_stats(self, handle, stats):
        # Npcap writes its Windows tail too. Must fit even in Linux test runners.
        values = C.cast(stats, C.POINTER(C.c_uint32))
        for index, value in enumerate((20, 3, 0, 7)):
            values[index] = value
        return -1 if self.fail == "stats" else 0

    def _pcap_close(self, handle):
        self.closed += 1


class NativeTests(unittest.TestCase):
    def adapter(self):
        from wifiscope.pcap_native import PcapBackend

        library = NativeLibrary()
        return library, PcapBackend(library=library, platform="Windows")

    def test_cabi_header_filter_stats_and_cleanup(self):
        from wifiscope.pcap_native import PcapHeader, PcapStats, Timeval, timeval_type

        self.assertEqual(C.sizeof(timeval_type("Windows")), 8)
        self.assertEqual(C.sizeof(Timeval), 2 * C.sizeof(C.c_long))
        self.assertGreaterEqual(C.sizeof(PcapStats), 16)
        self.assertGreaterEqual(C.sizeof(PcapHeader), 16)
        lib, backend = self.adapter()
        self.assertEqual(backend.enumerate()[0]["interface"], "owned-test")
        self.assertEqual(lib.freed, 1)
        handle = backend.open(
            "owned-test", snaplen=96, promiscuous=False, packet_filter="tcp"
        )
        self.assertEqual(handle.linktype, 101)
        self.assertTrue(handle.filter_applied)
        self.assertEqual(handle.read(96)[1][2], bytes(lib.frame.raw[:54]))
        self.assertEqual(
            handle.stats(), dict(received=20, dropped=3, interface_dropped=None)
        )
        handle.close()
        handle.close()
        self.assertEqual((lib.closed, lib.freefilters), (1, 1))
        self.assertIsNotNone(lib.pcap_next_ex.argtypes)
        self.assertEqual(lib.pcap_open_live.restype, C.c_void_p)

    def test_native_lengths_rejected_before_copy_and_statuses_distinct(self):
        from wifiscope.pcap_native import CaptureError

        lib, backend = self.adapter()
        handle = backend.open(
            "owned-test", snaplen=96, promiscuous=False, packet_filter=""
        )
        for caplen, wire, usec, remaining, code in (
            (97, 200, 0, 96, "invalid-packet"),
            (54, 50, 0, 96, "invalid-packet"),
            (54, 200, 1000000, 96, "invalid-packet"),
            (54, 200, 0, 53, "byte-limit"),
        ):
            lib.header.caplen, lib.header.len, lib.header.ts.tv_usec = (
                caplen,
                wire,
                usec,
            )
            with patch(
                "wifiscope.pcap_native.C.string_at",
                side_effect=AssertionError("copied before bounds"),
            ):
                with self.assertRaises(CaptureError) as error:
                    handle.read(remaining)
            self.assertEqual(error.exception.code, code)
        for status in (0, -1, -2, 99):
            lib.status = status
            if status in (0, -2):
                self.assertEqual(handle.read(96), (status, None))
            else:
                with self.assertRaises(CaptureError):
                    handle.read(96)
        handle.close()

    def test_enumeration_cycle_and_open_filter_failure_release_resources(self):
        from wifiscope.pcap_native import CaptureError

        lib, backend = self.adapter()
        lib.device.next = C.pointer(lib.device)
        with self.assertRaises(CaptureError):
            backend.enumerate()
        self.assertEqual(lib.freed, 1)
        for failure in ("nonblock", "compile", "filter"):
            lib, backend = self.adapter()
            lib.fail = failure
            with self.assertRaises(CaptureError):
                backend.open(
                    "owned-test", snaplen=96, promiscuous=False, packet_filter="tcp"
                )
            self.assertEqual(lib.closed, 1)
            self.assertEqual(lib.freefilters, 1 if failure == "filter" else 0)


class EdgeTests(unittest.TestCase):
    capture = LiveTests.capture

    def test_catalog_invalid_and_unsupported_options_refuse_before_open(self):
        from wifiscope.live_capture import capture_live

        backend = FakeBackend()
        good = backend.enumerate()
        for rows in (
            [good[0]] * 257,
            [good[0], good[0]],
            [dict(good[0], interface="any")],
            [dict(good[0], label="x" * 1025)],
        ):
            with (
                patch.object(backend, "enumerate", return_value=rows),
                self.assertRaises(ValueError),
            ):
                capture_live("owned-test", authorized=True, backend=backend)
        row = dict(good[0], supports_filter=False, supports_promiscuous=False)
        for opts in (dict(packet_filter="tcp"), dict(promiscuous=True)):
            with (
                patch.object(backend, "enumerate", return_value=[row]),
                self.assertRaises(ValueError),
            ):
                capture_live("owned-test", authorized=True, backend=backend, **opts)
        self.assertEqual(backend.opens, [])

    def test_partial_native_and_raw_write_failures_keep_metadata_and_valid_file(self):
        from wifiscope.pcap_native import CaptureError

        for failure in (CaptureError("native-error"), OSError("PRIVATE_NATIVE")):
            report = self.capture(FakeBackend([packet(), failure]))
            self.assertEqual(
                (
                    report["capture_session"]["packets"],
                    report["capture_session"]["status"],
                ),
                (1, "partial"),
            )
            self.assertNotIn("PRIVATE_NATIVE", json.dumps(report))
        backend = FakeBackend([packet(), packet()])

        class FailingWriter(io.BytesIO):
            def write(self, value):
                if self.tell() > 24:
                    super().write(value[:3])
                    raise OSError("PRIVATE_DISK")
                return super().write(value)

            def close(self):
                self.snapshot = self.getvalue()
                super().close()

        writer = FailingWriter()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.open", return_value=writer),
        ):
            report = self.capture(
                backend, raw_path=Path(directory) / "new.pcap", retain_packets=True
            )
        self.assertEqual(report["capture_session"]["stop_reason"], "raw-write-error")
        self.assertEqual(
            (
                report["capture_session"]["packets"],
                report["capture_session"]["raw_packets"],
            ),
            (2, 1),
        )
        self.assertEqual(
            analyze_capture(writer.snapshot)["packet_analysis"]["packets"], 1
        )
        self.assertEqual(backend.handle.closed, 1)

    def test_cli_invalid_output_and_listing_options_never_capture(self):
        backend = FakeBackend([packet()])
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("wifiscope.live_capture._default_backend", return_value=backend),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    cli.main(
                        [
                            "capture",
                            "--interface",
                            "owned-test",
                            "--authorized",
                            "--out",
                            directory,
                        ]
                    ),
                    2,
                )
            self.assertEqual(backend.opens, [])
        with (
            patch("wifiscope.live_capture._default_backend", return_value=backend),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                cli.main(["capture", "--list-interfaces", "--duration", "nan"]), 2
            )

    def test_progress_initial_failure_closes_and_preserves_empty_metadata(self):
        def fail(row):
            raise RuntimeError("PRIVATE_CALLBACK")

        backend = FakeBackend([packet()])
        report = self.capture(backend, progress=fail)
        self.assertEqual(
            (
                report["capture_session"]["packets"],
                report["capture_session"]["stop_reason"],
            ),
            (0, "progress-error"),
        )
        self.assertEqual((backend.handle.reads, backend.handle.closed), (0, 1))

    def test_malformed_adapter_frames_do_not_enter_parser(self):
        for row in (
            (1, 0, b"x" * 97, 200),
            (1, 1000000, b"x", 1),
            (1, 0, b"x", 0),
            (True, 0, b"x", 1),
        ):
            backend = FakeBackend()
            backend.handle.read = lambda remaining: (1, row)
            report = self.capture(backend)
            self.assertEqual(
                (
                    report["capture_session"]["packets"],
                    report["capture_session"]["stop_reason"],
                ),
                (0, "invalid-packet"),
            )

    def test_model_aggregate_limit_preserves_prefix_before_derived_budget(self):
        import wifiscope.investigate as investigation

        actual = investigation._check_budget

        def smaller(report):
            # Reduced budget applies to derived investigation rows too.
            if len(report.get("investigation", {}).get("assets", [])) > 2:
                raise ValueError("Report nesting or element budget exceeded.")
            return actual(report)

        frames = [
            packet(ethernet(ipv4(tcp(), src=src)))
            for src in ("192.0.2.1", "192.0.2.3", "192.0.2.4")
        ]
        with patch.object(investigation, "_check_budget", side_effect=smaller):
            report = self.capture(FakeBackend(frames))
        self.assertLess(report["capture_session"]["analyzed_packets"], 3)
        self.assertIn("capture-analysis-limit", report["gaps"])


class NativeEdges(unittest.TestCase):
    adapter = NativeTests.adapter

    def test_null_native_pointers_rejected_and_stats_unavailable_unknown(self):
        from wifiscope.pcap_native import CaptureError

        lib, backend = self.adapter()
        handle = backend.open(
            "owned-test", snaplen=96, promiscuous=False, packet_filter=""
        )
        for missing in ("header", "data"):

            def read(pointer, header, data):
                if missing != "header":
                    C.cast(header, C.POINTER(C.c_void_p))[0] = C.cast(
                        C.pointer(lib.header), C.c_void_p
                    )
                if missing != "data":
                    C.cast(data, C.POINTER(C.c_void_p))[0] = C.cast(
                        lib.frame, C.c_void_p
                    )
                return 1

            lib.pcap_next_ex.callback = read
            with self.assertRaises(CaptureError):
                handle.read(96)
        lib.fail = "stats"
        self.assertEqual(
            handle.stats(), dict(received=None, dropped=None, interface_dropped=None)
        )
        handle.close()

    def test_native_enumeration_strings_counts_and_error_cleanup(self):
        from wifiscope.pcap_native import CaptureError, PcapDevice

        for text in (b"x" * 1025, b"bad\nname"):
            lib, backend = self.adapter()
            lib.name = C.create_string_buffer(text)
            lib.device.name = C.cast(lib.name, C.c_void_p)
            with self.assertRaises(CaptureError):
                backend.enumerate()
            self.assertEqual(lib.freed, 1)
        lib, backend = self.adapter()
        devices = [PcapDevice() for _ in range(257)]
        names = [
            C.create_string_buffer(("test-" + str(n)).encode()) for n in range(257)
        ]
        for index, device in enumerate(devices):
            device.name = C.cast(names[index], C.c_void_p)
            if index < 256:
                device.next = C.pointer(devices[index + 1])
        lib.device = devices[0]
        with self.assertRaises(CaptureError):
            backend.enumerate()
        self.assertEqual(lib.freed, 1)

    def test_windows_loader_uses_absolute_system_npcap_and_restricted_dependencies(
        self,
    ):
        from wifiscope.pcap_native import load_library

        with (
            patch(
                "wifiscope.pcap_native._system_directory",
                return_value=Path("C:/Windows/System32"),
            ),
            patch("pathlib.Path.is_file", return_value=True),
            patch("wifiscope.pcap_native.C.CDLL", return_value="fake") as loader,
        ):
            self.assertEqual(load_library("Windows"), "fake")
        args, kwargs = loader.call_args
        self.assertTrue(
            str(args[0])
            .replace("\\", "/")
            .endswith("/Windows/System32/Npcap/wpcap.dll")
        )
        self.assertEqual(kwargs, dict(winmode=0x900))

    def test_linux_fallback_bound_nonblocking_cooked_header_and_real_lengths(self):
        from wifiscope.pcap_native import LinuxSocketBackend

        class Stream:
            def __init__(self):
                self.bound = None
                self.blocking = None
                self.closed = False

            def setblocking(self, value):
                self.blocking = value

            def bind(self, address):
                self.bound = address

            def recvmsg_into(self, buffers, ancillary, flags):
                body = ipv4(tcp())
                buffers[0][: min(len(body), len(buffers[0]))] = body[: len(buffers[0])]
                return 200, [], 0, ("owned-test", 0x800, 0, 1, b"\0" * 6)

            def close(self):
                self.closed = True

        stream = Stream()
        with (
            patch("wifiscope.pcap_native.socket.AF_PACKET", 17, create=True),
            patch("wifiscope.pcap_native.socket.MSG_TRUNC", 32, create=True),
            patch(
                "wifiscope.pcap_native.socket.socket", return_value=stream
            ) as factory,
            patch(
                "wifiscope.pcap_native.socket.if_nametoindex",
                return_value=9,
                create=True,
            ),
        ):
            handle = LinuxSocketBackend().open(
                "owned-test", snaplen=64, promiscuous=False, packet_filter=""
            )
            status, row = handle.read(64)
        self.assertEqual(factory.call_args.args, (17, 2, 0))
        self.assertEqual(stream.bound, ("owned-test", 3))
        self.assertFalse(stream.blocking)
        self.assertEqual((status, len(row[2]), row[3]), (1, 64, 220))
        self.assertEqual(
            struct.unpack("!HHIHBB8s", row[2][:20]), (0x800, 0, 9, 1, 0, 6, b"\0" * 8)
        )
        self.assertEqual(
            handle.stats(), dict(received=None, dropped=None, interface_dropped=None)
        )
        handle.close()
        self.assertTrue(stream.closed)


class FinalEdges(unittest.TestCase):
    capture = LiveTests.capture
    adapter = NativeTests.adapter

    def test_live_html_has_measured_capture_heading_and_shared_provenance(self):
        report = self.capture(
            FakeBackend([packet(ethernet(ipv4(tcp(b"GET /secret HTTP/1.1\r\n"))))])
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = export_report(report, Path(directory) / "bundle")
            text = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertIn("Live capture packet metadata", text)
        self.assertNotIn("Offline packet metadata", text)
        finding = report["investigation"]["findings"][0]
        self.assertEqual(
            finding["evidence"]["source_sha256"],
            report["capture_session"]["source_sha256"],
        )
        self.assertEqual(finding["evidence"]["source"], "measured")

    def test_typed_session_rejects_contradictory_status_stats_and_limits(self):
        report = self.capture()
        changes = [
            dict(status="complete", stop_reason="native-error"),
            dict(status="cancelled", stop_reason="eof"),
            dict(raw_retained=True, retain_packets=False),
            dict(analyzed_packets=0, analysis_limited=False),
            dict(pcap_stats=dict(received=True, dropped=0, interface_dropped=None)),
            dict(
                limits=dict(
                    report["capture_session"]["limits"], duration_seconds=float("inf")
                )
            ),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                prepare_export(
                    dict(
                        report,
                        capture_session=dict(report["capture_session"], **change),
                    )
                )

    def test_native_open_retains_specific_controlled_capability_reason(self):
        from wifiscope.live_capture import capture_live
        from wifiscope.pcap_native import CaptureError

        backend = FakeBackend()
        backend.open = lambda *a, **k: (_ for _ in ()).throw(
            CaptureError("unsupported-link")
        )
        with self.assertRaises(CaptureError) as error:
            capture_live("owned-test", authorized=True, backend=backend)
        self.assertEqual(error.exception.code, "unsupported-link")

    def test_busy_progress_throttle_counts_and_final_cancel_preservation(self):
        from wifiscope.live_capture import capture_live

        clock = Clock()
        backend = FakeBackend([packet()] * 200, terminal=0)
        read = backend.handle.read

        def stepped(remaining):
            clock.value += 0.01
            return read(remaining)

        backend.handle.read = stepped
        events = []
        with (
            patch("wifiscope.live_capture._monotonic", clock.now),
            patch("wifiscope.live_capture._sleep", clock.sleep),
        ):
            report = capture_live(
                "owned-test",
                backend=backend,
                authorized=True,
                duration=1.0,
                progress=events.append,
            )
        for a, b in zip(events[:-2], events[1:-1]):
            self.assertGreaterEqual(b["elapsed_ms"] - a["elapsed_ms"], 200)
            self.assertLessEqual(a["packets"], b["packets"])
            self.assertLessEqual(a["captured_bytes"], b["captured_bytes"])
        self.assertEqual(events[-1]["packets"], report["capture_session"]["packets"])
        self.assertLessEqual(len(events), 7)

    def test_linux_permission_filter_and_idle_fail_cleanly(self):
        from wifiscope.pcap_native import (
            LinuxSocketBackend,
            LinuxSocketHandle,
            CaptureError,
        )

        backend = LinuxSocketBackend()
        with patch(
            "wifiscope.pcap_native.socket.socket", side_effect=AssertionError("opened")
        ):
            for options in (
                dict(packet_filter="tcp", promiscuous=False),
                dict(packet_filter="", promiscuous=True),
            ):
                with self.assertRaises(CaptureError):
                    backend.open("owned-test", snaplen=96, **options)
        with (
            patch("wifiscope.pcap_native.socket.AF_PACKET", 17, create=True),
            patch(
                "wifiscope.pcap_native.socket.socket",
                side_effect=PermissionError("PRIVATE"),
            ),
        ):
            with self.assertRaises(CaptureError) as error:
                backend.open(
                    "owned-test", snaplen=96, packet_filter="", promiscuous=False
                )
        self.assertEqual(error.exception.code, "permission-denied")

        class Idle:
            def recvmsg_into(self, *args):
                raise BlockingIOError()

            def close(self):
                pass

        handle = LinuxSocketHandle(Idle(), 1, 96)
        with patch("wifiscope.pcap_native.socket.MSG_TRUNC", 32, create=True):
            self.assertEqual(handle.read(96), (0, None))
        handle.close()


class StrictBoundaryTests(unittest.TestCase):
    capture = LiveTests.capture

    def test_authorization_raw_optin_extremes_and_capture_merge(self):
        from wifiscope.live_capture import capture_live
        from wifiscope.investigate import merge_reports

        backend = FakeBackend()
        for options in (
            dict(authorized=1),
            dict(raw_path="new.pcap"),
            dict(snaplen=97),
            dict(snaplen=False),
        ):
            with self.assertRaises(ValueError):
                capture_live(
                    "owned-test", backend=backend, **(dict(authorized=True) | options)
                )
        self.assertEqual(backend.opens, [])
        for options in (
            dict(duration=0.2, max_packets=1, max_bytes=4096, snaplen=64),
            dict(
                duration=120,
                max_packets=20000,
                max_bytes=16777216,
                snaplen=65535,
                retain_packets=True,
            ),
        ):
            report = self.capture(FakeBackend(), **options)
            self.assertEqual(report["capture_session"]["stop_reason"], "eof")
        report = self.capture()
        with self.assertRaisesRegex(ValueError, "capture contexts"):
            merge_reports([report, report])

    def test_offline_strict_aggregate_default_stays_strict(self):
        frames = [ethernet(ipv4(tcp(), src=src)) for src in ("192.0.2.1", "192.0.2.3")]
        with (
            patch.dict("wifiscope.packets.CAPS", {"endpoints": 2}),
            self.assertRaisesRegex(ValueError, "aggregate limit"),
        ):
            analyze_capture(pcap(frames))


class RawHeaderTests(unittest.TestCase):
    capture = LiveTests.capture

    def test_short_global_header_write_cannot_claim_valid_retention(self):
        class Short(io.BytesIO):
            def write(self, value):
                return super().write(value[:3])

        writer = Short()
        backend = FakeBackend([packet()])
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.open", return_value=writer),
        ):
            with self.assertRaises(ValueError):
                self.capture(
                    backend, raw_path=Path(directory) / "new.pcap", retain_packets=True
                )
        self.assertEqual(backend.handle.reads, 0)
        self.assertEqual(backend.handle.closed, 1)


class RawInterruptTests(unittest.TestCase):
    capture = LiveTests.capture

    def test_interrupt_during_record_write_keeps_only_complete_raw_records(self):
        class InterruptWriter(io.BytesIO):
            def write(self, value):
                if self.tell() > 24:
                    super().write(value[:3])
                    raise KeyboardInterrupt()
                return super().write(value)

            def close(self):
                self.snapshot = self.getvalue()
                super().close()

        writer = InterruptWriter()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("pathlib.Path.open", return_value=writer),
        ):
            report = self.capture(
                FakeBackend([packet(), packet()]),
                raw_path=Path(directory) / "new.pcap",
                retain_packets=True,
            )
        self.assertEqual(report["capture_session"]["status"], "cancelled")
        self.assertEqual(report["capture_session"]["raw_packets"], 1)
        self.assertEqual(len(writer.snapshot), 94)
        self.assertEqual(
            analyze_capture(writer.snapshot)["packet_analysis"]["packets"], 1
        )


class ExtremeNumericTests(unittest.TestCase):
    def test_extreme_integer_duration_is_a_controlled_prevalidation_error(self):
        from wifiscope.live_capture import capture_live

        backend = FakeBackend()
        with self.assertRaises(ValueError):
            capture_live(
                "owned-test", duration=10**1000, authorized=True, backend=backend
            )
        self.assertEqual(backend.opens, [])


class CaptureOutputPreflightTests(unittest.TestCase):
    def invoke(self, backend, *options):
        output, error = io.StringIO(), io.StringIO()
        with (
            patch('wifiscope.live_capture._default_backend', return_value=backend),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(error),
        ):
            code = cli.main(['capture', '--interface', 'owned-test', '--authorized', *map(str, options)])
        return code, output.getvalue()

    def test_existing_file_report_ancestor_is_rejected_before_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            ancestor = Path(directory) / 'existing-file'
            ancestor.write_bytes(b'keep-existing')
            raw = Path(directory) / 'new.pcap'
            backend = FakeBackend([packet()])
            code, output = self.invoke(backend, '--out', ancestor / 'nested' / 'report',
                                       '--retain-packets', '--raw-out', raw)
            self.assertEqual((code, output), (2, ''))
            self.assertEqual((backend.opens, backend.handle.reads), ([], 0))
            self.assertFalse(raw.exists())
            self.assertEqual(ancestor.read_bytes(), b'keep-existing')

    def test_new_raw_file_report_ancestor_and_aliases_are_rejected_before_capture(self):
        report_paths = ['new.pcap/report', 'alias/../new.pcap/report', 'alias/../new.pcap']
        if __import__('os').name == 'nt':
            report_paths.extend(['NEW.PCAP/report', 'NEW.PCAP'])
        for relative_report in report_paths:
            with self.subTest(report=relative_report), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'alias').mkdir()
                raw = root / 'new.pcap'
                report = root / relative_report
                backend = FakeBackend([packet()])
                code, output = self.invoke(backend, '--out', report,
                                           '--retain-packets', '--raw-out', raw)
                self.assertEqual((code, output), (2, ''))
                self.assertEqual((backend.opens, backend.handle.reads), ([], 0))
                self.assertFalse(raw.exists())
                self.assertFalse(report.exists())

    def test_valid_new_nested_report_directories_still_export_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'new-parent' / 'nested' / 'report'
            backend = FakeBackend([packet()])
            code, text = self.invoke(backend, '--out', output)
            self.assertEqual(code, 0)
            self.assertEqual(len(backend.opens), 1)
            self.assertEqual(backend.handle.reads, 2)
            self.assertEqual(set(json.loads(text)), {'json', 'csv', 'html'})
            saved = json.loads((output / 'report.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['capture_session']['packets'], 1)
            self.assertFalse(saved['capture_session']['raw_retained'])
