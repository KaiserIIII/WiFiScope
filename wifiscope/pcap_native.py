"""Optional installed libpcap/Npcap and bound Linux packet-socket adapters.

No send API is exposed. Native errors are reduced to controlled reason codes.
The backend seam is local Python only; it is never loaded from evidence files.
"""

import ctypes as C
import ctypes.util
from pathlib import Path
import platform as _platform
import socket
import struct
import time

SUPPORTED_LINKS = (0, 1, 101, 113, 276)
ERROR_CODES = frozenset(
    (
        "unavailable",
        "enumeration-error",
        "open-error",
        "permission-denied",
        "nonblocking-error",
        "filter-error",
        "unsupported-link",
        "native-error",
        "invalid-packet",
        "byte-limit",
        "storage-limit",
        "stats-error",
        "close-error",
    )
)


class CaptureError(ValueError):
    def __init__(self, code):
        self.code = code if code in ERROR_CODES else "native-error"
        super().__init__(
            "Capture capability: "
            + self.code
            + ". Windows needs installed Npcap and capture permission; Linux needs CAP_NET_RAW and libpcap for filters. No driver is installed automatically."
        )


def timeval_type(platform):
    # Windows LLP64 long is 32-bit, including 64-bit Npcap. Unix uses native long.
    scalar = C.c_int32 if platform == "Windows" else C.c_long

    class Timeval(C.Structure):
        _fields_ = [("tv_sec", scalar), ("tv_usec", scalar)]

    return Timeval


def header_type(platform):
    class Header(C.Structure):
        _fields_ = [
            ("ts", timeval_type(platform)),
            ("caplen", C.c_uint32),
            ("len", C.c_uint32),
        ]

    return Header


Timeval = timeval_type(_platform.system())
PcapHeader = header_type(_platform.system())


class PcapStats(C.Structure):
    # Standard three unsigned ints plus documented Windows tail. Reserve a
    # correctly aligned tail for vendor/platform additions; interpret only 0..2.
    _fields_ = [
        ("ps_recv", C.c_uint32),
        ("ps_drop", C.c_uint32),
        ("ps_ifdrop", C.c_uint32),
        ("ps_capt", C.c_uint32),
        ("ps_sent", C.c_uint32),
        ("ps_netdrop", C.c_uint32),
        ("_reserved", C.c_uint32 * 10),
    ]


class BpfProgram(C.Structure):
    _fields_ = [("bf_len", C.c_uint), ("bf_insns", C.c_void_p)]


class PcapDevice(C.Structure):
    pass


PcapDevice._fields_ = [
    ("next", C.POINTER(PcapDevice)),
    ("name", C.c_void_p),
    ("description", C.c_void_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint),
]


def _bounded_string(pointer):
    if not pointer:
        return ""
    chars = C.cast(pointer, C.POINTER(C.c_ubyte))
    result = bytearray()
    for index in range(1025):
        value = chars[index]
        if value == 0:
            return result.decode("utf-8", errors="replace")
        if index == 1024 or value < 32 or value == 127:
            raise CaptureError("enumeration-error")
        result.append(value)
    raise CaptureError("enumeration-error")


def _system_directory():
    kernel = C.WinDLL("kernel32.dll", winmode=0x800)
    kernel.GetSystemDirectoryW.argtypes = [C.c_wchar_p, C.c_uint]
    kernel.GetSystemDirectoryW.restype = C.c_uint
    buffer = C.create_unicode_buffer(32768)
    count = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < count < len(buffer):
        raise CaptureError("unavailable")
    return Path(buffer.value)


def load_library(platform):
    try:
        if platform == "Windows":
            # LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32.
            # Never load a working-directory/PATH copy, including dependencies.
            path = _system_directory() / "Npcap" / "wpcap.dll"
            if not path.is_file():
                raise CaptureError("unavailable")
            return C.CDLL(str(path), winmode=0x100 | 0x800)
        if platform == "Linux":
            name = C.util.find_library("pcap")
            if name:
                return C.CDLL(name)
    except (OSError, AttributeError):
        pass
    raise CaptureError("unavailable")


class PcapBackend:
    def __init__(self, *, library=None, platform=None):
        self.platform = platform or _platform.system()
        self.name = "npcap" if self.platform == "Windows" else "libpcap"
        self.library = library if library is not None else load_library(self.platform)
        self.header = header_type(self.platform)
        # C calling convention (ctypes.CDLL), explicit widths and pointer levels.
        specs = {
            "pcap_findalldevs": (
                [C.POINTER(C.POINTER(PcapDevice)), C.c_char_p],
                C.c_int,
            ),
            "pcap_freealldevs": ([C.POINTER(PcapDevice)], None),
            "pcap_open_live": (
                [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p],
                C.c_void_p,
            ),
            "pcap_datalink": ([C.c_void_p], C.c_int),
            "pcap_setnonblock": ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
            "pcap_next_ex": (
                [C.c_void_p, C.POINTER(C.POINTER(self.header)), C.POINTER(C.c_void_p)],
                C.c_int,
            ),
            "pcap_compile": (
                [C.c_void_p, C.POINTER(BpfProgram), C.c_char_p, C.c_int, C.c_uint32],
                C.c_int,
            ),
            "pcap_setfilter": ([C.c_void_p, C.POINTER(BpfProgram)], C.c_int),
            "pcap_freecode": ([C.POINTER(BpfProgram)], None),
            "pcap_stats": ([C.c_void_p, C.POINTER(PcapStats)], C.c_int),
            "pcap_close": ([C.c_void_p], None),
        }
        try:
            for name, (args, result) in specs.items():
                function = getattr(self.library, name)
                function.argtypes, function.restype = args, result
        except (AttributeError, TypeError):
            raise CaptureError("unavailable") from None

    def enumerate(self):
        head = C.POINTER(PcapDevice)()
        error = C.create_string_buffer(256)
        rows, seen = [], set()
        try:
            if self.library.pcap_findalldevs(C.byref(head), error) != 0:
                raise CaptureError("enumeration-error")
            current = head
            count = 0
            linux_names = (
                {name for _, name in socket.if_nameindex()}
                if self.platform == "Linux"
                else None
            )
            while current:
                address = C.addressof(current.contents)
                if address in seen or count >= 256:
                    raise CaptureError("enumeration-error")
                seen.add(address)
                count += 1
                device = current.contents
                name = _bounded_string(device.name)
                label = _bounded_string(device.description) or name
                # Restrict to concrete local devices. Never use the automatic any
                # device, remote rpcap URLs or Linux pseudo-device sources.
                if (
                    name
                    and name != "any"
                    and "://" not in name
                    and (linux_names is None or name in linux_names)
                ):
                    if any(row["interface"] == name for row in rows):
                        raise CaptureError("enumeration-error")
                    rows.append(
                        dict(
                            interface=name,
                            label=label,
                            backend=self.name,
                            linktype=None,
                            loopback=bool(device.flags & 1),
                            supports_filter=True,
                            supports_promiscuous=True,
                        )
                    )
                current = device.next
            return rows
        except OSError:
            raise CaptureError("enumeration-error") from None
        finally:
            if head:
                self.library.pcap_freealldevs(head)

    def open(self, interface, *, snaplen, promiscuous, packet_filter):
        error = C.create_string_buffer(256)
        try:
            encoded = interface.encode("ascii")
        except UnicodeError:
            raise CaptureError("open-error") from None
        pointer = self.library.pcap_open_live(
            encoded, snaplen, int(promiscuous), 50, error
        )
        if not pointer:
            raise CaptureError("open-error")
        handle = PcapHandle(self, pointer, snaplen)
        try:
            native_link = self.library.pcap_datalink(pointer)
            handle.linktype = 101 if native_link == 12 else native_link
            if handle.linktype not in SUPPORTED_LINKS:
                raise CaptureError("unsupported-link")
            if self.library.pcap_setnonblock(pointer, 1, error) != 0:
                raise CaptureError("nonblocking-error")
            if packet_filter:
                program = BpfProgram()
                if (
                    self.library.pcap_compile(
                        pointer,
                        C.byref(program),
                        packet_filter.encode("ascii"),
                        1,
                        0xFFFFFFFF,
                    )
                    != 0
                ):
                    raise CaptureError("filter-error")
                try:
                    if self.library.pcap_setfilter(pointer, C.byref(program)) != 0:
                        raise CaptureError("filter-error")
                    handle.filter_applied = True
                finally:
                    self.library.pcap_freecode(C.byref(program))
            return handle
        except BaseException:
            handle.close()
            raise


class PcapHandle:
    timestamp_source = "native-unspecified"
    filter_applied = False

    def __init__(self, backend, pointer, snaplen):
        self.backend, self.pointer, self.snaplen = backend, pointer, snaplen

    def read(self, remaining):
        header = C.POINTER(self.backend.header)()
        data = C.c_void_p()
        status = self.backend.library.pcap_next_ex(
            self.pointer, C.byref(header), C.byref(data)
        )
        if status in (0, -2):
            return status, None
        if status != 1:
            raise CaptureError("native-error")
        if not header or not data:
            raise CaptureError("invalid-packet")
        info = header.contents
        seconds, microseconds, caplen, wirelen = (
            int(info.ts.tv_sec),
            int(info.ts.tv_usec),
            int(info.caplen),
            int(info.len),
        )
        if not (
            0 <= seconds <= 0xFFFFFFFF
            and 0 <= microseconds <= 999999
            and caplen <= self.snaplen
            and caplen <= wirelen
        ):
            raise CaptureError("invalid-packet")
        if caplen > remaining:
            raise CaptureError("byte-limit")
        # Native bytes are copied only after ALL lengths, pointers and time bounds.
        frame = C.string_at(data, caplen)
        return 1, (seconds, microseconds, frame, wirelen)

    def stats(self):
        values = PcapStats()
        if self.backend.library.pcap_stats(self.pointer, C.byref(values)) != 0:
            return dict(received=None, dropped=None, interface_dropped=None)
        # Zero driver drops is ambiguous on supported platforms, so leave unknown.
        return dict(
            received=int(values.ps_recv),
            dropped=int(values.ps_drop),
            interface_dropped=int(values.ps_ifdrop) or None,
        )

    def close(self):
        if self.pointer:
            pointer, self.pointer = self.pointer, None
            self.backend.library.pcap_close(pointer)


class LinuxSocketBackend:
    name = "af-packet"

    def enumerate(self):
        try:
            interfaces = socket.if_nameindex()
        except OSError:
            raise CaptureError("enumeration-error") from None
        if len(interfaces) > 256:
            raise CaptureError("enumeration-error")
        return [
            dict(
                interface=name,
                label=name,
                backend=self.name,
                linktype=276,
                loopback=name == "lo",
                supports_filter=False,
                supports_promiscuous=False,
            )
            for _, name in interfaces
        ]

    def open(self, interface, *, snaplen, promiscuous, packet_filter):
        if packet_filter or promiscuous:
            raise CaptureError("filter-error")
        stream = None
        try:
            # SOCK_DGRAM supplies real sockaddr_ll metadata and network-layer
            # bytes. Encode its Linux cooked-v2 header, never fake Ethernet.
            # Protocol zero receives nothing until bind selects this interface.
            stream = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
            stream.setblocking(False)
            stream.bind((interface, 3))
            return LinuxSocketHandle(stream, socket.if_nametoindex(interface), snaplen)
        except (OSError, AttributeError) as error:
            if stream is not None:
                stream.close()
            raise CaptureError(
                "permission-denied"
                if isinstance(error, PermissionError)
                else "open-error"
            ) from None


class LinuxSocketHandle:
    linktype = 276
    timestamp_source = "userspace-receive"
    filter_applied = False

    def __init__(self, stream, index, snaplen):
        self.stream, self.index, self.snaplen = stream, index, snaplen

    def read(self, remaining):
        size = min(self.snaplen, remaining)
        if size < 20:
            raise CaptureError("byte-limit")
        buffer = bytearray(size - 20)
        try:
            length, _, _, address = self.stream.recvmsg_into(
                [buffer], 0, socket.MSG_TRUNC
            )
        except BlockingIOError:
            return 0, None
        except OSError:
            raise CaptureError("native-error") from None
        if (
            not isinstance(address, tuple)
            or len(address) < 5
            or not isinstance(address[4], bytes)
            or len(address[4]) > 8
            or not 0 <= length <= 0xFFFFFFFF - 20
        ):
            raise CaptureError("invalid-packet")
        _, protocol, packet_type, hardware, physical = address[:5]
        try:
            cooked = struct.pack(
                "!HHIHBB8s",
                protocol,
                0,
                self.index,
                hardware,
                packet_type,
                len(physical),
                physical,
            )
        except (struct.error, TypeError):
            raise CaptureError("invalid-packet") from None
        now = time.time_ns()
        return 1, (
            now // 1000000000,
            now // 1000 % 1000000,
            cooked + bytes(buffer[:length]),
            length + 20,
        )

    def stats(self):
        return dict(received=None, dropped=None, interface_dropped=None)

    def close(self):
        if self.stream is not None:
            stream, self.stream = self.stream, None
            stream.close()


def default_backend():
    system = _platform.system()
    if system == "Windows":
        return PcapBackend(platform=system)
    if system == "Linux":
        try:
            return PcapBackend(platform=system)
        except CaptureError as error:
            if error.code != "unavailable":
                raise
        return LinuxSocketBackend()
    raise CaptureError("unavailable")
