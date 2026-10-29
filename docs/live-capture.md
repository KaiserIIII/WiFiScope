# Built-in live capture

`capture` reads one explicitly selected local interface. It never sends packets,
installs a driver, selects an interface automatically, or changes Wi-Fi channels
or monitor mode. Use only interfaces and traffic you are authorized to observe.
The desktop's persistent **实时抓包** tool is available in novice and professional
modes. Explicit enumeration never selects an interface or starts capture. Review
all limits/filter/promiscuous/raw choices, then check adjacent authorization;
editing the plan clears it. A distinct unchecked consent covers >96-byte
snapshots or raw retention. Actual monotonic packet/byte/time callbacks update at
most five times per second. Idle cancellation retains acquired partial evidence.
Results remain separate from the main case until an explicit Apply; metadata
export requires no Apply and defaults to HMAC. The offline demo uses the real
packet parser on invented data and never opens native handles.

## Start with a short metadata capture

```console
python -m wifiscope capture --list-interfaces
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --authorized --duration 10 --out NEW_REPORT
```

Listing is read-only. It intentionally prints operational local interface names
and labels so that you can select one. It is not a privacy-projected report.
Capture JSON on stdout and JSON/CSV/HTML bundles use the existing shared privacy
projection. Interface, session, and capture-source references are pseudonymized
with the same per-export HMAC identities as packet evidence. Local raw identifier
exports require `--include-identifiers` separately.

Report output must be a new directory. Before opening capture or creating a raw
file, the CLI rejects existing report outputs, existing non-directory ancestors,
and report paths equal to or nested beneath the requested raw file. Path aliases
are resolved and comparisons follow the platform's case rules. New nested report
directories are allowed. This preflight cannot guarantee later filesystem access;
permissions, disk failures, or concurrent path changes can still prevent export.

Defaults: 10 seconds, at most 2,000 packets, at most 8 MiB of frame-prefix bytes,
96 bytes per packet, non-promiscuous. Packet prefixes can contain application data
in memory. Default operation writes no packet file; the temporary PCAP buffer is
discarded after metadata analysis. Packet contents and raw paths are absent from
ordinary reports, identifier-retaining reports, cases, CSV and HTML.

## Professional controls and explicit raw retention

```console
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --authorized --duration 5 --max-packets 1000 --max-bytes 8388608 --filter "tcp port 443" --out NEW_REPORT
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --authorized --retain-packets --snaplen 65535 --raw-out NEW_CAPTURE.pcap --out NEW_REPORT
```

A snapshot above 96 bytes, or any `--raw-out`, requires the distinct
`--retain-packets` opt-in. Merely increasing the snapshot does not write a file.
Raw retention creates an explicitly named new file exclusively. Existing paths
are refused. The parent directory must already exist. Raw packet files contain
sensitive prefixes or packets and must be handled separately from report exports.
Cooperative cancellation retains complete acquired PCAP records. A disk error
stops with partial metadata and records how many raw records completed; if a
partial trailing record cannot be truncated, `raw_retained` becomes false.
An initial header-write failure is a controlled startup error and may leave an
incomplete newly created file; no packet is read in that case.

`--promiscuous` is a separate explicit request. The tool does not enable it by
default. A requested mode cannot establish what another application or driver has
already configured on the interface.

Limits are strict finite numeric values: duration 0.2..120 seconds, packet count
1..20,000, frame-prefix budget 4,096..16,777,216 bytes, snapshot 64..65,535 bytes.
The filter is at most 512 printable ASCII bytes. Native BPF compile and set must
both succeed before reading. Filter text is not retained in reports or echoed in
native error explanations; `filter_requested` and `filter_applied` are recorded.

`max_bytes` counts acquired frame-prefix bytes, excluding PCAP framing. An
independent total-storage ceiling of 16 MiB includes the 24-byte global header
and each 16-byte record header. Capture stops before either ceiling can be
exceeded. `packets`, `captured_bytes`, `wire_bytes`, `storage_bytes`, and
`raw_packets` are distinct counters. `wire_bytes` means the original untruncated
record length in the chosen link format, not Ethernet physical airtime, FCS,
preamble or bandwidth. Linux fallback uses genuine cooked-v2 metadata and its
20-byte header; its lengths follow that format rather than fabricated Ethernet.

If an endpoint, conversation, ARP, observation, or derived investigation budget
is exhausted, final analysis retains the longest valid metadata prefix and adds
`capture-analysis-limit`. `analyzed_packets` can be lower than acquired `packets`;
it counts frames processed by the metadata analyzer, not fully decoded packets.
Raw retention can include acquired frames beyond that analysis prefix. The full
acquired PCAP hash still links the session and analyzed evidence. The offline
untrusted-file parser continues to reject aggregate excess by default.

## Capabilities and prerequisites

Windows uses only the installed system `Npcap/wpcap.dll` under the Windows system
directory, loaded with the C calling convention and restricted DLL-directory plus
SYSTEM32 dependency lookup. Npcap and its capture permissions must be supplied by
the user or administrator. No copy of Npcap, SDK, driver or binary is shipped.

Linux prefers installed libpcap. Without it, the bound nonblocking AF_PACKET
fallback needs CAP_NET_RAW (or suitable administrative privileges) and supports
empty filters with non-promiscuous capture only. A nonempty filter or promiscuous
request on that fallback fails before socket creation. The socket initially has
protocol zero and starts receiving only when bound to the selected interface.
The fallback records userspace receive time and leaves all drop statistics unknown.
macOS currently reports the capability as unavailable.

Native reads are explicitly nonblocking; the loop checks an absolute monotonic
deadline and cancellation between polls, even on an idle interface. Native
`timeval` uses Windows 32-bit long or Unix native long. Lengths, timestamps and
null pointers are checked before copying packet bytes. Statistics storage includes
Npcap's extra fields; only supported common counters are interpreted. Native
received counts are not the tool's captured count. Unavailable stats and ambiguous
zero interface-driver drops remain null, not proof of zero loss.

Supported formats: DLT_NULL (0), Ethernet (1), raw IP LINKTYPE 101 (native DLT_RAW
12 is mapped), Linux cooked (113), and cooked-v2 (276). Other native formats fail
with a controlled capability state. Captures retain timing, truncation, offload,
checksum, fragmentation and scope caveats. This is bounded metadata analysis,
without DPI, stream reassembly, throughput measurement or proof of losslessness.

CLI exit codes: 0 for time, packet, byte/storage limits or EOF; 1 for a partial
runtime error; 2 for invalid parameters or unavailable/startup capability; 130 for
cancellation. Every completed session still reports partial coverage. Session
errors preserve acquired metadata. Live findings and coverage say `measured` and
`live-capture`, joined to the session's source hash. Merging capture sessions is
explicitly refused until distinct session contexts can be retained safely.

## Python and UI integration

```python
from wifiscope.live_capture import list_capture_interfaces, capture_live

interfaces = list_capture_interfaces()  # never starts capture
report = capture_live(
    chosen_interface, authorized=True, duration=5,
    cancel=cancel_event, progress=queue.put,
)
```

`capture_live` also accepts `max_packets`, `max_bytes`, `snaplen`, `promiscuous`,
`packet_filter`, `raw_path`, `retain_packets`, and a local test-only `backend`.
Cancellation accepts an Event-like `is_set()` or local callable. The progress
callback receives a fresh dictionary with only `packets`, `captured_bytes`,
`elapsed_ms`, and `status` (`running`, then session status). Updates are throttled
to at most 5 Hz plus final completion, including idle periods. It receives no
packet bytes, paths or native error text. Callback exceptions stop capture with
`progress-error` and partial metadata. A UI worker can use a queue; it must not
call Tk directly. Metadata analysis runs at finalization, not on each packet.

`capture_schema.py` validates and explicitly projects the typed session. The
shared extension dispatcher preserves both `capture_session` and
`vulnerability_audit` through export and case persistence. Unknown extension
fields are discarded. See the source for the exact typed fields and controlled
enums; raw content is never part of the session schema.

## Verification scope and API references

Tests use fake native DLL functions, fake sockets/clocks/adapters, and synthetic
frames. A separately authorized parent smoke on 2026-10-28 used Windows
Python 3.12 and the installed Npcap backend on an owned loopback interface. It
captured and analyzed eight synthetic UDP frames with the exact own-port filter
applied, retained no raw packet file, and verified that default export contained
neither raw identifiers nor the payload marker. This verifies that bounded
Windows loopback path only; physical-interface and Linux native capture remain
unverified. No physical or unknown interface was captured during this work.

Official references reviewed 2026-10-28: [libpcap C structures](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h),
[Npcap API](https://npcap.com/guide/npcap-devguide.html),
[nonblocking reads](https://npcap.com/guide/wpcap/pcap_setnonblock.html),
[capture statistics](https://npcap.com/guide/wpcap/pcap_stats.html),
[Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html),
[Python socket addresses](https://docs.python.org/3.12/library/socket.html#socket-families),
and [Linux cooked headers](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h).
