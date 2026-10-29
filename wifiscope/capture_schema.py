"""Typed capture session and the shared export identity closure."""

from datetime import datetime

BACKENDS = ("npcap", "libpcap", "af-packet")
STATUSES = ("complete", "cancelled", "partial")
STOP_REASONS = (
    "duration",
    "packet-limit",
    "byte-limit",
    "storage-limit",
    "eof",
    "cancelled",
    "native-error",
    "invalid-packet",
    "progress-error",
    "raw-write-error",
    "close-error",
)
FIELDS = (
    "schema_version",
    "id",
    "interface",
    "backend",
    "source_sha256",
    "source",
    "timestamp_source",
    "started_at",
    "ended_at",
    "duration_ms",
    "status",
    "stop_reason",
    "packets",
    "analyzed_packets",
    "captured_bytes",
    "wire_bytes",
    "storage_bytes",
    "raw_packets",
    "raw_retained",
    "retain_packets",
    "promiscuous",
    "filter_applied",
    "filter_requested",
    "linktype",
    "partial",
    "limits",
    "pcap_stats",
    "analysis_limited",
)
IDENTITIES = ("id", "interface", "source_sha256")
LIMIT_FIELDS = (
    "duration_seconds",
    "max_packets",
    "max_bytes",
    "snaplen",
    "max_storage_bytes",
)


def _bad():
    raise ValueError("Invalid typed capture session; use capture schema_version=1.")


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _bad()


def validate_capture_session(value):
    if not isinstance(value, dict) or not set(FIELDS) <= value.keys():
        _bad()
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _bad()
    for key in IDENTITIES:
        if (
            not isinstance(value[key], str)
            or not 1 <= len(value[key]) <= 1024
            or any(ord(c) < 32 for c in value[key])
        ):
            _bad()
    if (
        value["backend"] not in BACKENDS
        or value["source"] != "measured"
        or value["status"] not in STATUSES
        or value["stop_reason"] not in STOP_REASONS
        or value["timestamp_source"] not in ("native-unspecified", "userspace-receive")
    ):
        _bad()
    successful = ("duration", "packet-limit", "byte-limit", "storage-limit", "eof")
    if (value["status"] == "complete") != (value["stop_reason"] in successful) or (
        value["status"] == "cancelled"
    ) != (value["stop_reason"] == "cancelled"):
        _bad()
    for key in ("started_at", "ended_at"):
        if not isinstance(value[key], str) or len(value[key]) > 64:
            _bad()
        try:
            parsed = datetime.fromisoformat(value[key].replace("Z", "+00:00"))
        except ValueError:
            _bad()
        if parsed.tzinfo is None:
            _bad()
    if datetime.fromisoformat(value["ended_at"]) < datetime.fromisoformat(
        value["started_at"]
    ):
        _bad()
    _int(value["duration_ms"], 0, 2**53 - 1)
    for key in ("packets", "analyzed_packets", "raw_packets"):
        _int(value[key], 0, 20000)
    for key in ("captured_bytes", "storage_bytes"):
        _int(value[key], 0, 16777216)
    _int(value["wire_bytes"], 0, 20000 * 0xFFFFFFFF)
    _int(value["linktype"], 0, 65535)
    for key in (
        "raw_retained",
        "retain_packets",
        "promiscuous",
        "filter_applied",
        "filter_requested",
        "partial",
        "analysis_limited",
    ):
        if type(value[key]) is not bool:
            _bad()
    limits = value["limits"]
    if not isinstance(limits, dict) or not set(LIMIT_FIELDS) <= limits.keys():
        _bad()
    if (
        type(limits["duration_seconds"]) not in (int, float)
        or not 0.2 <= limits["duration_seconds"] <= 120
    ):
        _bad()
    _int(limits["max_packets"], 1, 20000)
    _int(limits["max_bytes"], 4096, 16777216)
    _int(limits["snaplen"], 64, 65535)
    _int(limits["max_storage_bytes"], 24, 16777216)
    if (
        value["analyzed_packets"] > value["packets"]
        or value["raw_packets"] > value["packets"]
        or value["packets"] > limits["max_packets"]
        or value["captured_bytes"] > limits["max_bytes"]
        or value["storage_bytes"] > limits["max_storage_bytes"]
        or value["storage_bytes"]
        != 24 + 16 * value["packets"] + value["captured_bytes"]
        or value["wire_bytes"] < value["captured_bytes"]
        or not value["partial"]
        or value["filter_applied"] != value["filter_requested"]
        or (value["raw_retained"] or limits["snaplen"] > 96)
        and not value["retain_packets"]
    ):
        _bad()
    if value["analysis_limited"] != (value["analyzed_packets"] < value["packets"]):
        _bad()
    stats = value["pcap_stats"]
    if (
        not isinstance(stats, dict)
        or not {"received", "dropped", "interface_dropped"} <= stats.keys()
    ):
        _bad()
    for key in ("received", "dropped", "interface_dropped"):
        if stats[key] is not None:
            _int(stats[key], 0, 0xFFFFFFFF)


def project_capture_session(value, identity):
    validate_capture_session(value)
    result = {key: value[key] for key in FIELDS if key not in ("limits", "pcap_stats")}
    for key in IDENTITIES:
        result[key] = identity(value[key])
    result["limits"] = {key: value["limits"][key] for key in LIMIT_FIELDS}
    result["pcap_stats"] = {
        key: value["pcap_stats"][key]
        for key in ("received", "dropped", "interface_dropped")
    }
    return result
