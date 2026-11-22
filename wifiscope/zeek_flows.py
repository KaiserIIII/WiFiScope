"""Bounded offline Zeek conn.log parser. Raw log text and connection IDs stay local."""
import hashlib
import io
import json
import math
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from itertools import chain

MAX_ZEEK_BYTES = 16 * 1024 * 1024
MAX_ZEEK_LINE = 32 * 1024
MAX_ZEEK_FLOWS = 10000
SERVICES = ("http", "ssl", "dns", "ssh", "quic", "smtp", "imap", "pop3", "ftp", "dhcp", "ntp", "smb",
            "rdp", "sip", "mqtt", "modbus", "snmp", "kerberos", "ldap", "syslog", "websocket")
_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "sctp", "unknown_transport")
_STATES = ("S0", "S1", "S2", "S3", "SF", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")
_REQUIRED = frozenset(("ts", "id.orig_h", "id.resp_h", "proto"))
_CONN_FIELDS = frozenset(("conn_state", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "missed_bytes"))
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _ip(value):
    if not isinstance(value, str) or not 2 <= len(value) <= 45 or "%" in value:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


def _count(value, maximum=2**64 - 1):
    if isinstance(value, str) and 0 < len(value) <= 20 and value.isascii() and value.isdecimal():
        value = int(value)
    return value if type(value) is int and 0 <= value <= maximum else None


def _number(value, maximum):
    if isinstance(value, str) and 0 < len(value) <= 30 and value.isascii():
        try:
            value = float(value)
        except ValueError:
            return None
    return float(value) if type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value) else None


def _time(value):
    number = _number(value, 253370764799)
    return (_EPOCH + timedelta(seconds=number)).isoformat() if number is not None else None


def _service_tags(value):
    if isinstance(value, str) and len(value) <= 512:
        value = value.split(",")
    return [tag for tag in value[:48] if isinstance(tag, str)] if isinstance(value, list) else []


def _services(value, failed):
    tags = _service_tags(value)
    denied = {tag.removeprefix("-") for tag in _service_tags(failed)}
    denied.update(tag[1:] for tag in tags if tag.startswith("-"))
    return list(dict.fromkeys(tag for tag in tags if tag in SERVICES and tag not in denied))


def _flow(values, line):
    origin, responder = _ip(values.get("id.orig_h")), _ip(values.get("id.resp_h"))
    protocol, observed = values.get("proto"), _time(values.get("ts"))
    if (origin is None or responder is None or origin.version != responder.version
            or protocol not in _PROTOCOLS or observed is None):
        return None
    duration = _number(values.get("duration"), 10 * 365 * 24 * 3600)
    state = values.get("conn_state")
    row = {
        "source_line": line, "observed_at": observed, "src_address": str(origin), "dst_address": str(responder),
        "protocol": protocol, "service": _services(values.get("service"), values.get("failed_service")),
        "duration_ms": round(duration * 1000, 3) if duration is not None else None,
        "state": state if state in _STATES else None, "orig_bytes": _count(values.get("orig_bytes")),
        "resp_bytes": _count(values.get("resp_bytes")), "missed_bytes": _count(values.get("missed_bytes")),
    }
    ports = protocol in ("tcp", "udp", "sctp")
    row["src_port"] = _count(values.get("id.orig_p"), 65535) if ports else None
    row["dst_port"] = _count(values.get("id.resp_p"), 65535) if ports else None
    if protocol in ("icmp", "icmpv6"):
        row["icmp_type"] = _count(values.get("id.orig_p"), 255)
        row["icmp_code"] = _count(values.get("id.resp_p"), 255)
    for field in ("vlan", "inner_vlan"):
        tag = _count(values.get(field), 4094)
        if tag is not None:
            row[field] = tag
    return row


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value
    return result


def _json_record(line):
    try:
        record = json.loads(line, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError):
        return None
    return record if isinstance(record, dict) and _CONN_FIELDS.intersection(record) else None


class _Tabular:
    def __init__(self):
        self.fields = None
        self.unset = "-"

    def header(self, line):
        key, _, value = line.partition("\t")
        if line.startswith("#separator") and line != r"#separator \x09":
            raise ValueError("Zeek conn.log 仅支持标准制表符分隔或 JSON Lines。")
        if key == "#path" and value != "conn":
            raise ValueError("请选择 Zeek conn.log。")
        if key == "#unset_field" and value and "\t" not in value:
            self.unset = value
        if key == "#fields":
            fields = value.split("\t")
            if not _REQUIRED <= set(fields) or len(set(fields)) != len(fields) or len(fields) > 256:
                raise ValueError("Zeek conn.log 字段表不完整或有重复列。")
            self.fields = fields

    def record(self, line):
        if self.fields is None:
            raise ValueError("Zeek conn.log 缺少 #fields 字段表。")
        parts = line.split("\t")
        if len(parts) != len(self.fields):
            return None
        return {field: value for field, value in zip(self.fields, parts, strict=True) if value != self.unset}


def parse_zeek_flows(data):
    """Project metadata from a single standard Zeek TSV or JSON-lines connection log."""
    if len(data) > MAX_ZEEK_BYTES:
        raise ValueError("Zeek conn.log 超过 16 MiB。")
    stream = enumerate(io.BytesIO(data), 1)
    first = next(((n, raw.removeprefix(b"\xef\xbb\xbf") if n == 1 else raw)
                  for n, raw in stream if raw.strip()), None)
    if first is None or not first[1].lstrip().startswith((b"#", b"{")):
        raise ValueError("请选择 UTF-8 格式的 Zeek conn.log。")
    tabular = _Tabular() if first[1].lstrip().startswith(b"#") else None
    flows = []
    skipped = dropped = loss_rows = unknown_loss_rows = 0
    start = end = None
    for line, raw in chain((first,), stream):
        if not raw.strip():
            continue
        if len(raw) > MAX_ZEEK_LINE:
            skipped += 1
            continue
        try:
            text = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            skipped += 1
            continue
        if tabular and text.startswith("#"):
            tabular.header(text)
            continue
        if len(flows) >= MAX_ZEEK_FLOWS:
            dropped += 1
            continue
        values = tabular.record(text) if tabular else _json_record(text)
        row = _flow(values, line) if values is not None else None
        if row is None:
            skipped += 1
            continue
        flows.append(row)
        loss_rows += (row["missed_bytes"] or 0) > 0
        unknown_loss_rows += row["missed_bytes"] is None
        observed = row["observed_at"]
        start = observed if start is None else min(start, observed)
        end = observed if end is None else max(end, observed)
    if not flows and not (tabular and tabular.fields is not None and not skipped):
        raise ValueError("文件中没有可读取的 Zeek conn.log 会话记录。")
    return {"schema_version": 1, "kind": "zeek-flows", "source_digest": hashlib.sha256(data).hexdigest(),
            "observed_at": start, "ended_at": end, "status": "partial" if skipped or dropped or loss_rows else "observed",
            "format": "tsv" if tabular else "jsonl", "skipped_rows": skipped, "dropped_rows": dropped,
            "loss_rows": loss_rows, "unknown_loss_rows": unknown_loss_rows, "flow_rows": len(flows), "flows": flows}
