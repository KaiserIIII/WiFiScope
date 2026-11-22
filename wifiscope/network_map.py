"""Source-scoped asset relationships and defensive observations from existing evidence."""
import math
import re
from ipaddress import ip_address, ip_interface, ip_network

MAX_MAP_SOURCES = 24
MAX_NODES = 6000
MAX_EDGES = 12000
MAX_FINDINGS = 2400
FINDING_TEXT = {
    "cleartext-http": ("明文 HTTP", "核对该端口是否应使用加密传输，并检查应用的 HTTPS 配置。"),
    "zeek-http": ("Zeek 记录 HTTP 会话", "按源日志行号核对会话和采集位置，确认业务是否要求 HTTPS。"),
    "arp-claims-differ": ("同一 IP 的 ARP 声明不同", "先核对抓包接口、VLAN 和设备切换，再确认登记的 IP/MAC。"),
    "listener-wildcard": ("通配地址监听", "核对应用所需的监听范围和主机防火墙规则。"),
    "listener-nonloopback": ("非回环地址监听", "核对指定地址是否符合应用和防火墙预期。"),
    "baseline-change": ("设备基线有变化", "对照变更记录与设备配置，确认变更是否符合预期。"),
    "imported-scanner": ("导入的扫描器发现", "按原报告定位条目，通过版本、配置或补丁记录复核。"),
}

_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CVE = re.compile(r"CVE-\d{4}-\d{4,10}\Z")
_PROTOCOLS = ("tcp", "udp", "sctp", "icmp", "icmpv6")
_CHANGE_SECTIONS = ("ports", "trunks", "routes", "config", "ospf_neighbors", "lldp_neighbors")


def _records(value):
    if isinstance(value, list):
        yield from (row for row in value if isinstance(row, dict))


def _label(value):
    if isinstance(value, str) and 0 < len(value) <= 180 and value.isprintable():
        return value.strip() or None
    return None


def _normalize(factory, value):
    if not _label(value):
        return None
    try:
        return factory(value)
    except ValueError:
        return None


def _mac(value):
    return value.lower() if _label(value) and _MAC.fullmatch(value) else None


def _number(value, minimum=0, maximum=2**63 - 1):
    return value if type(value) is int and minimum <= value <= maximum else None


def _source_state(value):
    if value in ("partial", "unknown", "cancelled"):
        return "partial" if value == "partial" else "unavailable"
    return "observed"


class _Map:
    def __init__(self):
        self.sources = []
        self.nodes = {}
        self.edges = []
        self.findings = {}
        self.limits = set()

    def source(self, kind, evidence, status="observed", section_coverage=(), source_hash=None, observed_at=None):
        if len(self.sources) == MAX_MAP_SOURCES:
            raise ValueError(f"单张测绘图最多汇总 {MAX_MAP_SOURCES} 份证据。")
        index = len(self.sources) + 1
        redacted = evidence.get("identifiers_included") is False
        row = {"source_id": index, "kind": kind, "status": "redacted" if redacted else status}
        if (label := _label(evidence.get("map_label"))) is not None:
            row["label"] = label
        if evidence.get("synthetic") is True:
            row["synthetic"] = True
        if source_hash and isinstance(source_hash, str) and _SHA256.fullmatch(source_hash):
            row["source_digest"] = source_hash
        if _label(observed_at):
            row["observed_at"] = observed_at
        if section_coverage:
            row["coverage"] = list(section_coverage)
        self.sources.append(row)
        return None if redacted else index

    def node(self, source, kind, label, context=None):
        if label is None:
            return None
        key = source, kind, label, context
        if key in self.nodes:
            return self.nodes[key]["node_id"]
        if len(self.nodes) == MAX_NODES:
            self.limits.add("node-limit")
            return None
        node_id = len(self.nodes) + 1
        row = {"node_id": node_id, "source_id": source, "kind": kind, "label": label}
        if context:
            row["context"] = context
        self.nodes[key] = row
        return node_id

    def ip(self, source, value, kind="ip", context=None):
        address = _normalize(ip_address, value)
        if address is None:
            return None
        if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
            return self.node(source, "special-address", str(address), context)
        return self.node(source, kind, str(address), context)

    def edge(self, source, kind, origin, target, section, row, **details):
        if origin is None or target is None:
            return
        if len(self.edges) == MAX_EDGES:
            self.limits.add("edge-limit")
            return
        self.edges.append({"edge_id": len(self.edges) + 1, "source_id": source, "kind": kind,
                           "from_node": origin, "to_node": target, "section": section, "row": row, **details})

    def finding(self, source, code, node, severity, section, row, *, related=None, group=None, **details):
        if node is None:
            return
        key = source, code, node, related, group
        if key in self.findings:
            self.findings[key]["count"] += 1
            return
        if len(self.findings) == MAX_FINDINGS:
            self.limits.add("finding-limit")
            return
        self.findings[key] = {"finding_id": len(self.findings) + 1, "source_id": source, "node_id": node,
                              "code": code, "severity": severity, "section": section, "row": row,
                              "related_node": related, "count": 1, **details}


def _capture(graph, report):
    capture = report.get("packet_analysis")
    if not isinstance(capture, dict):
        graph.source("pcap", report, "unavailable")
        return
    timeline = capture.get("protocol_timeline")
    partial = capture.get("partial") or not isinstance(timeline, dict)
    source = graph.source("pcap", report, "partial" if partial else "observed",
                          source_hash=capture.get("source_sha256"), observed_at=capture.get("observed_at"))
    if source is None:
        return
    graph.sources[source - 1]["scope_status"] = "capture-address-aggregate"
    for entry in _records(capture.get("endpoints")):
        graph.ip(source, entry.get("address"))
    for row, entry in enumerate(_records(capture.get("conversations")), 1):
        protocol = entry.get("protocol")
        if protocol not in _PROTOCOLS:
            continue
        origin = graph.ip(source, entry.get("src_address"))
        target = graph.ip(source, entry.get("dst_address"))
        graph.edge(source, "observed-traffic", origin, target, "conversations", row,
                   protocol=protocol, src_port=_number(entry.get("src_port"), 0, 65535),
                   dst_port=_number(entry.get("dst_port"), 0, 65535), packets=_number(entry.get("packets")))
    for row, entry in enumerate(_records(capture.get("arp_bindings")), 1):
        ip = graph.ip(source, entry.get("address"))
        mac = graph.node(source, "mac", _mac(entry.get("mac")))
        graph.edge(source, "arp-claim", ip, mac, "arp_bindings", row)
    events = timeline.get("events") if isinstance(timeline, dict) else None
    _capture_findings(graph, source, events)


def _capture_findings(graph, source, events):
    claims = {}
    for row, entry in enumerate(_records(events), 1):
        frame = _number(entry.get("packet_number"), 1)
        if frame is None:
            continue
        group = _number(entry.get("observation_group"), 1)
        if entry.get("protocol") == "arp" and entry.get("event_type") in ("arp-request", "arp-reply"):
            ip = _normalize(ip_address, entry.get("src_address"))
            mac = _mac(entry.get("arp_sender_mac"))
            if group is None or ip is None or ip.version != 4 or ip.is_unspecified or mac is None:
                continue
            seen = claims.setdefault((group, str(ip)), {})
            if mac in seen:
                continue
            if seen:
                first_frame = next(iter(seen.values()))
                graph.finding(source, "arp-claims-differ", graph.ip(source, str(ip)), "medium", "protocol_timeline",
                              row, group=group, observation_group=group, packet_number=frame,
                              related_packet_number=first_frame)
            seen[mac] = frame
            continue
        if entry.get("protocol") != "http" or entry.get("event_type") not in ("http-request", "http-response"):
            continue
        reply = entry["event_type"] == "http-response"
        server = graph.ip(source, entry.get("src_address" if reply else "dst_address"))
        client = graph.ip(source, entry.get("dst_address" if reply else "src_address"))
        port = _number(entry.get("src_port" if reply else "dst_port"), 1, 65535)
        graph.finding(source, "cleartext-http", server, "medium", "protocol_timeline", row,
                      related=client, group=(group, port), observation_group=group, port=port, packet_number=frame)


def _device(graph, report):
    sections = tuple({"section": row["section"], "status": row["status"]} for row in _records(report.get("coverage"))
                     if row.get("section") in (*_CHANGE_SECTIONS, "vlans", "ospf_interfaces", "ospf_lsdb")
                     and row.get("status") in ("observed", "partial", "missing"))
    status = "observed" if sections and all(row["status"] == "observed" for row in sections) else "partial"
    source = graph.source("device", report, status, sections)
    if source is None:
        return
    for section in ("ports", "trunks", "lldp_neighbors", "ospf_neighbors", "routes"):
        for row, entry in enumerate(_records(report.get(section)), 1):
            device = _label(entry.get("source_device")) or "本设备"
            origin = graph.node(source, "device", device)
            port_name = _label(entry.get("local_interface") if section == "lldp_neighbors" else entry.get("interface"))
            port = graph.node(source, "interface", port_name, device)
            line = _number(entry.get("source_line"), 1)
            graph.edge(source, "device-interface", origin, port, section, row, source_line=line)
            if section in ("ports", "trunks"):
                vlan_id = _number(entry.get("vlan_id" if section == "ports" else "native_vlan"), 1, 4094)
                vlan = graph.node(source, "vlan", f"VLAN {vlan_id}", device) if vlan_id else None
                kind = "vlan-member" if section == "ports" else "native-vlan"
                graph.edge(source, kind, port, vlan, section, row, source_line=line, vlan_id=vlan_id)
            elif section == "lldp_neighbors":
                remote = graph.node(source, "lldp-device", _label(entry.get("device")), device)
                graph.edge(source, "lldp-neighbor", port, remote, section, row, source_line=line,
                           remote_interface=_label(entry.get("remote_interface")))
            elif section == "ospf_neighbors":
                remote = graph.ip(source, entry.get("neighbor_id"), "ospf-router-id", device)
                state = entry.get("state")
                graph.edge(source, "ospf-neighbor", port or origin, remote, section, row, source_line=line,
                           address=_label(entry.get("address")), state=state if state in (
                               "DOWN", "ATTEMPT", "INIT", "2WAY", "2-WAY", "EXSTART", "EXCHANGE", "LOADING", "FULL") else None)
            else:
                vrf = _label(entry.get("vrf"))
                context = f"{device} / {vrf}" if vrf else device
                destination = _normalize(lambda value: ip_network(value, strict=False), entry.get("prefix"))
                prefix = graph.node(source, "prefix", str(destination), context) if destination else None
                graph.edge(source, "route-prefix", origin, prefix, section, row, source_line=line)
                via = graph.ip(source, entry.get("next_hop"), context=context)
                graph.edge(source, "route-next-hop", prefix, via, section, row, source_line=line, interface=port_name)
    _device_config(graph, source, report.get("config"))


def _device_config(graph, source, config):
    if not isinstance(config, dict):
        return
    for section in ("vlans", "interfaces"):
        for row, entry in enumerate(_records(config.get(section)), 1):
            device = _label(entry.get("source_device")) or "本设备"
            origin = graph.node(source, "device", device)
            line = _number(entry.get("source_line"), 1)
            locator = "config_" + section
            if section == "vlans":
                vlan_id = _number(entry.get("vlan_id"), 1, 4094)
                vlan = graph.node(source, "vlan", f"VLAN {vlan_id}", device) if vlan_id else None
                graph.edge(source, "configured-vlan", origin, vlan, locator, row, source_line=line, vlan_id=vlan_id)
                continue
            name = _label(entry.get("interface"))
            port = graph.node(source, "interface", name, device)
            graph.edge(source, "configured-interface", origin, port, locator, row, source_line=line)
            access_vlan = _number(entry.get("access_vlan"), 1, 4094)
            if access_vlan is not None:
                vlan = graph.node(source, "vlan", f"VLAN {access_vlan}", device)
                graph.edge(source, "configured-access-vlan", port, vlan, locator, row, source_line=line, vlan_id=access_vlan)
            addresses = entry.get("addresses")
            for raw in addresses if isinstance(addresses, list) else []:
                address = _normalize(ip_interface, raw)
                if address is not None:
                    ip = graph.ip(source, str(address.ip), "configured-ip", device)
                    graph.edge(source, "configured-address", port, ip, locator, row, source_line=line)


def _local_ip(graph, source, value, interface=None):
    address = _normalize(ip_address, value)
    scoped = address is not None and address.is_link_local and getattr(address, "scope_id", None) is None
    return graph.ip(source, str(address) if address is not None else None,
                    context=(interface or "接口未知") if scoped else None)


def _diagnostics(graph, report):
    current = next(iter(reversed(list(_records(report.get("samples"))))), {})
    stages = current.get("stages")
    local = stages.get("local") if isinstance(stages, dict) else None
    local = local if isinstance(local, dict) else {}
    local_status = _source_state(local.get("status", "unknown"))
    gaps = local.get("gaps")
    gaps = [gap for gap in gaps if isinstance(gap, str)] if isinstance(gaps, list) else []
    coverage = []
    for section in ("interfaces", "routes", "neighbors", "listeners"):
        incomplete = any(gap.endswith((f"{section}-unavailable", f"{section}-incomplete")) for gap in gaps)
        status = "partial" if incomplete or local_status == "partial" and not gaps else "observed"
        if local_status == "unavailable" or not isinstance(local.get(section), list):
            status = "missing"
        coverage.append({"section": section, "status": status})
    source = graph.source("local", report, local_status, coverage, observed_at=current.get("observed_at"))
    if source is None or not local:
        return
    sample = _number(current.get("sequence"), 1)
    host = graph.node(source, "local-host", "本机")
    for row, entry in enumerate(_records(local.get("interfaces")), 1):
        name = _label(entry.get("interface"))
        port = graph.node(source, "interface", name)
        graph.edge(source, "device-interface", host, port, "interfaces", row, sample=sample)
        addresses = entry.get("addresses")
        for raw in addresses if isinstance(addresses, list) else []:
            cidr = _normalize(ip_interface, raw)
            if cidr is None:
                continue
            ip = _local_ip(graph, source, str(cidr).split("/")[0], name)
            graph.edge(source, "interface-address", port, ip, "interfaces", row, sample=sample)
    for row, entry in enumerate(_records(local.get("neighbors")), 1):
        name = _label(entry.get("interface"))
        port = graph.node(source, "interface", name)
        ip = _local_ip(graph, source, entry.get("ip"), name)
        mac = graph.node(source, "mac", _mac(entry.get("mac")))
        graph.edge(source, "cached-neighbor", port or host, ip, "neighbors", row, sample=sample)
        graph.edge(source, "cached-link-address", ip, mac, "neighbors", row, sample=sample, interface=name)
    for row, entry in enumerate(_records(local.get("routes")), 1):
        destination = _normalize(lambda value: ip_network(value, strict=False), entry.get("destination"))
        table = entry.get("table")
        context = str(table) if type(table) is int else _label(table)
        prefix = graph.node(source, "prefix", str(destination), context) if destination else None
        graph.edge(source, "route-prefix", host, prefix, "routes", row, sample=sample)
        seen = set()
        for path in (entry, *_records(entry.get("nexthops"))):
            name = _label(path.get("interface"))
            via = _local_ip(graph, source, path.get("gateway"), name)
            if via and (via, name) not in seen:
                seen.add((via, name))
                graph.edge(source, "route-next-hop", prefix, via, "routes", row, sample=sample, interface=name)
    for row, entry in enumerate(_records(local.get("listeners")), 1):
        raw, protocol = entry.get("address"), entry.get("protocol")
        port = _number(entry.get("port"), 1, 65535)
        ip = _normalize(ip_address, raw)
        if protocol not in ("tcp", "udp") or not port or (ip is None and raw != "*"):
            continue
        wildcard = raw == "*" or ip.is_unspecified
        bind = "wildcard" if wildcard else "loopback" if ip.is_loopback else "specific"
        address = raw if wildcard else str(ip)
        endpoint = graph.node(source, "local-socket", f"{address} · {protocol.upper()}/{port}")
        graph.edge(source, "listening-socket", host, endpoint, "listeners", row, sample=sample,
                   address=address, protocol=protocol, port=port, bind=bind)
        if bind != "loopback":
            code = "listener-wildcard" if wildcard else "listener-nonloopback"
            graph.finding(source, code, endpoint, "low", "listeners", row, port=port, protocol=protocol,
                          bind=bind, sample=sample)


def _comparison(graph, report):
    source = graph.source("baseline", report, "partial" if any(
        row.get("comparable") is False for row in _records(report.get("coverage"))) else "observed")
    if source is None:
        return
    for row, change in enumerate(_records(report.get("changes")), 1):
        section, action = change.get("section"), change.get("change")
        if section not in _CHANGE_SECTIONS or action not in ("added", "removed", "changed"):
            continue
        evidence = change.get("after") or change.get("before")
        if not isinstance(evidence, dict):
            continue
        node = graph.node(source, "device", _label(evidence.get("source_device")) or "本设备")
        lines = {}
        for side in ("before", "after"):
            item = change.get(side)
            if isinstance(item, dict):
                lines[f"{side}_source_line"] = _number(item.get("source_line"), 1)
        graph.finding(source, "baseline-change", node, "low", section, row, group=row, change=action,
                      identity=_label(change.get("identity")), **lines)


def _inventory(graph, report):
    by_key = {}
    for row in _records(report.get("sources")):
        kind, digest = row.get("type"), row.get("sha256")
        if kind not in ("nmap", "greenbone"):
            continue
        if report.get("identifiers_included") is False:
            graph.source(kind, report)
            continue
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            graph.source(kind, report, "unavailable")
            continue
        coverage = row.get("coverage")
        status = "partial" if not isinstance(coverage, dict) or coverage.get("partial") is not False else "observed"
        if (kind, digest) not in by_key:
            by_key[kind, digest] = graph.source(kind, report, status, source_hash=digest, observed_at=row.get("observed_at"))
    if report.get("identifiers_included") is False:
        return
    for row, asset in enumerate(_records(report.get("assets")), 1):
        key = asset.get("source"), asset.get("source_sha256")
        if not all(isinstance(value, str) for value in key) or key not in by_key:
            continue
        source = by_key[key]
        ip = graph.ip(source, asset.get("address"))
        for item, service in enumerate(_records(asset.get("services")), 1):
            protocol, port = service.get("protocol"), _number(service.get("port"), 1, 65535)
            if protocol not in ("tcp", "udp", "sctp") or not port or service.get("state") != "open":
                continue
            endpoint = graph.node(source, "reported-service", f"{protocol.upper()}/{port}", _label(asset.get("address")))
            graph.edge(source, "reported-service", ip, endpoint, "assets", row, item=item, port=port, protocol=protocol)
    for row, finding in enumerate(_records(report.get("imported_findings")), 1):
        digest = finding.get("source_sha256")
        if finding.get("source") != "greenbone" or not isinstance(digest, str) or ("greenbone", digest) not in by_key:
            continue
        source = by_key["greenbone", digest]
        ip = graph.ip(source, finding.get("address"))
        rating = finding.get("score")
        score = rating if type(rating) in (int, float) and 0 <= rating <= 10 and math.isfinite(rating) else None
        severity = ("info" if not score else "low" if score < 4 else "medium" if score < 7
                    else "high" if score < 9 else "critical")
        ids = finding.get("cves")
        cves = [value for value in ids[:12] if isinstance(value, str) and _CVE.fullmatch(value)] if isinstance(ids, list) else []
        graph.finding(source, "imported-scanner", ip, severity, "imported_findings", row, group=row,
                      status="imported-unverified", score=score, port=_number(finding.get("port"), 1, 65535), cves=cves)


def _zeek(graph, report):
    source = graph.source("zeek", report, report["status"],
                          source_hash=report["source_digest"], observed_at=report["observed_at"])
    if source is None:
        return
    metadata = ("format", "ended_at", "flow_rows", "skipped_rows", "dropped_rows", "loss_rows", "unknown_loss_rows")
    graph.sources[source - 1].update((field, report[field]) for field in metadata)
    for index, flow in enumerate(report["flows"], 1):
        outer, inner = flow.get("vlan"), flow.get("inner_vlan")
        context = f"VLAN {outer}" if outer is not None else None
        if inner is not None:
            context = f"{context or 'VLAN ?'} / {inner}"
        origin = graph.ip(source, flow["src_address"], context=context)
        target = graph.ip(source, flow["dst_address"], context=context)
        fields = {key: value for key, value in flow.items() if key not in ("src_address", "dst_address")}
        graph.edge(source, "zeek-flow", origin, target, "conn_log", index, **fields)
        if flow["protocol"] == "tcp" and "http" in flow["service"]:
            graph.finding(source, "zeek-http", target, "info", "conn_log", index, related=origin, group=flow["dst_port"],
                          source_line=flow["source_line"], observed_at=flow["observed_at"], port=flow["dst_port"])


def build_network_map(*, captures=(), devices=(), diagnostics=(), comparisons=(), inventories=(), flow_logs=()):
    """Build only within-source relationships, retaining a locator for each evidence row."""
    graph = _Map()
    for gather, reports in ((_capture, captures), (_device, devices), (_diagnostics, diagnostics),
                            (_comparison, comparisons), (_inventory, inventories), (_zeek, flow_logs)):
        for report in reports:
            gather(graph, report)
    return {"schema_version": 1, "kind": "network-map", "status": "partial" if graph.limits else "complete",
            "map_sources": graph.sources, "nodes": list(graph.nodes.values()), "edges": graph.edges,
            "findings": list(graph.findings.values()), "gaps": sorted(graph.limits)}


def read_map_evidence(kind, path):
    """Read an existing file using the same bounded parsers as the workbench."""
    from .network_devices import local_evidence_path
    from .workstation import read_bounded, read_json_object

    source = local_evidence_path(path)
    if not source.is_file():
        raise ValueError("请选用现有的本地证据文件。")
    if kind == "device":
        from .network_devices import read_device_evidence

        report = read_device_evidence(source)
    elif kind == "diagnostics":
        report = read_json_object(source)
        schema = report.get("schema_version")
        samples = report.get("samples")
        if (type(schema) is not int or schema != 1 or report.get("kind") not in ("network-diagnostics", "network-monitor")
                or not isinstance(samples, list) or len(samples) > 60 or not all(
                    isinstance(row, dict) and isinstance(row.get("stages"), dict) for row in samples)):
            raise ValueError("请选择 WiFiScope 诊断或监测 JSON。")
    elif kind == "pcap":
        from .packets import analyze_capture

        report = analyze_capture(read_bounded(source))
    elif kind == "zeek":
        from .zeek_flows import parse_zeek_flows

        report = parse_zeek_flows(read_bounded(source))
    else:
        from .importers import import_greenbone, import_nmap

        report = {"nmap": import_nmap, "greenbone": import_greenbone}[kind](read_bounded(source))
    return dict(report, map_label=source.name)
