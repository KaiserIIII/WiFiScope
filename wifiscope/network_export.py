"""Privacy projection and local browsing for the network workbench."""
import html
import json
import re
import secrets
from collections import Counter

from .export_schema import _project_identity
from .network_present import diagnostic_rows
from .network_present import topology_links as observed_links
from .reports import export_prepared_report, prepare_export

_IDENTITIES = {
    "address", "addresses", "application", "bssid", "destination", "dns", "doh",
    "endpoint", "expected_peer", "gateway", "gateways", "host", "hostname",
    "id", "identity", "interface", "interface_alias", "label", "link_id", "local_interface",
    "mac", "mac_address", "name", "neighbor_id", "next_hop", "ntp", "peer", "peers",
    "portal", "port_name", "ports", "prefix", "remote_interface", "router_id",
    "source", "source_device", "device", "devices", "trace", "src_address",
    "dst_address", "ssid", "target", "url", "vrf", "advertising_router",
    "cname", "server", "fqdn", "dns_servers", "remote_address", "local_address", "ip",
    "preferred_source", "configured_gateways", "configured_servers", "network",
    "secondary_addresses", "passive_interfaces", "active_interfaces", "router",
    "context", "source_digest",
}
_LITERAL_FIELDS = {
    "area", "change", "encoding", "event_type", "family", "field", "fields",
    "flags", "gap", "gaps", "kind", "lsa_type", "method", "mode", "network_type",
    "protocol", "protocols", "role", "section", "stage", "state", "status",
    "stop_reason", "type", "capabilities", "stop_detail", "binding", "reason",
    "health", "observation", "source_status", "table", "platform", "bind", "address_method", "wildcard",
}
_TIME_FIELDS = {"started_at", "ended_at", "observed_at", "timestamp"}
_LITERAL = re.compile(r"[a-zA-Z0-9_.:/+|() -]{1,80}\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ][0-9:.+\-]{8,27}Z?\Z")
_LOCAL_ONLY = {"raw", "raw_text", "raw_config", "file_path", "path_to_file", "preview_lines", "notices", "warnings"}
_MAP_LITERALS = {"code", "severity", "cves", "scope_status"}


def project_network(report, include_identifiers=False):
    """Allow typed values and pseudonymize topology identifiers per export."""
    include = include_identifiers is True
    if "packet_analysis" in report:
        return prepare_export(report, include)
    key = secrets.token_bytes(32)

    def walk(value, field=""):
        if isinstance(value, dict):
            if field == "by_device":
                return {_project_identity(k, include, key): walk(v) for k, v in value.items()}
            return {k: walk(v, k) for k, v in value.items() if k not in _LOCAL_ONLY}
        if isinstance(value, list):
            return [walk(item, field) for item in value]
        if not isinstance(value, str):
            return value
        if field in _IDENTITIES:
            return _project_identity(value, include, key)
        if field in _TIME_FIELDS and _TIME.fullmatch(value):
            return value
        if field in _LITERAL_FIELDS and _LITERAL.fullmatch(value):
            return value
        if report.get("kind") == "network-map" and field in _MAP_LITERALS and _LITERAL.fullmatch(value):
            return value
        if field == "command" and value.startswith("show ") and _LITERAL.fullmatch(value):
            return value
        return None

    result = dict(walk(report), identifiers_included=include)
    config = result.get("config")
    if isinstance(config, dict) and all(isinstance(config.get(section), list)
                                        for section in ("vlans", "interfaces", "ospf")):
        from .network_device_config import config_preview

        config["preview_lines"] = config_preview(config)
    return result


def _cell(value):
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return str(value)


def _table(title, labels, rows):
    if not rows:
        return ""
    esc = html.escape
    headers = "".join("<th>" + esc(label) + "</th>" for _, label in labels)
    body = "".join(
        "<tr>" + "".join("<td>" + esc(_cell(row.get(key))) + "</td>" for key, _ in labels) + "</tr>"
        for row in rows
    )
    return ('<section><h2>' + esc(title) + '</h2><div class="scroll"><table><thead><tr>' +
            headers + '</tr></thead><tbody>' + body + '</tbody></table></div></section>')


def _bar_chart(protocols):
    top = Counter(protocols).most_common(12)
    if not top or top[0][1] < 1:
        return ""
    maximum = top[0][1]
    lines = "".join(
        f'<li><span>{html.escape(protocol)}</span><meter min="0" max="{maximum}" value="{count}"></meter>'
        f'<strong>{count}</strong></li>' for protocol, count in top
    )
    return '<section><h2>协议分布（帧数）</h2><ul class="bars">' + lines + '</ul></section>'


def _page(prepared, fields, _packet_metadata):
    from .network_map import FINDING_TEXT

    capture = prepared.get("packet_analysis", {})
    timeline = capture.get("protocol_timeline", {})
    chart = _bar_chart(capture.get("protocol_counts", {}))
    if prepared.get("synthetic"):
        chart = '<section><strong>合成示例</strong></section>' + chart
    if capture:
        chart += '<p>源报文：' + html.escape(_cell(capture.get("packets"))) + ' 帧 · 时间线省略：' + html.escape(_cell(timeline.get("dropped_events", 0))) + ' 个事件</p>'
    comparisons = prepared.get("changes", [])
    map_findings = []
    if prepared.get("kind") == "network-map":
        for row in prepared.get("findings", []):
            title, action = FINDING_TEXT.get(row["code"], (row["code"], ""))
            map_findings.append(dict(row, title=title, action=action))
    results = [
        _table("测绘来源", (("source_id", "来源"), ("kind", "类型"), ("label", "标识"),
                           ("observed_at", "观测时间"), ("status", "覆盖"), ("scope_status", "范围"),
                           ("coverage", "分区证据")), prepared.get("map_sources", [])),
        _table("安全发现", (("title", "发现"), ("severity", "级别"), ("node_id", "节点"),
                            ("source_id", "来源"), ("section", "证据区"), ("row", "记录"),
                            ("packet_number", "帧"), ("related_packet_number", "关联帧"), ("sample", "采样"),
                            ("before_source_line", "基线行"), ("after_source_line", "当前行"),
                            ("status", "状态"), ("cves", "CVE"), ("action", "复核")), map_findings),
        _table("测绘节点", (("node_id", "节点"), ("source_id", "来源"), ("kind", "类型"),
                            ("label", "标识"), ("context", "范围")), prepared.get("nodes", [])),
        _table("观测关系", (("from_node", "起点"), ("to_node", "终点"), ("kind", "关系"),
                            ("source_id", "来源"), ("section", "证据区"), ("row", "记录")),
               prepared.get("edges", [])),
        _table("协议时间线", (
            ("packet_number", "帧"), ("observed_at", "观测时间"), ("protocol", "协议"),
            ("event_type", "事件"), ("exchange_id", "交互"), ("src_address", "来源"),
            ("dst_address", "目标"), ("rtt_ms", "往返 ms"),
        ), timeline.get("events", [])),
        _table("TShark 解码", (("packet_number", "帧"), ("relative_ms", "相对 ms"),
                              ("wire_bytes", "字节"), ("protocols", "协议栈")), prepared.get("frames", [])),
        _table("拓扑关系", (("kind", "证据"), ("source", "来源"), ("target", "对象"), ("label", "状态")),
               observed_links(prepared)),
        _table("路由", (("prefix", "网段"), ("next_hop", "下一跳"), ("metric", "开销"),
                        ("interface", "接口"), ("protocol", "来源")), prepared.get("routes", [])),
        _table("设备证据差异", (("section", "类别"), ("identity", "对象"), ("change", "变化"),
                               ("before", "基线"), ("after", "当前")), comparisons),
        _table("诊断样本", (("sequence", "轮次"), ("observed_at", "时间"), ("stage", "环节"),
                            ("status", "状态")), diagnostic_rows(prepared)),
        _table("配置预览", (("line", "行"), ("command", "配置摘要")), [
            {"line": i, "command": line} for i, line in
            enumerate(prepared.get("config", {}).get("preview_lines", []), 1)
        ]),
        _table("监测告警", (("sequence", "轮次"), ("stage", "环节"), ("target", "目标"),
                           ("type", "变化")), prepared.get("alerts", [])),
    ]
    map_note = ('<p>抓包地址按文件汇总。关系和安全发现只覆盖所列来源与证据记录。</p>'
                if prepared.get("kind") == "network-map" else "")
    return (
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width,initial-scale=1"><title>WiFiScope 网络工作台</title>'
        '<style>body{margin:0;background:#eef2f7;color:#172b43;font:14px/1.6 system-ui,sans-serif}'
        'main{width:min(1200px,calc(100% - 36px));margin:24px auto}header{background:#142941;padding:22px;color:white;border-radius:12px}'
        'h1{margin:0}section,details{margin:16px 0;background:white;padding:15px 18px;border-radius:10px}'
        'h2{font-size:18px;margin:0 0 10px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}'
        'td,th{border-bottom:1px solid #dbe3ee;padding:7px 10px;text-align:left;overflow-wrap:anywhere}'
        'th{background:#e3ebf5}.bars{padding:0;list-style:none;margin:0}.bars li{display:grid;gap:8px;align-items:center;grid-template-columns:90px 1fr 58px}'
        'meter{width:100%;height:17px;accent-color:#28618e}summary{cursor:pointer;font-weight:650}</style>'
        '<main><header><h1>WiFiScope 网络工作台</h1><p>本地证据与本次结果</p></header>' +
        map_note + chart + "".join(results) +
        '<details><summary>原始字段表</summary><div class="scroll"><table>' + fields + '</table></div></details></main></html>'
    )


def export_network(report, directory, include_identifiers=False):
    return export_prepared_report(project_network(report, include_identifiers), directory, render_page=_page)
