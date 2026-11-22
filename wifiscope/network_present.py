"""Select workbench rows without changing the underlying evidence."""
import math


def packet_rows(events, *, protocol="", query="", page=0, size=120):
    query = query.strip().casefold()
    matches = []
    for event in events:
        if protocol and event.get("protocol") != protocol:
            continue
        if query and not any(query in str(event.get(key, "")).casefold() for key in (
            "protocol", "event_type", "src_address", "dst_address", "packet_number", "exchange_id",
            "src_port", "dst_port", "http_method", "status_code", "dns_type",
        )):
            continue
        matches.append(event)
    page = min(page, max(0, (len(matches) - 1) // size))
    return {"rows": matches[page * size:(page + 1) * size], "total": len(matches), "page": page}


def topology_links(device):
    """Show explicit adjacency and membership relationships from the imported data."""
    links = []
    for row in device.get("ospf_neighbors", []):
        if row.get("neighbor_id"):
            links.append({
                "source": row.get("source_device") or "本设备",
                "target": row["neighbor_id"], "label": row.get("state") or "OSPF",
                "kind": "OSPF", "note": row.get("interface"),
            })
    for row in device.get("lldp_neighbors", []):
        if row.get("device"):
            links.append({
                "source": row.get("source_device") or "本设备", "target": row["device"],
                "label": row.get("local_interface") or "LLDP", "kind": "LLDP",
                "note": row.get("remote_interface"),
            })
    for row in device.get("ports", []):
        if row.get("interface") and row.get("vlan_id") is not None:
            source = row.get("source_device")
            port = (source + "/" if source else "") + row["interface"]
            links.append({"source": "VLAN " + str(row["vlan_id"]), "target": port,
                              "label": "成员端口", "kind": "VLAN"})
    return links


def _ms(value):
    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
        return round(value, 3)
    return None


def diagnostic_rows(report):
    rows = []
    for sample in report.get("samples", []):
        for stage, item in sample.get("stages", {}).items():
            rows.append({
                "sequence": sample.get("sequence"), "observed_at": sample.get("observed_at"),
                "stage": stage, "status": item.get("status"), "evidence": item,
            })
    return rows


def latency_points(report):
    """Use measured stage latencies, retaining gaps as empty points."""
    series = {}
    for sample in report.get("samples", []):
        for stage, item in sample.get("stages", {}).items():
            if stage in ("gateway", "dns", "application"):
                evidence = item.get("evidence", item)
                value = next((_ms(evidence.get(k)) for k in (
                    "rtt_ms", "elapsed_ms", "rtt_mean_ms", "latency_ms", "duration_ms",
                ) if _ms(evidence.get(k)) is not None), None) if isinstance(evidence, dict) else None
                series.setdefault(stage, []).append((sample.get("sequence"), value))
    return {stage: points for stage, points in series.items() if any(v is not None for _, v in points)}
