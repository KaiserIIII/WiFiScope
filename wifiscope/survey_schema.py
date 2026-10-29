"""Bounded typed survey extension and shared per-export identity projection."""

from datetime import datetime
import math

MAX_BYTES = 16 * 1024 * 1024
GAPS = frozenset(
    ("signal-unavailable", "selected-network-missing", "ambiguous-network")
)


def _bad():
    raise ValueError(
        "Invalid bounded survey; use schema_version=1, one selected network and normalized typed samples."
    )


def bounded(value):
    pending = [(value, 0)]
    count = size = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        size += 8
        if depth > 16 or count > 300000 or size > MAX_BYTES:
            _bad()
        if isinstance(item, dict):
            if len(item) > 32 or any(
                not isinstance(k, str) or len(k) > 128 for k in item
            ):
                _bad()
            pending.extend(
                (child, depth + 1) for pair in item.items() for child in pair
            )
        elif isinstance(item, list):
            if len(item) > 10000:
                _bad()
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > 4096:
                _bad()
            try:
                size += len(item.encode("utf-8"))
            except UnicodeError:
                _bad()
        elif item is not None and type(item) not in (int, float, bool):
            _bad()
        if type(item) in (int, float) and (
            not -(10**12) <= item <= 10**12 or not math.isfinite(item)
        ):
            _bad()


def number(value, low, high):
    if (
        type(value) not in (int, float)
        or not low <= value <= high
        or not math.isfinite(value)
    ):
        _bad()
    return value


def _identity(value, optional=False):
    if value is None and optional:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(ord(c) < 32 or ord(c) in (65534, 65535) for c in value)
    ):
        _bad()
    return value


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        _bad()
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            _bad()
    except (ValueError, OverflowError):
        _bad()
    return stamp.isoformat()


def settings(grid_size=40, radius=0.35, power=2):
    if type(grid_size) is not int or not 10 <= grid_size <= 100:
        _bad()
    return dict(
        size=grid_size, radius=number(radius, 0.05, 1.5), power=number(power, 1, 4)
    )


def validate_survey(value) -> dict:
    """Return fresh canonical data, discarding notes, titles and external paths."""
    bounded(value)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
    ):
        _bad()
    ssid, bssid = (
        _identity(value.get("ssid"), True),
        _identity(value.get("bssid"), True),
    )
    if ssid is None and bssid is None:
        _bad()
    metric = value.get("metric")
    if metric not in ("signal_percent", "dbm"):
        _bad()
    rows = value.get("samples")
    if not isinstance(rows, list) or len(rows) > 2000:
        _bad()
    result = dict(
        schema_version=1,
        id=_identity(value.get("id")),
        ssid=ssid,
        bssid=bssid,
        metric=metric,
        samples=[],
    )
    seen, explicit_bssids = set(), set()
    for row in rows:
        if not isinstance(row, dict):
            _bad()
        identifier = _identity(row.get("id"))
        if identifier in seen:
            _bad()
        seen.add(identifier)
        rs, rb = (
            _identity(row.get("ssid", ssid), True),
            _identity(row.get("bssid", bssid), True),
        )
        if (ssid is not None and rs != ssid) or (bssid is not None and rb != bssid):
            _bad()
        if rb is not None:
            explicit_bssids.add(rb)
        signal, gap = row.get("value"), row.get("gap")
        if signal is None:
            if not isinstance(gap, str) or gap not in GAPS:
                _bad()
        else:
            number(
                signal,
                0 if metric == "signal_percent" else -150,
                100 if metric == "signal_percent" else 0,
            )
            if gap is not None:
                _bad()
        source = row.get("source", "imported")
        if source not in ("measured", "imported"):
            _bad()
        result["samples"].append(
            dict(
                id=identifier,
                x=number(row.get("x"), 0, 1),
                y=number(row.get("y"), 0, 1),
                value=signal,
                observed_at=_time(row.get("observed_at")),
                ssid=rs,
                bssid=rb,
                source=source,
                gap=gap,
            )
        )
    if len(explicit_bssids) > 1:
        _bad()
    # Every explicit AP identity participates, including unavailable signals.
    # Earlier known signals with an unidentified AP cannot join a later AP:
    # doing so would invent their historical provenance and may blend APs.
    if bssid is None and explicit_bssids:
        if any(
            row["value"] is not None and row["bssid"] is None
            for row in result["samples"]
        ):
            raise ValueError(
                "Survey AP identity is ambiguous; start a new BSSID-selected survey for readings with an unidentified AP."
            )
        result["bssid"] = next(iter(explicit_bssids))
        for row in result["samples"]:
            if row["bssid"] is None and row["value"] is None:
                row["bssid"] = result["bssid"]
    result["gaps"] = sorted({row["gap"] for row in result["samples"] if row["gap"]})
    if "grid" in value:
        grid = value["grid"]
        if not isinstance(grid, dict):
            _bad()
        config = settings(grid.get("size"), grid.get("radius"), grid.get("power"))
        cells, locations = grid.get("cells"), grid.get("locations")
        if (
            not isinstance(cells, list)
            or len(cells) != config["size"] ** 2
            or not isinstance(locations, list)
            or len(locations) > 2000
            or grid.get("notice") not in ("supported-surface", "insufficient-support")
        ):
            _bad()
        for name in ("measured_count", "unknown_count", "estimated_count"):
            if type(grid.get(name)) is not int or not 0 <= grid[name] <= 10000:
                _bad()
        for cell in cells:
            if not isinstance(cell, dict) or cell.get("kind") not in (
                "measured",
                "interpolated",
                "unknown",
            ):
                _bad()
            number(cell.get("x"), 0, 1)
            number(cell.get("y"), 0, 1)
            if (
                type(cell.get("contributors")) is not int
                or not 0 <= cell["contributors"] <= 16
            ):
                _bad()
            if cell["kind"] == "unknown":
                if cell.get("value") is not None or cell["contributors"] != 0:
                    _bad()
            else:
                number(
                    cell.get("value"),
                    0 if metric == "signal_percent" else -150,
                    100 if metric == "signal_percent" else 0,
                )
                if cell["contributors"] < (3 if cell["kind"] == "interpolated" else 1):
                    _bad()
        for location in locations:
            if (
                not isinstance(location, dict)
                or type(location.get("count")) is not int
                or not 1 <= location["count"] <= 2000
            ):
                _bad()
            number(location.get("x"), 0, 1)
            number(location.get("y"), 0, 1)
            number(
                location.get("value"),
                0 if metric == "signal_percent" else -150,
                100 if metric == "signal_percent" else 0,
            )
        # Derived fields are regenerated from samples, never trusted on import.
        from .heatmap import _build_grid

        result["grid"] = _build_grid(result, config)
    return result


def project_survey(value, identity) -> dict:
    result = validate_survey(value)
    for field in ("id", "ssid", "bssid"):
        result[field] = identity(result[field])
    for row in result["samples"]:
        for field in ("id", "ssid", "bssid"):
            row[field] = identity(row[field])
    return result
