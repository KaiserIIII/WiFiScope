"""Offline sampled survey projects. No collection, network IO or external images."""

import csv
import io
import json
from pathlib import Path
import uuid

from .survey_schema import MAX_BYTES, _bad, _identity, number, validate_survey


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _bad()
        result[key] = value
    return result


def add_sample(survey, x, y, wifi_rows, observed_at) -> dict:
    data = validate_survey(survey)
    data.pop("grid", None)
    number(x, 0, 1)
    number(y, 0, 1)
    if (
        not isinstance(wifi_rows, list)
        or len(wifi_rows) > 2000
        or any(not isinstance(row, dict) for row in wifi_rows)
    ):
        _bad()
    rows = [
        row
        for row in wifi_rows
        if (
            row.get("bssid") == data["bssid"]
            if data["bssid"] is not None
            else row.get("ssid") == data["ssid"]
        )
    ]
    gap, value = "selected-network-missing", None
    sample_bssid = data["bssid"]
    if rows:
        for row in rows:
            _identity(row.get("bssid"), True)
        if len(rows) != 1:
            gap = "ambiguous-network"
        else:
            row = rows[0]
            if data["ssid"] is not None and row.get("ssid") != data["ssid"]:
                gap = "ambiguous-network"
            else:
                sample_bssid = row.get("bssid") or data["bssid"]
                value = row.get(data["metric"])
                try:
                    number(
                        value,
                        0 if data["metric"] == "signal_percent" else -150,
                        100 if data["metric"] == "signal_percent" else 0,
                    )
                except ValueError:
                    value = None
                gap = "signal-unavailable" if value is None else None
    data["samples"].append(
        dict(
            id=uuid.uuid4().hex,
            x=x,
            y=y,
            value=value,
            observed_at=observed_at,
            ssid=data["ssid"],
            bssid=sample_bssid,
            source="measured",
            gap=gap,
        )
    )
    return validate_survey(data)


def import_survey(data: bytes, kind: str) -> dict:
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        _bad()
    try:
        text = data.decode("utf-8-sig")
        if kind == "json":

            def reject(_):
                _bad()

            result = validate_survey(
                json.loads(text, parse_constant=reject, object_pairs_hook=_json_pairs)
            )
        elif kind == "csv":
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            headers = next(reader)
            required = ["x", "y", "value", "observed_at", "ssid", "bssid", "metric"]
            if len(headers) != len(required) or set(headers) != set(required):
                _bad()
            result, chosen = None, None
            for index, fields in enumerate(reader):
                if (
                    index >= 2000
                    or len(fields) != 7
                    or any(len(field) > 256 for field in fields)
                ):
                    _bad()
                row = dict(zip(headers, fields))
                network = (row["ssid"] or None, row["bssid"] or None, row["metric"])
                if chosen is not None and chosen != network:
                    _bad()
                if result is None:
                    chosen = network
                    result = dict(
                        schema_version=1,
                        id=uuid.uuid4().hex,
                        ssid=network[0],
                        bssid=network[1],
                        metric=network[2],
                        samples=[],
                    )
                value = float(row["value"]) if row["value"] else None
                result["samples"].append(
                    dict(
                        id=uuid.uuid4().hex,
                        x=float(row["x"]),
                        y=float(row["y"]),
                        value=value,
                        observed_at=row["observed_at"],
                        ssid=network[0],
                        bssid=network[1],
                        source="imported",
                        gap="signal-unavailable" if value is None else None,
                    )
                )
            result = validate_survey(result)
        else:
            _bad()
        # A native project is imported evidence, never an implied live collection.
        for row in result["samples"]:
            row["source"] = "imported"
        return result
    except (
        ValueError,
        TypeError,
        UnicodeError,
        RecursionError,
        OverflowError,
        csv.Error,
        StopIteration,
    ):
        _bad()


def load_project(path) -> dict:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        _bad()
    try:

        def reject(_):
            _bad()

        return validate_survey(
            json.loads(
                raw.decode("utf-8-sig"),
                parse_constant=reject,
                object_pairs_hook=_json_pairs,
            )
        )
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _bad()


def save_project(survey, path) -> None:
    data = validate_survey(survey)
    encoded = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    )
    if len(encoded) > MAX_BYTES:
        _bad()
    with Path(path).open("xb") as stream:
        stream.write(encoded)
