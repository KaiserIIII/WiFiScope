"""Pure normalized geometry, conservative IDW support and safe static SVG."""

import html
import math

from .survey_schema import settings, validate_survey


def _cross(a, b, c):
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def _hull(points):
    points = sorted(points)
    lower, upper = [], []
    for chain, ordered in ((lower, points), (upper, reversed(points))):
        for point in ordered:
            while len(chain) >= 2 and _cross(chain[-2], chain[-1], point) <= 0:
                chain.pop()
            chain.append(point)
    return lower[:-1] + upper[:-1]


def _build_grid(survey, config):
    grouped = {}
    for row in survey["samples"]:
        if row["value"] is not None:
            grouped.setdefault((row["x"], row["y"]), []).append(row["value"])
    locations = [
        dict(x=x, y=y, value=math.fsum(values) / len(values), count=len(values))
        for (x, y), values in sorted(grouped.items())
    ]
    hull = _hull(grouped)
    surface = len(hull) >= 3
    cells = []
    size, radius, power = config["size"], config["radius"], config["power"]
    # Spatial buckets avoid scanning all 2000 observations for every grid cell.
    buckets = {}
    for row in locations:
        key = (math.floor(row["x"] / radius), math.floor(row["y"] / radius))
        buckets.setdefault(key, []).append(row)
    exact = {(row["x"], row["y"]): row for row in locations}
    for iy in range(size):
        for ix in range(size):
            x, y = ix / (size - 1), iy / (size - 1)
            cell = dict(x=x, y=y, value=None, kind="unknown", contributors=0)
            point = exact.get((x, y))
            if point is not None:
                cell.update(value=point["value"], kind="measured", contributors=1)
            elif surface and all(
                _cross(hull[i - 1], hull[i], (x, y)) >= -1e-12 for i in range(len(hull))
            ):
                bx, by = math.floor(x / radius), math.floor(y / radius)
                nearest = []
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        for row in buckets.get((bx + dx, by + dy), ()):
                            distance = math.hypot(x - row["x"], y - row["y"])
                            if distance <= radius:
                                nearest.append(
                                    (distance, row["x"], row["y"], row["value"])
                                )
                nearest = sorted(nearest)[:16]
                if len(nearest) >= 3:
                    # Relative weights keep tiny nonzero distances finite.
                    weights = [(nearest[0][0] / item[0]) ** power for item in nearest]
                    signal = math.fsum(
                        w * item[3] for w, item in zip(weights, nearest)
                    ) / math.fsum(weights)
                    signal = max(
                        min(item[3] for item in nearest),
                        min(max(item[3] for item in nearest), signal),
                    )
                    cell.update(
                        value=signal, kind="interpolated", contributors=len(nearest)
                    )
            cells.append(cell)
    measured = sum(row["value"] is not None for row in survey["samples"])
    return dict(
        config,
        cells=cells,
        locations=locations,
        measured_count=measured,
        unknown_count=len(survey["samples"]) - measured,
        estimated_count=sum(c["kind"] == "interpolated" for c in cells),
        notice="supported-surface" if surface else "insufficient-support",
    )


def interpolate_survey(survey, *, grid_size=40, radius=0.35, power=2) -> dict:
    config = settings(grid_size, radius, power)
    # Avoid rebuilding an obsolete imported grid before replacing settings.
    source = (
        {key: value for key, value in survey.items() if key != "grid"}
        if isinstance(survey, dict)
        else survey
    )
    result = validate_survey(source)
    result["grid"] = _build_grid(result, config)
    return result


def render_heatmap_svg(prepared_survey, *, synthetic: bool = False) -> str:
    """Render only bounded prepared identities, numbers and controlled prose."""
    if type(synthetic) is not bool:
        raise ValueError("Synthetic provenance must be an explicit boolean.")
    data = validate_survey(prepared_survey)
    if "grid" not in data:
        raise ValueError("Prepare survey interpolation before rendering the heatmap.")
    grid = data["grid"]

    def color(value):
        percent = (
            value if data["metric"] == "signal_percent" else (value + 150) * 100 / 150
        )
        level = round(255 * max(0, min(100, percent)) / 100)
        return f"#{255 - level:02x}{level:02x}40"

    height = 890 if synthetic else 860
    title = (
        "SYNTHETIC DEMO - Wireless survey signal heatmap"
        if synthetic else "Wireless survey signal heatmap"
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="720" height="{height}" viewBox="0 0 720 {height}">',
        f"<title>{title}</title>",
        '<rect x="10" y="10" width="700" height="700" fill="#eeeeee"/>',
    ]
    step = 700 / (grid["size"] - 1)
    hull = _hull([(r["x"], r["y"]) for r in grid["locations"]])
    for cell in grid["cells"]:
        if cell["kind"] != "interpolated":
            continue
        # Clip boundary cells to the normalized canvas, without SVG clip resources.
        x, y = 10 + cell["x"] * 700, 10 + cell["y"] * 700
        left, top = max(10, x - step / 2), max(10, y - step / 2)
        width, height = min(710, x + step / 2) - left, min(710, y + step / 2) - top
        corners = [
            ((px - 10) / 700, (py - 10) / 700)
            for px in (left, left + width)
            for py in (top, top + height)
        ]
        # A supported cell center does not license extrapolating its rectangular
        # footprint. Omit tiles crossing the hull or a shared three-point radius.
        if any(
            _cross(hull[i - 1], hull[i], corner) < -1e-12
            for corner in corners
            for i in range(len(hull))
        ):
            continue
        supported = 0
        for location in grid["locations"]:
            if all(
                math.hypot(cx - location["x"], cy - location["y"]) <= grid["radius"]
                for cx, cy in corners
            ):
                supported += 1
                if supported == 3:
                    break
        if supported < 3:
            continue
        parts.append(
            f'<rect x="{left:.6f}" y="{top:.6f}" width="{width:.6f}" height="{height:.6f}" fill="{color(cell["value"])}" opacity="0.55"/>'
        )
    for row in grid["locations"]:
        parts.append(
            f'<circle cx="{10 + row["x"] * 700:.6f}" cy="{10 + row["y"] * 700:.6f}" r="5" fill="{color(row["value"])}" stroke="#111111" stroke-width="2"/>'
        )
    for row in data["samples"]:
        if row["value"] is None:
            parts.append(
                f'<circle cx="{10 + row["x"] * 700:.6f}" cy="{10 + row["y"] * 700:.6f}" r="6" fill="none" stroke="#666666"/>'
            )
    metric = (
        "Signal percent (0 to 100)"
        if data["metric"] == "signal_percent"
        else "Signal dBm (-150 to 0)"
    )
    lines = [
        metric + ": red low, green high.",
        "Measured: outlined dots; Interpolated: translucent cells; Unknown: open circles.",
        f"Measured readings: {grid['measured_count']}; unknown readings: {grid['unknown_count']}.",
        "Insufficient support: no estimated surface."
        if grid["notice"] == "insufficient-support"
        else "Estimates masked to convex hull and three nearby locations.",
        "Signal only: time changes do not establish interference, throughput or security.",
        "Network: "
        + " / ".join(
            identity for identity in (data["ssid"], data["bssid"]) if identity
        ),
    ]
    if synthetic:
        lines.insert(0, "SYNTHETIC DEMO: illustrative readings; no actual network was sampled.")
    for i, line in enumerate(lines):
        emphasis = ' font-weight="bold" fill="#8b0000"' if synthetic and i == 0 else ''
        parts.append(
            f'<text x="10" y="{735 + i * 22}" font-size="12"{emphasis}>{html.escape(line, quote=True)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)
