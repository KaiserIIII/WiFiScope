# Sampled Wi-Fi survey and heatmap

The offline survey engine associates timestamped signal readings with normalized
coordinates on one selected network. Importing a project or running the command
does not collect Wi-Fi data or access the network. The sample API consumes an
existing collector's Wi-Fi rows. The desktop **Wi-Fi 热力图** tool offers an actual
normalized canvas in both modes: choose network and metric, create a project,
click a position, then explicitly sample once. The observed timestamp comes from
that collector result. Clicking, opening, resizing, panning, zooming or importing
does not collect. Changed network/metric fields require a new project instead of
silently changing historical identities. Synthetic projects reject measured
sampling to prevent mixed evidence.

The optional PNG/GIF background is local only, bounded to 8 MiB, 8192 per axis and
32 million pixels before image allocation. GIF frames are also checked against
the declared canvas and aggregate pixel/frame limits. URLs/UNC backgrounds, SVG
and external images are refused. Imported projects never load a floorplan path.
Background pixels and paths never enter ordinary exports/cases. Blank canvas
works without a floorplan. Zoom/pan only change display transforms; source x/y
remain normalized. The canvas paints cached engine-prepared safe footprints;
geometry preparation and exports use the shared worker. The sample table lists
actual timestamps, values/unknown gaps and coordinates. Local point removal can
be undone in memory. Project saves are new exclusive files retaining local
identifiers; tool report export defaults to HMAC and adds safe `heatmap.svg`.

Synthetic desktop projects cannot be saved in the native project format: that
format stores the survey extension alone and does not preserve the surrounding
report's synthetic warning. The Save action explains this and writes no file.
Use **导出工具结果** instead to retain the synthetic marker in the report and SVG
bundle; synthetic projects remain blocked from live sampling. Ordinary project
save/load formats are unchanged. Successful JSON/CSV/demo replacement clears
point-removal history, even when the imported project reuses the same ID. Undo
within one project restores its complete report provenance; a failed import
preserves the current project and its undo history.

```console
python -m wifiscope survey --input samples.csv --format csv --grid-size 40 --radius .35 --power 2 --out NEW_BUNDLE
python -m wifiscope survey --input project.json --format json
```

`--out` requires a new directory. It publishes `report.json`, `report.csv`,
`report.html` and `heatmap.svg` together through the existing exclusive exporter.
Without `--out`, stdout is a privacy-projected JSON report. Identifiers are
independent per-export HMAC pseudonyms by default. `--include-identifiers` retains
them explicitly. The SVG uses the exact same prepared identities as the JSON;
there is no separate heatmap key. Case snapshots and re-exports retain joins.
No floorplan image or local path is copied or embedded. The CSV report is the
existing flattened typed report, not a second survey import format.

## CSV input

UTF-8 and UTF-8 BOM are accepted. These seven headers are required, in any order:

```csv
x,y,value,observed_at,ssid,bssid,metric
0,0,42,2026-10-28T12:00:00+00:00,Example,02:00:00:00:00:01,signal_percent
1,0,70,2026-10-28T12:01:00+00:00,Example,02:00:00:00:00:01,signal_percent
0,1,,2026-10-28T12:02:00+00:00,Example,02:00:00:00:00:01,signal_percent
```

Every row repeats the same network and metric. At least SSID or BSSID must be
nonempty. Prefer a BSSID, since an SSID may name multiple APs. Blank values are
unknown readings, not zero. Percent is 0–100; measured `dbm` is −150–0. No
conversion is inferred. Coordinates are 0–1, independent of background pixels.
Dates must be valid timezone-aware ISO timestamps. Arbitrary prose, HTML or
formula strings cannot become coordinates or signal values. Identifiers are
escaped as text only, and spreadsheet-formula prefixes are neutralized in the
exported CSV. Different APs or metrics cannot be combined silently.

## Native JSON and Python API

Native JSON is a single versioned survey object, not an enclosing report:

```json
{
  "schema_version": 1,
  "id": "example-survey",
  "ssid": "Example",
  "bssid": "02:00:00:00:00:01",
  "metric": "signal_percent",
  "samples": [
    {"id": "point-1", "x": 0, "y": 0, "value": 42,
     "observed_at": "2026-10-28T12:00:00+00:00",
     "ssid": "Example", "bssid": "02:00:00:00:00:01",
     "source": "imported", "gap": null}
  ]
}
```

`validate_survey(value) -> dict` returns fresh canonical typed data and never
mutates the input. Sample SSID/BSSID may be omitted to inherit the selection;
`source` defaults to `imported`. Unknown values require one controlled gap:
`signal-unavailable`, `selected-network-missing` or `ambiguous-network`.
Known values require a null/omitted gap. Titles, notes, commands, floorplan paths
and other unknown fields are discarded. Duplicate JSON keys/sample IDs, malformed
shapes, contradictory network identities, booleans in numeric fields, nonfinite
values and excessive numbers are rejected with a controlled error.

`survey.add_sample(survey, x, y, wifi_rows, observed_at) -> dict` reads no adapter.
It matches the explicit selected BSSID, or selected SSID if no BSSID was chosen.
Multiple APs/rows produce an unknown `ambiguous-network` reading. One explicitly identified AP
pins an SSID-only selection to that BSSID, including the chosen identity on
earlier unknown samples; this association does not fill their signal values.
Earlier known signals whose AP was unidentified cannot safely join the later
AP: this context is rejected with a controlled instruction to start a new
BSSID-selected survey. Their historical BSSID is never inferred. All explicit
sample AP identities participate in conflict checks, including unknown signals.
The strongest unrelated AP is never substituted. Missing/invalid signal remains
unknown. Only the selected metric field is read; percent cannot supply dBm.

`survey.import_survey(bytes, 'json'|'csv')` marks samples as imported, even if a
JSON source claimed measurement. `survey.load_project(path)` preserves the typed
stored sources and IDs, and never loads external references. These local stored
sources are provenance labels, not proof of authenticity.
`survey.save_project(survey, path)` saves canonical JSON with actual associations
to an exclusive new file. It refuses overwrite. Local project files contain
identifiers; use ordinary report export for a shareable privacy projection.

## Geometry and data quality

`heatmap.interpolate_survey(survey, *, grid_size=40, radius=.35, power=2)` returns
the survey plus a typed `grid`. Grid size is 10–100 per side, radius .05–1.5
normalized units, and IDW power 1–4. The engine uses at most 16 nearest distinct
valid locations within radius, with deterministic coordinate ordering for ties.
Repeated valid readings at exactly the same location use their arithmetic mean
and retain a reading count. Unknown readings do not contribute or gain values.

An estimated cell needs at least three distinct nearby valid locations and a
position inside the convex hull. Three non-collinear valid locations are needed
for a surface anywhere. Exact grid-point matches retain the observed-location
mean with `kind=measured`; all estimates have `kind=interpolated`. Other cells
remain `kind=unknown`. Empty, one/two-location and collinear data show only dots
and an insufficient-support notice. Local unknown samples remain explicit open
circles even where a separate estimate is supported.

`grid` contains `size/radius/power`, `cells` with
`x/y/value/kind/contributors`, `locations` with `x/y/value/count`,
`measured_count`, `unknown_count`, `estimated_count` and the controlled `notice`.
Counts refer to known/unknown sample readings, not floor area or security checks.
Any imported grid must have valid typed shapes; derived numbers are regenerated
from samples/settings before export, so a saved grid cannot forge estimates.

`heatmap.render_heatmap_svg(prepared_survey)` accepts only this prepared typed
data. It renders numeric rectangles/circles and escaped text, without scripts,
links, external resources, images or executable styles. Measurements have solid
outlines; estimates are translucent; unknown readings have open outlines. A
rectangle is omitted if any part crosses the hull or lacks three common
in-radius contributors covering its entire footprint. This conservative tile
mask may omit edge cells counted in the numeric grid. The legend preserves the
metric and shows measured/unknown counts and support limitations.

Inputs are limited to 16 MiB, 2,000 samples, 10,000 grid cells, 16 nesting levels,
300,000 traversed elements and bounded fields/strings. CSV limits rows and field
length before retaining samples. IDs/network strings are at most 256 characters;
dates at most 64. No dependencies or plotting packages are required.

Investigation coverage has `category=wireless-survey`, `partial=true`, known,
unknown, measured and imported reading counts. Attempted means all supplied
sample locations; unknown readings are not labeled unattempted. No signal value
or absence of findings implies a security pass. Temporal signal changes do not
establish RF interference, throughput, wall attenuation or building coverage.
Merging survey reports is explicitly refused until distinct coordinate/network
contexts can be retained; existing audit and capture extensions remain intact.

Validation uses synthetic observations, real local file/bundle/case operations,
and fake capture adapters only. No physical Wi-Fi measurement, background image
calibration, RF model, live survey UI or field accuracy claim is made.
