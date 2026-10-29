"""Literal geometry and safe standalone SVG regression fixtures."""

import copy
import unittest
import xml.etree.ElementTree as ET

from wifiscope import heatmap


STAMP = "2026-10-28T12:00:00+00:00"


def survey(points, metric="signal_percent"):
    return dict(
        schema_version=1,
        id="survey-private",
        ssid="private-network",
        bssid="aa:bb:cc:dd:ee:ff",
        metric=metric,
        samples=[
            dict(
                id=f"sample-{i}",
                x=x,
                y=y,
                value=value,
                observed_at=STAMP,
                ssid="private-network",
                bssid="aa:bb:cc:dd:ee:ff",
                source="imported",
                gap="signal-unavailable" if value is None else None,
            )
            for i, (x, y, value) in enumerate(points)
        ],
    )


class HeatmapTests(unittest.TestCase):
    def test_renderer_synthetic_warning_is_explicit_boolean_and_default_is_ordinary(self):
        prepared = heatmap.interpolate_survey(survey([(0, 0, 40)]))
        self.assertNotIn('SYNTHETIC DEMO', heatmap.render_heatmap_svg(prepared))
        svg = heatmap.render_heatmap_svg(prepared, synthetic=True)
        root = ET.fromstring(svg)
        texts = root.findall('{http://www.w3.org/2000/svg}text')
        self.assertIn('SYNTHETIC DEMO', texts[0].text)
        self.assertLess(float(texts[-1].attrib['y']), float(root.attrib['height']))
        for value in ('PRIVATE PROSE', 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                heatmap.render_heatmap_svg(prepared, synthetic=value)

    def test_triangle_exact_boundary_outside_and_literal_idw(self):
        data = survey([(0, 0, 0), (1, 0, 100), (0, 1, 100)])
        before = copy.deepcopy(data)
        result = heatmap.interpolate_survey(data, grid_size=11, radius=1.5)
        cells = {(c["x"], c["y"]): c for c in result["grid"]["cells"]}
        self.assertEqual(cells[0, 0]["value"], 0)
        self.assertEqual(cells[0, 0]["kind"], "measured")
        self.assertAlmostEqual(cells[0.5, 0.5]["value"], 200 / 3)
        self.assertEqual(cells[0.5, 0.5]["contributors"], 3)
        self.assertEqual(cells[1, 1]["kind"], "unknown")
        self.assertEqual(data, before)

    def test_radius_requires_three_locations_even_inside_hull(self):
        result = heatmap.interpolate_survey(
            survey([(0, 0, 0), (1, 0, 100), (0, 1, 100)]), grid_size=11, radius=0.2
        )
        self.assertFalse(
            any(c["kind"] == "interpolated" for c in result["grid"]["cells"])
        )
        self.assertEqual(result["grid"]["cells"][0]["value"], 0)

    def test_duplicate_mean_counts_once_and_collinear_no_surface(self):
        result = heatmap.interpolate_survey(
            survey([(0, 0, 20), (0, 0, 60), (0.5, 0.5, 70), (1, 1, 90)]), grid_size=11
        )
        self.assertEqual(result["grid"]["locations"][0]["value"], 40)
        self.assertEqual(result["grid"]["locations"][0]["count"], 2)
        self.assertEqual(result["grid"]["notice"], "insufficient-support")
        self.assertEqual(result["grid"]["estimated_count"], 0)

    def test_unknown_and_two_points_do_not_paint(self):
        for points in ([], [(0, 0, None)], [(0, 0, 40)], [(0, 0, 40), (1, 1, 60)]):
            with self.subTest(points=points):
                result = heatmap.interpolate_survey(survey(points))
                self.assertEqual(result["grid"]["estimated_count"], 0)
                self.assertEqual(result["grid"]["notice"], "insufficient-support")

    def test_dbm_stays_dbm_and_svg_contains_only_safe_elements(self):
        data = survey([(0, 0, -90), (1, 0, -60), (0, 1, -60)], "dbm")
        data["ssid"] = '<svg onload="bad">&network'
        for row in data["samples"]:
            row["ssid"] = data["ssid"]
        data["notes"] = "arbitrary injected command"
        prepared = heatmap.interpolate_survey(data, grid_size=11, radius=1.5)
        self.assertAlmostEqual(prepared["grid"]["cells"][60]["value"], -70)
        svg = heatmap.render_heatmap_svg(prepared)
        root = ET.fromstring(svg)
        self.assertTrue(
            all(
                e.tag.rsplit("}", 1)[-1] in {"svg", "rect", "circle", "text", "title"}
                for e in root.iter()
            )
        )
        self.assertNotIn("<svg onload=", svg)
        self.assertNotIn("arbitrary injected", svg)
        self.assertIn("&lt;svg", svg)
        self.assertIn("dBm", svg)
        self.assertIn("Interpolated", svg)
        for element in root.iter():
            self.assertFalse(
                any(
                    k in {"href", "style", "src"} or k.startswith("on")
                    for k in element.attrib
                )
            )

    def test_settings_are_strict_and_bounded(self):
        for kwargs in (
            {"grid_size": True},
            {"grid_size": 101},
            {"radius": float("nan")},
            {"power": 10**500},
            {"power": 0.5},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                heatmap.interpolate_survey(survey([]), **kwargs)

    def test_svg_estimated_rectangles_never_extend_outside_hull(self):
        data = heatmap.interpolate_survey(
            survey([(0, 0, 0), (1, 0, 100), (0, 1, 100)]), grid_size=11, radius=1.5
        )
        root = ET.fromstring(heatmap.render_heatmap_svg(data))
        painted = [r for r in root if r.tag.endswith("rect") and "opacity" in r.attrib]
        self.assertGreater(len(painted), 0)
        for rect in painted:
            right = float(rect.attrib["x"]) + float(rect.attrib["width"])
            bottom = float(rect.attrib["y"]) + float(rect.attrib["height"])
            self.assertLessEqual(right + bottom, 720.000001)

    def test_max_sixteen_nearest_and_order_independent(self):
        points = [(i / 10, j / 10, 50) for i in range(4) for j in range(5)]
        a = heatmap.interpolate_survey(survey(points), grid_size=21, radius=1.5)
        b = heatmap.interpolate_survey(
            survey(list(reversed(points))), grid_size=21, radius=1.5
        )
        self.assertEqual(a["grid"], b["grid"])
        estimated = [c for c in a["grid"]["cells"] if c["kind"] == "interpolated"]
        self.assertTrue(estimated)
        self.assertEqual(max(c["contributors"] for c in estimated), 16)
        for cell in estimated:
            self.assertAlmostEqual(cell["value"], 50)

    def test_metric_extremes_roundtrip_typed_grid_without_overflow(self):
        from wifiscope.survey_schema import validate_survey

        for metric, signal in [("signal_percent", 100), ("dbm", -150)]:
            points = [(i / 10, j / 10, signal) for i in range(4) for j in range(5)]
            data = heatmap.interpolate_survey(
                survey(points, metric), grid_size=21, radius=1.5
            )
            validate_survey(data)
            for cell in data["grid"]["cells"]:
                if cell["value"] is not None:
                    self.assertEqual(cell["value"], signal)
