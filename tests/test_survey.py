"""Offline survey validation, selected network, persistence and privacy boundaries."""

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from wifiscope import survey as engine
from wifiscope.heatmap import interpolate_survey
from wifiscope.survey_schema import validate_survey
from test_heatmap import survey, STAMP


class SurveyTests(unittest.TestCase):
    def test_validation_copies_discards_prose_and_rejects_conflicts(self):
        data = survey([(0, 0, 42)])
        data["floorplan"] = "C:/secret.png"
        before = copy.deepcopy(data)
        result = validate_survey(data)
        self.assertNotIn("floorplan", result)
        self.assertEqual(data, before)
        result["samples"][0]["x"] = 0.5
        self.assertEqual(data["samples"][0]["x"], 0)
        for field, value in [
            ("x", True),
            ("x", -1),
            ("y", float("inf")),
            ("value", 101),
            ("observed_at", "yesterday"),
            ("bssid", "other"),
        ]:
            broken = copy.deepcopy(data)
            broken["samples"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_survey(broken)
        for field, value in [
            ("schema_version", True),
            ("metric", "rssi"),
            ("samples", [data["samples"][0]] * 2001),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_survey(dict(data, **{field: value}))

    def test_duplicate_id_bad_date_huge_number_and_unknown_gap(self):
        for mutate in (
            lambda d: d["samples"].append(copy.deepcopy(d["samples"][0])),
            lambda d: d["samples"][0].update(value=10**500),
            lambda d: d["samples"][0].update(observed_at="2026-02-30T00:00:00Z"),
            lambda d: d["samples"][0].update(value=None, gap="injected prose"),
        ):
            data = survey([(0, 0, 40)])
            mutate(data)
            with self.assertRaises(ValueError):
                validate_survey(data)

    def test_add_sample_only_selected_bssid_and_preserves_unknown(self):
        data = survey([])
        rows = [
            dict(ssid="private-network", bssid="other", signal_percent=99),
            dict(ssid="private-network", bssid=data["bssid"], signal_percent=42),
        ]
        actual = engine.add_sample(data, 0.2, 0.3, rows, STAMP)
        self.assertEqual(actual["samples"][0]["value"], 42)
        self.assertEqual(actual["samples"][0]["source"], "measured")
        self.assertEqual(data["samples"], [])
        missing = engine.add_sample(data, 0.2, 0.3, rows[:1], STAMP)
        self.assertIsNone(missing["samples"][0]["value"])
        self.assertEqual(missing["samples"][0]["gap"], "selected-network-missing")
        dbm = engine.add_sample(dict(data, metric="dbm"), 0, 0, rows, STAMP)
        self.assertIsNone(dbm["samples"][0]["value"])

    def test_ssid_ambiguity_cannot_mix_bssids_across_samples(self):
        data = dict(survey([]), bssid=None)
        rows = [
            dict(ssid=data["ssid"], bssid="first", signal_percent=50),
            dict(ssid=data["ssid"], bssid="second", signal_percent=80),
        ]
        result = engine.add_sample(data, 0, 0, rows, STAMP)
        self.assertEqual(result["samples"][0]["gap"], "ambiguous-network")
        first = engine.add_sample(data, 0, 0, rows[:1], STAMP)
        self.assertEqual(first["bssid"], "first")
        second = engine.add_sample(first, 1, 0, rows[1:], STAMP)
        self.assertIsNone(second["samples"][1]["value"])

    def test_import_save_bounds_and_no_overwrite(self):
        csv = (
            "\ufeffx,y,value,observed_at,ssid,bssid,metric\n0,0,42,"
            + STAMP
            + ",network,ap,signal_percent\n1,1,,"
            + STAMP
            + ",network,ap,signal_percent\n"
        )
        loaded = engine.import_survey(csv.encode("utf-8"), "csv")
        self.assertEqual([s["value"] for s in loaded["samples"]], [42, None])
        for raw, kind in [
            (b"[]", "json"),
            (b'{"schema_version":NaN}', "json"),
            (b"x,y\n0,0", "csv"),
            (csv.replace("42", "=1+2").encode(), "csv"),
            (
                csv.replace("1,1,,", "1,1,22,")
                .replace(
                    "network,ap,signal_percent\n", "network,ap,signal_percent\n", 1
                )
                .replace(
                    "1,1,22," + STAMP + ",network,ap",
                    "1,1,22," + STAMP + ",network,other",
                )
                .encode(),
                "csv",
            ),
            (b" " * (16 * 1024 * 1024 + 1), "json"),
        ]:
            with self.subTest(kind=kind, size=len(raw)), self.assertRaises(ValueError):
                engine.import_survey(raw, kind)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "project.json"
            engine.save_project(loaded, path)
            self.assertEqual(engine.load_project(path), loaded)
            with self.assertRaises(FileExistsError):
                engine.save_project(survey([]), path)

    def test_export_case_reexport_identity_joins_and_bundle(self):
        from wifiscope.reports import prepare_export, export_report
        from wifiscope.investigate import build_investigation, merge_reports
        from wifiscope.cases import CaseStore

        data = interpolate_survey(
            survey([(0, 0, 50), (1, 0, 80), (0, 1, None)]), grid_size=11
        )
        report = build_investigation(
            dict(
                schema_version=1,
                wifi_survey=data,
                wifi=[dict(ssid=data["ssid"], bssid=data["bssid"])],
            )
        )
        prepared = prepare_export(report)
        self.assertEqual(prepared["wifi"][0]["bssid"], prepared["wifi_survey"]["bssid"])
        self.assertEqual(
            prepared["wifi_survey"]["samples"][0]["bssid"], prepared["wifi"][0]["bssid"]
        )
        self.assertNotIn("private-network", json.dumps(prepared))
        coverage = next(
            c
            for c in prepared["investigation"]["coverage"]
            if c["category"] == "wireless-survey"
        )
        self.assertEqual(coverage["evaluated"], 2)
        self.assertEqual(coverage["attempted"], 3)
        self.assertIsNone(coverage["unattempted"])
        self.assertEqual(coverage["unknown"], 1)
        self.assertEqual(coverage["imported"], 2)
        self.assertEqual(coverage["measured"], 0)
        with self.assertRaises(ValueError):
            merge_reports([report])
        with tempfile.TemporaryDirectory() as tmp:
            with CaseStore(Path(tmp) / "case.db") as store:
                for raw in (False, True):
                    loaded = store.load_snapshot(
                        store.add_snapshot(report, include_identifiers=raw)
                    )
                    again = prepare_export(loaded, include_identifiers=True)
                    self.assertEqual(
                        again["wifi_survey"]["bssid"], loaded["wifi"][0]["bssid"]
                    )
                    self.assertEqual(
                        again["wifi_survey"]["samples"][0]["id"],
                        loaded["wifi_survey"]["samples"][0]["id"],
                    )
            files = export_report(report, Path(tmp) / "bundle")
            self.assertIn("svg", files)
            self.assertNotIn("private-network", Path(files["svg"]).read_text())
            self.assertIn(
                "Wireless survey", Path(files["html"]).read_text(encoding="utf-8")
            )
            with self.assertRaises(FileExistsError):
                export_report(report, Path(tmp) / "bundle")

    def test_cli_offline_new_bundle_and_controlled_invalid_input(self):
        from wifiscope.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(survey([(0, 0, 50)])))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(
                    main(
                        [
                            "survey",
                            "--input",
                            str(path),
                            "--format",
                            "json",
                            "--out",
                            str(Path(tmp) / "bundle"),
                        ]
                    ),
                    0,
                )
            self.assertIn("svg", out.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "survey",
                            "--input",
                            str(path),
                            "--format",
                            "json",
                            "--out",
                            str(Path(tmp) / "bundle"),
                        ]
                    ),
                    2,
                )

    def test_malformed_grid_shape_is_rejected_and_forged_values_regenerated(self):
        original = interpolate_survey(
            survey([(0, 0, 20), (1, 0, 80), (0, 1, 80)]), grid_size=11, radius=1.5
        )
        malformed = copy.deepcopy(original)
        malformed["grid"]["cells"] = "malformed"
        with self.assertRaises(ValueError):
            validate_survey(malformed)
        forged = copy.deepcopy(original)
        forged["grid"]["cells"][0]["value"] = 99
        self.assertEqual(validate_survey(forged)["grid"]["cells"][0]["value"], 20)

    def test_project_keeps_measured_source_and_ssid_pin_after_unknown(self):
        data = dict(survey([]), bssid=None)
        data = engine.add_sample(data, 0, 0, [], STAMP)
        data = engine.add_sample(
            data,
            1,
            0,
            [dict(ssid=data["ssid"], bssid="one-ap", signal_percent=50)],
            STAMP,
        )
        self.assertEqual(data["bssid"], "one-ap")
        self.assertEqual(data["samples"][0]["bssid"], "one-ap")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "measured.json"
            engine.save_project(data, path)
            self.assertEqual(engine.load_project(path), data)

    def test_nested_and_csv_row_field_bounds_control_errors(self):
        for value in (
            [[]],
            {"schema_version": 1, "metric": []},
            dict(survey([]), unknown="x" * 4097),
        ):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError):
                validate_survey(value)
        nested = survey([])
        node = nested
        for _ in range(20):
            node["extra"] = {}
            node = node["extra"]
        with self.assertRaises(ValueError):
            validate_survey(nested)
        header = "x,y,value,observed_at,ssid,bssid,metric\n"
        row = "0,0,50," + STAMP + ",network,ap,signal_percent\n"
        for raw in (
            (header + row * 2001).encode(),
            (header + row.replace("network", "x" * 257)).encode(),
            b'{"schema_version":1,"samples":' + b"[" * 100 + b"]" * 100 + b"}",
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                engine.import_survey(raw, "csv" if raw.startswith(b"x,") else "json")

    def test_extension_preserves_vulnerability_and_capture_in_case(self):
        from test_live_capture import FakeBackend, packet
        from wifiscope.live_capture import capture_live
        from wifiscope.vulnerabilities import audit_vulnerabilities
        from wifiscope.cases import CaseStore
        from wifiscope.reports import prepare_export

        report = capture_live(
            "owned-test", authorized=True, backend=FakeBackend([packet()])
        )
        report = audit_vulnerabilities(report)
        report["wifi_survey"] = interpolate_survey(survey([(0, 0, 50)]), grid_size=11)
        with (
            tempfile.TemporaryDirectory() as tmp,
            CaseStore(Path(tmp) / "all.db") as store,
        ):
            loaded = store.load_snapshot(store.add_snapshot(report))
            again = prepare_export(loaded)
            for field in ("vulnerability_audit", "capture_session", "wifi_survey"):
                self.assertIn(field, again)
            self.assertEqual(again["capture_session"]["packets"], 1)

    def test_collection_invalid_signal_and_missing_identity_do_not_fabricate(self):
        data = survey([])
        for signal in (True, float("nan"), float("inf"), 10**500, -1):
            result = engine.add_sample(
                data,
                0,
                0,
                [dict(ssid=data["ssid"], bssid=data["bssid"], signal_percent=signal)],
                STAMP,
            )
            self.assertIsNone(result["samples"][0]["value"])
        for mutate in (
            lambda d: d.update(ssid=None, bssid=None),
            lambda d: d["samples"][0].update(gap=[]),
            lambda d: d["samples"][0].update(value=float("nan")),
        ):
            broken = survey([(0, 0, None)])
            mutate(broken)
            with self.assertRaises(ValueError):
                validate_survey(broken)

    def test_duplicate_json_fields_are_refused_and_raw_import_is_not_measured(self):
        raw = json.dumps(survey([(0, 0, 50)])).replace('"x": 0', '"x": 1, "x": 0')
        with self.assertRaises(ValueError):
            engine.import_survey(raw.encode(), "json")
        data = survey([(0, 0, 50)])
        data["samples"][0]["source"] = "measured"
        imported = engine.import_survey(json.dumps(data).encode(), "json")
        self.assertEqual(imported["samples"][0]["source"], "imported")

    def test_collector_malformed_identity_is_controlled_and_limit_grid_survives(self):
        data = dict(survey([]), bssid=None)
        with self.assertRaises(ValueError):
            engine.add_sample(
                data,
                0,
                0,
                [dict(ssid=data["ssid"], bssid=[], signal_percent=50)],
                STAMP,
            )
        data = survey([(0, 0, 50)] * 2000)
        result = interpolate_survey(data, grid_size=100)
        self.assertEqual(len(result["grid"]["cells"]), 10000)
        self.assertEqual(result["grid"]["locations"][0]["count"], 2000)
        self.assertEqual(validate_survey(result)["grid"]["measured_count"], 2000)

    def test_canonical_survey_used_by_investigation(self):
        from wifiscope.investigate import build_investigation

        data = survey([(0, 0, None)])
        del data["samples"][0]["value"]
        model = build_investigation(dict(schema_version=1, wifi_survey=data))
        self.assertIsNone(model["wifi_survey"]["samples"][0]["value"])

    def test_only_root_survey_bypasses_generic_metric_validation(self):
        from wifiscope.case_validation import validate_report

        with self.assertRaises(ValueError):
            validate_report(
                dict(
                    schema_version=1,
                    investigation=dict(wifi_survey=dict(metric="not-a-routing-number")),
                )
            )


class SurveyIdentityTests(unittest.TestCase):
    def test_schema_refuses_to_assign_an_ap_to_historical_known_unidentified_signal(
        self,
    ):
        data = survey([(0, 0, 20), (1, 0, 80)])
        data["bssid"] = None
        data["samples"][0]["bssid"] = None
        data["samples"][1]["bssid"] = "AP-A"
        before = copy.deepcopy(data)
        with self.assertRaises(ValueError):
            validate_survey(data)
        self.assertEqual(data, before)
        self.assertIsNone(data["samples"][0]["bssid"])

    def test_add_sample_refuses_later_ap_without_rewriting_known_unidentified_signal(
        self,
    ):
        data = survey([(0, 0, 20)])
        data["bssid"] = data["samples"][0]["bssid"] = None
        before = copy.deepcopy(data)
        with self.assertRaises(ValueError):
            engine.add_sample(
                data,
                1,
                0,
                [dict(ssid=data["ssid"], bssid="AP-A", signal_percent=80)],
                STAMP,
            )
        self.assertEqual(data, before)
        self.assertIsNone(data["samples"][0]["bssid"])

    def test_unknown_explicit_other_ap_is_rejected_before_canonicalization_and_export(
        self,
    ):
        from wifiscope.reports import prepare_export

        for reverse in (False, True):
            data = survey([(0, 0, None), (1, 0, 80)])
            data["bssid"] = None
            data["samples"][0]["bssid"] = "AP-B"
            data["samples"][1]["bssid"] = "AP-A"
            if reverse:
                data["samples"].reverse()
            before = copy.deepcopy(data)
            with self.subTest(reverse=reverse), self.assertRaises(ValueError):
                validate_survey(data)
            with self.subTest(export_reverse=reverse), self.assertRaises(ValueError):
                prepare_export(dict(schema_version=1, wifi_survey=data))
            self.assertEqual(data, before)

    def test_accepted_single_ap_canonical_survey_is_idempotent_and_exportable(self):
        from wifiscope.reports import prepare_export

        for known in (False, True):
            data = survey([(0, 0, None), (1, 0, 80 if known else None)])
            data["bssid"] = None
            data["samples"][0]["bssid"] = None
            data["samples"][1]["bssid"] = "AP-A"
            canonical = validate_survey(data)
            self.assertEqual(validate_survey(canonical), canonical)
            exported = prepare_export(
                dict(schema_version=1, wifi_survey=canonical), include_identifiers=True
            )
            self.assertEqual(exported["wifi_survey"], canonical)
            self.assertIsNone(canonical["samples"][0]["value"])
