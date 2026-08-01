import json
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import tower_intel_server as intel

try:
    from fastapi.testclient import TestClient
except Exception:
    try:
        from starlette.testclient import TestClient
    except Exception:
        TestClient = None


def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


class TowerIntelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "tower.sqlite")
        self.log = Path(self.tmp.name) / "sample.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def make_rows(self):
        rows = []
        for i in range(20):
            lat = 50.0 if i < 10 else 50.02
            lon = 14.0 if i < 10 else 14.02
            rows.append({
                "timestamp_utc": f"2027-01-01T{i:02d}:00:00Z",
                "location": {"lat": lat, "lon": lon},
                "network": {
                    "cops_current": {"operator": "TestNet"},
                    "csq": {"rssi_dbm": -70 + (i % 3)},
                },
                "towers": [{
                    "rat": "LTE",
                    "tac_lac": 123,
                    "cell_id": 456,
                    "pci": 7,
                    "earfcn": 1400,
                    "rsrp": -90 + (i % 2),
                }],
            })
        return rows

    def test_map_groups_marker_colors_by_tac_lac(self):
        page = intel.index_html()
        self.assertIn("function tacLacColor(value)", page)
        self.assertIn("const color=tacLacColor(areaKey)", page)
        self.assertIn("areaGroups.set(areaKey", page)
        self.assertIn("TAC/LAC colors", page)
        self.assertIn("TAC/LAC ${esc(areaKey===null?'unknown':areaKey)}", page)
        self.assertIn('id="showAreaLegend"', page)
        self.assertIn("function setAreaLegendVisible(show,persist=true)", page)
        self.assertIn("towerShowAreaLegend", page)

    def test_map_has_explicit_weird_gps_tower_layer_and_warning(self):
        page = intel.index_html()
        self.assertIn("weirdTowerLayer", page)
        self.assertIn("Weird GPS tower locations (unreliable)", page)
        self.assertIn("WEIRD GPS — UNRELIABLE LOCATION", page)
        self.assertIn("fallback observation centroid, not a base-station position", page)

    def test_identity_and_jsonl_import_are_idempotent(self):
        write_jsonl(self.log, self.make_rows())
        first = intel.ingest_files(self.db, [str(self.log)])
        second = intel.ingest_files(self.db, [str(self.log)])
        self.assertEqual(first["imported_rows"], 20)
        self.assertEqual(first["new_samples"], 20)
        self.assertEqual(first["tower_fingerprints"], 1)
        self.assertEqual(first["new_towers"], 1)
        self.assertEqual(first["tower_observations"], 20)
        self.assertEqual(first["new_observations"], 20)
        self.assertEqual(second["skipped"], 1)
        with intel.connect_db(self.db) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM raw_samples").fetchone()[0], 20)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM tower_observations").fetchone()[0], 20)
            tower = con.execute("SELECT * FROM towers").fetchone()
            self.assertEqual(tower["operator"], "TestNet")
            self.assertEqual(tower["cell_id"], 456)

    def test_recompute_excludes_bad_gps_and_exports_report(self):
        rows = self.make_rows()
        rows.append({
            "timestamp_utc": "2027-01-01T20:00:01Z",
            "location": {"lat": 52.0, "lon": 16.0},
            "network": {"cops_current": {"operator": "TestNet"}, "csq": {"rssi_dbm": -60}},
            "towers": [{"rat": "LTE", "tac_lac": 123, "cell_id": 456, "pci": 7, "earfcn": 1400}],
        })
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        result = intel.recompute(self.db, sample_size=100)
        self.assertEqual(result["updated_towers"], 1)
        with intel.connect_db(self.db) as con:
            features = json.loads(con.execute("SELECT features_json FROM tower_features").fetchone()[0])
            self.assertGreaterEqual(features["bad_gps_skipped"], 1)
            report = intel.export_markdown(con, con.execute("SELECT id FROM towers").fetchone()[0])
            self.assertIn("Tower report", report)
            self.assertIn("Evidence terms", report)
            docx = intel.export_docx(con, con.execute("SELECT id FROM towers").fetchone()[0])
            docx_path = Path(self.tmp.name) / "tower.docx"
            docx_path.write_bytes(docx)
            with zipfile.ZipFile(docx_path) as z:
                document_xml = z.read("word/document.xml").decode("utf-8")
            self.assertIn("Tower Intelligence Report", document_xml)
            self.assertIn("<w:tbl>", document_xml)
            self.assertIn('w:fill="', document_xml)
            imports = con.execute("SELECT path, imported_rows, new_samples, tower_fingerprints, new_towers, observation_rows, new_observations FROM import_files").fetchall()
            self.assertEqual(len(imports), 1)
            self.assertEqual(imports[0]["imported_rows"], 21)
            self.assertEqual(imports[0]["new_samples"], 21)
            self.assertEqual(imports[0]["tower_fingerprints"], 1)
            self.assertEqual(imports[0]["new_towers"], 1)
            self.assertEqual(imports[0]["observation_rows"], 21)
            self.assertEqual(imports[0]["new_observations"], 21)

    def test_weird_gps_only_tower_is_retained_but_not_used_as_valid_center(self):
        rows = [{
            "timestamp_utc": "2027-01-01T00:00:00Z",
            "location": {"lat": 50.1001, "lon": 14.2002, "source": "gps_device"},
            "gps_device": {
                "location": {"lat": 50.1001, "lon": 14.2002},
                "status": "V",
                "fix_quality": 0,
                "fix_type": 1,
                "satellites": {"in_use": 0},
            },
            "network": {"cops_current": {"operator": "IndoorNet"}, "csq": {"rssi_dbm": -73}},
            "towers": [{
                "rat": "LTE",
                "tac_lac": 777,
                "cell_id": 999,
                "pci": 12,
                "earfcn": 1650,
                "rsrp": -95,
            }],
        }]
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=100)

        with intel.connect_db(self.db) as con:
            observation = con.execute(
                "SELECT bad_gps, lat, lon FROM tower_observations"
            ).fetchone()
            quality = con.execute("SELECT * FROM tower_location_quality").fetchone()
            feature = con.execute("SELECT center_lat, center_lon FROM tower_features").fetchone()
            tower_row = con.execute(
                f"""SELECT t.*, f.*, {intel.LOCATION_QUALITY_SELECT_SQL}
                FROM towers t
                LEFT JOIN tower_features f ON f.tower_id=t.id
                LEFT JOIN tower_location_quality lq ON lq.tower_id=t.id"""
            ).fetchone()
            payload = intel.tower_payload(tower_row)
            report = intel.export_markdown(con, tower_row["id"])

        self.assertEqual(observation["bad_gps"], 1)
        self.assertAlmostEqual(observation["lat"], 50.1001)
        self.assertIsNone(feature["center_lat"])
        self.assertIsNone(feature["center_lon"])
        self.assertEqual(quality["location_quality"], "weird_gps")
        self.assertEqual(quality["valid_gps_count"], 0)
        self.assertEqual(quality["weird_gps_count"], 1)
        self.assertAlmostEqual(quality["weird_center_lat"], 50.1001)
        self.assertAlmostEqual(quality["weird_center_lon"], 14.2002)
        self.assertEqual(payload["location_quality"], "weird_gps")
        self.assertEqual(payload["total_observation_count"], 1)
        self.assertIn("Weird-GPS fallback centroid (unreliable)", report)
        self.assertIn("excluded from geographic scoring", report)

    def test_recompute_skips_stationary_refresh_by_default(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(self.db, [str(self.log)])
        with mock.patch.object(intel, "refresh_stationary_flags", wraps=intel.refresh_stationary_flags) as refresh_mock:
            intel.recompute(self.db, sample_size=100)
        refresh_mock.assert_not_called()

    def test_recompute_can_force_stationary_refresh(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(self.db, [str(self.log)])
        with mock.patch.object(intel, "refresh_stationary_flags", wraps=intel.refresh_stationary_flags) as refresh_mock:
            intel.recompute(self.db, sample_size=100, refresh_stationary=True)
        self.assertGreaterEqual(refresh_mock.call_count, 1)

    def test_method_setting_changes_score_after_recompute(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=100)
        with intel.connect_db(self.db) as con:
            before = con.execute("SELECT bayes_post_p FROM tower_features").fetchone()[0]
            con.execute("UPDATE method_settings SET weight=8 WHERE method_id='multi_location'")
            con.commit()
        intel.recompute(self.db, sample_size=100)
        with intel.connect_db(self.db) as con:
            after = con.execute("SELECT bayes_post_p FROM tower_features").fetchone()[0]
        self.assertGreater(after, before)

    def test_new_area_code_in_well_covered_place_triggers_for_locally_unseen_tac(self):
        rows = []
        for i in range(50):
            day = 1 if i < 25 else 2
            minute = i % 25
            rows.append({
                "timestamp_utc": f"2027-01-0{day}T12:{minute:02d}:00Z",
                "location": {"lat": 50.0, "lon": 14.0},
                "network": {
                    "cops_current": {"operator": "TestNet"},
                    "csq": {"rssi_dbm": -72},
                },
                "towers": [{
                    "rat": "LTE",
                    "tac_lac": 100,
                    "cell_id": 456,
                    "pci": 7,
                    "earfcn": 1400,
                    "rsrp": -92,
                }],
            })
        for i in range(6):
            rows.append({
                "timestamp_utc": f"2027-01-03T12:{i:02d}:00Z",
                "location": {"lat": 50.0, "lon": 14.0},
                "network": {
                    "cops_current": {"operator": "TestNet"},
                    "csq": {"rssi_dbm": -70},
                },
                "towers": [{
                    "rat": "LTE",
                    "tac_lac": 200,
                    "cell_id": 789,
                    "pci": 8,
                    "earfcn": 1400,
                    "rsrp": -89,
                }],
            })
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=200)

        with intel.connect_db(self.db) as con:
            row = con.execute(
                """
                SELECT f.features_json, f.methods_json
                FROM tower_features f
                JOIN towers t ON t.id=f.tower_id
                WHERE t.operator=? AND t.rat=? AND t.tac_lac=? AND t.cell_id=?
                """,
                ("TestNet", "LTE", 200, 789),
            ).fetchone()
        self.assertIsNotNone(row)
        features = json.loads(row["features_json"])
        methods = json.loads(row["methods_json"])
        method = next(m for m in methods if m["id"] == "new_area_code_in_well_covered_place")

        self.assertTrue(method["triggered"])
        self.assertGreater(features["new_area_code_prior_same_rat_count"], 40)
        self.assertEqual(features["new_area_code_prior_same_code_count"], 0)
        self.assertEqual(features["new_area_code_prior_dominant_code"], 100)
        self.assertGreater(features["new_area_code_prior_dominant_frac"], 0.9)

    def test_method_xai_rows_explain_equation_thresholds_and_effects(self):
        intel.init_db(self.db)
        with intel.connect_db(self.db) as con:
            settings = intel.get_method_settings(con)
        features = {
            "rat": "LTE",
            "count": 20,
            "stationary_count": 12,
            "stationary_clusters": 2,
            "stationary_cluster_top2_sep_m": 1600.0,
        }
        methods, _bayes, _rule, _post = intel.evaluate_methods(
            features,
            settings,
            mostly_lte=True,
            known=False,
            ignored=False,
        )
        method = next(m for m in methods if m["id"] == "multi_location_stationary")
        enriched = intel.enrich_method_result(method, features)
        rows = {row["name"]: row for row in enriched["xai_rows"]}
        self.assertEqual(rows["sep_start_m"]["value"], 800)
        self.assertIn("threshold", rows["sep_start_m"]["definition"].lower())
        self.assertEqual(rows["stationary_count"]["value"], 12)
        self.assertTrue(rows["stationary_count"]["definition"])
        self.assertGreater(rows["odds_multiplier"]["value"], 1.0)
        self.assertIn("clamp", enriched["equation_note"])
        self.assertIn("Requires", enriched["trigger_summary"])

    def test_non_triggered_method_does_not_change_score(self):
        intel.init_db(self.db)
        with intel.connect_db(self.db) as con:
            settings = intel.get_method_settings(con)
        features = {
            "rat": "LTE",
            "count": 1,
            "new_place_count": 1,
            "new_place_prior_count": 500,
            "new_place_prior_days": 5,
        }
        methods, bayes, rule_score, post = intel.evaluate_methods(
            features,
            settings,
            mostly_lte=True,
            known=False,
            ignored=False,
        )
        method = next(m for m in methods if m["id"] == "new_in_well_covered_place")
        self.assertFalse(method["triggered"])
        self.assertEqual(method["norm01"], 0.0)
        self.assertEqual(method["delta_logodds"], 0.0)
        self.assertEqual(rule_score, 0.0)
        self.assertAlmostEqual(post, bayes["posterior"])
        self.assertEqual(bayes["total_delta_logodds"], 0.0)

    def test_wigle_evidence_absence_raises_suspicion_and_history_lowers_it(self):
        intel.init_db(self.db)
        with intel.connect_db(self.db) as con:
            settings = intel.get_method_settings(con)

        absent_features = {}
        intel.apply_wigle_features(absent_features, {
            "checked_at": "2026-06-01T00:00:00+00:00",
            "exists": False,
            "match_count": 0,
            "results": [],
        })
        absent_methods, _bayes, _rule, _post = intel.evaluate_methods(
            absent_features, settings, mostly_lte=True, known=False, ignored=False,
        )
        absent = next(m for m in absent_methods if m["id"] == "wigle_absent")
        self.assertTrue(absent["triggered"])
        self.assertGreater(absent["delta_logodds"], 0.0)

        recent_historical = {}
        intel.apply_wigle_features(recent_historical, {
            "checked_at": "2026-06-01T00:00:00+00:00",
            "exists": True,
            "match_count": 1,
            "results": [{"firsttime": "2020-01-01T00:00:00.000Z", "lasttime": "2026-05-01T00:00:00.000Z"}],
        })
        stale_young = {}
        intel.apply_wigle_features(stale_young, {
            "checked_at": "2026-06-01T00:00:00+00:00",
            "exists": True,
            "match_count": 1,
            "results": [{"firsttime": "2026-01-01T00:00:00.000Z", "lasttime": "2024-01-01T00:00:00.000Z"}],
        })
        historical_methods, _bayes, _rule, _post = intel.evaluate_methods(
            recent_historical, settings, mostly_lte=True, known=False, ignored=False,
        )
        weak_methods, _bayes, _rule, _post = intel.evaluate_methods(
            stale_young, settings, mostly_lte=True, known=False, ignored=False,
        )
        historical = next(m for m in historical_methods if m["id"] == "wigle_historical_presence")
        weak = next(m for m in weak_methods if m["id"] == "wigle_historical_presence")
        self.assertTrue(historical["triggered"])
        self.assertLess(historical["delta_logodds"], 0.0)
        self.assertLess(historical["delta_logodds"], weak["delta_logodds"])

    def test_get_method_settings_is_read_only_under_foreign_write_lock(self):
        intel.init_db(self.db)
        writer = intel.connect_db(self.db)
        try:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("UPDATE app_settings SET updated_at=updated_at WHERE key=?", ("altitude_high_point_m",))
            with intel.connect_db(self.db) as reader:
                settings = intel.get_method_settings(reader)
            self.assertIn("multi_location", settings)
        finally:
            try:
                writer.rollback()
            except sqlite3.Error:
                pass
            writer.close()

    def test_ingest_progress_callback_reports_live_rows_and_done(self):
        write_jsonl(self.log, self.make_rows())
        seen = []

        def progress(payload):
            seen.append(dict(payload))

        result = intel.ingest_files(self.db, [str(self.log)], progress_callback=progress)

        self.assertEqual(result["files_imported"], 1)
        self.assertTrue(seen)
        self.assertEqual(seen[0]["phase"], "starting")
        self.assertTrue(any(item["phase"] == "importing" and item["current_rows"] >= 1 for item in seen))
        self.assertEqual(seen[-1]["phase"], "done")
        self.assertFalse(seen[-1]["active"])
        self.assertIn("Import complete", seen[-1]["message"])

    def test_stationary_detection_uses_direct_gps_speed_when_available(self):
        rows = []
        for i in range(6):
            rows.append({
                "timestamp_utc": f"2027-01-01T00:0{i}:00Z",
                "location": {
                    "lat": 50.0,
                    "lon": 14.0,
                    "speed_knots": 4.0,
                    "source": "gps_device",
                },
                "gps_device": {
                    "location": {
                        "lat": 50.0,
                        "lon": 14.0,
                        "speed_knots": 4.0,
                    },
                    "status": "A",
                    "fix_quality": 1,
                    "fix_type": 3,
                },
                "network": {"cops_current": {"operator": "TestNet"}},
                "towers": [{"rat": "LTE", "tac_lac": 1, "cell_id": 2, "pci": 3, "earfcn": 4}],
            })
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        with intel.connect_db(self.db) as con:
            stationary = con.execute("SELECT SUM(stationary) FROM raw_samples").fetchone()[0]
        self.assertEqual(stationary or 0, 0)

        for row in rows:
            row["location"]["speed_knots"] = 0.2
            row["gps_device"]["location"]["speed_knots"] = 0.2
        write_jsonl(self.log, rows)
        self.db = str(Path(self.tmp.name) / "tower-low-speed.sqlite")
        intel.ingest_files(self.db, [str(self.log)])
        with intel.connect_db(self.db) as con:
            stationary = con.execute("SELECT SUM(stationary) FROM raw_samples").fetchone()[0]
        self.assertEqual(stationary or 0, 6)

    def test_ingest_extracts_altitude_from_raw_gga(self):
        rows = [{
            "timestamp_utc": "2027-01-01T00:00:00Z",
            "location": {"lat": 50.0, "lon": 14.0, "alt_m": None, "source": "gps_device"},
            "gps_device": {
                "location": {"lat": 50.0, "lon": 14.0, "alt_m": None},
                "gga": {"alt_m": 245.5},
                "status": "A",
                "fix_quality": 1,
                "fix_type": 3,
            },
            "network": {"cops_current": {"operator": "TestNet"}},
            "towers": [{"rat": "LTE", "tac_lac": 1, "cell_id": 2, "pci": 3, "earfcn": 4}],
        }]
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        with intel.connect_db(self.db) as con:
            alt_m = con.execute("SELECT alt_m FROM raw_samples").fetchone()[0]
        self.assertEqual(alt_m, 245.5)

    def test_invalid_fix_does_not_backfill_altitude_from_top_level_location(self):
        rows = [{
            "timestamp_utc": "2027-01-01T00:00:00Z",
            "location": {"lat": 50.0, "lon": 14.0, "alt_m": 245.5, "source": "gps_device"},
            "gps_device": {
                "location": {"lat": 50.0, "lon": 14.0, "alt_m": 245.5},
                "gga": {"alt_m": 245.5},
                "status": "V",
                "fix_quality": 0,
                "fix_type": 1,
            },
            "network": {"cops_current": {"operator": "TestNet"}},
            "towers": [{"rat": "LTE", "tac_lac": 1, "cell_id": 2, "pci": 3, "earfcn": 4}],
        }]
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        with intel.connect_db(self.db) as con:
            alt_m = con.execute("SELECT alt_m FROM raw_samples").fetchone()[0]
        self.assertIsNone(alt_m)

    def test_altitude_confidence_reduces_geo_method_strength(self):
        intel.init_db(self.db)
        with intel.connect_db(self.db) as con:
            settings = intel.get_method_settings(con)
        base_features = {
            "rat": "LTE",
            "count": 20,
            "clusters": 2,
            "cluster_top2_sep_m": 4000.0,
            "geo_altitude_confidence": 1.0,
        }
        methods_hi, _bayes, _rule, _post = intel.evaluate_methods(
            dict(base_features),
            settings,
            mostly_lte=True,
            known=False,
            ignored=False,
        )
        delta_hi = next(m["delta_logodds"] for m in methods_hi if m["id"] == "multi_location")

        low_features = dict(base_features)
        low_features.update({
            "geo_altitude_confidence": 0.4,
            "altitude_samples": 20,
            "altitude_rel_median_m": 18.0,
            "altitude_rel_p90_m": 30.0,
            "high_altitude_obs_frac": 0.7,
        })
        methods_lo, _bayes, _rule, _post = intel.evaluate_methods(
            low_features,
            settings,
            mostly_lte=True,
            known=False,
            ignored=False,
        )
        multi = next(m for m in methods_lo if m["id"] == "multi_location")
        self.assertLess(multi["delta_logodds"], delta_hi)
        self.assertEqual(multi["altitude_factor_name"], "geo_altitude_confidence")
        self.assertAlmostEqual(multi["altitude_factor"], 0.4, places=6)

    def test_altitude_default_curve_is_about_half_at_10m(self):
        weight = intel.altitude_confidence_weight(10.0, intel.GLOBAL_CONFIG_DEFAULTS)
        self.assertAlmostEqual(weight, 0.5, places=6)

    def test_robust_ground_altitude_ignores_low_outlier(self):
        floor = intel.robust_ground_altitude([40.0, 100.0, 100.5, 101.0, 101.2], iqr_k=1.5)
        self.assertAlmostEqual(floor, 100.0, places=6)

    def test_dependency_free_multipart_upload_parser(self):
        payload = json.dumps(self.make_rows()[0]).encode("utf-8") + b"\n"
        boundary = "----tower-intel-test"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="files"; filename="upload.jsonl"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + payload + f"\r\n--{boundary}--\r\n".encode("utf-8")
        paths = intel.parse_multipart_paths(
            f"multipart/form-data; boundary={boundary}",
            body,
            Path(self.tmp.name) / "uploads",
        )
        self.assertEqual(len(paths), 1)
        self.assertTrue(Path(paths[0]).exists())
        result = intel.ingest_files(self.db, paths)
        self.assertEqual(result["imported_rows"], 1)
        self.assertEqual(result["new_towers"], 1)

    def test_wigle_enrichment_infers_tesco_o2_plmn_and_filters_exact_match(self):
        rows = [{
            "timestamp_utc": "2027-01-01T00:00:00Z",
            "location": {"lat": 50.0, "lon": 14.0},
            "network": {"cops_current": {"operator": "TESCO Mobile TESCO mobile"}},
            "towers": [{"rat": "LTE", "tac_lac": 1137, "cell_id": 154762598, "pci": 228, "earfcn": 1404}],
        }]
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        with intel.connect_db(self.db) as con:
            tower_id = con.execute("SELECT id FROM towers").fetchone()["id"]

        response_payload = {
            "success": True,
            "totalResults": 1,
            "results": [{
                "id": "23002_1137_154762598",
                "ssid": "O2 Czech Republic",
                "gentype": "LTE",
                "channel": 1404,
                "qos": 7,
                "firsttime": "2022-10-15T13:00:00.000Z",
                "lasttime": "2025-10-27T05:00:00.000Z",
            }],
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps(response_payload).encode("utf-8")

        with mock.patch.dict(os.environ, {"WIGLE_API_NAME": "api-name", "WIGLE_API_TOKEN": "api-token"}):
            with mock.patch.object(intel.urllib.request, "urlopen", return_value=FakeResponse()) as urlopen:
                result = intel.wigle_enrich_tower(self.db, tower_id)
                cached = intel.wigle_enrich_tower(self.db, tower_id)

        requested_url = urlopen.call_args.args[0].full_url
        self.assertEqual(urlopen.call_count, 1)
        self.assertIn("cell_op=23002", requested_url)
        self.assertIn("cell_net=1137", requested_url)
        self.assertIn("cell_id=154762598", requested_url)
        self.assertTrue(result["exists"])
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["results"][0]["channel"], 1404)
        self.assertFalse(result["cached"])
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["results"][0]["id"], "23002_1137_154762598")
        with intel.connect_db(self.db) as con:
            stored = intel.get_wigle_enrichment(con, tower_id)
        self.assertIsNotNone(stored)
        self.assertTrue(stored["cached"])
        intel.recompute_one_tower(self.db, tower_id)
        with intel.connect_db(self.db) as con:
            methods = json.loads(con.execute("SELECT methods_json FROM tower_features WHERE tower_id=?", (tower_id,)).fetchone()[0])
        historical = next(m for m in methods if m["id"] == "wigle_historical_presence")
        self.assertTrue(historical["triggered"])
        self.assertLess(historical["delta_logodds"], 0.0)

    @unittest.skipIf(TestClient is None, "FastAPI test client not available")
    def test_api_towers_searches_notes_and_analysis_status(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=100)
        app = intel.create_app(self.db)
        client = TestClient(app)

        items = client.get("/api/towers", params={"limit": 10, "include_ignored": 1}).json()["items"]
        self.assertEqual(len(items), 1)
        tower_id = items[0]["id"]

        update = client.put(
            f"/api/admin/towers/{tower_id}",
            json={"notes": "roof repeater near stadium", "analysis_status": "under analysis"},
        )
        self.assertEqual(update.status_code, 200)

        note_match = client.get("/api/towers", params={"q": "stadium", "include_ignored": 1}).json()["items"]
        self.assertEqual(len(note_match), 1)
        self.assertTrue(note_match[0]["has_note"])
        self.assertEqual(note_match[0]["analysis_status"], "under analysis")

        tag_match = client.get("/api/towers", params={"q": "under analysis", "include_ignored": 1}).json()["items"]
        self.assertEqual(len(tag_match), 1)
        self.assertEqual(tag_match[0]["id"], tower_id)

    @unittest.skipIf(TestClient is None, "FastAPI test client not available")
    def test_api_towers_filters_by_inclusive_last_seen_date_range(self):
        rows = self.make_rows()
        rows.append({
            "timestamp_utc": "2027-01-03T23:59:59Z",
            "location": {"lat": 50.1, "lon": 14.1},
            "network": {"cops_current": {"operator": "LaterNet"}},
            "towers": [{
                "rat": "LTE",
                "tac_lac": 999,
                "cell_id": 888,
                "pci": 6,
                "earfcn": 1300,
            }],
        })
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=100)
        client = TestClient(intel.create_app(self.db))

        first_day = client.get(
            "/api/towers",
            params={"last_seen_from": "2027-01-01", "last_seen_to": "2027-01-01"},
        )
        self.assertEqual(first_day.status_code, 200)
        self.assertEqual([item["operator"] for item in first_day.json()["items"]], ["TestNet"])

        through_third = client.get(
            "/api/towers",
            params={"last_seen_from": "2027-01-03", "last_seen_to": "2027-01-03"},
        )
        self.assertEqual(through_third.status_code, 200)
        self.assertEqual([item["operator"] for item in through_third.json()["items"]], ["LaterNet"])

        reversed_range = client.get(
            "/api/towers",
            params={"last_seen_from": "2027-01-04", "last_seen_to": "2027-01-03"},
        )
        self.assertEqual(reversed_range.status_code, 400)

    @unittest.skipIf(TestClient is None, "FastAPI test client not available")
    def test_api_anomaly_towers_filters_by_triggered_positive_method(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(self.db, [str(self.log)])
        intel.recompute(self.db, sample_size=100)
        app = intel.create_app(self.db)
        client = TestClient(app)

        payload = client.get("/api/anomaly-towers").json()
        self.assertEqual(len(payload["items"]), 1)
        tower = payload["items"][0]
        triggered = tower["triggered_anomalies"]
        self.assertTrue(triggered)
        self.assertTrue(all(m["triggered"] and m["direction"] == "up" for m in triggered))

        method_id = triggered[0]["id"]
        filtered = client.get("/api/anomaly-towers", params={"method_id": method_id}).json()
        self.assertEqual([item["id"] for item in filtered["items"]], [tower["id"]])
        self.assertIn(method_id, {method["id"] for method in filtered["available_methods"]})

        label_query = triggered[0]["label"].split()[0]
        searched = client.get("/api/anomaly-towers", params={"q": label_query}).json()
        self.assertEqual([item["id"] for item in searched["items"]], [tower["id"]])

        id_query = method_id.replace("_", " ").split()[0]
        searched = client.get("/api/anomaly-towers", params={"q": id_query}).json()
        self.assertEqual([item["id"] for item in searched["items"]], [tower["id"]])

    @unittest.skipIf(TestClient is None, "FastAPI test client not available")
    def test_api_points_include_raw_point_payloads(self):
        rows = [{
            "timestamp_utc": "2027-01-01T00:00:00Z",
            "location": {"lat": 50.0, "lon": 14.0, "source": "gps_device"},
            "gps_device": {
                "location": {"lat": 50.0, "lon": 14.0},
                "status": "A",
                "fix_quality": 1,
                "fix_type": 3,
            },
            "network": {"cops_current": {"operator": "TestNet"}, "csq": {"rssi_dbm": -70}},
            "towers": [{
                "rat": "LTE",
                "tac_lac": 123,
                "cell_id": 456,
                "pci": 7,
                "earfcn": 1400,
                "rsrp": -91,
                "source": "registration",
            }],
        }]
        write_jsonl(self.log, rows)
        intel.ingest_files(self.db, [str(self.log)])
        app = intel.create_app(self.db)
        client = TestClient(app)

        items = client.get("/api/towers", params={"limit": 10, "include_ignored": 1}).json()["items"]
        self.assertEqual(len(items), 1)
        tower_id = items[0]["id"]
        payload = client.get(f"/api/towers/{tower_id}/points").json()

        self.assertEqual(len(payload["points"]), 1)
        point = payload["points"][0]
        self.assertEqual(point["raw_cell"]["cell_id"], 456)
        self.assertEqual(point["raw_sample"]["timestamp_utc"], "2027-01-01T00:00:00Z")
        self.assertTrue(bool(point["sample_uid"]))
        self.assertTrue(bool(point["obs_uid"]))


if __name__ == "__main__":
    unittest.main()
