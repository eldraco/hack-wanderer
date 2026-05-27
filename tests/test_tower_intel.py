import json
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
