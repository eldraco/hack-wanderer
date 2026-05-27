import json
import tempfile
import unittest
from pathlib import Path

import tower_capture_cli as cli
import tower_intel_server as intel


def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


class TowerCaptureCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db = self.tmp_path / "tower.sqlite"
        self.log = self.tmp_path / "sample.jsonl"
        self.status = self.tmp_path / "status.json"

    def tearDown(self):
        self.tmp.cleanup()

    def make_rows(self):
        return [
            {
                "timestamp_utc": "2027-01-01T00:00:00Z",
                "location": {"lat": 50.0, "lon": 14.0, "source": "gps_device"},
                "gps_device": {"status": "A"},
                "network": {
                    "cops_current": {"operator": "TestNet"},
                    "csq": {"rssi_dbm": -71},
                },
                "towers": [
                    {"source": "registration", "rat": "LTE", "tac_lac": 123, "cell_id": 456},
                    {"source": "cpsi", "rat": "LTE", "tac_lac": 123, "cell_id": 456, "pci": 7, "earfcn": 1400, "rsrp": -91},
                ],
            },
            {
                "timestamp_utc": "2027-01-01T00:05:00Z",
                "location": {"lat": 50.0005, "lon": 14.0005, "source": "gps_device"},
                "gps_device": {"status": "A"},
                "network": {
                    "cops_current": {"operator": "TestNet"},
                    "csq": {"rssi_dbm": -65},
                },
                "towers": [
                    {"source": "registration", "rat": "LTE", "tac_lac": 123, "cell_id": 456},
                    {"source": "cpsi", "rat": "LTE", "tac_lac": 123, "cell_id": 456, "pci": 7, "earfcn": 1400, "rsrp": -88},
                ],
            },
        ]

    def test_load_db_snapshot_uses_latest_sample_and_latest_per_tower(self):
        write_jsonl(self.log, self.make_rows())
        intel.ingest_files(str(self.db), [str(self.log)])

        snap = cli.load_db_snapshot(str(self.db), limit=5)

        self.assertEqual(snap["source_kind"], "db")
        self.assertEqual(snap["updated_at"], "2027-01-01T00:05:00Z")
        self.assertEqual(snap["gps"]["lat"], 50.0005)
        self.assertEqual(snap["gps"]["lon"], 14.0005)
        self.assertEqual(len(snap["towers"]), 2)
        self.assertEqual(snap["towers"][0]["last_seen"], "2027-01-01T00:05:00Z")
        self.assertEqual(snap["towers"][0]["seen_count"], 2)

    def test_load_status_snapshot_prefers_seen_time_and_cache_key(self):
        payload = {
            "timestamp_utc": "2027-01-01T01:00:00Z",
            "location": {"lat": 51.1, "lon": 15.2, "source": "gps_device", "timestamp_utc": "2027-01-01T00:59:58Z"},
            "network": {"cops_current": {"operator": "StatusNet"}},
            "gps_device": {"status": "A"},
            "towers_all": [
                {
                    "key": "LTE|123|456|None|None",
                    "source": "registration",
                    "rat": "LTE",
                    "tac_lac": 123,
                    "cell_id": 456,
                    "seen_count": 9,
                    "seen_time_utc": "2027-01-01T00:59:59Z",
                    "first_seen_time_utc": "2027-01-01T00:00:00Z",
                    "seen_location": {"lat": 51.1, "lon": 15.2},
                }
            ],
        }
        self.status.write_text(json.dumps(payload), encoding="utf-8")

        snap = cli.load_status_snapshot(str(self.status), limit=5)

        self.assertEqual(snap["source_kind"], "status")
        self.assertEqual(snap["updated_at"], "2027-01-01T01:00:00Z")
        self.assertEqual(snap["gps"]["lat"], 51.1)
        self.assertEqual(snap["towers"][0]["id"], "LTE|123|456|None|None")
        self.assertEqual(snap["towers"][0]["seen_count"], 9)
        self.assertEqual(snap["towers"][0]["last_seen"], "2027-01-01T00:59:59Z")

    def test_load_jsonl_snapshot_dedupes_to_latest_per_identity(self):
        write_jsonl(self.log, self.make_rows())

        snap = cli.load_jsonl_snapshot(str(self.log), limit=5, tail_lines=20)

        self.assertEqual(snap["source_kind"], "jsonl")
        self.assertEqual(snap["updated_at"], "2027-01-01T00:05:00Z")
        self.assertEqual(len(snap["towers"]), 2)
        self.assertEqual(snap["towers"][0]["last_seen"], "2027-01-01T00:05:00Z")
        self.assertGreaterEqual(snap["towers"][0]["seen_count"], 1)

    def test_render_text_mentions_gps_and_latest_towers(self):
        snapshot = {
            "source_kind": "status",
            "source_path": "/tmp/status.json",
            "updated_at": "2027-01-01T01:00:00Z",
            "updated_at_epoch": 1798765200.0,
            "gps": {"lat": 51.1, "lon": 15.2, "alt_m": None, "source": "gps_device", "status": "A", "bad_gps": 0},
            "towers": [{
                "id": "LTE/123/456/7/1400",
                "last_seen": "2027-01-01T00:59:59Z",
                "last_seen_epoch": 1798765199.0,
                "seen_count": 9,
                "signal": -88.0,
                "rat": "LTE",
                "tac_lac": 123,
                "cell_id": 456,
                "pci": 7,
                "earfcn": 1400,
                "operator": "StatusNet",
            }],
        }

        text = cli.render_text(snapshot, limit=5)

        self.assertIn("GPS:", text)
        self.assertIn("Latest towers", text)
        self.assertIn("StatusNet", text)
