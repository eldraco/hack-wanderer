import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "hack-wanderer.py"
SPEC = importlib.util.spec_from_file_location("hack_wanderer_module", MODULE_PATH)
hack_wanderer = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(hack_wanderer)


class FakeLogger:
    def warning(self, _message):
        pass


class HackWandererStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.status_dir = Path(self.tmp.name) / "status"
        self.status_path = self.status_dir / "status.json"
        hack_wanderer._STATUS_SESSION_STARTED_UTC = None
        hack_wanderer._STATUS_SESSION_STARTED_LOCAL = None

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_snapshot_defaults_to_current_session_towers(self):
        cache_path = self.status_dir / "towers_cache.json"
        self.status_dir.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps([{
            "key": "LTE|111|1|230|8",
            "rat": "LTE",
            "cell_id": 111,
            "tac_lac": 1,
            "mcc": 230,
            "mnc": 8,
            "first_seen_session_utc": "2026-05-15T09:00:00Z",
            "seen_time_local": "2026-05-15T11:00:00+02:00",
            "seen_time_utc": "2026-05-15T09:00:00Z",
            "seen_count": 4,
        }], indent=2), encoding="utf-8")
        snapshot = {
            "timestamp_utc": "2026-05-16T08:00:00Z",
            "timestamp_local": "2026-05-16T10:00:00+02:00",
            "timezone": "Europe/Prague",
            "location": {"lat": 50.0, "lon": 14.0},
            "network": {},
            "gps": {},
            "gps_device": {},
            "towers": [{
                "rat": "LTE",
                "cell_id": 222,
                "tac_lac": 2,
                "mcc": 230,
                "mnc": 8,
            }],
            "sim_status": "READY",
            "scan_activity": "idle",
        }

        hack_wanderer.write_status_snapshot(
            str(self.status_path),
            snapshot,
            FakeLogger(),
            {"status_page": {"show_current_session_only": True}},
        )

        payload = json.loads(self.status_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["session_started_utc"], "2026-05-16T08:00:00Z")
        self.assertTrue(payload["status_page"]["show_current_session_only"])
        self.assertEqual(len(payload["towers_all"]), 2)
        self.assertEqual(len(payload["towers_current_session"]), 1)
        self.assertEqual(payload["towers_current_session"][0]["cell_id"], 222)
        self.assertTrue(payload["towers_current_session"][0]["in_current_session"])
        old_entry = next(item for item in payload["towers_all"] if item["cell_id"] == 111)
        self.assertFalse(old_entry["in_current_session"])
        new_entry = next(item for item in payload["towers_all"] if item["cell_id"] == 222)
        self.assertEqual(new_entry["first_seen_session_utc"], "2026-05-16T08:00:00Z")
        self.assertEqual(new_entry["seen_count"], 1)


if __name__ == "__main__":
    unittest.main()
