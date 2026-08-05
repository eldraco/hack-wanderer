import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "hack-wanderer.py"
SPEC = importlib.util.spec_from_file_location("hack_wanderer_module", MODULE_PATH)
hack_wanderer = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(hack_wanderer)


class FakeLogger:
    def warning(self, _message):
        pass


class FakeAT:
    def __init__(self, responses):
        self.responses = {key: [dict(item) for item in value] for key, value in responses.items()}
        self.commands = []

    def send(self, cmd, **_kwargs):
        self.commands.append(cmd)
        queue = self.responses.get(cmd)
        if queue:
            item = queue.pop(0)
            return {
                "command": cmd,
                "lines": item.get("lines", []),
                "ok": item.get("ok", True),
                "error": item.get("error"),
                "elapsed_s": item.get("elapsed_s", 0.0),
            }
        return {"command": cmd, "lines": ["OK"], "ok": True, "error": None, "elapsed_s": 0.0}


class HackWandererStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.status_dir = Path(self.tmp.name) / "status"
        self.status_path = self.status_dir / "status.json"
        hack_wanderer._STATUS_SESSION_STARTED_UTC = None
        hack_wanderer._STATUS_SESSION_STARTED_LOCAL = None
        hack_wanderer._LAST_AUTO_REGISTER_ATTEMPT_MONO = None

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

    def test_collect_network_skips_auto_register_when_already_registered(self):
        at = FakeAT({
            "AT+CSQ": [{"lines": ["+CSQ: 31,0", "OK"]}],
            "AT+CREG?": [{"lines": ["+CREG: 2,5,FFFE,17F900", "OK"]}],
            "AT+CGREG?": [{"lines": ["+CGREG: 2,5,DA4,17F900", "OK"]}],
            "AT+CEREG?": [{"lines": ["+CEREG: 2,5,DA4,17F900,7", "OK"]}],
            "AT+COPS?": [{"lines": ["+COPS: 0,2,\"21670\",7", "OK"]}],
        })
        config = json.loads(json.dumps(hack_wanderer.DEFAULT_CONFIG))

        network = hack_wanderer.collect_network(at, config)

        self.assertTrue(hack_wanderer.network_is_registered(network))
        self.assertNotIn("AT+COPS=0", at.commands)
        self.assertIn("AT+COPS=3,2", at.commands)
        self.assertEqual(network["cops_current_numeric"]["operator"], "21670")

    def test_parse_numeric_cops_without_optional_access_technology(self):
        parsed = hack_wanderer.parse_cops_current(['+COPS: 0,2,"23002"', "OK"])

        self.assertEqual(parsed["operator"], "23002")
        self.assertEqual(parsed["format"], 2)
        self.assertIsNone(parsed["act"])

    def test_tower_snapshot_uses_numeric_plmn_not_sim_brand(self):
        network = {
            "cereg": {
                "stat_code": 1,
                "stat_text": "registered_home",
                "rat": "LTE",
                "act": 7,
                "lac_tac": 481,
                "cell_id": 153825646,
            },
            "cops_current": {"format": 0, "operator": "TESCO Mobile TESCO Mobile"},
            "cops_current_numeric": {"format": 2, "operator": "23002"},
        }

        towers = hack_wanderer.build_towers_snapshot(network, {})

        self.assertEqual(towers[0]["plmn"], "23002")
        self.assertEqual(towers[0]["mcc"], 230)
        self.assertEqual(towers[0]["mnc"], 2)
        self.assertNotIn("TESCO", json.dumps(towers))

    def test_cpsi_cell_plmn_overrides_registered_network_fallback(self):
        network = {
            "cops_current_numeric": {"format": 2, "operator": "23002"},
        }
        vendor = {"cpsi": {
            "system_mode": "LTE",
            "scell_id": 42,
            "tac": 7,
            "pcell_id": 3,
            "plmn": "262-01",
            "mcc": 262,
            "mnc": 1,
        }}

        towers = hack_wanderer.build_towers_snapshot(network, vendor)

        self.assertEqual(towers[0]["plmn"], "262-01")
        self.assertEqual((towers[0]["mcc"], towers[0]["mnc"]), (262, 1))

    def test_collect_network_throttles_auto_register_retries_while_searching(self):
        at = FakeAT({
            "AT+CSQ": [{"lines": ["+CSQ: 99,99", "OK"]}],
            "AT+CREG?": [{"lines": ["+CREG: 2,2", "OK"]}],
            "AT+CGREG?": [{"lines": ["+CGREG: 2,2", "OK"]}],
            "AT+CEREG?": [{"lines": ["+CEREG: 2,4", "OK"]}],
            "AT+COPS?": [{"lines": ["+COPS: 0", "OK"]}],
        })
        config = json.loads(json.dumps(hack_wanderer.DEFAULT_CONFIG))
        hack_wanderer._LAST_AUTO_REGISTER_ATTEMPT_MONO = 100.0

        with mock.patch.object(hack_wanderer.time, "monotonic", return_value=120.0):
            network = hack_wanderer.collect_network(at, config)

        self.assertFalse(hack_wanderer.network_is_registered(network))
        self.assertNotIn("AT+COPS=0", at.commands)

    def test_collect_network_retries_auto_register_after_cooldown(self):
        at = FakeAT({
            "AT+CSQ": [
                {"lines": ["+CSQ: 99,99", "OK"]},
                {"lines": ["+CSQ: 31,0", "OK"]},
            ],
            "AT+CREG?": [
                {"lines": ["+CREG: 2,2", "OK"]},
                {"lines": ["+CREG: 2,5,FFFE,17F900", "OK"]},
            ],
            "AT+CGREG?": [
                {"lines": ["+CGREG: 2,2", "OK"]},
                {"lines": ["+CGREG: 2,5,DA4,17F900", "OK"]},
            ],
            "AT+CEREG?": [
                {"lines": ["+CEREG: 2,4", "OK"]},
                {"lines": ["+CEREG: 2,5,DA4,17F900,7", "OK"]},
            ],
            "AT+COPS?": [{"lines": ["+COPS: 0,2,\"21670\",7", "OK"]}],
        })
        config = json.loads(json.dumps(hack_wanderer.DEFAULT_CONFIG))
        hack_wanderer._LAST_AUTO_REGISTER_ATTEMPT_MONO = 100.0

        with mock.patch.object(hack_wanderer.time, "monotonic", return_value=200.0):
            network = hack_wanderer.collect_network(at, config)

        self.assertTrue(hack_wanderer.network_is_registered(network))
        self.assertIn("AT+COPS=0", at.commands)


if __name__ == "__main__":
    unittest.main()
