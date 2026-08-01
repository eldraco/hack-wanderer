import unittest

import check_lte


class CheckLteTests(unittest.TestCase):
    def test_latest_cpsi_uses_last_status(self):
        lines = [
            "INFO +CPSI: NO SERVICE,Online\n",
            "DEBUG AT response: +CPSI: LTE,Online,230-03\n",
        ]
        self.assertEqual(check_lte.latest_cpsi(lines), "LTE,Online,230-03")

    def test_latest_statuses_include_external_and_modem_gps(self):
        lines = [
            "INFO GPS (device /dev/ttyACM0) source=device: lat=50.1 lon=14.2 sats_used=4 sats_view=9\n",
            "INFO GPS (LTE modem) source=lte_modem: no fix reported.\n",
        ]
        self.assertEqual(
            check_lte.latest_statuses(lines),
            (
                None,
                "/dev/ttyACM0: lat=50.1 lon=14.2 sats_used=4 sats_view=9",
                "no fix reported.",
            ),
        )

    def test_interpret_lte(self):
        self.assertEqual(check_lte.interpret_cpsi("LTE,Online"), ("LTE/5G CONNECTED", 0))

    def test_interpret_gsm(self):
        self.assertEqual(
            check_lte.interpret_cpsi("GSM,Online"),
            ("CELLULAR CONNECTED, BUT GSM/2G ONLY", 1),
        )

    def test_interpret_no_service(self):
        self.assertEqual(check_lte.interpret_cpsi("NO SERVICE,Online"), ("NO CELLULAR SERVICE", 1))

    def test_interpret_valid_gps_fix(self):
        self.assertEqual(
            check_lte.interpret_gps_device("/dev/ttyACM0: lat=50.1 lon=14.2 sats_used=4"),
            ("GPS FIX AVAILABLE (4 SATELLITES USED)", 0),
        )

    def test_interpret_invalid_gps_fix(self):
        self.assertEqual(
            check_lte.interpret_gps_device("/dev/ttyACM0: lat=50.1 lon=14.2 sats_used=0"),
            ("GPS POSITION REPORTED, BUT FIX IS INVALID (0 SATELLITES USED)", 1),
        )

    def test_time_source_prefers_external_gps(self):
        self.assertEqual(
            check_lte.time_source(
                "/dev/ttyACM0: lat=50.1 timestamp=2026-08-01T07:23:12Z",
                "lat=50.1 utc=20260801072310.0",
            ),
            ("EXTERNAL GPS", "2026-08-01T07:23:12Z"),
        )

    def test_time_source_can_use_modem_gps(self):
        self.assertEqual(
            check_lte.time_source(None, "lat=50.1 utc=20260801072310.0"),
            ("LTE MODEM GPS", "20260801072310.0"),
        )

    def test_time_source_falls_back_to_system_clock(self):
        self.assertEqual(
            check_lte.time_source(None, "no fix reported."),
            ("RASPBERRY PI SYSTEM CLOCK ONLY", None),
        )


if __name__ == "__main__":
    unittest.main()
