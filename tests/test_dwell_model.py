"""Regression tests for dwell-time-invariant local tower novelty.

These tests deliberately exercise the pure evidence helper rather than the
SQLite recompute pipeline.  That keeps the essential semantics explicit:
raw polling rows are not independent evidence, a visit is not split at
midnight, and local novelty requires a completed prior visit to the place.
"""

import datetime as dt
import unittest

import tower_intel_server as intel


BASE_TS = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc).timestamp()
PLACE_ID = "venue:test-stationary-place"
OPERATOR = "TestNet"
RAT = "LTE"
TAC = 123
BASELINE_CELL = 100
CANDIDATE_CELL = 999
DISAPPEARING_CELL = 300
CHANGE_CELL = 500
REFERENCE_CELLS = (601, 602, 603)


def observation(
    ts: float,
    cell_id: int,
    *,
    pci: int = 7,
    earfcn: int = 1400,
    sample_uid: str | None = None,
    tac_lac: int = TAC,
    signal: float | None = None,
    source: str = "synthetic",
    signal_metric: str | None = None,
) -> dict:
    """Return one reliable, stationary radio observation for the v2 helper."""

    return {
        "ts": float(ts),
        "sample_uid": sample_uid or f"sample-{ts:.0f}",
        "place_id": PLACE_ID,
        "operator": OPERATOR,
        "rat": RAT,
        "tac_lac": tac_lac,
        "cell_id": cell_id,
        "pci": pci,
        "earfcn": earfcn,
        "bad_gps": False,
        "ignored": False,
        "stationary": True,
        "signal": signal,
        "signal_metric": signal_metric or ("rsrp" if signal is not None else None),
        "observation_source": source,
    }


def identity_key(cell_id: int, *, tac_lac: int = TAC) -> str:
    return intel.base_identity_key(intel.BaseKey(OPERATOR, RAT, tac_lac, cell_id))


def analyze(rows: list[dict]) -> dict:
    return intel.compute_dwell_evidence(
        rows,
        window_s=10 * 60,
        visit_gap_s=6 * 3600,
        min_prior_windows=3,
    )


class DwellEvidenceTests(unittest.TestCase):
    def test_cell_appearing_late_during_first_visit_is_baseline_not_local_novelty(self):
        rows = []
        # This known cell establishes that we were continuously observing the
        # same radio context throughout the first visit.
        for window in range(8):
            ts = BASE_TS + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL))
            # A less frequently broadcast neighbour discovered halfway through
            # a first visit is normal baseline expansion, even when repeated.
            if window >= 4:
                rows.append(observation(ts, CANDIDATE_CELL))

        result = analyze(rows)
        candidate = result["identities"][identity_key(CANDIDATE_CELL)]
        novelty = candidate["local_novelty"]

        self.assertEqual(candidate["raw_observations"], 4)
        self.assertEqual(candidate["opportunity_windows"], 4)
        self.assertEqual(candidate["independent_visits"], 1)
        self.assertEqual(novelty["state"], "baseline_building")
        self.assertFalse(novelty["eligible"])
        self.assertFalse(novelty["triggered"])
        self.assertEqual(novelty["prior_windows"], 0)
        self.assertEqual(novelty["effect"], 0.0)

    def test_repeated_cell_on_later_well_covered_visit_triggers_local_novelty(self):
        rows = []
        # Completed first visit: sufficient comparable opportunity, but no
        # observation of the candidate Cell ID.
        for window in range(6):
            rows.append(observation(BASE_TS + window * 10 * 60, BASELINE_CELL))

        # A day later is an independent visit.  The candidate repeats in four
        # windows, rather than being a one-off neighbour scan.
        revisit_ts = BASE_TS + 24 * 3600
        for window in range(4):
            ts = revisit_ts + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL))
            rows.append(observation(ts, CANDIDATE_CELL))

        result = analyze(rows)
        candidate = result["identities"][identity_key(CANDIDATE_CELL)]
        novelty = candidate["local_novelty"]

        self.assertTrue(novelty["eligible"])
        self.assertTrue(novelty["triggered"])
        self.assertGreaterEqual(novelty["prior_windows"], 3)
        self.assertEqual(novelty["current_windows"], 4)
        self.assertGreater(novelty["effect"], 0.0)
        self.assertLessEqual(novelty["effect"], 1.0)

    def test_polling_frequency_and_duplicate_rows_do_not_inflate_evidence(self):
        def scenario(samples_per_window: int) -> list[dict]:
            rows = []
            for visit_start, include_candidate in (
                (BASE_TS, False),
                (BASE_TS + 24 * 3600, True),
            ):
                for window in range(4):
                    window_start = visit_start + window * 10 * 60
                    for sample in range(samples_per_window):
                        ts = window_start + sample * (9 * 60 / max(1, samples_per_window))
                        uid = f"sample-{ts:.3f}"
                        rows.append(observation(ts, BASELINE_CELL, sample_uid=uid))
                        if include_candidate:
                            rows.append(observation(ts, CANDIDATE_CELL, sample_uid=uid))
            return rows

        sparse = analyze(scenario(1))
        dense_rows = scenario(10)
        dense = analyze(dense_rows)
        # Simulate accidental duplicate rows as well as a faster polling rate.
        duplicated = analyze(dense_rows + [dict(row) for row in dense_rows])

        key = identity_key(CANDIDATE_CELL)
        sparse_candidate = sparse["identities"][key]
        dense_candidate = dense["identities"][key]
        duplicate_candidate = duplicated["identities"][key]

        self.assertGreater(dense_candidate["raw_observations"], sparse_candidate["raw_observations"])
        self.assertEqual(sparse_candidate["opportunity_windows"], dense_candidate["opportunity_windows"])
        self.assertEqual(dense_candidate["opportunity_windows"], duplicate_candidate["opportunity_windows"])
        self.assertEqual(sparse_candidate["independent_visits"], dense_candidate["independent_visits"])
        self.assertEqual(
            sparse_candidate["local_novelty"]["prior_windows"],
            dense_candidate["local_novelty"]["prior_windows"],
        )
        self.assertEqual(
            sparse_candidate["local_novelty"]["current_windows"],
            dense_candidate["local_novelty"]["current_windows"],
        )
        self.assertAlmostEqual(
            sparse_candidate["local_novelty"]["effect"],
            dense_candidate["local_novelty"]["effect"],
        )
        self.assertAlmostEqual(
            dense_candidate["local_novelty"]["effect"],
            duplicate_candidate["local_novelty"]["effect"],
        )

        stable_key = identity_key(BASELINE_CELL)
        self.assertAlmostEqual(
            sparse["identities"][stable_key]["normality_credit"],
            dense["identities"][stable_key]["normality_credit"],
        )
        self.assertAlmostEqual(
            dense["identities"][stable_key]["normality_credit"],
            duplicated["identities"][stable_key]["normality_credit"],
        )

    def test_long_unchanged_dwell_adds_bounded_normality(self):
        def stable_dwell(window_count: int) -> list[dict]:
            return [
                observation(BASE_TS + window * 10 * 60, BASELINE_CELL)
                for window in range(window_count)
            ]

        short = analyze(stable_dwell(3))["identities"][identity_key(BASELINE_CELL)]
        long = analyze(stable_dwell(24))["identities"][identity_key(BASELINE_CELL)]
        very_long = analyze(stable_dwell(240))["identities"][identity_key(BASELINE_CELL)]

        self.assertGreater(short["normality_credit"], 0.0)
        self.assertGreater(long["normality_credit"], short["normality_credit"])
        self.assertGreaterEqual(very_long["normality_credit"], long["normality_credit"])
        for metrics in (short, long, very_long):
            self.assertGreaterEqual(metrics["normality_credit"], 0.0)
            self.assertLessEqual(metrics["normality_credit"], 1.0)

    def test_continuous_visit_crossing_midnight_is_not_split(self):
        start = BASE_TS + 23 * 3600 + 40 * 60
        rows = [
            observation(start + window * 10 * 60, BASELINE_CELL)
            for window in range(5)
        ]

        metrics = analyze(rows)["identities"][identity_key(BASELINE_CELL)]

        self.assertEqual(metrics["opportunity_windows"], 5)
        self.assertEqual(metrics["independent_visits"], 1)
        self.assertEqual(metrics["local_novelty"]["state"], "baseline_building")
        self.assertFalse(metrics["local_novelty"]["triggered"])

    def test_pci_and_earfcn_variants_share_one_local_cell_identity(self):
        rows = []
        for window in range(4):
            ts = BASE_TS + window * 10 * 60
            uid = f"sample-{ts:.0f}"
            rows.append(observation(ts, BASELINE_CELL, pci=7, earfcn=1400, sample_uid=uid))
            rows.append(observation(ts, BASELINE_CELL, pci=31, earfcn=1650, sample_uid=uid))

        result = analyze(rows)

        self.assertEqual(set(result["identities"]), {identity_key(BASELINE_CELL)})
        metrics = result["identities"][identity_key(BASELINE_CELL)]
        self.assertEqual(metrics["raw_observations"], 8)
        self.assertEqual(metrics["opportunity_windows"], 4)
        self.assertEqual(metrics["independent_visits"], 1)
        self.assertFalse(metrics["local_novelty"]["triggered"])

    def test_bad_gps_ignored_and_moving_rows_cannot_build_local_baseline(self):
        rows = []
        for window in range(6):
            row = observation(BASE_TS + window * 10 * 60, BASELINE_CELL)
            row["bad_gps"] = True
            rows.append(row)
        ignored = observation(BASE_TS + 24 * 3600, BASELINE_CELL)
        ignored["ignored"] = True
        rows.append(ignored)
        moving = observation(BASE_TS + 25 * 3600, BASELINE_CELL)
        moving["stationary"] = False
        rows.append(moving)
        # This is the only reliable stationary visit. It must therefore build
        # the baseline, not appear new because of rejected earlier fixes.
        for window in range(4):
            rows.append(observation(BASE_TS + 48 * 3600 + window * 10 * 60, CANDIDATE_CELL))

        result = analyze(rows)

        self.assertNotIn(identity_key(BASELINE_CELL), result["identities"])
        candidate = result["identities"][identity_key(CANDIDATE_CELL)]
        self.assertEqual(candidate["local_novelty"]["state"], "baseline_building")
        self.assertFalse(candidate["local_novelty"]["triggered"])

    def test_zero_cell_id_is_incomplete_and_never_locally_new(self):
        rows = []
        for window in range(5):
            rows.append(observation(BASE_TS + window * 10 * 60, BASELINE_CELL))
        revisit = BASE_TS + 24 * 3600
        for window in range(4):
            ts = revisit + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL))
            rows.append(observation(ts, 0))

        metrics = analyze(rows)["identities"][identity_key(0)]

        self.assertEqual(metrics["local_novelty"]["state"], "incomplete_cell_identity")
        self.assertFalse(metrics["local_novelty"]["eligible"])
        self.assertFalse(metrics["local_novelty"]["triggered"])
        self.assertEqual(metrics["local_novelty"]["effect"], 0.0)

    def test_transient_activation_requires_two_prior_and_two_post_visits(self):
        rows = []
        # Two completed prior visits establish a durable local baseline.
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                rows.append(observation(visit_start + window * 10 * 60, BASELINE_CELL))

        revisit = BASE_TS + 48 * 3600
        for window in range(12):
            ts = revisit + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL))
            if 2 <= window <= 9:
                rows.append(observation(ts, CANDIDATE_CELL))
        # Two later visits provide independent evidence that the burst did not
        # simply persist under a slower network scan cycle.
        for visit_index in range(3, 5):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                rows.append(observation(visit_start + window * 10 * 60, BASELINE_CELL))

        transient = analyze(rows)["identities"][identity_key(CANDIDATE_CELL)]["transient_activation"]

        self.assertTrue(transient["eligible"])
        self.assertTrue(transient["triggered"])
        self.assertGreaterEqual(transient["pre_windows"], 12)
        self.assertGreaterEqual(transient["prior_visits"], 2)
        self.assertEqual(transient["present_windows"], 8)
        self.assertGreaterEqual(transient["post_windows"], 12)
        self.assertGreaterEqual(transient["post_visits"], 2)
        self.assertGreater(transient["effect"], 0.0)
        self.assertLessEqual(transient["effect"], 1.0)

    def test_transient_pattern_during_first_visit_is_only_baseline_building(self):
        rows = []
        for window in range(11):
            ts = BASE_TS + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL))
            if 2 <= window <= 4:
                rows.append(observation(ts, CANDIDATE_CELL))

        metrics = analyze(rows)["identities"][identity_key(CANDIDATE_CELL)]
        transient = metrics["transient_activation"]

        self.assertEqual(metrics["local_novelty"]["state"], "baseline_building")
        self.assertFalse(transient["eligible"])
        self.assertFalse(transient["triggered"])
        self.assertEqual(transient["effect"], 0.0)

    def test_disappearance_requires_reliable_history_and_two_later_visits(self):
        def scenario(*, historical_visits: int, historical_windows: int, later_visits: int) -> dict:
            rows = []
            for visit_index in range(historical_visits):
                visit_start = BASE_TS + visit_index * 24 * 3600
                for window in range(6):
                    ts = visit_start + window * 10 * 60
                    rows.append(observation(ts, BASELINE_CELL))
                    if window < historical_windows:
                        rows.append(observation(ts, DISAPPEARING_CELL))
            for later_index in range(later_visits):
                visit_start = BASE_TS + (historical_visits + later_index) * 24 * 3600
                for window in range(6):
                    rows.append(observation(visit_start + window * 10 * 60, BASELINE_CELL))
            return analyze(rows)["identities"][identity_key(DISAPPEARING_CELL)]["disappearance"]

        reliable_and_repeatedly_absent = scenario(historical_visits=2, historical_windows=6, later_visits=2)
        only_one_later_visit = scenario(historical_visits=2, historical_windows=6, later_visits=1)
        only_one_baseline_visit = scenario(historical_visits=1, historical_windows=6, later_visits=2)
        unreliable_history = scenario(historical_visits=2, historical_windows=1, later_visits=2)

        self.assertTrue(reliable_and_repeatedly_absent["eligible"])
        self.assertTrue(reliable_and_repeatedly_absent["triggered"])
        self.assertGreaterEqual(reliable_and_repeatedly_absent["historical_detection_rate"], 0.8)
        self.assertGreaterEqual(reliable_and_repeatedly_absent["later_visits"], 2)
        self.assertGreaterEqual(reliable_and_repeatedly_absent["later_windows"], 12)
        self.assertGreater(reliable_and_repeatedly_absent["effect"], 0.0)

        self.assertFalse(only_one_later_visit["triggered"])
        self.assertLess(only_one_later_visit["later_visits"], 2)
        self.assertFalse(only_one_baseline_visit["triggered"])
        self.assertFalse(unreliable_history["triggered"])
        self.assertLess(unreliable_history["historical_detection_rate"], 0.5)

    def test_new_tac_requires_stable_prior_tac_and_repeated_later_windows(self):
        old_tac = 123
        new_tac = 456
        rows = []
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                rows.append(observation(visit_start + window * 10 * 60, BASELINE_CELL, tac_lac=old_tac))

        revisit = BASE_TS + 48 * 3600
        for window in range(4):
            ts = revisit + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL, tac_lac=old_tac))
            rows.append(observation(ts, CANDIDATE_CELL, tac_lac=new_tac))

        tac_evidence = analyze(rows)["identities"][identity_key(CANDIDATE_CELL, tac_lac=new_tac)]["local_tac_novelty"]

        self.assertTrue(tac_evidence["eligible"])
        self.assertTrue(tac_evidence["triggered"])
        self.assertEqual(tac_evidence["prior_dominant_tac"], old_tac)
        self.assertGreaterEqual(tac_evidence["prior_dominant_fraction"], 0.85)
        self.assertGreaterEqual(tac_evidence["prior_windows"], 12)
        self.assertEqual(tac_evidence["current_windows"], 4)
        self.assertGreater(tac_evidence["effect"], 0.0)
        self.assertLessEqual(tac_evidence["effect"], 1.0)

        # Merely having prior coverage is insufficient when the area's TAC
        # pattern was already mixed. A third TAC is then not a stable-baseline
        # violation by itself.
        unstable_rows = []
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                prior_tac = old_tac if window % 2 == 0 else old_tac + 1
                unstable_rows.append(observation(
                    visit_start + window * 10 * 60,
                    BASELINE_CELL,
                    tac_lac=prior_tac,
                ))
        for window in range(4):
            ts = revisit + window * 10 * 60
            unstable_rows.append(observation(ts, BASELINE_CELL, tac_lac=old_tac))
            unstable_rows.append(observation(ts, CANDIDATE_CELL, tac_lac=new_tac))

        unstable = analyze(unstable_rows)["identities"][identity_key(CANDIDATE_CELL, tac_lac=new_tac)]["local_tac_novelty"]
        self.assertFalse(unstable["triggered"])
        self.assertLessEqual(unstable["prior_dominant_fraction"], 0.6)

        # Stable context still cannot establish TAC novelty when either the
        # independent-visit or twelve-window baseline requirement is missing.
        one_prior_visit = [
            observation(BASE_TS + window * 10 * 60, BASELINE_CELL, tac_lac=old_tac)
            for window in range(6)
        ]
        one_prior_revisit = BASE_TS + 24 * 3600
        for window in range(4):
            ts = one_prior_revisit + window * 10 * 60
            one_prior_visit.append(observation(ts, BASELINE_CELL, tac_lac=old_tac))
            one_prior_visit.append(observation(ts, CANDIDATE_CELL, tac_lac=new_tac))
        one_prior = analyze(one_prior_visit)["identities"][identity_key(CANDIDATE_CELL, tac_lac=new_tac)]["local_tac_novelty"]
        self.assertFalse(one_prior["triggered"])

        too_few_windows = []
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(5):
                too_few_windows.append(observation(
                    visit_start + window * 10 * 60,
                    BASELINE_CELL,
                    tac_lac=old_tac,
                ))
        for window in range(4):
            ts = revisit + window * 10 * 60
            too_few_windows.append(observation(ts, BASELINE_CELL, tac_lac=old_tac))
            too_few_windows.append(observation(ts, CANDIDATE_CELL, tac_lac=new_tac))
        insufficient_coverage = analyze(too_few_windows)["identities"][identity_key(CANDIDATE_CELL, tac_lac=new_tac)]["local_tac_novelty"]
        self.assertFalse(insufficient_coverage["triggered"])
        self.assertLess(insufficient_coverage["prior_windows"], 12)

    def test_tac_discovered_during_first_visit_is_not_locally_new(self):
        old_tac = 123
        new_tac = 456
        rows = []
        for window in range(8):
            ts = BASE_TS + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL, tac_lac=old_tac))
            if window >= 4:
                rows.append(observation(ts, CANDIDATE_CELL, tac_lac=new_tac))

        tac_evidence = analyze(rows)["identities"][identity_key(CANDIDATE_CELL, tac_lac=new_tac)]["local_tac_novelty"]

        self.assertFalse(tac_evidence["eligible"])
        self.assertFalse(tac_evidence["triggered"])
        self.assertEqual(tac_evidence["effect"], 0.0)

    def test_visit_change_is_cell_specific_and_removes_common_mode_shift(self):
        base_signals = {
            CHANGE_CELL: -92.0,
            BASELINE_CELL: -80.0,
            REFERENCE_CELLS[0]: -84.0,
            REFERENCE_CELLS[1]: -88.0,
            REFERENCE_CELLS[2]: -96.0,
        }

        def four_visit_rows(recent_signal_changes: dict[int, float]) -> list[dict]:
            rows = []
            for visit_index in range(4):
                visit_start = BASE_TS + visit_index * 24 * 3600
                for window in range(6):
                    ts = visit_start + window * 10 * 60
                    uid = f"sample-{ts:.0f}"
                    for cell_id, base_signal in base_signals.items():
                        shift = recent_signal_changes.get(cell_id, 0.0) if visit_index >= 2 else 0.0
                        rows.append(observation(ts, cell_id, signal=base_signal + shift, sample_uid=uid))
            return rows

        cell_specific = analyze(four_visit_rows({CHANGE_CELL: 22.0}))
        changed = cell_specific["identities"][identity_key(CHANGE_CELL)]["visit_change"]

        self.assertTrue(changed["eligible"])
        self.assertTrue(changed["triggered"])
        self.assertGreater(abs(changed["signal_shift_db"]), 10.0)
        self.assertLess(abs(changed["common_mode_shift_db"]), 3.0)
        self.assertGreater(changed["effect"], 0.0)
        for cell_id in (BASELINE_CELL, *REFERENCE_CELLS):
            unchanged_reference = cell_specific["identities"][identity_key(cell_id)]["visit_change"]
            self.assertFalse(unchanged_reference["triggered"], f"target-only shift propagated to Cell ID {cell_id}")

        common_shift = {cell_id: 15.0 for cell_id in base_signals}
        common_mode = analyze(four_visit_rows(common_shift))
        for cell_id in base_signals:
            evidence = common_mode["identities"][identity_key(cell_id)]["visit_change"]
            self.assertFalse(evidence["triggered"], f"common-mode shift flagged Cell ID {cell_id}")
            self.assertEqual(evidence["effect"], 0.0)
            self.assertGreater(abs(evidence["common_mode_shift_db"]), 10.0)

    def test_all_v2_dwell_method_effects_are_polling_and_duplicate_invariant(self):
        new_tac = 456

        def scenario(samples_per_window: int) -> list[dict]:
            rows = []
            visit_windows = (6, 6, 12, 6, 6)
            for visit_index, window_count in enumerate(visit_windows):
                visit_start = BASE_TS + visit_index * 24 * 3600
                for window in range(window_count):
                    window_start = visit_start + window * 10 * 60
                    for sample in range(samples_per_window):
                        ts = window_start + sample * (9 * 60 / max(1, samples_per_window))
                        uid = f"sample-{ts:.3f}"
                        rows.append(observation(ts, BASELINE_CELL, signal=-80.0, sample_uid=uid))
                        for ref_index, ref_cell in enumerate(REFERENCE_CELLS):
                            rows.append(observation(ts, ref_cell, signal=-84.0 - 4 * ref_index, sample_uid=uid))
                        if visit_index <= 1:
                            rows.append(observation(ts, DISAPPEARING_CELL, signal=-82.0, sample_uid=uid))
                        change_signal = -92.0 if visit_index <= 1 else -68.0
                        rows.append(observation(ts, CHANGE_CELL, signal=change_signal, sample_uid=uid))
                        if visit_index == 2 and 2 <= window <= 9:
                            rows.append(observation(
                                ts,
                                CANDIDATE_CELL,
                                tac_lac=new_tac,
                                signal=-76.0,
                                sample_uid=uid,
                            ))
            return rows

        sparse_rows = scenario(1)
        dense_rows = scenario(8)
        sparse = analyze(sparse_rows)
        dense = analyze(dense_rows)
        duplicated = analyze(dense_rows + [dict(row) for row in dense_rows])

        cases = (
            (identity_key(CANDIDATE_CELL, tac_lac=new_tac), "transient_activation"),
            (identity_key(DISAPPEARING_CELL), "disappearance"),
            (identity_key(CANDIDATE_CELL, tac_lac=new_tac), "local_tac_novelty"),
            (identity_key(CHANGE_CELL), "visit_change"),
        )
        for key, method_name in cases:
            sparse_metrics = sparse["identities"][key]
            dense_metrics = dense["identities"][key]
            duplicate_metrics = duplicated["identities"][key]
            sparse_evidence = sparse_metrics[method_name]
            dense_evidence = dense_metrics[method_name]
            duplicate_evidence = duplicate_metrics[method_name]

            self.assertTrue(sparse_evidence["triggered"], method_name)
            self.assertTrue(dense_evidence["triggered"], method_name)
            self.assertTrue(duplicate_evidence["triggered"], method_name)
            self.assertGreater(dense_metrics["raw_observations"], sparse_metrics["raw_observations"])
            self.assertAlmostEqual(sparse_evidence["effect"], dense_evidence["effect"], msg=method_name)
            self.assertAlmostEqual(dense_evidence["effect"], duplicate_evidence["effect"], msg=method_name)

    def test_registration_windows_are_not_cpsi_opportunities(self):
        rows = []
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                rows.append(observation(
                    visit_start + window * 10 * 60,
                    BASELINE_CELL,
                    source="registration",
                ))
        revisit = BASE_TS + 48 * 3600
        for window in range(4):
            ts = revisit + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL, source="registration"))
            rows.append(observation(ts, CANDIDATE_CELL, source="cpsi"))

        candidate = analyze(rows)["identities"][identity_key(CANDIDATE_CELL)]

        self.assertFalse(candidate["local_novelty"]["triggered"])
        self.assertEqual(candidate["local_novelty"]["prior_windows"], 0)
        self.assertFalse(candidate["local_tac_novelty"]["triggered"])
        self.assertEqual(candidate["local_tac_novelty"]["prior_windows"], 0)

    def test_cross_source_reappearance_moves_disappearance_cutoff(self):
        rows = []
        for visit_index in range(2):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                ts = visit_start + window * 10 * 60
                rows.append(observation(ts, BASELINE_CELL, source="cpsi"))
                rows.append(observation(ts, DISAPPEARING_CELL, source="cpsi"))
        absent_visit = BASE_TS + 48 * 3600
        for window in range(6):
            rows.append(observation(absent_visit + window * 10 * 60, BASELINE_CELL, source="cpsi"))
        reappearing_visit = BASE_TS + 72 * 3600
        for window in range(6):
            ts = reappearing_visit + window * 10 * 60
            rows.append(observation(ts, BASELINE_CELL, source="cpsi"))
            rows.append(observation(ts, DISAPPEARING_CELL, source="registration"))

        evidence = analyze(rows)["identities"][identity_key(DISAPPEARING_CELL)]["disappearance"]

        self.assertFalse(evidence["triggered"])
        self.assertEqual(evidence["later_windows"], 0)

    def test_cpsi_tenths_are_normalized_before_visit_signal_change(self):
        base_signals = {
            CHANGE_CELL: -920.0,
            BASELINE_CELL: -800.0,
            REFERENCE_CELLS[0]: -840.0,
            REFERENCE_CELLS[1]: -880.0,
            REFERENCE_CELLS[2]: -960.0,
        }
        rows = []
        for visit_index in range(4):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(6):
                ts = visit_start + window * 10 * 60
                for cell_index, (cell_id, raw_signal) in enumerate(base_signals.items()):
                    cell_ts = ts + cell_index * 20
                    shift = 220.0 if cell_id == CHANGE_CELL and visit_index >= 2 else 0.0
                    rows.append(observation(
                        cell_ts,
                        cell_id,
                        signal=raw_signal + shift,
                        signal_metric="rsrp",
                        source="cpsi",
                        sample_uid=f"single-cell-{cell_ts:.0f}-{cell_id}",
                    ))

        evidence = analyze(rows)["identities"][identity_key(CHANGE_CELL)]["visit_change"]

        self.assertTrue(evidence["triggered"])
        self.assertAlmostEqual(evidence["baseline_signal_median"], -92.0)
        self.assertAlmostEqual(evidence["recent_signal_median"], -70.0)
        self.assertAlmostEqual(evidence["signal_shift_db"], 22.0)

    def test_long_unchanged_visits_add_normality_without_v2_anomalies(self):
        rows = []
        stable_cells = (BASELINE_CELL, *REFERENCE_CELLS)
        for visit_index in range(5):
            visit_start = BASE_TS + visit_index * 24 * 3600
            for window in range(48):
                ts = visit_start + window * 10 * 60
                for cell_index, cell_id in enumerate(stable_cells):
                    rows.append(observation(
                        ts + cell_index * 20,
                        cell_id,
                        signal=-80.0 - 4.0 * cell_index,
                        sample_uid=f"stable-{visit_index}-{window}-{cell_id}",
                    ))

        result = analyze(rows)
        for cell_id in stable_cells:
            metrics = result["identities"][identity_key(cell_id)]
            self.assertGreater(metrics["normality_credit"], 0.8)
            for method_name in (
                "transient_activation",
                "disappearance",
                "local_tac_novelty",
                "visit_change",
            ):
                self.assertFalse(metrics[method_name]["triggered"], f"{method_name} flagged stable Cell ID {cell_id}")


if __name__ == "__main__":
    unittest.main()
