# Tower anomaly detection: statistical tests & ML methods

This repo can log cellular “tower fingerprints” over time. From that, you can rank **anomalous cells** for manual review.

There are now two analysis workflows:

- `tower_anomaly_dashboard.py`: one-shot static HTML report.
- `tower_intel_server.py`: persistent SQLite + FastAPI local app with editable method settings, DB administration, map exploration, per-tower XAI, and exports. Prefer this for multi-day evidence accumulation. See `TOWER_INTEL_APP.md`.

The persistent app stores the method registry in SQLite (`anomaly_methods`) and your edited thresholds/weights in `method_settings`. Recomputing scores updates only derived rows (`tower_features`); raw samples and observations are not mutated by threshold experiments.

Limits (important):
- **Attribution is hard.** A tower being anomalous does not prove it is a cell-site simulator.
- Stronger signals (e.g., Rayhunter) rely on **control-plane** visibility (NAS/RRC/SIB, ciphering negotiation, identity-request sequences). Typical USB LTE modems expose only *summaries* via AT commands.

---

## Evidence types you can extract from `hack-wanderer.jsonl`

Commonly available today:
- `operator` (from `network.cops_current.operator`)
- coarse IDs: `tac_lac`, `cell_id`, `rat` (from registration; and optionally richer LTE fields like `earfcn`, `pci`, `rsrp/rsrq/rssnr` if modem supports `AT+CPSI?`)
- device location/time series (`location.lat/lon`, timestamps)
- coarse signal (`network.csq.rssi_dbm`), and optionally LTE metrics (`rsrp`, `rsrq`, `rssnr`) if available

These support two big families of detection:
1) **Historical baseline + outlier detection** (per place / per route / per time-of-day)
2) **Consistency checks** (does a cell behave like a real network cell over days?)

---

## Metric glossary (what the dashboard shows)

Tower identity-ish fields:
- `operator`: string from `network.cops_current.operator`.
- `rat`: radio access technology (e.g., `LTE`, `GSM`) from registration / modem.
- `tac_lac`: LTE TAC or 2G/3G LAC (area code).
- `cell_id`: serving cell identifier (coarse; can be reused by networks over time).
- `earfcn`: LTE frequency channel number (when available; helps disambiguate).
- `pci`: LTE physical cell ID (when available; helps disambiguate sectors).

Counts / time coverage:
- `count`: how many samples this fingerprint was observed.
- `days_seen`: number of distinct calendar days with ≥1 observation.
- `duration_min`: `(last_seen - first_seen)` in minutes (first/last in the dataset window, not continuous uptime).
- `sessions`: number of “sessions” separated by gaps ≥ 6 hours (crude disappear/reappear metric).
- `max_gap_days`: largest time gap between consecutive observations (days).

Stationary-only evidence (stronger, less biased by you moving):
- A “stationary sample” is a log sample where the device stayed near an anchor (≤`--stationary-radius-m`) and implied speed stayed ≤`--stationary-max-speed-mps` for at least `--stationary-min-dur-s`.
- `stationary_count`: # of observations of this tower fingerprint that happened during stationary samples.
- `stationary_span_min`: span (minutes) between first and last stationary observation of this tower.
- `local_stationary_window_min`: stationary “opportunity window” (minutes) in the *same place buckets* where this tower appears (based on place stationary timestamps).
- `local_stationary_window_frac`: `stationary_span / local_stationary_window` (smaller = more “bursty” even though you were stationary nearby).

GPS robustness / “unbiasing”:
- `gps_spread_m`: median distance (meters) from observations to the inferred tower center **after outlier trimming**; higher means less consistent.
- Inferred tower center is computed via: median lat/lon → MAD trimming → trimmed/weighted mean (see script).

Multi-location / “moving” proxies:
- `clusters`: number of spatial clusters for this fingerprint using a small greedy clustering radius (default 400m).
- `cluster_top2_sep_m`: distance (meters) between the two biggest clusters’ centers. Big values suggest the same fingerprint appears in multiple distinct places (often ID reuse or logging bias).
- `center_drift_m`: maximum distance (meters) between weekly-binned inferred centers (proxy for long-term drift / ID reuse).
- `stationary_clusters`: same idea as `clusters`, but recomputed using only stationary-only GPS points (harder to explain via your movement).
- `stationary_cluster_top2_sep_m`: separation between the top two stationary clusters.

Signal & signal-vs-distance:
- `signal_median`: median of the chosen signal metric for this tower (often `rssi_dbm`; sometimes LTE `rsrp` if present).
- `signal_robust_z`: robust z-score of `signal_median` vs the global dataset signal distribution, using MAD as scale.
- `dist_outlier_frac`: fraction of samples that are large residual outliers (≥ 4*MAD) in a per-tower robust model `signal ~ a + b*log10(distance+1)`, where distance is computed from the inferred center (proxy for “signal too strong/weak for where you were”).
- `stationary_signal_mad`: robust spread (MAD) of signals observed while stationary for this tower.
- `stationary_signal_mad_z`: robust z-score of `stationary_signal_mad` vs baseline across towers.
- `stationary_jump_rate_8db`: within stationary samples, fraction of consecutive signals that jump by ≥8 dB.
- `stationary_jump_rate_z`: robust z-score of `stationary_jump_rate_8db` vs baseline.

Place-bucket baselines (tile buckets):
- `places_n`: number of place buckets (OSM tiles at `--place-zoom`) where this tower was observed.
- `place_entropy`: entropy of the tower’s place distribution (higher = more spread out across buckets).
- `dense_place_novelty`: count of “dense” places (≥500 total samples in that place) where this tower appears only 1–2 times (a novelty-in-dense-areas indicator).
- `change_places_frac`: fraction of this tower’s samples that occurred in places whose signal distribution appears to have changed sharply (place KS/CUSUM).
- `change_places_frac_stationary`: same as above, but using stationary-only bucket-change flags when available (preferred).
- `place_rat_surprise`: average “RAT transition surprise” in places where this tower appears, computed as average negative log-probability under a smoothed bigram (Markov) model (higher = more chaotic RAT switching in that place).

Stationary parameter churn (PCI/EARFCN instability for same coarse cell identity):
- These are computed for a coarse key `(operator, RAT, TAC/LAC, Cell ID)` (i.e., without PCI/EARFCN), using only stationary samples.
- `stationary_param_obs`: # of stationary observations contributing.
- `stationary_pci_distinct`, `stationary_earfcn_distinct`: distinct PCI/EARFCN values observed while stationary.
- `stationary_pci_change_rate`, `stationary_earfcn_change_rate`: fraction of stationary observations that changed vs previous stationary observation.
- `stationary_pci_change_rate_z`, `stationary_earfcn_change_rate_z`: robust z-scores vs dataset baseline.

Negative evidence:
- `stability_bonus`: when present, the dashboard subtracts points because the tower looks stable across multiple checks (helps reduce false positives).

Pure-Python “ML-ish” outlier rankers (feature-vector novelty):
- `ml_knn_score`: average distance to k nearest neighbors (k=5) in a scaled tower-feature space (higher = more isolated).
- `ml_knn_z`: robust z-score of `ml_knn_score` across towers.
- `ml_lof_score`: LOF-like density ratio (k=10) (higher = locally sparser than neighbors).
- `ml_lof_z`: robust z-score of `ml_lof_score` across towers.

--- 

## Statistical tests (practical)

### A) Univariate outlier tests
Run these per *place bucket* (geohash/grid) and per tower fingerprint.

- **Robust Z-score using MAD**: flag samples where `|x - median| / MAD` exceeds a threshold.
  - Apply to: `rsrp`, `rsrq`, `rssnr`, `rssi_dbm`, dwell time, or “time-between-handoffs”.
- **Generalized ESD (Extreme Studentized Deviate)**: detect up to `k` outliers in a sample.
  - Works best when distributions are roughly normal; use with care.
- **IQR rule** (Tukey fences): simple, explainable; good first pass.

### B) Distribution-change tests (day-to-day / before-vs-after)
Use to spot that a place’s serving-cell behavior changed abruptly.

- **KS test (Kolmogorov–Smirnov)**: compare the distribution of signal strength or cell IDs between two windows.
- **Mann–Whitney U**: compare medians of signal distributions between windows (non-parametric).

### C) Time-series change-point detection
Useful when you’re logging continuously.

- **CUSUM**: detects shifts in mean (e.g., sudden uplift in signal or sudden 2G appearance).
- **Bayesian Online Change Point Detection (BOCPD)**: more complex, good for streaming.

### D) Rarity / ephemerality tests
Not a single “test”, but strong evidence when combined.

- **Ephemeral cell score (stationary-opportunity based)**: towers that appear only for a short *stationary* span relative to the stationary opportunity window in the same place buckets (so “I walked past quickly” does not automatically trigger).
- **Novelty in place**: first-ever appearance of a cell in a place bucket.
- **New tower in a well-covered place**: if a tower first appears in a place bucket where you already have lots of prior good GPS observations, you can be more confident it is genuinely new (not just previously unobserved due to sparse sampling). In the persistent Tower Intel app this is implemented as method id `new_in_well_covered_place` using `new_place_prior_count`/`new_place_prior_days` (and stationary-only variants).

### E) Consistency / plausibility tests
These are often the most useful because they’re explainable.

- **Location inconsistency**: same `(operator, rat, tac_lac, cell_id)` observed in far-separated GPS points within an implausibly short time.
- **Parameter churn**: in the same small area, does `cell_id`/`tac_lac` churn more than baseline?
- **Parameter churn while stationary** (stronger): for the same `(operator,RAT,TAC/LAC,Cell ID)`, do PCI/EARFCN change *while you are stationary* more than baseline?
- **RAT downgrade rate**: if your baseline is “mostly LTE”, spikes of 2G/3G presence in a place/time window can be ranked.
- **Disappear / reappear**: towers that come and go in distinct “sessions” (long gaps), especially if the reappearance correlates with other anomalies.
- **Multi-location / moving behavior**: the same fingerprint forms multiple spatial clusters or the inferred center drifts materially over time (often indicates cell-ID reuse, logging bias, or something worth review).

### F) Signal vs distance consistency (important for “far-away towers”)
Some cells are rarely seen simply because they’re far away or only reachable from specific vantage points. To avoid false alarms:

- Build a per-tower model of **signal vs distance** using the inferred tower center as a proxy (distance from center).
  - Simple/robust: `signal ~ a + b * log10(distance_m + 1)` with **Theil–Sen** slope and MAD-based residual checks.
  - Flag: a high fraction of large residual outliers (“signal too strong/weak for where you were”) or a sudden regime change in that relationship.
- Prefer doing this **per place bucket and per band/earfcn** if you have those fields, because propagation differs by frequency.
- Add a stationary-only check: when you are stationary, distance-to-tower is approximately constant, so big signal jumps are stronger evidence of inconsistency (`stationary_signal_mad_z`, `stationary_jump_rate_z`).

### G) “Tower moved” vs “ID reused” vs “route bias”
You generally can’t prove a tower moved from these logs alone. What you *can* detect is:

- **Multi-cluster geometry**: the same fingerprint yields 2+ distinct clusters separated by km.
- **Center drift**: the inferred center shifts a lot between weeks/months.

In practice, this often means **cell-ID reuse**, **sector/PCI changes**, or that your device observed the cell from different corridors at different times. Treat it as “needs review”, not a conclusion.

### H) Altitude-aware discounting (important for windows / upper floors)
Higher vantage points can legitimately hear farther towers, so geo-heavy anomaly methods should not overreact just because you were on an upper floor or looking out of a window.

The persistent dashboard now handles this explicitly:

- altitude is ingested into `raw_samples.alt_m` when the GPS fix looks valid,
- a **local ground/floor baseline** is computed per place bucket using a robust minimum,
- each observation gets a **relative altitude above that local floor**,
- observations that are clearly elevated reduce the strength of some anomaly methods instead of being deleted.

This is intentionally local. A city hill and a tall building are different things, so we do **not** compare raw sea-level altitude across the whole dataset.

Ground/floor baseline details:

- collect valid altitudes in the same place bucket,
- reject suspiciously low GPS-altitude outliers with `Q1 - k*IQR`,
- take the **minimum remaining altitude** as the local ground/floor baseline.

Discount curve details:

- relative altitude up to the “no discount” height keeps full value,
- after that, evidence halves every configured “half-value height”,
- by default this gives **about half evidence around 10 m above local ground**,
- the factor is clamped by a configurable minimum confidence so evidence is softened, not erased.

Altitude discount features shown in the UI:

- `altitude_samples`: observations with usable altitude.
- `altitude_rel_median_m`: median relative altitude above the local floor.
- `altitude_rel_p90_m`: 90th percentile of relative altitude.
- `high_altitude_obs_frac`: fraction of observations clearly above the local floor.
- `geo_altitude_confidence`: multiplier in `[0,1]` that discounts geo/distance methods.
- `stationary_geo_altitude_confidence`: same idea, but computed from stationary-only observations when available.

Methods currently discounted by altitude:

- multi-location,
- stationary multi-location,
- GPS spread,
- center drift,
- signal-vs-distance mismatch,
- stationary signal MAD / jump rate,
- stationary PCI churn / EARFCN churn,
- ephemeral despite stationary opportunity.

This means a tower can still rank high, but if most of the evidence came from elevated observations, the final contribution is softened.
--- 

## Machine learning methods (ranking anomalies)

These methods are best used to *rank* candidates for review, not to output a binary verdict.

### A) Unsupervised anomaly detection (tabular)
You create per-tower (or per tower-in-place) feature vectors.

- **Isolation Forest**: strong default for mixed features; outputs anomaly score.
- **Local Outlier Factor (LOF)**: flags points that are locally sparse compared to neighbors.
- **One-Class SVM**: can work, but sensitive to scaling and kernel choice.
- **Robust covariance / Elliptic Envelope**: works if features are roughly Gaussian.

### B) Clustering-based novelty
- **DBSCAN/HDBSCAN**: cluster towers by behavior; points not belonging to clusters are candidates.
- **Gaussian Mixture Models (GMM)**: soft clustering; outliers via low likelihood.

### C) Sequence / time-series ML
If you model the *sequence* of events at a place (handoffs, RAT changes), not just per-tower aggregates.

- **Hidden Markov Models (HMMs)**: learn typical state transitions; anomalous sequences have low probability.
- **LSTM/Transformer autoencoders**: can detect unusual sequences but require more data + care to avoid overfitting.

### D) Supervised learning (only if you have labels)
You probably don’t. Without reliable ground truth, supervised models will mislead.
If you ever get labels:
- gradient boosted trees (XGBoost/LightGBM)
- calibrated logistic regression (explainability)

---

## GPS “unbiasing” (how to fix noisy location estimates)

When you infer a tower’s “position” from where *your device* was when it observed the tower, two issues occur:

1) **GPS noise/outliers** (bad fixes)
2) **Sampling bias** (you only drove certain roads; you rarely surround the tower uniformly)

Practical fixes:
- Use a **robust center estimator** per tower (median → MAD trimming → trimmed mean).
- Down-weight outlier points and optionally *mildly* up-weight stronger-signal observations.
- Report an uncertainty statistic (e.g., median distance to center), not a single point.

The script `tower_anomaly_dashboard.py` implements this robust approach and visualizes “GPS spread” as a circle.

---

## Ephemeral burst (what it really means here)

The dashboard’s “ephemeral” rule is **ratio-based** (place-aware), not “you only logged for 10 minutes”.

It compares:

- `duration_min`: how long the tower fingerprint spans in your dataset (first→last time you saw it)
- `local_window_min`: how long you were logging in the *same place buckets* where that tower appears
- `local_window_frac = duration / local_window`

It triggers when the tower is seen many times but occupies a small fraction of the local opportunity window (details are shown per tower in the HTML).

## “Clusters” (multi-location) — what they are

In the dashboard, “clusters” are computed from the GPS samples associated with a tower fingerprint using a streaming greedy method:

- Maintain cluster centers.
- Each new sample is assigned to the nearest existing cluster within `--cluster-radius-m` meters.
- Otherwise, a new cluster is created.

The HTML “Explain” view lists cluster centers and draws them on the map via the “Focus (clusters/buckets)” overlay.

## “Place buckets” (KS/CUSUM) — what is a bucket?

A “place bucket” is an OpenStreetMap Web Mercator **tile** at zoom `--place-zoom` (default 17). We group samples by tile to create a stable “where you were” context.

For each bucket, the dashboard keeps a bounded reservoir of signal samples and computes:

- KS two-sample D statistic (early vs late samples)
- a CUSUM-style change score

The HTML “Explain” view shows *which buckets* were involved for a given tower (with KS/CUSUM), and draws bucket rectangles on the map (Focus overlay).

### Place-bucket column glossary (what you see in the HTML)

- `place_id`: tile ID in `z/x/y` format (Web Mercator at zoom `--place-zoom`).
- `tower_count`: number of times this tower fingerprint was observed in that bucket.
- `place_total`: total number of log samples in that bucket (all towers).
- `place_dur_min`: minutes between the first and last logging activity timestamps seen in that bucket.
- `ks_d`: Kolmogorov–Smirnov D statistic comparing early vs late signal samples within the bucket (higher = distributions differ more). (No p-value.)
- `cusum`: CUSUM-like change score over the bucket’s signal time series (higher = stronger shift evidence).
- `changed`: boolean; true if `ks_d ≥ 0.25` or `cusum ≥ 8.0`.

### What is a “log sample”?

A “log sample” is one JSON object (one line) in your `hack-wanderer*.jsonl` file at a particular timestamp.
That JSON object can include multiple towers in `towers[]`, so:

- `place_total` counts JSONL lines whose GPS falls in that tile
- `tower_count` counts how many of those lines include this particular tower fingerprint

## Bad GPS jump filter (excluded but shown)

If the device GPS jumps unrealistically far in a short time (poor lock), those fixes can create fake “moving towers”.
The dashboard excludes such device fixes using `--gps-max-speed-mps` (default 60 m/s) but keeps a sample to display on the map in the “Bad GPS fixes (excluded)” overlay.

---

## Best overall approach (recommended)

1) **Start with explainable heuristics**:
   - novelty-in-place + ephemerality + disappear/reappear + signal-vs-distance mismatch + location inconsistency
2) Combine them into a **score** (not a yes/no).
3) Only then add **unsupervised ML** (Isolation Forest) to help rank long lists.
4) Keep everything **auditable**: show which features contributed.

If you later gain access to control-plane indicators (identity-request chains, ciphering anomalies, downgrade redirects), fold them into the same scoring framework—those signals are typically far more discriminative than RSSI-only approaches.

## Bayesian score (how we reduce false positives)

The dashboard now computes a **Bayesian log-odds** score per tower:

`logit(P(suspicious)) = logit(prior) + Σ Δ_i`

- `prior` defaults to `1e-4` (`--bayes-prior`), so the model starts very conservative.
- Each `Δ_i` is a **bounded** contribution derived from one evidence component (multi-location, stationary churn, distance mismatch, etc.).
- Some `Δ_i` are **negative evidence** (e.g. strong stability across days + stationary sessions), which *reduces* suspicion instead of only ever increasing it.

In the HTML, each tower’s “Explain” modal includes a **Bayesian score breakdown (XAI)** showing:
- prior → posterior probability
- each term’s `Δ log-odds`, odds multiplier, and its raw inputs (plus z/norm where applicable)

This is intentionally not “IMSI-catcher = true/false”; it is a conservative **ranking** designed to minimize false positives while still surfacing towers with multiple independent inconsistencies.
