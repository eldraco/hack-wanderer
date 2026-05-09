# Tower anomaly detection: statistical tests & ML methods

This repo can log cellular “tower fingerprints” over time. From that, you can rank **anomalous cells** for manual review.

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

- **Ephemeral cell score**: towers that appear only for a short time window (minutes–hours) and then disappear.
- **Novelty in place**: first-ever appearance of a cell in a place bucket.

### E) Consistency / plausibility tests
These are often the most useful because they’re explainable.

- **Location inconsistency**: same `(operator, rat, tac_lac, cell_id)` observed in far-separated GPS points within an implausibly short time.
- **Parameter churn**: in the same small area, does `cell_id`/`tac_lac` churn more than baseline?
- **RAT downgrade rate**: if your baseline is “mostly LTE”, spikes of 2G/3G presence in a place/time window can be ranked.
- **Disappear / reappear**: towers that come and go in distinct “sessions” (long gaps), especially if the reappearance correlates with other anomalies.
- **Multi-location / moving behavior**: the same fingerprint forms multiple spatial clusters or the inferred center drifts materially over time (often indicates cell-ID reuse, logging bias, or something worth review).

### F) Signal vs distance consistency (important for “far-away towers”)
Some cells are rarely seen simply because they’re far away or only reachable from specific vantage points. To avoid false alarms:

- Build a per-tower model of **signal vs distance** using the inferred tower center as a proxy (distance from center).
  - Simple/robust: `signal ~ a + b * log10(distance_m + 1)` with **Theil–Sen** slope and MAD-based residual checks.
  - Flag: a high fraction of large residual outliers (“signal too strong/weak for where you were”) or a sudden regime change in that relationship.
- Prefer doing this **per place bucket and per band/earfcn** if you have those fields, because propagation differs by frequency.

### G) “Tower moved” vs “ID reused” vs “route bias”
You generally can’t prove a tower moved from these logs alone. What you *can* detect is:\n\n- **Multi-cluster geometry**: the same fingerprint yields 2+ distinct clusters separated by km.\n- **Center drift**: the inferred center shifts a lot between weeks/months.\n\nIn practice, this often means **cell-ID reuse**, **sector/PCI changes**, or that your device observed the cell from different corridors at different times. Treat it as “needs review”, not a conclusion.\n+
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

## Best overall approach (recommended)

1) **Start with explainable heuristics**:
   - novelty-in-place + ephemerality + disappear/reappear + signal-vs-distance mismatch + location inconsistency
2) Combine them into a **score** (not a yes/no).
3) Only then add **unsupervised ML** (Isolation Forest) to help rank long lists.
4) Keep everything **auditable**: show which features contributed.

If you later gain access to control-plane indicators (identity-request chains, ciphering anomalies, downgrade redirects), fold them into the same scoring framework—those signals are typically far more discriminative than RSSI-only approaches.
