# Local Tower Intelligence Dashboard

`tower_intel_server.py` is the persistent local dashboard for exploring `hack-wanderer` JSONL logs. It replaces the one-shot static HTML flow with a SQLite database plus a live FastAPI/Leaflet web app.

Important: this ranks anomalous or inconsistent cell fingerprints for manual review. It does **not** prove attribution to police, governments, or any actor.

## Install

The core import/recompute CLI uses the Python standard library plus the existing dashboard code. The live web app needs FastAPI:

```bash
pip install fastapi uvicorn python-multipart
```

or:

```bash
pip install -r requirements-tower-intel.txt
```

## First Run

Import one log:

```bash
python3 tower_intel_server.py ingest logs/14-5-2026.jsonl
```

Import many logs:

```bash
python3 tower_intel_server.py ingest logs/*.jsonl hack-wanderer.jsonl
```

Recompute features and scores:

```bash
python3 tower_intel_server.py recompute
```

Start the local app:

```bash
python3 tower_intel_server.py serve
```

Open:

```text
http://127.0.0.1:8890
```

Use another DB path if you want separate experiments:

```bash
python3 tower_intel_server.py --db experiments/prague.sqlite ingest logs/14-5-2026.jsonl
python3 tower_intel_server.py --db experiments/prague.sqlite recompute
python3 tower_intel_server.py --db experiments/prague.sqlite serve
```

## Commands

- `serve`: starts the local FastAPI server. Defaults to `127.0.0.1:8890`.
- `ingest FILE [FILE ...]`: streams JSONL files into SQLite.
- `recompute`: recomputes robust centers, stationary flags, feature values, method evidence, rule score, and Bayes score.
- `stats`: prints DB counts.
- `vacuum`: compacts the SQLite DB.

Useful bounded import for quick tests:

```bash
python3 tower_intel_server.py ingest logs/14-5-2026.jsonl --max-lines 5000
```

## Database

Default DB:

```text
tower_intel.sqlite
```

Back it up by copying the DB after stopping the server. If the server is running, copy the `-wal` and `-shm` files too, or run a SQLite backup externally.

Main tables:

- `import_files`: imported file path, size, mtime, SHA-256, row/error counts, import time.
- `raw_samples`: one row per JSONL log sample, including raw JSON, GPS position, `alt_m`, bad-GPS flag, stationary flag, and place bucket.
- `tower_observations`: one row per tower/cell observation inside a log sample. `observation_source` and `signal_metric` preserve which modem path produced the observation and what its signal value means.
- `towers`: stable tower fingerprint plus editable label, notes, known flag, and ignored flag.
- `tower_features`: latest derived values, method evidence, Bayes score, rule score, and robust center.
- `dwell_identity_features`: the latest dwell/local-novelty v2 context for each coarse identity (`operator + RAT + TAC/LAC + Cell ID`). It stores independent-window, visit, local-newness, detection-rate, and bounded-normality features as JSON, plus the representative fingerprint allowed to contribute coarse Cell-ID novelty to ranking.
- `tower_location_quality`: a live SQLite view that labels each tower `valid_gps`, `weird_gps`, or `unlocated`, includes accepted/rejected coordinate counts, and exposes an explicitly unreliable fallback centroid for towers seen only with rejected GPS.
- `anomaly_methods`: built-in method registry with help text, equations, variables, default thresholds, and map-layer hints.
- `method_settings`: your edited enabled/weight/threshold settings.

Imports are idempotent:

- The same file is skipped if path, size, mtime, and SHA-256 match.
- Overlapping identical JSONL lines are deduplicated by content hash.
- Tower observations use deterministic IDs, so re-importing overlapping data does not duplicate evidence.

## Pages

### Map

Shows towers as Leaflet markers. Marker color groups cells by their reported TAC/LAC: every marker with the same TAC/LAC uses the same deterministic color, and missing TAC/LAC values are gray. The map legend lists the colors and the number of currently visible towers in each group. Hide it with its × button or the **TAC/LAC legend** toolbar checkbox; the choice is remembered across reloads. This makes a cell using one area's code from a geographically separate location easier to spot. Bayes posterior remains visible in each marker tooltip and in the tower drawer.

Location quality is deliberately separate from TAC/LAC color:

- normal markers are robust centers made only from accepted GPS fixes,
- orange, thick, dashed markers with a warning tooltip are coarse centroids made only from rejected/weird GPS fixes,
- the Leaflet layer control can independently hide **Weird GPS tower locations (unreliable)**,
- weird-GPS centroids are never treated as base-station positions and never enter geographic anomaly scoring,
- when valid centers exist, weird-GPS points do not expand the initial map bounds.

Use the toolbar to search identifiers, filter towers by an inclusive UTC last-seen date range, hide known towers, include ignored towers, or show anomaly-only towers.

Click a tower to open the side drawer. The drawer shows:

- identity fields,
- local Cell-ID status, independent-window/visit counts, and bounded dwell-normality credit,
- Bayes and rule scores,
- per-method XAI breakdown,
- variables, values, equations, thresholds, and effect on score,
- buttons for observation overlays (raw obs dots, stationary, bad GPS), clusters, place buckets, and center,
- an **Observations table** (loaded on demand) where you can click **Show** to open a specific point (useful when a tower has 1 point that overlaps the tower marker),
- per-observation **Ignore/Use** toggles. Ignored points stay visible but are excluded from recompute,
- a **Recompute this tower** button to update scores/features for just the selected tower (faster than full recompute when you are iterating on one case).

Terminology note: a **place bucket** is a small local area bucketed from GPS using a Web‑Mercator map tile at zoom 17 (shown like `z17/x/y`). It’s used for map overlays and fine local grouping without addresses/geocoding. Dwell/local-novelty v2 rolls these buckets up to coarser **zoom-16 dwell venues**. The larger venue reduces false changes caused by ordinary indoor GPS wander across adjacent zoom-17 buckets.

A confirmed locally new Cell ID gets a red dashed outer ring on its valid-GPS map marker. A purple dotted outer ring means at least one experimental v2 replacement produced a **shadow candidate**. Purple candidates are visible in the tooltip, table, and drawer, but contribute zero to the live score. Neither ring replaces the TAC/LAC fill color or proves that the cell is rogue. Both ring meanings are shown in the hideable TAC/LAC legend.

### Towers

Search and sort the tower list by operator, RAT, TAC/LAC, cell ID, PCI, EARFCN, count, score, local evidence, location, and first/last-seen date. Click the **Local evidence** heading to sort that column. Its badges distinguish **NEW HERE**, **new, unconfirmed**, **first-visit baseline**, **stable dwell**, incomplete identities, and other insufficient-context states. Location shows the valid robust-center coordinates or, when no valid fix exists, the explicitly labeled weird-GPS fallback coordinates. First/last seen use all non-ignored observations, so indoor towers still retain their observation dates. Hover a displayed date to see its full UTC timestamp. Click **Show** to open the same tower detail drawer on the map.

### Anomalies

Browse every tower that currently triggers positive anomaly evidence. Search tower identifiers, notes, tags, anomaly names, and anomaly method IDs, or filter the table to one anomaly method. Each row lists its triggered methods and their score contributions. Ignored towers are hidden unless explicitly included.

### Methods

Each anomaly method is data-driven:

- `enabled`: whether the method contributes to the score.
- `weight`: max log-odds contribution.
- threshold JSON: editable method thresholds.

After changes, click **Save settings**, then **Recompute scores**. Raw data is never mutated by threshold changes.

Four legacy methods are disabled because their raw-count or wall-clock formulas could make a long stay look anomalous by itself:

- `disappears_despite_coverage`
- `new_area_code_in_well_covered_place`
- `ephemeral_stationary_opportunity`
- `place_change_correlation`

Their visit/window replacements are implemented as `transient_activation_v2`, `visit_aware_disappearance_v2`, `local_tac_novelty_v2`, and `per_cell_visit_change_v2`. They currently run in shadow mode: `would_trigger`, `shadow_norm01`, and `shadow_delta_logodds` retain the full diagnostic result, while `triggered`, `norm01`, and `delta_logodds` remain false/zero. The drawer labels shadow hits explicitly.

The core `new_in_well_covered_place` method now uses dwell/local-novelty v2 windows and completed visits instead of the old raw-observation-count definition.

The same page also exposes the **altitude discount configuration**:

- local ground/floor is estimated per place bucket as a **robust minimum** altitude after rejecting suspicious low outliers,
- points near that local ground keep full value,
- higher points reduce geo-heavy evidence,
- with the default settings, roughly **10 m above local ground gives about half value**.

After changing altitude settings, click **Save altitude config**, then **Recompute scores**.

### Imports

Import logs by local path or upload JSONL files through the browser. After import, run recompute to update scores.

### Admin

Search towers and edit:

- `known`: verified/expected tower; adds negative evidence to reduce false positives.
- `ignored`: hidden from default anomaly views, but still kept in the DB.
- delete: removes a tower and its observations.

You can also ignore individual observation points from the tower drawer (map popup or observation table). This is intended for “I know this fix is garbage” cases. It does not delete data; it only flips an `ignored` flag so recompute can skip those points.

### Help

Explains:

- Bayes equation,
- every method,
- every variable shown in the UI,
- the meaning of “log sample”, “tower observation”, “place bucket”, “stationary”, “bad GPS”, and each score component.

## Exports

Each tower detail drawer has:

- `Export MD`: Markdown report with identity, scores, methods, equations, values, timestamps, and feature JSON.
- `Export DOCX`: Word-compatible report generated locally.

API paths:

```text
/api/towers/{id}/export.md
/api/towers/{id}/export.docx
```

## Scoring Model

The primary score is Bayesian log-odds:

```text
logit(P suspicious | evidence) = logit(prior) + Σ method Δlog-odds
```

Positive evidence raises suspicion. Negative evidence lowers it. This is intentional: the whole point is to reduce false positives and rank towers for human review.

### Dwell and local novelty v2

Raw polling rows are not treated as independent evidence. Recompute builds the following hierarchy from accepted, non-ignored stationary observations:

1. Fine zoom-17 place buckets are rolled up into zoom-16 dwell venues.
2. Observations in a venue are grouped into epoch-aligned **10-minute independent windows**. A cell seen repeatedly inside one window still contributes only one presence window.
3. A new visit requires more than **6 hours** of separation. Crossing midnight does not split a continuous visit.
4. Opportunity is compared only in compatible `operator + RAT + observation source` context. A registration-only scan cannot prove that a CPSI cell was absent.

The first visit to a venue builds its local Cell-ID baseline. A Cell ID appearing late during that same visit is ordinary baseline expansion and receives no local-newness evidence. The default confirmed local-new rule is:

```text
completed comparable prior visit exists
+ enough independent prior windows where the Cell ID was absent
+ the Cell ID appears in at least two independent windows now
= locally new Cell ID
```

Insufficient prior coverage remains unknown rather than suspicious. A one-window appearance after an adequate baseline is shown as **new, unconfirmed**, but it contributes no local-newness score until repeated. Cell IDs that were first learned during the first visit remain marked as baseline discoveries, not anomalies.

Long, unchanged observation contributes bounded negative evidence through `dwell_stability`. More independent windows, days, and revisits improve confidence, while diminishing returns prevent thousands of scans from producing unlimited normality credit. Repeated raw rows inside the same window add no credit. This means a long stable stay makes established cells less suspicious and simultaneously makes the local baseline more useful for detecting a later change.

The dwell identity is coarse: `operator + RAT + TAC/LAC + Cell ID`. PCI/EARFCN variants share the same dwell diagnosis, so discovering more radio variants during a long stay does not multiply Cell-ID novelty candidates. A stable deterministic representative fingerprint is the only child allowed to add that coarse novelty contribution to ranking; the other variants retain the shared diagnostic fields. Sampling longer cannot move the contribution merely by changing which child has the largest raw row count. Missing, incomplete, or zero Cell IDs are retained for review but cannot trigger local-newness evidence.

Registration, CPSI, and other modem sources are analyzed separately before their evidence is consolidated. TAC/LAC context remains source-specific because real modems can report incompatible encodings for the same network value. Signal changes are compared only within the same source, metric, and EARFCN; CPSI tenths are normalized first (for example, `-920` becomes `-92.0 dBm`). A later sighting of the same coarse identity from another source cancels or postpones a disappearance result.

The four recovered analyses are deliberately conservative:

- transient activation: two prior visits/12 windows, a dense fixed burst, then two later visits/12 windows and a conservative rate drop;
- disappearance: a repeatable baseline, two later visits/12 windows with zero hits, and posterior-predictive `P(zero) <= 0.01`;
- TAC/LAC novelty: two prior visits/12 windows, an 85% dominant prior code, and a candidate in at least three windows/60% of current opportunity;
- per-cell visit change: fixed two-versus-two visit phases, at least three comparable peers, and like-for-like robust signal/detection change after common-mode subtraction.

On the August 2, 2026 local database, the shadow backtest produced 3 transient candidates, 2 disappearance candidates, 1 TAC/LAC event, and 0 peer-corrected visit-change candidates. The sparse results are visible for review, but all four replacements remain disabled until those examples can be labeled; only seven towers currently have manual review labels, which is not enough to estimate a false-positive rate.

Bad-GPS and ignored observations never create dwell venues, visits, windows, baselines, or local-newness evidence.

You can inspect the materialized coarse-identity context directly:

```sql
SELECT coarse_identity_key, computed_at, model_version,
       primary_tower_id, features_json
FROM dwell_identity_features;
```

### Correlated evidence families

Methods still show every diagnostic reason, but correlated methods no longer contribute as if each were independent. Effective log-odds are capped within the location/GPS, radio-stability, network-identity, cell-lifecycle, place-context, external, and normality families. Each method record preserves its raw delta, family, and applied family scale for explanation; Bayes posterior and rule score use the capped effective delta. Manual known/ignored handling remains separate.

Examples of positive evidence:

- same fingerprint forms far clusters,
- same fingerprint forms far clusters even while stationary,
- signal is inconsistent with distance,
- signal jumps while stationary,
- PCI/EARFCN churn while stationary,
- a Cell ID confirmed locally new after a completed, comparable prior visit.

Examples of negative evidence:

- stable repeated presence across independent dwell windows and visits,
- stable repeated observations across days,
- known/verified tower flag,
- many-day presence.
- elevated observation points, which automatically discount geo-heavy methods because higher windows/floors can hear farther towers.

## GPS Handling

Raw GPS is stored exactly as observed. Derived calculations exclude bad GPS fixes by default.

Bad GPS means either:

- the GPS source reports an invalid/no-fix state (for example external GPS `gps_device.fix_quality == 0` / `status != A`, or modem GPS fix_status == 0), or
- consecutive valid fixes imply an impossible speed jump.

These points remain visible in the UI, but they do not create false anomaly evidence.

For indoor/airport logs where every coordinate is rejected, the app still permits coarse cellular and temporal review. It stores the individual observations with `bad_gps=1`, labels the tower `weird_gps` in the `tower_location_quality` view, and draws its rejected-coordinate centroid in the warning layer. This is intentionally marked unreliable everywhere: map tooltip, tower drawer, Towers/Anomalies tables, Markdown export, and DOCX export.

Rejected GPS coordinates never receive a `place_id` and never contribute to place-bucket counts, prior/post coverage, local altitude floors, or the **Place buckets** map overlay. Ignored observations are excluded from those bucket calculations and overlays as well.

They are also excluded from dwell/local-novelty v2. Only accepted, stationary, non-ignored observations can establish a zoom-16 dwell venue, opportunity window, visit baseline, local-newness result, or dwell-stability credit.

You can inspect the distinction directly in SQLite:

```sql
SELECT tower_id, location_quality,
       valid_gps_count, weird_gps_count, unlocated_count,
       weird_center_lat, weird_center_lon
FROM tower_location_quality
ORDER BY weird_gps_count DESC;

SELECT tower_id, ts, lat, lon, bad_gps, ignored
FROM tower_observations
WHERE bad_gps = 1;
```

Altitude is also stored when the fix looks valid:

- external GPS altitude usually comes from the NMEA `GGA` sentence,
- modem GPS altitude comes from `AT+CGNSINF`,
- invalid / no-fix samples do not contribute altitude evidence.

The recompute step builds a **local ground/floor altitude baseline** per map bucket and uses **relative altitude above that local floor**, not raw sea-level altitude. This matters because a hill and a 5th-floor window should not be treated the same.

Ground/floor estimation is now:

- gather valid altitudes inside a place bucket,
- reject suspiciously low GPS-altitude outliers using `Q1 - k*IQR`,
- use the **minimum remaining altitude** as the local ground/floor baseline.

Altitude currently softens methods that rely on where you heard the tower:

- multi-location,
- stationary multi-location,
- GPS spread,
- center drift,
- signal-vs-distance mismatch,
- stationary signal instability / jump methods,
- stationary PCI / EARFCN churn,
- ephemeral despite stationary opportunity.

In the UI this appears as:

- `geo_altitude_confidence`
- `stationary_geo_altitude_confidence`
- `altitude_factor`

Smaller confidence means those methods still show up, but they count less because elevated positions can legitimately hear farther towers.

Default altitude curve:

- `0–2 m` above local ground: full value,
- `~10 m` above local ground: about half value,
- higher than that: keeps decaying, but never below the configured minimum confidence.

The app computes derived positions separately:

- robust tower center,
- all-point clusters,
- stationary-only clusters,
- place buckets,
- GPS spread.

## API

Useful endpoints:

- `POST /api/import`: import local paths or uploaded JSONL files.
- `POST /api/recompute`: recompute all derived evidence.
- `GET /api/towers`: searchable tower list.
- `GET /api/anomaly-towers`: all towers with triggered positive anomaly evidence, with optional search and method filtering.
- `GET /api/towers/{id}`: full tower profile.
- `GET /api/towers/{id}/points`: raw, stationary, bad GPS, clusters, place buckets, center.
- `POST /api/towers/{id}/wigle-enrich`: optional click-only WiGLE lookup using server-side credentials from `.env`.
- `GET/PUT /api/methods`: read/edit method settings.
- `GET/PUT /api/config`: read/edit global configuration such as the altitude discount model.
- `GET/PUT/DELETE /api/admin/towers/{id}`: edit/delete towers.
- `GET /api/help`: method and variable glossary.

The tower drawer has a **Check WiGLE** button. Set `WIGLE_API_NAME` and `WIGLE_API_TOKEN`
in `.env` to enable it. Successful lookups are stored in SQLite and shown automatically
when the tower drawer is reopened. Use **Refresh WiGLE** to explicitly ask WiGLE again.
The credentials stay on the server; the browser receives only the lookup result. New
captures key towers by the cell's numeric PLMN rather than an alphanumeric `AT+COPS?`
label, because that label may contain SIM/EONS branding. PLMN `23002` is displayed as
O2 Czech Republic. The exact legacy label `TESCO Mobile TESCO Mobile` is also displayed
as O2/`230-02`, while mixed roaming labels are left unchanged because they cannot be
safely migrated without historical numeric MCC/MNC data.

Stored WiGLE checks also feed two editable Bayes/XAI methods:

- **Absent from checked WiGLE records** raises suspicion when an explicit lookup found no exact match.
- **Historical WiGLE presence** lowers suspicion. Older first appearance and more recent last appearance strengthen that normality evidence.

## Maintenance

Show counts:

```bash
python3 tower_intel_server.py stats
```

Compact DB:

```bash
python3 tower_intel_server.py vacuum
```

Daily workflow:

```bash
python3 tower_intel_server.py ingest logs/$(date +%d-%m-%Y).jsonl
python3 tower_intel_server.py recompute
python3 tower_intel_server.py serve
```
