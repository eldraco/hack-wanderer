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
- `tower_observations`: one row per tower/cell observation inside a log sample.
- `towers`: stable tower fingerprint plus editable label, notes, known flag, and ignored flag.
- `tower_features`: latest derived values, method evidence, Bayes score, rule score, and robust center.
- `anomaly_methods`: built-in method registry with help text, equations, variables, default thresholds, and map-layer hints.
- `method_settings`: your edited enabled/weight/threshold settings.

Imports are idempotent:

- The same file is skipped if path, size, mtime, and SHA-256 match.
- Overlapping identical JSONL lines are deduplicated by content hash.
- Tower observations use deterministic IDs, so re-importing overlapping data does not duplicate evidence.

## Pages

### Map

Shows towers as Leaflet markers. Marker color follows Bayes posterior:

- green: low suspicion,
- orange: review-worthy,
- red: higher anomaly probability.

Use the toolbar to search identifiers, hide known towers, include ignored towers, or show anomaly-only towers.

Click a tower to open the side drawer. The drawer shows:

- identity fields,
- Bayes and rule scores,
- per-method XAI breakdown,
- variables, values, equations, thresholds, and effect on score,
- buttons for observation overlays (raw obs dots, stationary, bad GPS), clusters, place buckets, and center,
- an **Observations table** (loaded on demand) where you can click **Show** to open a specific point (useful when a tower has 1 point that overlaps the tower marker),
- per-observation **Ignore/Use** toggles. Ignored points stay visible but are excluded from recompute,
- a **Recompute this tower** button to update scores/features for just the selected tower (faster than full recompute when you are iterating on one case).

Terminology note: a **place bucket** is a small local area bucketed from GPS using a Web‑Mercator map tile at zoom 17 (shown like `z17/x/y`). It’s only used to group nearby points for local comparisons without addresses/geocoding.

### Towers

Search and sort the tower list by operator, RAT, TAC/LAC, cell ID, PCI, EARFCN, count, and score. Click a row to open the same tower detail drawer.

### Anomalies

Browse every tower that currently triggers positive anomaly evidence. Search tower identifiers, notes, tags, anomaly names, and anomaly method IDs, or filter the table to one anomaly method. Each row lists its triggered methods and their score contributions. Ignored towers are hidden unless explicitly included.

### Methods

Each anomaly method is data-driven:

- `enabled`: whether the method contributes to the score.
- `weight`: max log-odds contribution.
- threshold JSON: editable method thresholds.

After changes, click **Save settings**, then **Recompute scores**. Raw data is never mutated by threshold changes.

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

Examples of positive evidence:

- same fingerprint forms far clusters,
- same fingerprint forms far clusters even while stationary,
- signal is inconsistent with distance,
- signal jumps while stationary,
- PCI/EARFCN churn while stationary,
- bursty appearance despite stationary opportunity nearby.

Examples of negative evidence:

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
- `GET/PUT /api/methods`: read/edit method settings.
- `GET/PUT /api/config`: read/edit global configuration such as the altitude discount model.
- `GET/PUT/DELETE /api/admin/towers/{id}`: edit/delete towers.
- `GET /api/help`: method and variable glossary.

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
