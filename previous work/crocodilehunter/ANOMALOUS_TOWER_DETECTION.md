# Crocodilehunter: How It Detects “Anomalous” (Suspicious) Cell Towers

This document describes, from the code, the exact methods Crocodilehunter uses to flag cell towers/cells as anomalous. It also lists exactly what data is captured and stored.

Repo analyzed: `EFForg/crocodilehunter` (code under `src/`).

## What Data It Captures

### 1. Raw LTE measurement packet (ingest format)

`src/watchdog.py:Watchdog.process_tower(data)` expects a single comma-separated ASCII string read from a local UNIX socket (`/tmp/croc.sock`), then splits it and maps fields by fixed index:

1. `mcc` (int) = `data[0]`
2. `mnc` (int) = `data[1]`
3. `tac` (int) = `data[2]`  (LTE Tracking Area Code; the code sometimes calls this “lac” when talking to OpenCellID)
4. `cid` (int) = `data[3]`  (LTE Cell ID)
5. `phyid` (int) = `data[4]` (physical cell ID / PCI)
6. `earfcn` (int) = `data[5]` (LTE downlink EARFCN channel)
7. `rssi` (float) = `data[6]`
8. `frequency` (float) = `data[7]`
9. `enodeb_id` (float in ingest; stored as int column) = `data[8]`
10. `sector_id` (float in ingest; stored as int column) = `data[9]`
11. `cfo` (float) = `data[10]` (carrier frequency offset)
12. `rsrq` (float) = `data[11]`
13. `snr` (float) = `data[12]`
14. `rsrp` (float) = `data[13]`
15. `tx_pwr` (float) = `data[14]`
16. `raw_sib1` (string) = `data[15]` (raw SIB1 payload/representation as provided by the scanner)
17. `timestamp` (datetime) = `datetime.fromtimestamp(int(data[16]))`

These values are stored into the SQLAlchemy `Tower` model defined by `src/database.py:Tower` / `BaseTower`.

### 2. GPS location at time of ingest

Also inside `Watchdog.process_tower()`:

- `lat`, `lon` are taken from `Watchdog.get_gps()`, which prefers GPSD (`gpsd.get_current()`), and can fall back to:
  - OpenCellID/UnwiredLabs Wi-Fi geolocation (`src/ocid.py:ocid_get_location()`) if GPS is disabled and an OCID key exists, or
  - a configured default coordinate (`general.gps_default`) if GPS is disabled and OCID didn’t return a location.

### 3. Derived/computed fields stored per record

After constructing the `Tower` row, Crocodilehunter computes additional fields:

- `est_dist` (estimated tower distance in meters) via `src/database.py:Tower.est_distance()`
  - Uses a Free Space Path Loss style estimate based on the observed `rssi`, measured `tx_pwr`, and `frequency`.
- `suspiciousness` (integer score) and `classification` (`unknown` vs `suspicious`) via `src/watchdog.py:Watchdog.calculate_suspiciousness()`
- `external_db` (`unknown`, `wigle`, `opencellid`, `not_present`) via `src/watchdog.py:Watchdog.check_wigle()`

## Where “Anomaly Detection” Lives

Detection is an additive scoring system. There is no ML model in use (the code has a “TODO: let’s try some ML?” comment).

Entry point:

1. `src/watchdog.py:Watchdog.process_tower()` inserts a `Tower` row.
2. It then calls `src/watchdog.py:Watchdog.calculate_suspiciousness(new_tower)`.

Classification rule:

- If `tower.suspiciousness >= 20` then `tower.classification = TowerClassification.suspicious`
- Else `tower.classification = TowerClassification.unknown`

Note: `check_wigle()` can force suspicion regardless of the 20-point rule (see below) by adding `+30` and directly setting `classification = suspicious` when the tower cannot be externally confirmed.

## The EXACT Methods Used To Flag a Tower as Suspicious

All checks are invoked (in order) by `src/watchdog.py:Watchdog.calculate_suspiciousness()`:

1. `check_mcc(tower)` (optional; gated by config)
2. `check_mnc(tower)` (optional; gated by config)
3. `check_existing_rssi(tower)`
4. `check_changed_tac(tower)`
5. `check_new_location(tower)`
6. `check_rssi(tower)`
7. `check_wigle(tower)` (only if Wigle is enabled)

### 1. Geographic code mismatch: `check_mcc()` and `check_mnc()` (optional)

Called only if `general.check_geographic_codes` is enabled in config (`calculate_suspiciousness()` reads it via `config.getboolean(...)`).

- `src/watchdog.py:Watchdog.check_mcc(tower)`
  - Reads expected MCCs from `general.expected_mccs` (comma-separated ints).
  - If `tower.mcc` is not in that list: `tower.suspiciousness += 30`.

- `src/watchdog.py:Watchdog.check_mnc(tower)`
  - Reads expected MNCs from `general.expected_mncs` (comma-separated ints).
  - If `tower.mnc` is not in that list: `tower.suspiciousness += 20`.

### 2. “Same cell suddenly louder than before”: `check_existing_rssi()`

`src/watchdog.py:Watchdog.check_existing_rssi(tower)`

It looks up historical records for the *same* cell identity, defined as matching:

- `mcc`, `mnc`, `tac`, `cid`, `phyid`, `earfcn`

If there are more than 3 prior `rssi` samples:

- Compute `mean = numpy.mean(rssi_levels)` and `std = numpy.std(rssi_levels)`.
- If current `tower.rssi > mean + std`:
  - `tower.suspiciousness += (tower.rssi - mean)`

### 3. “Cell ID seen before, but TAC changed”: `check_changed_tac()`

`src/watchdog.py:Watchdog.check_changed_tac(tower)`

Finds an existing record matching:

- `mcc`, `mnc`, `cid`, `phyid`, `earfcn`

If found and `existing_tower.tac != tower.tac`:

- `tower.suspiciousness += 10`

### 4. “Same eNodeB appearing in a new place”: `check_new_location()`

`src/watchdog.py:Watchdog.check_new_location(tower)`

Pulls historical sightings for the same eNodeB identity, defined as matching:

- `mcc`, `mnc`, `enodeb_id`

Then:

1. Collect unique historical `lat`/`lon`.
2. If the historical latitude spread OR longitude spread is too small (`< 0.01` degrees), it returns early (it intentionally skips the check until there is enough geographic spread).
3. Compute:
   - `center_point = (mean(lat), mean(lon))`
   - `center_point_std_dev = (std(lat), std(lon))`
   - `border_point = (center_lat + std_lat, center_lon + std_lon)`
4. Convert these into a simple 2D Euclidean-like distance over degrees via `_get_point_distance(...)` (not a geodesic).
   - `radius = distance(center_point, border_point)`
   - `distance = distance(center_point, (tower.lat, tower.lon))`
5. If the new reading is outside the 1-sigma “radius” (`distance > radius`):
   - `s_coeff = (10 * distance - radius) ** 2`
   - `tower.suspiciousness += s_coeff`

This can add a large score depending on how far outside the expected cluster the new point is.

### 5. “Globally strong signal”: `check_rssi()`

`src/watchdog.py:Watchdog.check_rssi(tower)`

Looks at RSSI across *all* towers in the DB:

1. Query all records where `Tower.rssi is not None`.
2. If there are more than 3 RSSI values:
   - `rssi_mean = numpy.mean(rssis)`
   - `rssi_std  = numpy.std(rssis)`
3. If `tower.rssi > rssi_mean + rssi_std`:
   - `tower.suspiciousness += (tower.rssi - rssi_mean)`

### 6. External confirmation check (Wigle + OpenCellID): `check_wigle()`

`src/watchdog.py:Watchdog.check_wigle(tower)`

Purpose: mark towers/cells as more suspicious if they do not appear in external tower databases.

Steps:

1. Pre-cache reuse:
   - If a prior row exists for the same `(mcc, mnc, tac, cid)` where `external_db != unknown`, the new tower inherits that `external_db` (and if it was previously `unknown`, inherits its classification too).

2. Wigle query (if still unknown):
   - Calls `self.wigle.cell_search(tower.lat, tower.lon, 0.1, tower.cid, tower.tac)` (see `src/wigle.py:Wigle.cell_search()`).
   - If Wigle returns `resultCount < 1`: `tower.external_db = not_present`
   - Else: `tower.external_db = wigle`

3. OpenCellID query as a fallback (only if not Wigle-confirmed and an OCID key exists):
   - Calls `src/ocid.py:ocid_search_cell(db_session, api_key, mcc, mnc, lac=tac, cid)`
   - If response contains `'error'`: `tower.external_db = not_present`
   - Else: `tower.external_db = opencellid`

4. Scoring and forced classification:
   - If `tower.external_db == not_present`:
     - `tower.suspiciousness += 30`
     - `tower.classification = suspicious` (forced here)
   - If `tower.external_db` is `wigle` or `opencellid`:
     - No score is added by this method; it only records “externally confirmed”.

## Summary: What Makes a Tower “Anomalous” in This Codebase

In Crocodilehunter, a tower/cell becomes anomalous (classified `suspicious`) when any combination of the above checks pushes `suspiciousness` to 20+ (or when it’s missing from external DB checks, which immediately adds 30 and forces `suspicious`).

The anomaly signals are based on:

- Unexpected MCC/MNC compared to a configured allowlist (optional)
- Sudden RSSI increase compared to historical values for the same cell identity
- TAC change for the same `cid/phyid/earfcn` identity
- New geographic location outlier for a given `enodeb_id`
- Unusually strong RSSI compared to global DB history
- Lack of external confirmation (Wigle and/or OpenCellID)

