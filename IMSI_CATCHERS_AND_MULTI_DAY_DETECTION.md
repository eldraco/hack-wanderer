# IMSI catchers (cell-site simulators): how they work, and how to spot them with multi-day logs

This document is written for the `hack-wanderer` project. It focuses on *defensive* understanding and detection. IMSI-catcher/CSS detection is inherently probabilistic: you can usually produce “suspicious” or “unlikely” indicators, not courtroom-proof attribution.

Sources referenced throughout:
- EFF, **“Gotta Catch ’Em All: Understanding How IMSI-Catchers Exploit Cell Networks (Probably)”** (2019). https://www.eff.org/wp/gotta-catch-em-all-understanding-how-imsi-catchers-exploit-cell-networks
- EFF, **“Meet Rayhunter: A New Open Source Tool from EFF to Detect Cellular Spying”** (March 4, 2025). https://www.eff.org/deeplinks/2025/03/meet-rayhunter-new-open-source-tool-eff-detect-cellular-spying
- Rayhunter project + “book” docs (especially heuristics). https://github.com/EFForg/rayhunter and https://efforg.github.io/rayhunter/

---

## 1) How an IMSI catcher (police CSS) works

### The basic idea: a fake base station
An IMSI catcher (often called a **cell-site simulator**, CSS) is a device that **pretends to be a legitimate cell tower** so nearby phones try to connect to it. Once a phone is talking to the CSS, the operator can:

- **Identify** phones in the area by collecting **IMSI** (SIM identity) and/or **IMEI** (device identity). EFF describes “classic IMSI-catchers” as devices that record nearby IMSIs during the connection procedure. (EFF “Gotta Catch ’Em All”, Section 3.1). 
- **Locate** a specific phone by forcing it to keep interacting with the CSS (and/or by moving the CSS / using multiple vantage points). (EFF “Gotta Catch ’Em All”, overview sections; and EFF Rayhunter blog describes CSS use for pinpointing phone location without involving the carrier.)
- **Sometimes intercept communications**, especially in legacy **2G/GSM** scenarios, or by forcing downgrades to 2G first. (EFF “Gotta Catch ’Em All”, Section 3.2 and 3.2.4; Rayhunter heuristics explicitly treat 2G downgrade as suspicious.)

### Why this works (in plain terms)
Phones choose what “tower” to camp on using broadcast radio info like signal strength and “system information” messages. A CSS exploits that selection behavior by:

1. **Being the most attractive cell** (e.g., stronger signal, or seemingly “best” cell parameters).
2. **Getting the phone to reveal an identity**:
   - In older protocols, the network can request an identity (IMSI/IMEI) during attach procedures.
   - Even in LTE/4G, networks still sometimes legitimately request IMSI/IMEI (e.g., first attach, temporary ID expired), but Rayhunter treats certain *chains of events* around identity requests as suspicious.
3. **Using protocol weaknesses** to keep the phone talking / to force a downgrade.

### 2G vs 3G/4G/5G matters
EFF emphasizes that “IMSI-catcher” capabilities vary a lot by cellular generation.

- **2G/GSM** historically made **interception** more feasible because the phone can’t reliably authenticate the network, and encryption can be weak or disabled. (EFF “Gotta Catch ’Em All”, Section 3.2.)
- **4G/LTE** (and 5G) improved security, but **downgrade and control-plane manipulation** are still common concerns in the CSS threat model. EFF describes *service downgrading* and *protocol downgrade attacks* as a path to revealing IMSI and follow-on attacks. (EFF “Gotta Catch ’Em All”, sections 3.2.4 and 3.5.1.)

---

## 2) What Rayhunter does (and why it’s a big deal)

EFF’s Rayhunter is important because it’s an example of “real-world detection” that doesn’t rely on expensive SDR lab rigs.

### Rayhunter’s core technique: watch control-plane traffic
Rayhunter runs on certain consumer LTE hotspots (initially the Orbic RC400L). EFF’s intro post states that Rayhunter:

- **Intercepts, stores, and analyzes control traffic** between the hotspot and the base station it’s connected to.
- **Does not analyze user traffic** (e.g., web requests). 
- Detects **“suspicious events”** in real time, including:
  - attempts to **downgrade to 2G**, and
  - **IMSI requests under suspicious circumstances**.
- Exports logs as **PCAP** so experts can review. (EFF Rayhunter blog post.)

In short: Rayhunter “sees” low-level protocol messages (NAS/RRC/SIB etc) that typical phone apps can’t reliably access without deep platform hooks.

### Rayhunter’s heuristic approach (signals it looks for)
Rayhunter’s docs list multiple analyzers (heuristics). Highlights (see `https://efforg.github.io/rayhunter/heuristics.html`):

- **IMSI Requested (v3):** not “IMSI requested = bad”, but a *sequence* like: connect → identity request → **no authentication** → disconnect. Rayhunter considers this less prone to false positives than naive IMSI-request alarms, and notes a known false-positive scenario (e.g., reconnecting after long disconnect, sometimes seen when flying). 
- **2G downgrade signals:**
  - “Connection Release/Redirected Carrier 2G Downgrade” (release/redirect to 2G).
  - “LTE SIB6/7 Downgrade (v2)” (LTE broadcasting SIB6/7 with 2G/3G priorities). Rayhunter notes SIB messages are **not encrypted or authenticated**, enabling downgrade tricks.
- **Null cipher checks:**
  - “Null Cipher” at the RRC layer and “NAS Null Cipher” at the NAS layer: towers suggesting **EEA0 (no encryption)** should be extremely rare in real commercial networks.
- **Incomplete SIB chain:** fake or lazy base stations may broadcast minimal SIBs.

The important design lesson for `hack-wanderer`: **single indicators are noisy**; “chains of events” and “combinations of anomalies” are much stronger.

---

## 3) Using *this* project’s multi-day data to flag “tower looks like CSS”

### First: what `hack-wanderer` currently records
From `hack-wanderer.jsonl`, each observation already includes (at least):

- timestamps (`timestamp_utc`, and in newer logs `timestamp_local`, `timezone`)
- registration state (`network.creg`, `network.cgreg`, `network.cereg`) including `stat_code`, `lac_tac`, `cell_id`, and LTE `rat` when available
- signal quality (`network.csq.rssi_dbm`)
- operator (`network.cops_current.operator`, `act`)
- a `towers[]` list (currently mostly `source="registration"` with `cell_id`, `tac_lac`, and `rat`)
- a `location` block in many rows (`lat`, `lon`, speed/course)

You also attempt vendor-specific scans (`AT+QENG`, `AT+QNWINFO`, `AT+QCSQ`), but in practice the stored `vendor.*` fields may be inconsistent depending on modem/firmware and response parsing.

So: the most reliable, widely-available signals for multi-day detection are currently **(location, time, RAT, TAC/LAC, Cell ID, RSSI)**.

### The goal: build a “normal baseline”, then look for outliers
Across many days in the same city/neighborhood, *legitimate* cells have relatively stable fingerprints:

- a consistent set of **cells** that serve a given area
- reasonable **handover patterns** as you move
- stable-ish **TAC/LAC** regions and “who serves what”

A CSS tends to look different because it is:

- **ephemeral** (appears for a short time window), and/or
- **strong** (unusually high RSSI for a cell that otherwise never dominates there), and/or
- causes **unusual identity / downgrade / cipher behavior** (if you can observe it).

EFF explicitly calls out “ephemerality” as something worth investigating, but also warns it has false positives (temporary towers, maintenance, etc.). (EFF “Gotta Catch ’Em All”, detection section.)

### Practical multi-day scoring approach (works with your existing JSONL)
Treat detection as a *scoring* problem: every observation can add points to a “suspicion score” for a **cell fingerprint**, then you review high-scoring cells.

#### Step A — define the thing you’re scoring (“cell fingerprint”)
With current logs, a useful key is:

- `fingerprint = (operator, rat, tac_lac, cell_id)`

If you later get richer RF info (EARFCN/ARFCN, PCI, MCC/MNC, bands, etc.), expand the fingerprint.

#### Step B — build per-place baselines
Cluster observations into “places” so you compare like with like:

- simplest: geohash / grid (e.g., ~100–300m buckets)
- better: DBSCAN clustering on lat/lon

For each place bucket, compute:

- set of fingerprints commonly seen there
- per-fingerprint: typical RSSI distribution (median + MAD), typical dwell time, typical hours-of-day

#### Step C — compute anomaly features
For each fingerprint in each place bucket:

1. **Ephemeral appearance**
   - Appears only within a small time window (e.g., < 30–60 minutes) across all days.
   - Appears on one day only, never again.

2. **RSSI outlier vs. that place’s history**
   - RSSI is much stronger than expected for that area (e.g., > median + N*MAD).
   - Important: RSSI alone is weak evidence, but it’s useful combined with ephemerality.

3. **RAT downgrade / unusual RAT transitions** (coarse version)
   - Sudden switch from LTE (`network.cereg.rat == "LTE"`) to GSM/2G registration in a location where you almost never see 2G.
   - Repeated “bounce” between RATs in short intervals.

4. **Location inconsistency**
   - Same `(tac_lac, cell_id)` appears at GPS points far apart (km-level) within an implausibly short time. (Often indicates either logging issues, cell-ID reuse, or something unusual.)

5. **Registration oddities**
   - Spikes in `stat_text` like `registration_denied`, `searching`, etc., correlated with a new fingerprint.

#### Step D — combine into a score + thresholds
Example scoring (illustrative only):

- +3: fingerprint is new to that place bucket
- +4: fingerprint is ephemeral in that bucket
- +2: RSSI is a strong outlier
- +3: RAT downgrade event in same window
- +2: registration anomalies in same window

Alert only when score exceeds a threshold and persists for multiple consecutive samples (to reduce one-off noise).

### Why “multi-day history” helps (and what EFF criticized in older apps)
EFF notes research where IMSI-catcher detection apps often collected tower power measurements but **did not compare against historical values**, limiting their ability to detect abnormal power for a tower. (EFF “Gotta Catch ’Em All”, discussion of detection apps.)

Your project is well positioned to improve on that *because you already log over time*.

---

## 4) Getting closer to Rayhunter-level detection inside `hack-wanderer`

Rayhunter’s strongest signals come from **control-plane message inspection** (NAS/RRC/SIB) and **chains of events** (identity request without auth, redirects to 2G, null cipher, incomplete SIB chains).

To approximate that in this project, you’d need one of:

1. **A modem/platform that can expose control-plane traces** (or a vendor SDK/API that emits NAS/RRC events), or
2. **A device that can output PCAP-like captures** of those layers (similar to Rayhunter’s hotspot approach), or
3. **An SDR-based monitor** (more complex + more legal constraints).

Once you can observe those messages, you can implement Rayhunter-like heuristics directly:

- suspicious IMSI/IMEI identity requests *as a chain*, not a single event
- explicit 2G redirection / SIB priority manipulation
- null cipher proposals (EEA0) in RRC/NAS
- incomplete SIB chains

Even then, keep the “baseline + scoring” approach: real networks do weird things, and false positives are common.

---

## 5) Operational cautions (false positives, legality, safety)

- **False positives are expected.** Temporary cells (events), maintenance, roaming quirks, and modem parsing bugs can look “weird”. Always treat output as “suspicious, review needed.”
- **Be careful sharing raw captures/logs.** Rayhunter’s FAQ warns captures can contain sensitive identifiers like IMSIs and unique tower IDs that can reveal location. (Rayhunter FAQ.)
- **Avoid recommending illegal RF activity.** Do not transmit or attempt to “test” by building your own fake base station; Rayhunter explicitly discourages this and notes it can violate FCC rules. (Rayhunter FAQ.)

---

## Appendix: quick mapping to current `hack-wanderer` fields

- “Cell fingerprint” (coarse): `network.cops_current.operator`, `network.cereg.rat`, `network.cereg.lac_tac`, `network.cereg.cell_id`
- Signal strength: `network.csq.rssi_dbm`
- Place clustering: `location.lat`, `location.lon`
- Per-sample tower list: `towers[]` (currently mostly `source=registration`)

If you want, I can also add a small offline analysis script (reads a JSONL, builds per-place baselines, and outputs “top suspicious fingerprints” with reasons) using only the fields above.
