#!/usr/bin/env python3
"""tower_anomaly_dashboard.py

Reads `hack-wanderer.jsonl` and produces an *anomaly-oriented* tower dashboard:
- Aggregates observed cellular cells/towers over many days.
- Estimates a robust per-tower "center" from noisy device GPS samples.
- Computes anomaly features (ephemeral cells, unusual signal dominance, location inconsistency, etc.).
- Emits a local HTML page with an interactive map + sortable table.

Important:
- This tool intentionally reports *anomalies* and *inconsistencies*. It does not claim attribution.
- IMSI-catcher/cell-site-simulator detection requires low-level control-plane visibility (NAS/RRC/SIB/ciphering)
  that typical USB modems do not expose via AT commands.

Usage:
  python3 tower_anomaly_dashboard.py hack-wanderer.jsonl --out towers-dashboard.html

By default it uses Leaflet (OpenStreetMap tiles) via CDN; you need an internet connection to load map tiles.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import html
import json
import math
import os
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


def parse_time(ts: str) -> Optional[dt.datetime]:
    if not ts or not isinstance(ts, str):
        return None
    try:
        if ts.endswith("Z"):
            return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def parse_time_arg(value: str) -> Optional[dt.datetime]:
    """
    Parse CLI time values.
    Accepts:
      - ISO8601 with Z (UTC) or offset, e.g. 2026-05-01T12:00:00Z
      - ISO date, e.g. 2026-05-01 (interpreted as 00:00:00 UTC)
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "T" not in text and len(text) == 10:
        text = text + "T00:00:00Z"
    return parse_time(text)


def iter_jsonl(path: str, max_lines: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    """
    Stream JSON objects from a JSONL file.

    `max_lines` limits how many *lines* are read from disk (including malformed lines).
    This prevents accidentally scanning multi-GB logs.
    """
    with open(path, "rb") as f:
        for i, raw in enumerate(f, 1):
            if max_lines and i > max_lines:
                break
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith("\x00"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def pick_location(obj: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    loc = obj.get("location") or {}
    lat = loc.get("lat")
    lon = loc.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return float(lat), float(lon)

    gpsd = obj.get("gps_device") or {}
    loc2 = gpsd.get("location") or {}
    lat2 = loc2.get("lat")
    lon2 = loc2.get("lon")
    if isinstance(lat2, (int, float)) and isinstance(lon2, (int, float)):
        return float(lat2), float(lon2)

    return None


def to_epoch_seconds(t: dt.datetime) -> float:
    if t.tzinfo is None:
        # assume UTC-ish
        return t.replace(tzinfo=dt.timezone.utc).timestamp()
    return t.timestamp()


def epoch_to_iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat(timespec="seconds")


def day_id_from_epoch(ts: float) -> int:
    # UTC day number
    return int(ts // 86400)


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # WGS84 mean Earth radius
    r = 6371008.8
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = phi2 - phi1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def latlon_to_tile(lat: float, lon: float, zoom: int) -> Tuple[int, int]:
    """
    Web Mercator tile coordinates (like OSM).
    Useful for stable place bucketing without extra deps.
    """
    lat = max(-85.05112878, min(85.05112878, lat))
    n = 2.0 ** zoom
    x = int((lon + 180.0) / 360.0 * n)
    lat_rad = math.radians(lat)
    y = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
    # clamp
    x = max(0, min(int(n) - 1, x))
    y = max(0, min(int(n) - 1, y))
    return x, y


def ks_2samp(data1: List[float], data2: List[float]) -> Optional[float]:
    """
    Two-sample Kolmogorov–Smirnov D statistic (no p-value).
    Returns None if insufficient data.
    """
    if len(data1) < 20 or len(data2) < 20:
        return None
    x1 = sorted(data1)
    x2 = sorted(data2)
    n1 = len(x1)
    n2 = len(x2)
    i = 0
    j = 0
    d = 0.0
    while i < n1 and j < n2:
        v1 = x1[i]
        v2 = x2[j]
        if v1 <= v2:
            i += 1
        if v2 <= v1:
            j += 1
        f1 = i / n1
        f2 = j / n2
        d = max(d, abs(f1 - f2))
    return d


def mann_whitney_u(data1: List[float], data2: List[float]) -> Optional[float]:
    """
    Mann–Whitney U statistic normalized to [0,1] (effect-like).
    Returns None if insufficient data.
    """
    if len(data1) < 20 or len(data2) < 20:
        return None
    # rank all values (average ranks for ties)
    combined = [(v, 0) for v in data1] + [(v, 1) for v in data2]
    combined.sort(key=lambda x: x[0])
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i + 1
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j
    r1 = sum(r for r, (_, grp) in zip(ranks, combined) if grp == 0)
    n1 = len(data1)
    n2 = len(data2)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    # normalize: divide by max U
    return u1 / (n1 * n2)


def cusum_change_score(values: List[float], drift: float = 0.0) -> Optional[float]:
    """
    Simple two-sided CUSUM magnitude score over a sequence.
    Returns max absolute cumulative deviation from mean (normalized by MAD when possible).
    """
    if len(values) < 50:
        return None
    m = median(values)
    if m is None:
        return None
    scale = mad(values) or 0.0
    if scale <= 1e-9:
        scale = 1.0
    pos = 0.0
    neg = 0.0
    max_abs = 0.0
    for v in values:
        x = (v - m) / scale
        pos = max(0.0, pos + x - drift)
        neg = min(0.0, neg + x + drift)
        max_abs = max(max_abs, abs(pos), abs(neg))
    return max_abs


def markov_bigram_surprise(seq: List[str], alpha: float = 0.5) -> Optional[float]:
    """
    Average negative log probability of observed bigrams with add-alpha smoothing.
    Higher => less typical / more chaotic transition pattern.
    """
    if len(seq) < 50:
        return None
    states = sorted({s for s in seq if s})
    if len(states) < 2:
        return 0.0
    idx = {s: i for i, s in enumerate(states)}
    n = len(states)
    # transition counts
    counts = [[0 for _ in range(n)] for _ in range(n)]
    out = [0 for _ in range(n)]
    for a, b in zip(seq, seq[1:]):
        ia = idx.get(a)
        ib = idx.get(b)
        if ia is None or ib is None:
            continue
        counts[ia][ib] += 1
        out[ia] += 1
    total_bigrams = sum(out)
    if total_bigrams <= 0:
        return None
    # compute avg surprise
    s = 0.0
    for a, b in zip(seq, seq[1:]):
        ia = idx.get(a)
        ib = idx.get(b)
        if ia is None or ib is None:
            continue
        denom = out[ia] + alpha * n
        numer = counts[ia][ib] + alpha
        p = numer / denom
        s += -math.log(max(p, 1e-12))
    return s / max(1, len(seq) - 1)

def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    try:
        return statistics.median(values)
    except Exception:
        return None


def mad(values: List[float]) -> Optional[float]:
    if not values:
        return None
    m = median(values)
    if m is None:
        return None
    devs = [abs(v - m) for v in values]
    return median(devs)


def trimmed_mean(values: List[float], trim_frac: float) -> Optional[float]:
    if not values:
        return None
    if trim_frac <= 0:
        return sum(values) / len(values)
    xs = sorted(values)
    k = int(len(xs) * trim_frac)
    xs2 = xs[k: len(xs) - k] if len(xs) - 2 * k > 0 else xs
    return sum(xs2) / len(xs2)


def robust_center(points: List[Tuple[float, float, Optional[float]]]) -> Tuple[Optional[float], Optional[float], Dict[str, Any]]:
    """Estimate a robust center from (lat, lon, signal) samples.

    GPS noise is mostly random, but *tower location inference* becomes biased when:
    - you only observe a cell from one side (driving route),
    - outliers occur (bad fixes),
    - strong-signal moments are under/overrepresented.

    Strategy:
    1) Start with median lat/lon.
    2) Compute distances; remove far outliers using MAD.
    3) Compute a trimmed mean of the remaining points.
    4) Optionally weight by signal (stronger signal -> slightly higher weight).

    Returns (lat, lon, meta).
    """

    lats = [p[0] for p in points]
    lons = [p[1] for p in points]
    lat0 = median(lats)
    lon0 = median(lons)
    if lat0 is None or lon0 is None:
        return None, None, {"n": len(points), "n_used": 0}

    dists = [haversine_m(lat0, lon0, p[0], p[1]) for p in points]
    d_med = median(dists) or 0.0
    d_mad = mad(dists) or 0.0

    # Keep points within a robust radius. If MAD=0 (many identical points), keep all.
    # 3.5 * MAD is a common robust threshold.
    keep = []
    if d_mad <= 1e-6:
        keep = list(points)
    else:
        thr = d_med + 3.5 * d_mad
        keep = [p for p, d in zip(points, dists) if d <= thr]

    if not keep:
        keep = list(points)

    # Weighted trimmed mean
    # - baseline: trim 10% by coordinate dimension
    # - weights: mild, bounded influence from signal if available
    trim_frac = 0.10

    used_lats = [p[0] for p in keep]
    used_lons = [p[1] for p in keep]

    # Weighting: w in [0.5, 2.0]
    weights = []
    signals = [p[2] for p in keep if isinstance(p[2], (int, float))]
    s_med = median([float(s) for s in signals]) if signals else None
    for _, _, s in keep:
        if s_med is None or not isinstance(s, (int, float)):
            weights.append(1.0)
            continue
        # Many metrics are negative (e.g., RSRP). Stronger signal -> less negative.
        # Map delta of +/-15dB to a moderate multiplier.
        delta = float(s) - float(s_med)
        w = 1.0 + max(-0.5, min(1.0, delta / 30.0))
        weights.append(max(0.5, min(2.0, w)))

    # Apply trimming by distance from median center in 2D (more robust than per-dimension trim)
    lat1 = median(used_lats) or lat0
    lon1 = median(used_lons) or lon0
    scored = []
    for p, w in zip(keep, weights):
        d = haversine_m(lat1, lon1, p[0], p[1])
        scored.append((d, p, w))
    scored.sort(key=lambda x: x[0])
    k = int(len(scored) * trim_frac)
    core = scored[k: len(scored) - k] if len(scored) - 2 * k > 0 else scored

    sum_w = sum(w for _, _, w in core) or 1.0
    lat = sum(p[0] * w for _, p, w in core) / sum_w
    lon = sum(p[1] * w for _, p, w in core) / sum_w

    used_points = [p for _, p, _ in core]
    spread_m = None
    if len(used_points) >= 2:
        spread_m = median([haversine_m(lat, lon, p[0], p[1]) for p in used_points])

    meta = {
        "n": len(points),
        "n_used": len(used_points),
        "dist_m_median": d_med,
        "dist_m_mad": d_mad,
        "spread_m_median": spread_m,
    }
    return lat, lon, meta


def theil_sen_slope(xs: List[float], ys: List[float]) -> Optional[float]:
    """
    Robust slope estimator: median of pairwise slopes.
    Returns None for insufficient or degenerate data.
    """
    if len(xs) != len(ys) or len(xs) < 5:
        return None
    slopes: List[float] = []
    n = len(xs)
    for i in range(n):
        xi = xs[i]
        yi = ys[i]
        for j in range(i + 1, n):
            dx = xs[j] - xi
            if abs(dx) < 1e-9:
                continue
            slopes.append((ys[j] - yi) / dx)
    if not slopes:
        return None
    return statistics.median(slopes)


def robust_residuals_signal_vs_distance(
    center_lat: float,
    center_lon: float,
    points: List[Tuple[float, float, Optional[float]]],
    min_points: int = 12,
) -> Dict[str, Any]:
    """
    Build a simple robust model of signal ~ a + b * log10(distance_m + 1).

    This doesn't need the true tower location. We use the inferred center as a proxy to:
    - avoid penalizing far-away towers for being rarely seen,
    - detect observations where the signal is inconsistent with the tower's own distance pattern,
      and towers whose signal-vs-distance pattern is weird compared to its history.
    """
    xs: List[float] = []
    ys: List[float] = []
    for lat, lon, sig in points:
        if not isinstance(sig, (int, float)):
            continue
        d = haversine_m(center_lat, center_lon, lat, lon)
        xs.append(math.log10(max(0.0, d) + 1.0))
        ys.append(float(sig))
    if len(xs) < min_points:
        return {"n": len(xs)}

    slope = theil_sen_slope(xs, ys)
    if slope is None:
        return {"n": len(xs)}

    # Intercept as median(y - slope*x) (robust)
    intercept = statistics.median([y - slope * x for x, y in zip(xs, ys)])
    residuals = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    res_med = statistics.median(residuals)
    res_mad = mad(residuals) or 0.0

    outlier_frac = 0.0
    if res_mad > 1e-9:
        outlier_frac = sum(1 for r in residuals if abs(r - res_med) >= 4.0 * res_mad) / len(residuals)

    return {
        "n": len(xs),
        "slope": slope,
        "intercept": intercept,
        "residual_median": res_med,
        "residual_mad": res_mad,
        "outlier_frac": outlier_frac,
    }


def cluster_centers_simple(
    points: List[Tuple[float, float]],
    max_cluster_radius_m: float = 400.0,
) -> List[Tuple[float, float, int]]:
    """
    Very small, dependency-free clustering to detect \"multiple locations\":
    - greedy assignment to an existing cluster if within radius of its center
    - otherwise start a new cluster

    Returns list of (lat, lon, count) clusters, sorted by count desc.
    """
    clusters: List[Tuple[float, float, int]] = []
    for lat, lon in points:
        best_idx = None
        best_d = None
        for i, (clat, clon, n) in enumerate(clusters):
            d = haversine_m(clat, clon, lat, lon)
            if d <= max_cluster_radius_m and (best_d is None or d < best_d):
                best_idx = i
                best_d = d
        if best_idx is None:
            clusters.append((lat, lon, 1))
        else:
            clat, clon, n = clusters[best_idx]
            # incremental mean update
            n2 = n + 1
            clusters[best_idx] = (clat + (lat - clat) / n2, clon + (lon - clon) / n2, n2)
    clusters.sort(key=lambda x: -x[2])
    return clusters


def center_drift_over_time(
    points: List[Tuple[float, float, float, Optional[float]]],
    min_points_per_bin: int = 15,
) -> Dict[str, Any]:
    """
    Compute coarse center drift over time by binning into 7-day windows.
    Returns max drift in meters between any two bin centers.
    """
    if len(points) < 2 * min_points_per_bin:
        return {"bins": 0}

    pts = sorted(points, key=lambda x: x[0])
    start = pts[0][0]
    bins: Dict[int, List[Tuple[float, float, Optional[float]]]] = defaultdict(list)
    for t, lat, lon, sig in pts:
        week = int((t - start) // (7 * 24 * 3600))
        bins[week].append((lat, lon, sig))

    centers: List[Tuple[float, float]] = []
    for _, bpts in sorted(bins.items()):
        if len(bpts) < min_points_per_bin:
            continue
        clat, clon, _ = robust_center(bpts)
        if clat is None or clon is None:
            continue
        centers.append((clat, clon))

    if len(centers) < 2:
        return {"bins": len(centers)}

    max_d = 0.0
    for i in range(len(centers)):
        for j in range(i + 1, len(centers)):
            d = haversine_m(centers[i][0], centers[i][1], centers[j][0], centers[j][1])
            if d > max_d:
                max_d = d
    return {"bins": len(centers), "max_drift_m": max_d}


@dataclass(frozen=True)
class TowerKey:
    operator: str
    rat: str
    tac_lac: Optional[int]
    cell_id: Optional[int]
    earfcn: Optional[int]
    pci: Optional[int]

    def label(self) -> str:
        parts = [self.operator or "(unknown op)", self.rat or "(unknown rat)"]
        if self.tac_lac is not None:
            parts.append(f"TAC/LAC {self.tac_lac}")
        if self.cell_id is not None:
            parts.append(f"Cell {self.cell_id}")
        if self.pci is not None:
            parts.append(f"PCI {self.pci}")
        if self.earfcn is not None:
            parts.append(f"EARFCN {self.earfcn}")
        return " | ".join(parts)


@dataclass
class TowerAgg:
    key: TowerKey
    first_seen_ts: float
    last_seen_ts: float
    count: int = 0

    # distinct UTC days (as ints)
    days: set = dataclasses.field(default_factory=set)

    # session + gap tracking (streaming)
    last_observed_ts: Optional[float] = None
    max_gap_s: float = 0.0
    sessions: int = 0

    # Memory-bounded reservoir sample: (lat, lon, signal, ts)
    sample: List[Tuple[float, float, Optional[float], float]] = dataclasses.field(default_factory=list)
    sample_seen: int = 0

    # place buckets (tile IDs) where observed (counts only)
    places: Counter = dataclasses.field(default_factory=Counter)

    # online clusters (greedy) for multi-location detection: (lat, lon, n)
    clusters_online: List[Tuple[float, float, int]] = dataclasses.field(default_factory=list)

    # computed
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    center_meta: Dict[str, Any] = dataclasses.field(default_factory=dict)

    # anomaly scoring
    features: Dict[str, Any] = dataclasses.field(default_factory=dict)
    anomaly_score: float = 0.0

    def add(
        self,
        when_ts: float,
        lat: float,
        lon: float,
        signal: Optional[float],
        place_id: Optional[str],
        *,
        sample_size: int,
        cluster_radius_m: float,
        session_gap_s: float,
        rng: random.Random,
    ) -> None:
        if when_ts < self.first_seen_ts:
            self.first_seen_ts = when_ts
        if when_ts > self.last_seen_ts:
            self.last_seen_ts = when_ts
        self.count += 1

        self.days.add(day_id_from_epoch(when_ts))

        if self.last_observed_ts is None:
            self.sessions = 1
        else:
            gap = when_ts - self.last_observed_ts
            if gap > self.max_gap_s:
                self.max_gap_s = gap
            if gap >= session_gap_s:
                self.sessions += 1
        self.last_observed_ts = when_ts

        # reservoir sampling (bounded memory)
        self.sample_seen += 1
        if sample_size > 0:
            if len(self.sample) < sample_size:
                self.sample.append((lat, lon, signal, when_ts))
            else:
                j = rng.randrange(self.sample_seen)
                if j < sample_size:
                    self.sample[j] = (lat, lon, signal, when_ts)

        if place_id:
            self.places[place_id] += 1

        # online clustering
        if cluster_radius_m > 0:
            best_idx = None
            best_d = None
            for i, (clat, clon, n) in enumerate(self.clusters_online):
                d = haversine_m(clat, clon, lat, lon)
                if d <= cluster_radius_m and (best_d is None or d < best_d):
                    best_idx = i
                    best_d = d
            if best_idx is None:
                self.clusters_online.append((lat, lon, 1))
            else:
                clat, clon, n = self.clusters_online[best_idx]
                n2 = n + 1
                self.clusters_online[best_idx] = (clat + (lat - clat) / n2, clon + (lon - clon) / n2, n2)


@dataclass
class PlaceAgg:
    place_id: str
    count: int = 0
    # Reservoir sample of (ts, signal) for distribution/change estimation (bounded memory)
    signal_sample: List[Tuple[float, float]] = dataclasses.field(default_factory=list)
    signal_seen: int = 0
    signal_sample_size: int = 1000
    # Approx distinct tower count via bitmap hashing
    distinct_bitmap_bits: int = 2048
    distinct_bitmap: int = 0
    # RAT transition counts (for bigram surprise), streaming
    rat_states: set = dataclasses.field(default_factory=set)
    rat_out: Counter = dataclasses.field(default_factory=Counter)
    rat_trans: Dict[str, Counter] = dataclasses.field(default_factory=dict)
    last_rat: Optional[str] = None

    def add(self, when_ts: float, tower_key: TowerKey, signal: Optional[float]) -> None:
        self.count += 1
        # update approx distinct towers
        h = hash((tower_key.operator, tower_key.rat, tower_key.tac_lac, tower_key.cell_id, tower_key.earfcn, tower_key.pci))
        idx = h % self.distinct_bitmap_bits
        self.distinct_bitmap |= (1 << idx)

        # reservoir sample of signals
        if isinstance(signal, (int, float)):
            self.signal_seen += 1
            s = float(signal)
            if len(self.signal_sample) < self.signal_sample_size:
                self.signal_sample.append((when_ts, s))
            else:
                j = (h ^ int(when_ts)) % self.signal_seen
                if j < self.signal_sample_size:
                    self.signal_sample[j] = (when_ts, s)

        # RAT transitions
        rat = (tower_key.rat or "").upper()
        if rat:
            self.rat_states.add(rat)
            if self.last_rat is not None:
                self.rat_out[self.last_rat] += 1
                bucket = self.rat_trans.get(self.last_rat)
                if bucket is None:
                    bucket = Counter()
                    self.rat_trans[self.last_rat] = bucket
                bucket[rat] += 1
            self.last_rat = rat

    def distinct_towers_est(self) -> int:
        # Linear counting estimate from bitmap occupancy
        m = self.distinct_bitmap_bits
        v = m - self.distinct_bitmap.bit_count()
        if v <= 0:
            return m
        return int(round(-m * math.log(v / m)))

    def rat_surprise(self, alpha: float = 0.5) -> Optional[float]:
        """
        Average negative log-probability of observed RAT transitions using add-alpha smoothing.
        Computed from transition counts (streaming, no full sequence stored).
        """
        if not self.rat_trans:
            return None
        states = sorted(self.rat_states)
        n = len(states)
        if n < 2:
            return 0.0
        total = 0
        s = 0.0
        for a, out_n in self.rat_out.items():
            bucket = self.rat_trans.get(a) or Counter()
            denom = out_n + alpha * n
            for b, c in bucket.items():
                numer = c + alpha
                p = numer / denom
                s += (-math.log(max(p, 1e-12))) * c
                total += c
        if total <= 0:
            return None
        return s / total


def safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        return int(value)
    except Exception:
        return None


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        return float(value)
    except Exception:
        return None


def normalize_rat(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def extract_operator(obj: Dict[str, Any]) -> str:
    cops = (obj.get("network") or {}).get("cops_current") or {}
    op = cops.get("operator")
    if isinstance(op, str) and op.strip():
        return op.strip()
    return ""


def iter_observed_cells(obj: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    towers = obj.get("towers")
    if isinstance(towers, list) and towers:
        for t in towers:
            if isinstance(t, dict):
                yield t
        return

    # Fallback: registration entries
    net = obj.get("network") or {}
    for k in ("cereg", "cgreg", "creg"):
        reg = net.get(k) or {}
        if not isinstance(reg, dict):
            continue
        cell_id = reg.get("cell_id")
        tac = reg.get("lac_tac")
        rat = reg.get("rat")
        if cell_id is None and tac is None and rat is None:
            continue
        yield {
            "source": k,
            "cell_id": cell_id,
            "tac_lac": tac,
            "rat": rat,
        }


def tower_key_from_cell(operator: str, cell: Dict[str, Any]) -> TowerKey:
    rat = normalize_rat(cell.get("rat"))
    tac = safe_int(cell.get("tac_lac") if "tac_lac" in cell else cell.get("tac") if "tac" in cell else None)
    cell_id = safe_int(cell.get("cell_id") if "cell_id" in cell else cell.get("scell_id") if "scell_id" in cell else None)
    earfcn = safe_int(cell.get("earfcn"))
    pci = safe_int(cell.get("pci") if "pci" in cell else cell.get("pcell_id") if "pcell_id" in cell else None)
    return TowerKey(operator=operator, rat=rat, tac_lac=tac, cell_id=cell_id, earfcn=earfcn, pci=pci)


def observation_signal(obj: Dict[str, Any], cell: Dict[str, Any]) -> Optional[float]:
    # Prefer per-cell LTE metrics when available.
    # Note: RSRP is not RSSI; we treat any signal metric as an ordering proxy.
    for k in ("rsrp", "rssi_dbm", "rssi", "rssnr", "rsrq"):
        v = cell.get(k)
        fv = safe_float(v)
        if fv is not None:
            return fv

    # Fall back to AT+CSQ derived RSSI dBm
    csq = ((obj.get("network") or {}).get("csq") or {})
    v = csq.get("rssi_dbm")
    return safe_float(v)


def compute_features(agg: TowerAgg, global_stats: Dict[str, Any]) -> Tuple[Dict[str, Any], float]:
    """Compute anomaly features and a conservative anomaly score.

    This is not attribution; it’s a ranking of unusual towers for manual review.
    """

    feats: Dict[str, Any] = {}
    breakdown: List[Dict[str, Any]] = []

    # Ephemerality
    duration_s = float(agg.last_seen_ts - agg.first_seen_ts)
    feats["duration_s"] = duration_s
    feats["days_seen"] = len(agg.days)
    feats["max_gap_s"] = agg.max_gap_s
    feats["sessions"] = agg.sessions

    # Signal stats
    sig = [float(s) for _lat, _lon, s, _ts in agg.sample if isinstance(s, (int, float))]
    feats["signal_n"] = len(sig)
    feats["signal_median"] = median(sig) if sig else None
    feats["signal_mad"] = mad(sig) if sig else None

    # Location consistency around inferred center
    spread = agg.center_meta.get("spread_m_median")
    feats["gps_spread_m"] = spread

    # Global rarity in this dataset
    feats["count"] = agg.count

    # Place spread / entropy
    if agg.places:
        feats["places_n"] = len(agg.places)
        top_place = agg.places.most_common(1)[0][1]
        feats["place_top_frac"] = top_place / max(1, agg.count)
        probs = [c / max(1, agg.count) for c in agg.places.values()]
        ent = -sum(p * math.log(p + 1e-12) for p in probs)
        feats["place_entropy"] = ent
    else:
        feats["places_n"] = 0

    # Multi-location clustering (streaming, from online clusters)
    clusters = list(agg.clusters_online)
    clusters.sort(key=lambda x: -x[2])
    feats["clusters"] = len(clusters)
    if len(clusters) >= 2:
        feats["cluster_top2_sep_m"] = haversine_m(clusters[0][0], clusters[0][1], clusters[1][0], clusters[1][1])

    # Center drift over time (weekly bins)
    drift = center_drift_over_time([(ts, lat, lon, s) for (lat, lon, s, ts) in agg.sample], min_points_per_bin=15)
    feats["center_drift"] = drift

    # Signal vs (proxy) distance consistency
    if agg.center_lat is not None and agg.center_lon is not None:
        dist_model = robust_residuals_signal_vs_distance(
            agg.center_lat,
            agg.center_lon,
            [(lat, lon, s) for (lat, lon, s, _ts) in agg.sample],
        )
        feats["signal_dist_model"] = dist_model

    # Simple anomaly scoring (0..)
    score = 0.0

    # 1) Very short-lived cells
    if agg.count >= 5 and duration_s <= 20 * 60:
        score += 3.0
        feats["anomaly_ephemeral"] = True
        breakdown.append({
            "rule": "ephemeral",
            "points": 3.0,
            "because": f"count={agg.count} duration_min={round(duration_s/60,1)}",
        })

    # 2) Rare overall: do not score rarity alone (far-away cells are naturally rare).
    # We keep it as a label/feature that only becomes important when combined with other anomalies.
    feats["anomaly_rare"] = agg.count <= 10

    # 3) Strong-signal outlier relative to global distribution (if available)
    g_med = global_stats.get("signal_median")
    g_mad = global_stats.get("signal_mad")
    s_med = feats.get("signal_median")
    if isinstance(g_med, (int, float)) and isinstance(g_mad, (int, float)) and g_mad > 1e-6 and isinstance(s_med, (int, float)):
        # higher signal metric can mean "stronger" depending on metric
        z = (s_med - g_med) / g_mad
        feats["signal_robust_z"] = z
        if z >= 4.0:
            score += 2.0
            feats["anomaly_strong_signal"] = True
            breakdown.append({
                "rule": "strong_signal_global",
                "points": 2.0,
                "because": f"robust_z={round(z,2)} (median={s_med}, global_median={g_med}, global_mad={g_mad})",
            })

    # 4) Location inconsistency / high spread (bad GPS fixes, route bias, or cell-id reuse)
    if isinstance(spread, (int, float)) and spread >= 250.0 and agg.count >= 10:
        score += 2.0
        feats["anomaly_location_spread"] = True
        breakdown.append({
            "rule": "location_spread",
            "points": 2.0,
            "because": f"gps_spread_m={round(spread,1)} count={agg.count}",
        })
    # Multiple clusters far apart
    if isinstance(feats.get("clusters"), int) and feats["clusters"] >= 2:
        sep = feats.get("cluster_top2_sep_m")
        if isinstance(sep, (int, float)) and sep >= 1500.0 and agg.count >= 15:
            score += 2.5
            feats["anomaly_multi_location"] = True
            breakdown.append({
                "rule": "multi_location",
                "points": 2.5,
                "because": f"clusters={feats.get('clusters')} top2_sep_m={round(sep,1)} count={agg.count}",
            })

    # Center drift (likely cell-id reuse or strong route bias)
    cd = feats.get("center_drift") or {}
    if isinstance(cd, dict) and cd.get("bins", 0) >= 2:
        md = cd.get("max_drift_m")
        if isinstance(md, (int, float)) and md >= 1200.0 and agg.count >= 30:
            score += 2.0
            feats["anomaly_moving_or_reused_id"] = True
            breakdown.append({
                "rule": "center_drift",
                "points": 2.0,
                "because": f"weekly_bins={cd.get('bins')} max_drift_m={round(md,1)} count={agg.count}",
            })

    # 5) Unusual RAT (coarse; stronger if baseline is mostly LTE)
    rat = (agg.key.rat or "").upper()
    if rat in ("GSM", "2G") and global_stats.get("mostly_lte"):
        score += 2.0
        feats["anomaly_non_lte"] = True
        breakdown.append({
            "rule": "non_lte_when_mostly_lte",
            "points": 2.0,
            "because": f"rat={rat}",
        })

    # 6) Disappear/reappear (many sessions or large gaps)
    sessions = feats.get("sessions")
    max_gap_s = feats.get("max_gap_s")
    if isinstance(sessions, int) and sessions >= 4 and agg.count >= 20:
        score += 1.5
        feats["anomaly_reappears"] = True
        breakdown.append({
            "rule": "reappears",
            "points": 1.5,
            "because": f"sessions={sessions} count={agg.count}",
        })
    if isinstance(max_gap_s, (int, float)) and max_gap_s >= 7 * 24 * 3600 and agg.count >= 10:
        score += 1.5
        feats["anomaly_long_absence"] = True
        breakdown.append({
            "rule": "long_absence",
            "points": 1.5,
            "because": f"max_gap_days={round(max_gap_s/(24*3600),2)} count={agg.count}",
        })

    # 7) Signal-vs-distance inconsistency (many outliers relative to own pattern)
    dm = feats.get("signal_dist_model") or {}
    if isinstance(dm, dict) and dm.get("n", 0) >= 20:
        outlier_frac = dm.get("outlier_frac")
        if isinstance(outlier_frac, (int, float)) and outlier_frac >= 0.25:
            score += 2.0
            feats["anomaly_signal_distance_mismatch"] = True
            breakdown.append({
                "rule": "signal_distance_mismatch",
                "points": 2.0,
                "because": f"dist_model_n={dm.get('n')} outlier_frac={round(outlier_frac,3)} res_mad={dm.get('residual_mad')}",
            })

    # 8) Wide-area presence (high place entropy) - not necessarily bad, but worth a small bump if also inconsistent
    ent = feats.get("place_entropy")
    if isinstance(ent, (int, float)) and ent >= 2.5 and agg.count >= 30 and feats.get("anomaly_multi_location"):
        score += 1.0
        feats["anomaly_wide_area"] = True
        breakdown.append({
            "rule": "wide_area",
            "points": 1.0,
            "because": f"place_entropy={round(ent,2)} places_n={feats.get('places_n')}",
        })

    feats["score_breakdown"] = breakdown
    return feats, score


def compute_global_stats(aggs: List[TowerAgg]) -> Dict[str, Any]:
    all_sig = []
    rats = Counter()
    for a in aggs:
        rats[(a.key.rat or "").upper()] += a.count
        for _, _, sig, _ts in a.sample:
            if isinstance(sig, (int, float)):
                all_sig.append(float(sig))
    return {
        "signal_median": median(all_sig) if all_sig else None,
        "signal_mad": mad(all_sig) if all_sig else None,
        "mostly_lte": rats.get("LTE", 0) >= max(1, sum(rats.values()) * 0.80),
    }


def l1_normalize(v: List[float]) -> List[float]:
    s = sum(abs(x) for x in v) or 1.0
    return [x / s for x in v]


def vector_distance(a: List[float], b: List[float]) -> float:
    # simple Euclidean
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def knn_anomaly_scores(vectors: Dict[TowerKey, List[float]], k: int = 5) -> Dict[TowerKey, float]:
    """
    Pure-Python kNN anomaly score: average distance to k nearest neighbors.
    O(n^2) in number of towers; suitable for a few thousand towers.
    """
    keys = list(vectors.keys())
    if len(keys) < max(10, k + 1):
        return {k0: 0.0 for k0 in keys}
    scores: Dict[TowerKey, float] = {}
    for i, ki in enumerate(keys):
        vi = vectors[ki]
        dists = []
        for j, kj in enumerate(keys):
            if i == j:
                continue
            dists.append(vector_distance(vi, vectors[kj]))
        dists.sort()
        nn = dists[:k]
        scores[ki] = sum(nn) / len(nn) if nn else 0.0
    return scores


def lof_anomaly_scores(vectors: Dict[TowerKey, List[float]], k: int = 10) -> Dict[TowerKey, float]:
    """
    Pure-Python LOF-like score (higher => more outlier).
    Implementation follows the standard LOF idea using k-distance neighborhood.
    O(n^2).
    """
    keys = list(vectors.keys())
    if len(keys) < max(20, k + 1):
        return {k0: 1.0 for k0 in keys}

    # Precompute distances
    dist: Dict[Tuple[int, int], float] = {}
    for i in range(len(keys)):
        vi = vectors[keys[i]]
        for j in range(i + 1, len(keys)):
            d = vector_distance(vi, vectors[keys[j]])
            dist[(i, j)] = d

    def d(i: int, j: int) -> float:
        if i == j:
            return 0.0
        if i < j:
            return dist[(i, j)]
        return dist[(j, i)]

    # k-distance and neighbors
    neighbors: List[List[int]] = []
    kdist: List[float] = []
    for i in range(len(keys)):
        ds = [(d(i, j), j) for j in range(len(keys)) if j != i]
        ds.sort(key=lambda x: x[0])
        kth = ds[min(k - 1, len(ds) - 1)][0]
        kdist.append(kth)
        neigh = [j for (dd, j) in ds if dd <= kth]
        neighbors.append(neigh)

    # local reachability density
    lrd: List[float] = []
    for i in range(len(keys)):
        reach = []
        for j in neighbors[i]:
            reach.append(max(kdist[j], d(i, j)))
        denom = sum(reach) / len(reach) if reach else 1.0
        lrd.append(1.0 / max(denom, 1e-9))

    lof: Dict[TowerKey, float] = {}
    for i, ki in enumerate(keys):
        ratios = [(lrd[j] / lrd[i]) for j in neighbors[i]] if neighbors[i] else [1.0]
        lof[ki] = sum(ratios) / len(ratios)
    return lof


def knn_anomaly_scores_approx(
    vectors: Dict[TowerKey, List[float]],
    k: int = 5,
    reference_size: int = 800,
    seed: int = 1,
) -> Dict[TowerKey, float]:
    """
    Approximate kNN anomaly score using a fixed reference subset.
    Complexity: O(n * reference_size), no O(n^2) memory.
    """
    import random

    keys = list(vectors.keys())
    if len(keys) < max(10, k + 1):
        return {k0: 0.0 for k0 in keys}

    rnd = random.Random(seed)
    ref = keys[:] if len(keys) <= reference_size else rnd.sample(keys, reference_size)
    scores: Dict[TowerKey, float] = {}
    for ki in keys:
        vi = vectors[ki]
        dists = []
        for kj in ref:
            if kj == ki:
                continue
            dists.append(vector_distance(vi, vectors[kj]))
        dists.sort()
        nn = dists[:k]
        scores[ki] = sum(nn) / len(nn) if nn else 0.0
    return scores


def build_dashboard(markers: List[Dict[str, Any]], center: Tuple[float, float], out_path: str) -> None:
    marker_json = json.dumps(markers, ensure_ascii=False)
    center_lat, center_lon = center

    methods_html = """
<h2 style="margin:10px 0 6px 0;">Methods & scoring</h2>
<div class="muted" style="margin-bottom:10px; max-width: 980px;">
  This dashboard ranks <b>anomalous / inconsistent</b> cells for manual review. It is not attribution.
  Each tower row has a <b>score</b> that is the sum of triggered rules below.
</div>
<table style="width:100%; border-collapse: collapse; font-size: 13px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Rule</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Uses features</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Adds</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Trigger</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>ephemeral</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">count, duration_s</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+3.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Seen ≥ 5 times but only within ≤ 20 minutes.</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>strong_signal_global</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">signal_median, global MAD</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score ≥ 4 vs global signal distribution.</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>signal_distance_mismatch</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">signal_dist_model.outlier_frac</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">≥25% big residual outliers in a robust signal-vs-distance model (proxy distance from inferred center).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>location_spread</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">gps_spread_m</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Median spread around inferred center ≥ 250m (count ≥ 10).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>multi_location</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">clusters, cluster_top2_sep_m</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.5</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Same fingerprint forms ≥2 clusters separated by ≥1.5km (count ≥ 15).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>center_drift</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">center_drift.max_drift_m</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Weekly-binned inferred centers drift by ≥1.2km (count ≥ 30).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>reappears</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">sessions</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">≥4 distinct sessions (gap ≥6h), count ≥ 20.</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>long_absence</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">max_gap_s</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Max gap ≥ 7 days (count ≥ 10).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>non_lte_when_mostly_lte</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">rat, mostly_lte</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+2.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">RAT is GSM/2G while dataset baseline is mostly LTE.</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>novel_in_dense_places</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">dense_place_novelty</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Appears rarely (≤2) in ≥2 high-sample places (place count ≥500).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>place_change_correlation</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">change_places_frac</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">≥50% of this tower’s samples occur in places with strong distribution change (KS/CUSUM).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>rat_transition_surprise</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">place_rat_surprise</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Average negative log-probability of RAT transitions in its places is high (chaotic transitions).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>wide_area</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">place_entropy, places_n</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">High place entropy and already multi-location (small bump).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>ml_knn</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">ml_knn_z</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">kNN distance outlier z ≥ 4 over tower feature vectors (pure Python).</td>
    </tr>
    <tr>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>ml_lof</b></td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">ml_lof_z</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">LOF-like outlier z ≥ 4 over tower feature vectors (pure Python).</td>
    </tr>
  </tbody>
</table>
<div class="muted" style="margin-top:10px; max-width: 980px;">
  Note: <span class="mono">rare</span> is tracked but not scored by itself to avoid flagging far-away cells.
</div>

<h3 style="margin:18px 0 6px 0;">Metric glossary (columns)</h3>
<div class="muted" style="max-width: 980px; margin-bottom: 10px;">
  These are the raw values shown in the Towers table and in marker popups.
</div>
<table style="width:100%; border-collapse: collapse; font-size: 13px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Metric</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">count</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Samples where this fingerprint was observed.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">days_seen</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distinct calendar days with ≥1 sample.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">duration_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">(last_seen - first_seen) in minutes within the dataset window.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">sessions</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of segments separated by gaps ≥ 6 hours (disappear/reappear proxy).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">max_gap_days</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Largest time gap between consecutive observations (days).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">signal_median</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Median of the chosen signal metric for this tower (often RSSI dBm, sometimes RSRP).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">signal_robust_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of signal_median vs global distribution (MAD scale).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">gps_spread_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Median distance from samples to inferred center after robust trimming (uncertainty).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">clusters</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of spatial clusters (greedy, radius 400m) for this fingerprint.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">cluster_top2_sep_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distance between the two biggest clusters’ centers (multi-location indicator).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">center_drift_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Max distance between weekly-binned inferred centers (drift / ID reuse proxy).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">dist_outlier_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Fraction of big residual outliers in robust signal-vs-(proxy)distance model.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">dense_place_novelty</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;"># of dense places (≥500 samples) where this tower appears only 1–2 times.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">change_places_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Fraction of this tower’s samples in places with strong distribution change (KS/CUSUM).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_rat_surprise</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Average negative log-probability of RAT transitions in its places (higher = more chaotic).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">places_n</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of place buckets (OSM tile at --place-zoom) where seen.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_entropy</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Entropy of place distribution (higher = more spread out).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_knn_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of kNN distance outlier score in tower-feature space.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_lof_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of LOF-like density outlier score in tower-feature space.</td></tr>
  </tbody>
</table>
"""

    # Leaflet via CDN. Local HTML file loads tiles from OpenStreetMap.
    html_doc = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>Tower Anomaly Dashboard</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\" integrity=\"sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=\" crossorigin=\"\"/>
  <style>
    html, body {{ height: 100%; margin: 0; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
    #wrap {{ display: flex; flex-direction: column; height: 100%; }}
    /* Allow the map to shrink all the way down if the user drags the panel up. */
    #map {{ flex: 1 1 auto; min-height: 0; }}
    /* Allow the panel to shrink near-zero (but keep a tiny handle area). */
    #panel {{ flex: 0 0 auto; height: 40vh; padding: 10px; overflow: auto; border-top: 1px solid #ddd; }}
    /* Resize handle is at the top of the table/panel (drag down/up). */
    #resize-handle {{
      height: 10px;
      margin: -10px -10px 10px -10px;
      cursor: row-resize;
      background: linear-gradient(to bottom, #ffffff, #f3f4f6, #ffffff);
      border-bottom: 1px solid #ddd;
    }}
    #resize-handle:hover {{ background: #e5e7eb; }}
    #tabs {{ display:flex; gap:8px; margin: 8px 0 10px 0; }}
    .tabbtn {{ padding: 6px 10px; border: 1px solid #ddd; background: #fff; border-radius: 8px; cursor: pointer; }}
    .tabbtn.active {{ background: #f3f4f6; }}
    .tab {{ display: none; }}
    .tab.active {{ display: block; }}
    .row {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #f3f4f6; font-size: 12px; }}
    .badge.red {{ background: #fee2e2; }}
    .badge.yellow {{ background: #fef3c7; }}
    .badge.green {{ background: #dcfce7; }}
    input[type=search] {{ padding: 6px 8px; min-width: 280px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 6px 6px; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: #fff; z-index: 1; cursor: pointer; }}
    tr:hover {{ background: #fafafa; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .muted {{ color: #666; }}
    .btn {{ padding: 4px 8px; border: 1px solid #ddd; background: #fff; border-radius: 8px; cursor: pointer; }}
    .btn:hover {{ background: #f3f4f6; }}
    /* Modal explain panel */
    #modal {{ position: fixed; inset: 0; background: rgba(0,0,0,0.35); display:none; align-items: center; justify-content: center; z-index: 9999; }}
    #modal.open {{ display:flex; }}
    #modal-card {{ width: min(1100px, 96vw); height: min(86vh, 900px); background: #fff; border-radius: 14px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; display:flex; flex-direction: column; }}
    #modal-head {{ padding: 12px 14px; border-bottom: 1px solid #eee; display:flex; gap:10px; align-items:center; justify-content: space-between; }}
    #modal-body {{ padding: 12px 14px; overflow: auto; }}
    .grid2 {{ display:grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    .card {{ border: 1px solid #eee; border-radius: 12px; padding: 10px; }}
    .k {{ color:#111827; font-weight:600; }}
    .v {{ color:#111827; }}
    .pill {{ display:inline-block; padding: 2px 8px; border-radius: 999px; font-size:12px; border: 1px solid #e5e7eb; background:#f9fafb; }}
    .pill.on {{ border-color:#bbf7d0; background:#dcfce7; }}
    .pill.off {{ border-color:#fecaca; background:#fee2e2; }}
    .rule {{ border-top: 1px solid #f3f4f6; padding: 10px 0; }}
    .rule:first-child {{ border-top: 0; }}
    .rule-title {{ display:flex; gap:8px; align-items: baseline; flex-wrap: wrap; }}
    .rule-title .name {{ font-weight: 700; }}
    .rule-title .points {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .rule-desc {{ margin-top: 4px; color:#374151; }}
    .rule-why {{ margin-top: 6px; }}
    .why-row {{ display:flex; gap:10px; flex-wrap: wrap; margin-top: 6px; }}
    .why-box {{ border:1px solid #f3f4f6; border-radius: 10px; padding: 8px; background:#fff; }}
    .why-box .mono {{ font-size: 12px; }}
  </style>
</head>
<body>
<div id=\"wrap\">
  <div id=\"map\"></div>
  <div id=\"panel\">
    <div id=\"resize-handle\" title=\"Drag to resize\"></div>
    <div id=\"tabs\">
      <button class=\"tabbtn active\" data-tab=\"tab-towers\">Towers</button>
      <button class=\"tabbtn\" data-tab=\"tab-methods\">Methods</button>
    </div>

    <div id=\"tab-towers\" class=\"tab active\">
      <div class=\"row\">
        <div class=\"badge\">Ranking only (not attribution)</div>
        <input id=\"q\" type=\"search\" placeholder=\"Filter (operator / rat / cell / tac / earfcn / pci)\" />
        <span class=\"muted\">Click a row to zoom; open popup for full breakdown.</span>
      </div>
      <table id=\"tbl\">
        <thead>
          <tr>
            <th data-k=\"anomaly_score\">Score</th>
            <th data-k=\"label\">Tower</th>
            <th data-k=\"count\">Seen</th>
            <th data-k=\"days_seen\">Days</th>
            <th data-k=\"duration_min\">Dur (min)</th>
            <th data-k=\"sessions\">Sessions</th>
            <th data-k=\"max_gap_days\">Max gap (d)</th>
            <th data-k=\"signal_median\">Sig med</th>
            <th data-k=\"signal_robust_z\">Sig z</th>
            <th data-k=\"gps_spread_m\">GPS spread (m)</th>
            <th data-k=\"clusters\">Clusters</th>
            <th data-k=\"cluster_top2_sep_m\">Cl sep (m)</th>
            <th data-k=\"center_drift_m\">Drift (m)</th>
            <th data-k=\"dist_outlier_frac\">Dist outliers</th>
            <th data-k=\"dense_place_novelty\">Dense novelty</th>
            <th data-k=\"change_places_frac\">Change frac</th>
            <th data-k=\"place_rat_surprise\">RAT surprise</th>
            <th data-k=\"place_entropy\">Place ent</th>
            <th data-k=\"places_n\">Places</th>
            <th data-k=\"ml_knn_z\">kNN z</th>
            <th data-k=\"ml_lof_z\">LOF z</th>
            <th>Top drivers</th>
            <th>Explain</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <div id=\"tab-methods\" class=\"tab\">
      {methods_html}
    </div>
  </div>
</div>

<div id=\"modal\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Explain score\">
  <div id=\"modal-card\">
    <div id=\"modal-head\">
      <div>
        <div id=\"modal-title\" style=\"font-weight:800;\"></div>
        <div id=\"modal-sub\" class=\"muted mono\" style=\"margin-top:2px;\"></div>
      </div>
      <button id=\"modal-close\" class=\"btn\">Close</button>
    </div>
    <div id=\"modal-body\"></div>
  </div>
</div>

<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\" integrity=\"sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=\" crossorigin=\"\"></script>
<script>
  const MARKERS = {marker_json};

  const map = L.map('map').setView([{center_lat}, {center_lon}], 14);
  L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    // OSM tiles are typically native up to ~19, but Leaflet can \"overzoom\"
    // (scale tiles) beyond that for closer inspection.
    maxZoom: 22,
    maxNativeZoom: 19,
    attribution: '&copy; OpenStreetMap contributors'
  }}).addTo(map);
  // Keep Leaflet rendering correct if layout changes.
  window.addEventListener('resize', () => map.invalidateSize());

  // Splitter drag-to-resize implementation (more reliable than CSS resize handles).
  const panel = document.getElementById('panel');
  const handle = document.getElementById('resize-handle');
  // Keep at least a sliver so the resize handle remains reachable.
  const MIN_H = 28;
  function clamp(v, lo, hi) {{ return Math.max(lo, Math.min(hi, v)); }}

  function setPanelHeight(px) {{
    // No artificial ceiling: allow the panel to consume almost the whole viewport.
    const maxH = Math.max(MIN_H, Math.floor(window.innerHeight) - 0);
    panel.style.height = clamp(px, MIN_H, maxH) + 'px';
    try {{ localStorage.setItem('panel_h', panel.style.height); }} catch (e) {{}}
    map.invalidateSize();
  }}

  // Restore last size (if any)
  try {{
    const saved = localStorage.getItem('panel_h');
    if (saved) panel.style.height = saved;
  }} catch (e) {{}}

  let drag = null;
  handle.addEventListener('mousedown', (ev) => {{
    drag = {{ startY: ev.clientY, startH: panel.getBoundingClientRect().height }};
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'row-resize';
    ev.preventDefault();
  }});
  window.addEventListener('mousemove', (ev) => {{
    if (!drag) return;
    const dy = drag.startY - ev.clientY; // moving up increases panel height
    setPanelHeight(drag.startH + dy);
  }});
  window.addEventListener('mouseup', () => {{
    if (!drag) return;
    drag = null;
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
  }});

  function esc(s) {{
    return String(s ?? '')
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'",'&#039;');
  }}

  function scoreClass(score) {{
    if (score >= 5) return 'red';
    if (score >= 3) return 'yellow';
    return 'green';
  }}

  const layer = L.layerGroup().addTo(map);
  const byId = new Map();

  // Rule schema for XAI: points, description, thresholds, and feature usage.
  // The explanation UI will show pass/fail and what values contributed.
  const RULES = [
    {{
      id: 'ephemeral',
      points: 3.0,
      title: 'Ephemeral burst',
      desc: 'Seen many times but only within a short overall time window.',
      uses: ['count', 'duration_min'],
      eval: (m) => {{
        const ok = (m.count ?? 0) >= 5 && (m.duration_min ?? 1e9) <= 20;
        return {{ ok, because: `count=${{m.count}} and duration_min=${{m.duration_min}} (needs count≥5 and duration≤20min)` }};
      }}
    }},
    {{
      id: 'strong_signal_global',
      points: 2.0,
      title: 'Strong signal vs dataset',
      desc: 'Median signal is an outlier compared to the dataset-wide distribution (robust z).',
      uses: ['signal_median', 'signal_robust_z'],
      eval: (m) => {{
        const z = m.signal_robust_z;
        const ok = (typeof z === 'number') && z >= 4.0;
        return {{ ok, because: `signal_robust_z=${{z}} (needs ≥ 4.0)` }};
      }}
    }},
    {{
      id: 'signal_distance_mismatch',
      points: 2.0,
      title: 'Signal-distance mismatch',
      desc: 'Many samples are inconsistent with this tower’s own signal-vs-distance trend (proxy distance from inferred center).',
      uses: ['dist_outlier_frac'],
      eval: (m) => {{
        const f = m.dist_outlier_frac;
        const ok = (typeof f === 'number') && f >= 0.25;
        return {{ ok, because: `dist_outlier_frac=${{f}} (needs ≥ 0.25)` }};
      }}
    }},
    {{
      id: 'location_spread',
      points: 2.0,
      title: 'High location spread',
      desc: 'Observations are geographically inconsistent even after robust centering.',
      uses: ['gps_spread_m','count'],
      eval: (m) => {{
        const ok = (typeof m.gps_spread_m === 'number') && m.gps_spread_m >= 250 && (m.count ?? 0) >= 10;
        return {{ ok, because: `gps_spread_m=${{m.gps_spread_m}} with count=${{m.count}} (needs spread≥250m and count≥10)` }};
      }}
    }},
    {{
      id: 'multi_location',
      points: 2.5,
      title: 'Multi-location clusters',
      desc: 'Same fingerprint forms multiple spatial clusters far apart.',
      uses: ['clusters','cluster_top2_sep_m','count'],
      eval: (m) => {{
        const ok = (m.clusters ?? 0) >= 2 && (typeof m.cluster_top2_sep_m === 'number') && m.cluster_top2_sep_m >= 1500 && (m.count ?? 0) >= 15;
        return {{ ok, because: `clusters=${{m.clusters}}, top2_sep_m=${{m.cluster_top2_sep_m}} (needs clusters≥2, sep≥1500m, count≥15)` }};
      }}
    }},
    {{
      id: 'center_drift',
      points: 2.0,
      title: 'Center drift over weeks',
      desc: 'Inferred center shifts a lot across weekly bins (proxy for ID reuse / changed observation corridors).',
      uses: ['center_drift_m','count'],
      eval: (m) => {{
        const ok = (typeof m.center_drift_m === 'number') && m.center_drift_m >= 1200 && (m.count ?? 0) >= 30;
        return {{ ok, because: `center_drift_m=${{m.center_drift_m}} (needs ≥1200m, count≥30)` }};
      }}
    }},
    {{
      id: 'reappears',
      points: 1.5,
      title: 'Reappears in sessions',
      desc: 'Seen in many separated sessions (gap≥6h).',
      uses: ['sessions','count'],
      eval: (m) => {{
        const ok = (m.sessions ?? 0) >= 4 && (m.count ?? 0) >= 20;
        return {{ ok, because: `sessions=${{m.sessions}} (needs ≥4) with count=${{m.count}} (needs ≥20)` }};
      }}
    }},
    {{
      id: 'long_absence',
      points: 1.5,
      title: 'Long absence',
      desc: 'Large gaps between sightings (days).',
      uses: ['max_gap_days','count'],
      eval: (m) => {{
        const ok = (typeof m.max_gap_days === 'number') && m.max_gap_days >= 7 && (m.count ?? 0) >= 10;
        return {{ ok, because: `max_gap_days=${{m.max_gap_days}} (needs ≥7) with count=${{m.count}} (needs ≥10)` }};
      }}
    }},
    {{
      id: 'non_lte_when_mostly_lte',
      points: 2.0,
      title: 'Non-LTE while baseline is LTE',
      desc: 'RAT is GSM/2G while your dataset is mostly LTE.',
      uses: ['rat','dataset_mostly_lte'],
      eval: (m) => {{
        const rat = String(m.rat ?? '').toUpperCase();
        const ok = !!m.dataset_mostly_lte && (rat === 'GSM' || rat === '2G');
        return {{ ok, because: `rat=${{rat}} and dataset_mostly_lte=${{m.dataset_mostly_lte}} (needs GSM/2G + mostly LTE baseline)` }};
      }}
    }},
    {{
      id: 'novel_in_dense_places',
      points: 1.5,
      title: 'Novel in dense places',
      desc: 'Shows up only 1–2 times in places where you otherwise have lots of samples.',
      uses: ['dense_place_novelty','count'],
      eval: (m) => {{
        const ok = (m.dense_place_novelty ?? 0) >= 2 && (m.count ?? 0) >= 10;
        return {{ ok, because: `dense_place_novelty=${{m.dense_place_novelty}} (needs ≥2) with count=${{m.count}} (needs ≥10)` }};
      }}
    }},
    {{
      id: 'place_change_correlation',
      points: 1.0,
      title: 'Correlates with place changes',
      desc: 'Most sightings occur in place buckets whose distributions show change (KS/CUSUM).',
      uses: ['change_places_frac','count'],
      eval: (m) => {{
        const ok = (typeof m.change_places_frac === 'number') && m.change_places_frac >= 0.5 && (m.count ?? 0) >= 20;
        return {{ ok, because: `change_places_frac=${{m.change_places_frac}} (needs ≥0.5) with count=${{m.count}} (needs ≥20)` }};
      }}
    }},
    {{
      id: 'rat_transition_surprise',
      points: 1.0,
      title: 'RAT transition surprise',
      desc: 'Places associated with this tower show unusually chaotic RAT switching.',
      uses: ['place_rat_surprise','count'],
      eval: (m) => {{
        const ok = (typeof m.place_rat_surprise === 'number') && m.place_rat_surprise >= 1.2 && (m.count ?? 0) >= 30;
        return {{ ok, because: `place_rat_surprise=${{m.place_rat_surprise}} (needs ≥1.2) with count=${{m.count}} (needs ≥30)` }};
      }}
    }},
    {{
      id: 'wide_area',
      points: 1.0,
      title: 'Wide area (entropy)',
      desc: 'Spread across many place buckets; only adds points when already multi-location.',
      uses: ['place_entropy','places_n','clusters'],
      eval: (m) => {{
        const ok = (typeof m.place_entropy === 'number') && m.place_entropy >= 2.5 && (m.count ?? 0) >= 30 && (m.clusters ?? 0) >= 2;
        return {{ ok, because: `place_entropy=${{m.place_entropy}} (needs ≥2.5) and clusters=${{m.clusters}} (needs ≥2) and count=${{m.count}} (needs ≥30)` }};
      }}
    }},
    {{
      id: 'ml_knn',
      points: 1.0,
      title: 'kNN feature-space outlier',
      desc: 'Outlier in the multi-feature tower behavior space (kNN distance).',
      uses: ['ml_knn_z','count'],
      eval: (m) => {{
        const ok = (typeof m.ml_knn_z === 'number') && m.ml_knn_z >= 4.0 && (m.count ?? 0) >= 15;
        return {{ ok, because: `ml_knn_z=${{m.ml_knn_z}} (needs ≥4.0) with count=${{m.count}} (needs ≥15)` }};
      }}
    }},
    {{
      id: 'ml_lof',
      points: 1.0,
      title: 'LOF feature-space outlier',
      desc: 'Locally sparse vs neighbors in feature space (LOF-like).',
      uses: ['ml_lof_z','count','ml_mode'],
      eval: (m) => {{
        if (m.ml_mode === 'approx') return {{ ok:false, because:'LOF disabled in approx mode (kept neutral).'}};
        const ok = (typeof m.ml_lof_z === 'number') && m.ml_lof_z >= 4.0 && (m.count ?? 0) >= 15;
        return {{ ok, because: `ml_lof_z=${{m.ml_lof_z}} (needs ≥4.0) with count=${{m.count}} (needs ≥15)` }};
      }}
    }},
  ];

  function buildXai(m) {{
    const rows = [];
    let total = 0;
    for (const r of RULES) {{
      const ev = r.eval(m);
      const pts = ev.ok ? r.points : 0.0;
      total += pts;
      rows.push({{ id: r.id, ok: ev.ok, pts, title: r.title, desc: r.desc, uses: r.uses, because: ev.because }});
    }}
    // sort by points desc then title
    rows.sort((a,b) => (b.pts - a.pts) || a.title.localeCompare(b.title));
    return {{ total, rows }};
  }}

  function topDrivers(m, n=3) {{
    const x = buildXai(m);
    const on = x.rows.filter(r => r.pts > 0).slice(0, n);
    if (!on.length) return '—';
    return on.map(r => `${{r.id}} +${{r.pts}}`).join(' | ');
  }}

  function openExplain(m) {{
    const modal = document.getElementById('modal');
    const body = document.getElementById('modal-body');

    document.getElementById('modal-title').textContent = m.label;
    document.getElementById('modal-sub').textContent =
      `score=${{m.anomaly_score.toFixed(1)}}  count=${{m.count}}  days=${{m.days_seen}}  first=${{m.first_seen}}  last=${{m.last_seen}}`;

    const metricBox = (k, v) =>
      `<div class=\"why-box\"><div class=\"muted\">${{esc(k)}}</div><div class=\"mono\">${{esc(v ?? '—')}}</div></div>`;

    const summary = `
      <div class=\"grid2\">
        <div class=\"card\">
          <div class=\"k\">Total score</div>
          <div class=\"v mono\" style=\"font-size:18px; margin-top:4px;\">${{m.anomaly_score.toFixed(1)}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">Sum of rule point contributions below.</div>
        </div>
        <div class=\"card\">
          <div class=\"k\">Top drivers</div>
          <div class=\"v mono\" style=\"margin-top:4px;\">${{topDrivers(m, 6)}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">Rules that triggered and added points.</div>
        </div>
      </div>
    `;

    const metrics = `
      <div class=\"card\" style=\"margin-top:10px;\">
        <div class=\"k\">Key metrics (inputs)</div>
        <div class=\"why-row\">
          ${{metricBox('duration_min', m.duration_min)}}
          ${{metricBox('sessions', m.sessions)}}
          ${{metricBox('max_gap_days', m.max_gap_days)}}
          ${{metricBox('signal_median', m.signal_median)}}
          ${{metricBox('signal_robust_z', m.signal_robust_z)}}
          ${{metricBox('gps_spread_m', m.gps_spread_m)}}
          ${{metricBox('clusters', m.clusters)}}
          ${{metricBox('cluster_top2_sep_m', m.cluster_top2_sep_m)}}
          ${{metricBox('center_drift_m', m.center_drift_m)}}
          ${{metricBox('dist_outlier_frac', m.dist_outlier_frac)}}
          ${{metricBox('dense_place_novelty', m.dense_place_novelty)}}
          ${{metricBox('change_places_frac', m.change_places_frac)}}
          ${{metricBox('place_rat_surprise', m.place_rat_surprise)}}
          ${{metricBox('place_entropy', m.place_entropy)}}
          ${{metricBox('places_n', m.places_n)}}
          ${{metricBox('ml_knn_z', m.ml_knn_z)}}
          ${{metricBox('ml_lof_z', m.ml_lof_z)}}
          ${{metricBox('ml_mode', m.ml_mode)}}
          ${{metricBox('dataset_mostly_lte', m.dataset_mostly_lte)}}
        </div>
      </div>
    `;

    const x = buildXai(m);
    const rulesHtml = x.rows.map(r => {{
      const pill = r.ok ? '<span class=\"pill on\">triggered</span>' : '<span class=\"pill off\">not triggered</span>';
      const pts = r.ok ? `+${{r.pts.toFixed(1)}}` : '+0.0';
      const uses = (r.uses||[]).map(u => `<span class=\"pill mono\">${{esc(u)}}</span>`).join(' ');
      return `
        <div class=\"rule\">
          <div class=\"rule-title\">
            <span class=\"name\">${{esc(r.title)}}</span>
            ${{pill}}
            <span class=\"points\">${{pts}}</span>
          </div>
          <div class=\"rule-desc\">${{esc(r.desc)}}</div>
          <div class=\"rule-why\">
            <div class=\"muted\">Uses:</div>
            <div class=\"why-row\">${{uses}}</div>
            <div class=\"muted\" style=\"margin-top:6px;\">Decision:</div>
            <div class=\"mono\">${{esc(r.because)}}</div>
          </div>
        </div>
      `;
    }}).join('');

    body.innerHTML = summary + metrics +
      `<div class=\"card\" style=\"margin-top:10px;\"><div class=\"k\">Rule-by-rule contributions</div>${{rulesHtml}}</div>`;
    modal.classList.add('open');
  }}

  document.getElementById('modal-close').addEventListener('click', () => document.getElementById('modal').classList.remove('open'));
  document.getElementById('modal').addEventListener('click', (ev) => {{ if (ev.target && ev.target.id === 'modal') ev.currentTarget.classList.remove('open'); }});

  for (const m of MARKERS) {{
    if (m.lat == null || m.lon == null) continue;
    const cls = scoreClass(m.anomaly_score);
    const icon = L.divIcon({{
      className: '',
      html: `<div style="width:14px;height:14px;border-radius:50%;background:${{cls==='red'?'#ef4444':cls==='yellow'?'#f59e0b':'#22c55e'}};border:2px solid white;box-shadow:0 0 0 1px rgba(0,0,0,0.25)"></div>`,
      iconSize: [14,14],
      iconAnchor: [7,7],
    }});

    const marker = L.marker([m.lat, m.lon], {{icon}}).addTo(layer);
    if (m.gps_spread_m != null) {{
      L.circle([m.lat, m.lon], {{radius: Math.max(5, Math.min(500, m.gps_spread_m)), color:'#94a3b8', weight:1, fillOpacity:0.06}}).addTo(layer);
    }}

    const flags = (m.flags || []).map(f => `<span class="badge">${{esc(f)}}</span>`).join(' ');
    // Popup: human summary + link to full explain modal
    const driverText = topDrivers(m, 4);
    const popup = `
      <div style="min-width:280px">
        <div class="badge ${{cls}}"><b>Score</b>: ${{m.anomaly_score.toFixed(1)}}</div>
        <div style="margin-top:6px"><b>${{esc(m.label)}}</b></div>
        <div class="muted" style="margin-top:6px">center from ${{m.n_used}} / ${{m.n_points}} GPS points</div>
        <div style="margin-top:6px" class="mono">lat=${{m.lat.toFixed(6)}} lon=${{m.lon.toFixed(6)}}</div>
        <div style="margin-top:6px">
          <div><b>Seen</b>: ${{m.count}} samples across ${{m.days_seen}} day(s)</div>
          <div><b>First</b>: ${{esc(m.first_seen)}}</div>
          <div><b>Last</b>: ${{esc(m.last_seen)}}</div>
          <div><b>Duration</b>: ${{m.duration_min ?? ''}} min</div>
          <div><b>Sessions</b>: ${{m.sessions ?? ''}} (gap≥6h)</div>
          <div><b>Max gap</b>: ${{m.max_gap_days ?? ''}} days</div>
          <div><b>Signal median</b>: ${{m.signal_median ?? ''}}</div>
          <div><b>Signal robust z</b>: ${{m.signal_robust_z ?? ''}}</div>
          <div><b>GPS spread (median, m)</b>: ${{m.gps_spread_m ?? ''}}</div>
          <div><b>Clusters</b>: ${{m.clusters ?? ''}} sep_m=${{m.cluster_top2_sep_m ?? ''}}</div>
          <div><b>Center drift</b>: ${{m.center_drift_m ?? ''}} m (weekly)</div>
          <div><b>Signal-vs-distance outliers</b>: ${{m.dist_outlier_frac ?? ''}}</div>
          <div><b>Dense-place novelty</b>: ${{m.dense_place_novelty ?? ''}}</div>
          <div><b>Change-places fraction</b>: ${{m.change_places_frac ?? ''}}</div>
          <div><b>Place RAT surprise</b>: ${{m.place_rat_surprise ?? ''}}</div>
          <div><b>Place entropy</b>: ${{m.place_entropy ?? ''}} (places=${{m.places_n ?? ''}})</div>
          <div><b>ML kNN z</b>: ${{m.ml_knn_z ?? ''}} (score=${{m.ml_knn_score ?? ''}})</div>
          <div><b>ML LOF z</b>: ${{m.ml_lof_z ?? ''}} (score=${{m.ml_lof_score ?? ''}})</div>
        </div>
        <div style="margin-top:8px">${{flags}}</div>
        <div style="margin-top:10px"><b>Top drivers</b></div>
        <div class="mono" style="margin-top:6px">${{esc(driverText)}}</div>
        <div style="margin-top:10px"><button class="btn" onclick="window.__OPEN_EXPLAIN(${{m.id}})">Explain score</button></div>
      </div>
    `;
    marker.bindPopup(popup);

    byId.set(m.id, {{m, marker}});
  }}

  // Expose openExplain to popup onclick.
  window.__OPEN_EXPLAIN = (id) => {{
    const rec = byId.get(id);
    if (rec) openExplain(rec.m);
  }};

  // Table
  const tbody = document.querySelector('#tbl tbody');
  let sortKey = 'anomaly_score';
  let sortDir = -1;

  function render() {{
    const q = document.querySelector('#q').value.trim().toLowerCase();
    let rows = MARKERS.slice();
    if (q) {{
      rows = rows.filter(r => (r.search || '').includes(q));
    }}
    rows.sort((a,b) => {{
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === 'number' && typeof bv === 'number') return sortDir*(av-bv);
      return sortDir*String(av).localeCompare(String(bv));
    }});

    tbody.innerHTML = '';
    for (const r of rows) {{
      const cls = scoreClass(r.anomaly_score);
      const tr = document.createElement('tr');
      const drivers = topDrivers(r, 4);
      tr.innerHTML = `
        <td><span class="badge ${{cls}} mono">${{r.anomaly_score.toFixed(1)}}</span></td>
        <td>${{esc(r.label)}}</td>
        <td class="mono">${{r.count}}</td>
        <td class="mono">${{r.days_seen}}</td>
        <td class="mono">${{r.duration_min ?? ''}}</td>
        <td class="mono">${{r.sessions ?? ''}}</td>
        <td class="mono">${{r.max_gap_days ?? ''}}</td>
        <td class="mono">${{r.signal_median ?? ''}}</td>
        <td class="mono">${{r.signal_robust_z ?? ''}}</td>
        <td class="mono">${{r.gps_spread_m ?? ''}}</td>
        <td class="mono">${{r.clusters ?? ''}}</td>
        <td class="mono">${{r.cluster_top2_sep_m ?? ''}}</td>
        <td class="mono">${{r.center_drift_m ?? ''}}</td>
        <td class="mono">${{r.dist_outlier_frac ?? ''}}</td>
        <td class="mono">${{r.dense_place_novelty ?? ''}}</td>
        <td class="mono">${{r.change_places_frac ?? ''}}</td>
        <td class="mono">${{r.place_rat_surprise ?? ''}}</td>
        <td class="mono">${{r.place_entropy ?? ''}}</td>
        <td class="mono">${{r.places_n ?? ''}}</td>
        <td class="mono">${{r.ml_knn_z ?? ''}}</td>
        <td class="mono">${{r.ml_lof_z ?? ''}}</td>
        <td class="mono" title="${{esc(drivers)}}">${{esc(drivers)}}</td>
        <td><button class="btn" type="button">Explain</button></td>
        <td>${{(r.flags||[]).map(f=>`<span class="badge">${{esc(f)}}</span>`).join(' ')}}</td>
      `;
      tr.querySelector('button').addEventListener('click', (ev) => {{
        ev.stopPropagation();
        openExplain(r);
      }});
      tr.addEventListener('click', () => {{
        const rec = byId.get(r.id);
        if (rec) {{
          map.setView([r.lat, r.lon], 16);
          rec.marker.openPopup();
        }}
      }});
      tbody.appendChild(tr);
    }}
  }}

  // Tabs
  for (const btn of document.querySelectorAll('.tabbtn')) {{
    btn.addEventListener('click', () => {{
      for (const b of document.querySelectorAll('.tabbtn')) b.classList.remove('active');
      for (const t of document.querySelectorAll('.tab')) t.classList.remove('active');
      btn.classList.add('active');
      const id = btn.getAttribute('data-tab');
      const tab = document.getElementById(id);
      if (tab) tab.classList.add('active');
    }});
  }}

  document.querySelector('#q').addEventListener('input', render);
  for (const th of document.querySelectorAll('th[data-k]')) {{
    th.addEventListener('click', () => {{
      const k = th.getAttribute('data-k');
      if (k === sortKey) sortDir *= -1;
      else {{ sortKey = k; sortDir = (k==='label') ? 1 : -1; }}
      render();
    }});
  }}

  render();
</script>
</body>
</html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="Path to hack-wanderer JSONL")
    ap.add_argument("--out", default="towers-dashboard.html", help="Output HTML path")
    ap.add_argument("--min-count", type=int, default=3, help="Hide towers seen fewer than N times")
    ap.add_argument("--place-zoom", type=int, default=17, help="OSM tile zoom for place bucketing (higher => smaller buckets)")
    ap.add_argument("--max-lines", type=int, default=0, help="Read at most N lines from the JSONL (0 = no limit)")
    ap.add_argument("--after", default="", help="Only include samples at/after this datetime (ISO8601, e.g. 2026-05-01T00:00:00Z or 2026-05-01)")
    ap.add_argument("--before", default="", help="Only include samples before this datetime (ISO8601, e.g. 2026-05-10T00:00:00Z or 2026-05-10)")
    ap.add_argument("--ml-mode", choices=["auto", "off", "approx", "full"], default="auto", help="ML-style rankers mode (kNN/LOF). 'auto' disables heavy modes for large tower counts.")
    ap.add_argument("--ml-ref-size", type=int, default=800, help="Reference subset size for --ml-mode approx (kNN)")
    ap.add_argument("--sample-size", type=int, default=2000, help="Max per-tower reservoir samples kept for robust stats (memory bound).")
    ap.add_argument("--place-sample-size", type=int, default=800, help="Max per-place reservoir samples kept for distribution/change estimation (memory bound).")
    ap.add_argument("--place-bitmap-bits", type=int, default=2048, help="Bitmap size for approximate distinct-tower counts per place (memory bound).")
    ap.add_argument("--cluster-radius-m", type=float, default=400.0, help="Radius (m) for online multi-location clustering.")
    ap.add_argument("--session-gap-s", type=float, default=6*3600.0, help="Gap (seconds) that starts a new session.")
    args = ap.parse_args()

    if not os.path.exists(args.jsonl):
        raise SystemExit(f"No such file: {args.jsonl}")

    aggs: Dict[TowerKey, TowerAgg] = {}
    places: Dict[str, PlaceAgg] = {}
    all_lats: List[float] = []
    all_lons: List[float] = []

    rng = random.Random(1)
    max_lines = args.max_lines if args.max_lines and args.max_lines > 0 else None
    after_dt = parse_time_arg(args.after)
    before_dt = parse_time_arg(args.before)
    after_ts = to_epoch_seconds(after_dt) if after_dt else None
    before_ts = to_epoch_seconds(before_dt) if before_dt else None
    for obj in iter_jsonl(args.jsonl, max_lines=max_lines):
        when = parse_time(obj.get("timestamp_utc") or obj.get("timestamp_local") or "")
        if when is None:
            continue
        when_ts = to_epoch_seconds(when)
        if after_ts is not None and when_ts < after_ts:
            continue
        if before_ts is not None and when_ts >= before_ts:
            continue
        loc = pick_location(obj)
        if loc is None:
            continue
        lat, lon = loc
        all_lats.append(lat)
        all_lons.append(lon)
        x, y = latlon_to_tile(lat, lon, args.place_zoom)
        place_id = f"{args.place_zoom}/{x}/{y}"

        operator = extract_operator(obj)
        for cell in iter_observed_cells(obj):
            key = tower_key_from_cell(operator, cell)
            if key.cell_id is None and key.tac_lac is None:
                continue
            sig = observation_signal(obj, cell)
            if key not in aggs:
                aggs[key] = TowerAgg(key=key, first_seen_ts=when_ts, last_seen_ts=when_ts)
            aggs[key].add(
                when_ts,
                lat,
                lon,
                sig,
                place_id,
                sample_size=max(0, int(args.sample_size)),
                cluster_radius_m=float(args.cluster_radius_m),
                session_gap_s=float(args.session_gap_s),
                rng=rng,
            )

            p = places.get(place_id)
            if p is None:
                p = PlaceAgg(
                    place_id=place_id,
                    signal_sample_size=max(0, int(args.place_sample_size)),
                    distinct_bitmap_bits=max(256, int(args.place_bitmap_bits)),
                )
                places[place_id] = p
            p.add(when_ts, key, sig)

    if not aggs:
        raise SystemExit("No tower observations found (need location + towers/registration in JSONL).")

    # Compute robust centers
    agg_list = list(aggs.values())
    for a in agg_list:
        lat, lon, meta = robust_center([(lat, lon, sig) for (lat, lon, sig, _ts) in a.sample])
        a.center_lat = lat
        a.center_lon = lon
        a.center_meta = meta

    global_stats = compute_global_stats(agg_list)
    for a in agg_list:
        feats, score = compute_features(a, global_stats)
        a.features = feats
        a.anomaly_score = score

    # Place-level distribution & change metrics
    place_metrics: Dict[str, Dict[str, Any]] = {}
    for pid, p in places.items():
        st = sorted(p.signal_sample, key=lambda x: x[0])
        series = [v for _, v in st]
        km = {}
        if len(series) >= 60:
            split = int(len(series) * 0.7)
            early = series[:split]
            late = series[split:]
            km["ks_d"] = ks_2samp(early, late)
            km["mw_u_norm"] = mann_whitney_u(early, late)
            km["cusum"] = cusum_change_score(series, drift=0.05)
        km["count"] = p.count
        km["distinct_towers"] = p.distinct_towers_est()
        km["rat_surprise"] = p.rat_surprise()
        place_metrics[pid] = km

    # Add place-aware features to each tower
    for a in agg_list:
        dense_novel = 0
        change_weight = 0
        surprise_weighted = 0.0
        surprise_w = 0
        total = a.count or 1
        for pid, c in a.places.items():
            pm = place_metrics.get(pid) or {}
            if pm.get("count", 0) >= 500 and c <= 2:
                dense_novel += 1
            ks = pm.get("ks_d")
            cus = pm.get("cusum")
            changed = (isinstance(ks, (int, float)) and ks >= 0.25) or (isinstance(cus, (int, float)) and cus >= 8.0)
            if changed:
                change_weight += c
            rs = pm.get("rat_surprise")
            if isinstance(rs, (int, float)):
                surprise_weighted += rs * c
                surprise_w += c
        a.features["dense_place_novelty"] = dense_novel
        a.features["change_places_frac"] = change_weight / max(1, total)
        a.features["place_rat_surprise"] = (surprise_weighted / surprise_w) if surprise_w else None

        # scoring additions (explainable)
        breakdown = a.features.get("score_breakdown") or []
        if isinstance(dense_novel, int) and dense_novel >= 2 and a.count >= 10:
            a.anomaly_score += 1.5
            a.features["anomaly_novel_in_dense_places"] = True
            breakdown.append({
                "rule": "novel_in_dense_places",
                "points": 1.5,
                "because": f"dense_place_novelty={dense_novel} count={a.count}",
            })
        cpf = a.features.get("change_places_frac")
        if isinstance(cpf, (int, float)) and cpf >= 0.5 and a.count >= 20:
            a.anomaly_score += 1.0
            a.features["anomaly_correlates_with_place_change"] = True
            breakdown.append({
                "rule": "place_change_correlation",
                "points": 1.0,
                "because": f"change_places_frac={round(cpf,3)}",
            })
        prs = a.features.get("place_rat_surprise")
        if isinstance(prs, (int, float)) and prs >= 1.2 and a.count >= 30:
            a.anomaly_score += 1.0
            a.features["anomaly_rat_transition_surprise"] = True
            breakdown.append({
                "rule": "rat_transition_surprise",
                "points": 1.0,
                "because": f"avg_neglogp={round(prs,3)}",
            })
        a.features["score_breakdown"] = breakdown

    # Pure-Python ML-ish rankers over tower feature vectors (kNN + LOF).
    # WARNING: full LOF is O(n^2) memory/time and can be killed by the OS for large n.
    feature_names = [
        "count",
        "days_seen",
        "duration_s",
        "gps_spread_m",
        "clusters",
        "cluster_top2_sep_m",
        "sessions",
        "max_gap_s",
        "places_n",
        "place_entropy",
        "change_places_frac",
        "dense_place_novelty",
    ]

    # Build raw vectors (fill missing with 0)
    raw_vectors: Dict[TowerKey, List[float]] = {}
    for a in agg_list:
        vec = []
        for fn in feature_names:
            v = a.features.get(fn)
            if isinstance(v, bool):
                v = 1.0 if v else 0.0
            if v is None:
                v = 0.0
            if fn in ("count", "duration_s", "max_gap_s"):
                # compress heavy tails
                v = math.log1p(float(v))
            vec.append(float(v))
        raw_vectors[a.key] = vec

    # Robust scale each dimension (median/MAD)
    cols = list(zip(*raw_vectors.values())) if raw_vectors else []
    med = [statistics.median(col) for col in cols] if cols else []
    scale = [(mad(list(col)) or 1.0) for col in cols] if cols else []

    scaled_vectors: Dict[TowerKey, List[float]] = {}
    for k0, vec in raw_vectors.items():
        scaled = [((v - m) / (s if s > 1e-9 else 1.0)) for v, m, s in zip(vec, med, scale)]
        scaled_vectors[k0] = scaled

    n_towers = len(scaled_vectors)
    ml_mode = args.ml_mode
    if ml_mode == "auto":
        # Safe defaults: for large N, avoid O(n^2) LOF and compute only approximate kNN.
        ml_mode = "full" if n_towers <= 1200 else "approx"

    if ml_mode == "off":
        knn_scores = {k0: 0.0 for k0 in scaled_vectors.keys()}
        lof_scores = {k0: 1.0 for k0 in scaled_vectors.keys()}
    elif ml_mode == "approx":
        knn_scores = knn_anomaly_scores_approx(scaled_vectors, k=5, reference_size=args.ml_ref_size, seed=1)
        # LOF disabled in approx mode (too costly dependency-free); keep neutral values.
        lof_scores = {k0: 1.0 for k0 in scaled_vectors.keys()}
    else:
        knn_scores = knn_anomaly_scores(scaled_vectors, k=5)
        lof_scores = lof_anomaly_scores(scaled_vectors, k=10)

    # Add ML-ish scores and conservative scoring bumps
    knn_vals = list(knn_scores.values())
    lof_vals = list(lof_scores.values())
    knn_med = median(knn_vals) or 0.0
    knn_mad = mad(knn_vals) or 1.0
    lof_med = median(lof_vals) or 1.0
    lof_mad = mad(lof_vals) or 1.0

    for a in agg_list:
        kscore = knn_scores.get(a.key, 0.0)
        lscore = lof_scores.get(a.key, 1.0)
        a.features["ml_knn_score"] = kscore
        a.features["ml_lof_score"] = lscore

        breakdown = a.features.get("score_breakdown") or []
        kz = (kscore - knn_med) / (knn_mad if knn_mad > 1e-9 else 1.0)
        lz = (lscore - lof_med) / (lof_mad if lof_mad > 1e-9 else 1.0)
        a.features["ml_knn_z"] = kz
        a.features["ml_lof_z"] = lz

        if kz >= 4.0 and a.count >= 15:
            a.anomaly_score += 1.0
            a.features["anomaly_ml_knn"] = True
            breakdown.append({"rule": "ml_knn", "points": 1.0, "because": f"knn_z={round(kz,2)}"})
        if ml_mode != "approx" and lz >= 4.0 and a.count >= 15:
            a.anomaly_score += 1.0
            a.features["anomaly_ml_lof"] = True
            breakdown.append({"rule": "ml_lof", "points": 1.0, "because": f"lof_z={round(lz,2)}"})
        a.features["score_breakdown"] = breakdown

    # Build markers
    markers: List[Dict[str, Any]] = []
    for i, a in enumerate(sorted(agg_list, key=lambda x: (-x.anomaly_score, -x.count, x.key.label()))):
        if a.count < args.min_count:
            continue
        if a.center_lat is None or a.center_lon is None:
            continue

        flags = []
        for k in (
            "anomaly_ephemeral",
            "anomaly_strong_signal",
            "anomaly_location_spread",
            "anomaly_multi_location",
            "anomaly_moving_or_reused_id",
            "anomaly_non_lte",
            "anomaly_reappears",
            "anomaly_long_absence",
            "anomaly_signal_distance_mismatch",
            "anomaly_novel_in_dense_places",
            "anomaly_correlates_with_place_change",
            "anomaly_rat_transition_surprise",
            "anomaly_wide_area",
            "anomaly_ml_knn",
            "anomaly_ml_lof",
        ):
            if a.features.get(k):
                flags.append(k.replace("anomaly_", ""))
        if a.features.get("anomaly_rare") and flags:
            flags.append("rare")

        search = " ".join([
            a.key.operator,
            a.key.rat,
            str(a.key.tac_lac or ""),
            str(a.key.cell_id or ""),
            str(a.key.earfcn or ""),
            str(a.key.pci or ""),
        ]).strip().lower()

        markers.append({
            "id": i,
            "label": a.key.label(),
            "operator": a.key.operator,
            "rat": a.key.rat,
            "tac_lac": a.key.tac_lac,
            "cell_id": a.key.cell_id,
            "earfcn": a.key.earfcn,
            "pci": a.key.pci,
            "lat": a.center_lat,
            "lon": a.center_lon,
            "count": a.count,
            "first_seen": epoch_to_iso(a.first_seen_ts),
            "last_seen": epoch_to_iso(a.last_seen_ts),
            "days_seen": a.features.get("days_seen"),
            "duration_min": round((a.features.get("duration_s") or 0.0) / 60.0, 1) if a.features.get("duration_s") is not None else None,
            "sessions": a.features.get("sessions"),
            "max_gap_days": round((a.features.get("max_gap_s") or 0.0) / (24.0 * 3600.0), 2) if a.features.get("max_gap_s") is not None else None,
            "signal_median": a.features.get("signal_median"),
            "signal_robust_z": round(a.features.get("signal_robust_z"), 2) if isinstance(a.features.get("signal_robust_z"), (int, float)) else None,
            "gps_spread_m": a.features.get("gps_spread_m"),
            "clusters": a.features.get("clusters"),
            "cluster_top2_sep_m": round(a.features.get("cluster_top2_sep_m"), 1) if isinstance(a.features.get("cluster_top2_sep_m"), (int, float)) else None,
            "center_drift_m": round(((a.features.get("center_drift") or {}).get("max_drift_m") or 0.0), 1) if isinstance(((a.features.get("center_drift") or {}).get("max_drift_m")), (int, float)) else None,
            "dist_outlier_frac": round((((a.features.get("signal_dist_model") or {}).get("outlier_frac")) or 0.0), 3) if isinstance(((a.features.get("signal_dist_model") or {}).get("outlier_frac")), (int, float)) else None,
            "anomaly_score": a.anomaly_score,
            "score_breakdown": a.features.get("score_breakdown") or [],
            "flags": flags,
            "dense_place_novelty": a.features.get("dense_place_novelty"),
            "change_places_frac": round(a.features.get("change_places_frac"), 3) if isinstance(a.features.get("change_places_frac"), (int, float)) else None,
            "place_rat_surprise": round(a.features.get("place_rat_surprise"), 3) if isinstance(a.features.get("place_rat_surprise"), (int, float)) else None,
            "place_entropy": round(a.features.get("place_entropy"), 3) if isinstance(a.features.get("place_entropy"), (int, float)) else None,
            "places_n": a.features.get("places_n"),
            "ml_knn_score": round(a.features.get("ml_knn_score"), 4) if isinstance(a.features.get("ml_knn_score"), (int, float)) else None,
            "ml_lof_score": round(a.features.get("ml_lof_score"), 4) if isinstance(a.features.get("ml_lof_score"), (int, float)) else None,
            "ml_knn_z": round(a.features.get("ml_knn_z"), 2) if isinstance(a.features.get("ml_knn_z"), (int, float)) else None,
            "ml_lof_z": round(a.features.get("ml_lof_z"), 2) if isinstance(a.features.get("ml_lof_z"), (int, float)) else None,
            "ml_mode": ml_mode,
            "dataset_mostly_lte": bool(global_stats.get("mostly_lte")),
            "n_points": a.center_meta.get("n"),
            "n_used": a.center_meta.get("n_used"),
            "search": search,
        })

    # Center map on global median of device points
    c_lat = median(all_lats) or markers[0]["lat"]
    c_lon = median(all_lons) or markers[0]["lon"]

    build_dashboard(markers, (c_lat, c_lon), args.out)
    print(f"Wrote {args.out} (towers: {len(markers)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
