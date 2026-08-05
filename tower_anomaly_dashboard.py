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


@dataclass(frozen=True)
class BaseKey:
    operator: str
    rat: str
    tac_lac: Optional[int]
    cell_id: Optional[int]

    def label(self) -> str:
        parts = [self.operator or "(unknown op)", self.rat or "(unknown rat)"]
        if self.tac_lac is not None:
            parts.append(f"TAC/LAC {self.tac_lac}")
        if self.cell_id is not None:
            parts.append(f"Cell {self.cell_id}")
        return " | ".join(parts)


@dataclass
class BaseAgg:
    key: BaseKey
    stationary_obs: int = 0
    distinct_pci: set = dataclasses.field(default_factory=set)
    distinct_earfcn: set = dataclasses.field(default_factory=set)
    pci_changes: int = 0
    earfcn_changes: int = 0
    last_pci: Optional[int] = None
    last_earfcn: Optional[int] = None
    last_segment_id: Optional[int] = None

    def add_stationary(self, pci: Optional[int], earfcn: Optional[int], *, segment_id: int) -> None:
        # Count churn only within the same stationary segment (avoid counting changes across separate stops/days).
        if self.last_segment_id is None or int(segment_id) != int(self.last_segment_id):
            self.last_pci = None
            self.last_earfcn = None
            self.last_segment_id = int(segment_id)
        self.stationary_obs += 1
        if pci is not None:
            self.distinct_pci.add(int(pci))
            if self.last_pci is not None and int(pci) != int(self.last_pci):
                self.pci_changes += 1
            self.last_pci = int(pci)
        if earfcn is not None:
            self.distinct_earfcn.add(int(earfcn))
            if self.last_earfcn is not None and int(earfcn) != int(self.last_earfcn):
                self.earfcn_changes += 1
            self.last_earfcn = int(earfcn)


def parse_time(ts: str) -> Optional[dt.datetime]:
    if not ts or not isinstance(ts, str):
        return None
    try:
        if ts.endswith("Z"):
            return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def iter_jsonl_tail(path: str, tail_lines: int, *, block_size: int = 1024 * 1024) -> Iterable[Dict[str, Any]]:
    """
    Yield at most the last `tail_lines` JSONL objects from `path` without reading the full file into memory.
    Note: we still need to hold up to `tail_lines` lines in memory to return them in correct order.
    """
    n = int(tail_lines)
    if n <= 0:
        return
        yield  # pragma: no cover

    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        buf = b""
        # Read backwards until we have enough newlines.
        while pos > 0 and buf.count(b"\n") <= n:
            read_size = block_size if pos >= block_size else pos
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size)
            buf = chunk + buf

        lines = buf.splitlines()
        if not lines:
            return
            yield  # pragma: no cover

        # Take the last N lines in original order.
        for raw in lines[-n:]:
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue


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


def implied_speed_mps(
    lat1: float,
    lon1: float,
    t1: float,
    lat2: float,
    lon2: float,
    t2: float,
) -> Optional[float]:
    dt_s = float(t2 - t1)
    if dt_s <= 0:
        return None
    d = haversine_m(lat1, lon1, lat2, lon2)
    return d / dt_s


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


def tile_bounds_latlon(zoom: int, x: int, y: int) -> Tuple[float, float, float, float]:
    """
    Web Mercator tile bounds as (south_lat, west_lon, north_lat, east_lon).
    Useful for visualizing the "place bucket" rectangles in the HTML.
    """
    n = 2.0 ** zoom

    def lon_deg(tx: int) -> float:
        return tx / n * 360.0 - 180.0

    def lat_deg(ty: int) -> float:
        lat_rad = math.atan(math.sinh(math.pi * (1.0 - 2.0 * ty / n)))
        return math.degrees(lat_rad)

    west = lon_deg(x)
    east = lon_deg(x + 1)
    north = lat_deg(y)
    south = lat_deg(y + 1)
    return south, west, north, east


def ks_2samp(data1: List[float], data2: List[float]) -> Optional[float]:
    """
    Two-sample Kolmogorov–Smirnov D statistic (no p-value).
    Returns None if insufficient data.
    """
    if len(data1) < 20 or len(data2) < 20:
        return None
    x1 = sorted(float(x) for x in data1)
    x2 = sorted(float(x) for x in data2)
    n1 = len(x1)
    n2 = len(x2)
    i = 0
    j = 0
    d = 0.0
    # Walk the merged support, consuming *all ties* at once.
    while i < n1 or j < n2:
        if j >= n2:
            v = x1[i]
        elif i >= n1:
            v = x2[j]
        else:
            v = x1[i] if x1[i] <= x2[j] else x2[j]

        while i < n1 and x1[i] <= v:
            i += 1
        while j < n2 and x2[j] <= v:
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
    # number of observations excluded due to bad GPS fixes (global jump filter)
    bad_gps_skipped: int = 0

    # computed
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    center_meta: Dict[str, Any] = dataclasses.field(default_factory=dict)

    # anomaly scoring
    features: Dict[str, Any] = dataclasses.field(default_factory=dict)
    anomaly_score: float = 0.0

    # stationary-only evidence (device not moving much)
    stationary_count: int = 0
    stationary_signal: List[float] = dataclasses.field(default_factory=list)  # reservoir
    stationary_seen: int = 0
    stationary_last_signal: Optional[float] = None
    stationary_last_segment_id: Optional[int] = None
    stationary_jump_n: int = 0
    stationary_jump_gt_8db: int = 0
    stationary_pts: List[Tuple[float, float]] = dataclasses.field(default_factory=list)  # reservoir
    stationary_pts_seen: int = 0
    stationary_first_ts: Optional[float] = None
    stationary_last_ts: Optional[float] = None

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
        max_clusters: int,
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
                if max_clusters > 0 and len(self.clusters_online) >= max_clusters:
                    # Hard memory cap: merge into nearest existing cluster even if far.
                    # This preserves a rough notion of spread while staying bounded.
                    nearest_i = None
                    nearest_d = None
                    for i, (clat, clon, n) in enumerate(self.clusters_online):
                        d = haversine_m(clat, clon, lat, lon)
                        if nearest_d is None or d < nearest_d:
                            nearest_d = d
                            nearest_i = i
                    if nearest_i is None:
                        self.clusters_online.append((lat, lon, 1))
                    else:
                        clat, clon, n = self.clusters_online[nearest_i]
                        n2 = n + 1
                        self.clusters_online[nearest_i] = (clat + (lat - clat) / n2, clon + (lon - clon) / n2, n2)
                else:
                    self.clusters_online.append((lat, lon, 1))
            else:
                clat, clon, n = self.clusters_online[best_idx]
                n2 = n + 1
                self.clusters_online[best_idx] = (clat + (lat - clat) / n2, clon + (lon - clon) / n2, n2)

    def add_stationary(
        self,
        when_ts: float,
        lat: float,
        lon: float,
        signal: Optional[float],
        *,
        segment_id: int,
        signal_sample_size: int,
        pts_sample_size: int,
        rng: random.Random,
        jump_db: float = 8.0,
    ) -> None:
        self.stationary_count += 1
        if self.stationary_last_segment_id is None or int(segment_id) != int(self.stationary_last_segment_id):
            # Avoid counting jumps across separate stationary segments.
            self.stationary_last_signal = None
            self.stationary_last_segment_id = int(segment_id)
        if self.stationary_first_ts is None or when_ts < self.stationary_first_ts:
            self.stationary_first_ts = when_ts
        if self.stationary_last_ts is None or when_ts > self.stationary_last_ts:
            self.stationary_last_ts = when_ts
        # point reservoir
        self.stationary_pts_seen += 1
        if pts_sample_size > 0:
            if len(self.stationary_pts) < pts_sample_size:
                self.stationary_pts.append((lat, lon))
            else:
                j = rng.randrange(self.stationary_pts_seen)
                if j < pts_sample_size:
                    self.stationary_pts[j] = (lat, lon)

        # signal reservoir + jump rate
        if isinstance(signal, (int, float)):
            s = float(signal)
            if self.stationary_last_signal is not None:
                self.stationary_jump_n += 1
                if abs(s - self.stationary_last_signal) >= float(jump_db):
                    self.stationary_jump_gt_8db += 1
            self.stationary_last_signal = s

            self.stationary_seen += 1
            if signal_sample_size > 0:
                if len(self.stationary_signal) < signal_sample_size:
                    self.stationary_signal.append(s)
                else:
                    j = rng.randrange(self.stationary_seen)
                    if j < signal_sample_size:
                        self.stationary_signal[j] = s


@dataclass
class PlaceAgg:
    place_id: str
    count: int = 0
    first_seen_ts: Optional[float] = None
    last_seen_ts: Optional[float] = None
    stationary_count: int = 0
    first_stationary_ts: Optional[float] = None
    last_stationary_ts: Optional[float] = None
    # Reservoir sample of (ts, signal) for distribution/change estimation (bounded memory)
    signal_sample: List[Tuple[float, float]] = dataclasses.field(default_factory=list)
    signal_seen: int = 0
    signal_sample_size: int = 1000
    # Stationary-only reservoir sample of (ts, signal)
    signal_sample_stationary: List[Tuple[float, float]] = dataclasses.field(default_factory=list)
    signal_seen_stationary: int = 0
    # Approx distinct tower count via bitmap hashing
    distinct_bitmap_bits: int = 2048
    distinct_bitmap: int = 0
    # RAT transition counts (for bigram surprise), streaming
    rat_states: set = dataclasses.field(default_factory=set)
    rat_out: Counter = dataclasses.field(default_factory=Counter)
    rat_trans: Dict[str, Counter] = dataclasses.field(default_factory=dict)
    last_rat: Optional[str] = None

    def add(self, when_ts: float, tower_key: TowerKey, signal: Optional[float], *, stationary: bool) -> None:
        if self.first_seen_ts is None or when_ts < self.first_seen_ts:
            self.first_seen_ts = when_ts
        if self.last_seen_ts is None or when_ts > self.last_seen_ts:
            self.last_seen_ts = when_ts
        self.count += 1
        if stationary:
            self.stationary_count += 1
            if self.first_stationary_ts is None or when_ts < self.first_stationary_ts:
                self.first_stationary_ts = when_ts
            if self.last_stationary_ts is None or when_ts > self.last_stationary_ts:
                self.last_stationary_ts = when_ts
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
            if stationary:
                self.signal_seen_stationary += 1
                if len(self.signal_sample_stationary) < self.signal_sample_size:
                    self.signal_sample_stationary.append((when_ts, s))
                else:
                    j2 = (h ^ int(when_ts) ^ 0x9E3779B97F4A7C15) % self.signal_seen_stationary
                    if j2 < self.signal_sample_size:
                        self.signal_sample_stationary[j2] = (when_ts, s)

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


def _numeric_plmn(value: Any) -> str:
    text = str(value or "").strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    if len(digits) in (5, 6):
        return digits
    return ""


def extract_operator(obj: Dict[str, Any], cell: Optional[Dict[str, Any]] = None) -> str:
    """Return the cell PLMN, avoiding SIM-provided alphanumeric carrier names."""
    cell = cell or {}
    plmn = _numeric_plmn(cell.get("plmn"))
    if plmn:
        return plmn
    mcc = safe_int(cell.get("mcc"))
    mnc = safe_int(cell.get("mnc"))
    if mcc is not None and mnc is not None:
        return f"{mcc}{mnc:02d}"

    network = obj.get("network") or {}
    for name in ("cops_current_numeric", "cops_current"):
        cops = network.get(name) or {}
        plmn = _numeric_plmn(cops.get("operator"))
        if plmn and (cops.get("format") == 2 or name == "cops_current_numeric"):
            return plmn

    # Compatibility for old imported/test data that did not record the COPS
    # format. Explicit format 0/1 names are deliberately rejected because they
    # may be SIM/EONS branding rather than the cell network owner.
    cops = network.get("cops_current") or {}
    op = cops.get("operator")
    if cops.get("format") is None and isinstance(op, str) and op.strip():
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


def base_key_from_cell(operator: str, cell: Dict[str, Any]) -> BaseKey:
    rat = normalize_rat(cell.get("rat"))
    tac = safe_int(cell.get("tac_lac") if "tac_lac" in cell else cell.get("tac") if "tac" in cell else None)
    cell_id = safe_int(cell.get("cell_id") if "cell_id" in cell else cell.get("scell_id") if "scell_id" in cell else None)
    return BaseKey(operator=operator, rat=rat, tac_lac=tac, cell_id=cell_id)


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

    # Stationary-only evidence (device not moving much)
    feats["stationary_count"] = agg.stationary_count
    if isinstance(agg.stationary_first_ts, (int, float)) and isinstance(agg.stationary_last_ts, (int, float)) and agg.stationary_last_ts >= agg.stationary_first_ts:
        feats["stationary_span_s"] = float(agg.stationary_last_ts - agg.stationary_first_ts)
    else:
        feats["stationary_span_s"] = None
    if agg.stationary_signal:
        feats["stationary_signal_median"] = median([float(x) for x in agg.stationary_signal])
        feats["stationary_signal_mad"] = mad([float(x) for x in agg.stationary_signal])
    else:
        feats["stationary_signal_median"] = None
        feats["stationary_signal_mad"] = None
    if agg.stationary_jump_n > 0:
        feats["stationary_jump_rate_8db"] = agg.stationary_jump_gt_8db / agg.stationary_jump_n
    else:
        feats["stationary_jump_rate_8db"] = None

    # Stationary-only clusters (recomputed from stationary points)
    if agg.stationary_pts:
        s_clusters = cluster_centers_simple(agg.stationary_pts, max_cluster_radius_m=global_stats.get("cluster_radius_m", 400.0))
        feats["stationary_clusters"] = len(s_clusters)
        feats["stationary_clusters_detail"] = [{"lat": clat, "lon": clon, "n": n} for (clat, clon, n) in s_clusters[:8]]
        if len(s_clusters) >= 2:
            feats["stationary_cluster_top2_sep_m"] = haversine_m(s_clusters[0][0], s_clusters[0][1], s_clusters[1][0], s_clusters[1][1])
    else:
        feats["stationary_clusters"] = 0
        feats["stationary_clusters_detail"] = []
        feats["stationary_cluster_top2_sep_m"] = None

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
    feats["clusters_detail"] = [{"lat": clat, "lon": clon, "n": n} for (clat, clon, n) in clusters[:8]]
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

    # 1) Ephemeral burst is scored later using a *local opportunity window* (place-aware).

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
    # Stronger: multi-location even when stationary (harder to explain by your movement)
    if isinstance(feats.get("stationary_clusters"), int) and feats["stationary_clusters"] >= 2:
        ssep = feats.get("stationary_cluster_top2_sep_m")
        if isinstance(ssep, (int, float)) and ssep >= 1500.0 and agg.stationary_count >= 10:
            score += 1.5
            feats["anomaly_multi_location_stationary"] = True
            breakdown.append({
                "rule": "multi_location_stationary",
                "points": 1.5,
                "because": f"stationary_clusters={feats.get('stationary_clusters')} top2_sep_m={round(ssep,1)} stationary_count={agg.stationary_count}",
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

    # 7b) Stationary-only signal instability (when you are not moving, distance-to-tower is ~constant)
    if agg.stationary_count >= 15:
        smad = feats.get("stationary_signal_mad")
        g_med = global_stats.get("stationary_signal_mad_median")
        g_mad = global_stats.get("stationary_signal_mad_mad")
        if isinstance(smad, (int, float)) and isinstance(g_med, (int, float)) and isinstance(g_mad, (int, float)) and g_mad > 1e-9:
            z = (float(smad) - float(g_med)) / float(g_mad)
            feats["stationary_signal_mad_z"] = z
            if z >= 4.0:
                score += 1.5
                feats["anomaly_stationary_signal_instability"] = True
                breakdown.append({
                    "rule": "stationary_signal_instability",
                    "points": 1.5,
                    "because": f"stationary_signal_mad={round(float(smad),3)} z={round(z,2)} stationary_count={agg.stationary_count}",
                })

        jr = feats.get("stationary_jump_rate_8db")
        jr_med = global_stats.get("stationary_jump_rate_median")
        jr_mad = global_stats.get("stationary_jump_rate_mad")
        if isinstance(jr, (int, float)) and isinstance(jr_med, (int, float)) and isinstance(jr_mad, (int, float)) and jr_mad > 1e-9:
            z = (float(jr) - float(jr_med)) / float(jr_mad)
            feats["stationary_jump_rate_z"] = z
            if z >= 4.0:
                score += 1.0
                feats["anomaly_stationary_signal_jumps"] = True
                breakdown.append({
                    "rule": "stationary_signal_jumps",
                    "points": 1.0,
                    "because": f"jump_rate_8db={round(float(jr),3)} z={round(z,2)} stationary_count={agg.stationary_count}",
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

    # Stability bonus (negative evidence): reduce suspicion for very consistent towers.
    stab_pts = 0.0
    smad = feats.get("stationary_signal_mad")
    g_smad_med = global_stats.get("stationary_signal_mad_median")
    stable_signal = isinstance(smad, (int, float)) and isinstance(g_smad_med, (int, float)) and float(smad) <= float(g_smad_med)
    stable_geo = (feats.get("clusters") or 0) <= 1 and (feats.get("stationary_clusters") or 0) <= 1 and (isinstance(spread, (int, float)) and spread <= 120.0)
    cd = feats.get("center_drift") or {}
    stable_drift = not (isinstance(cd, dict) and isinstance(cd.get("max_drift_m"), (int, float)) and cd.get("max_drift_m") >= 800.0)
    stable_sessions = agg.stationary_count >= 30 and len(agg.days) >= 2
    if stable_sessions and stable_geo and stable_drift and stable_signal:
        stab_pts = 1.5
        score -= stab_pts
        feats["stability_bonus"] = stab_pts
        breakdown.append({
            "rule": "stability_bonus",
            "points": -stab_pts,
            "because": f"stationary_count={agg.stationary_count} days={len(agg.days)} gps_spread_m={round(float(spread),1) if isinstance(spread,(int,float)) else None} stationary_signal_mad={smad}",
        })

    if score < 0:
        score = 0.0
    feats["score_breakdown"] = breakdown
    return feats, score


def compute_global_stats(aggs: List[TowerAgg], *, global_signal_sample_size: int = 100000) -> Dict[str, Any]:
    # Reservoir sample for global signal distribution (avoid OOM on large datasets)
    cap = max(0, int(global_signal_sample_size))
    all_sig: List[float] = []
    seen = 0
    rats = Counter()
    stat_mads: List[float] = []
    stat_jump_rates: List[float] = []
    for a in aggs:
        rats[(a.key.rat or "").upper()] += a.count
        for _, _, sig, _ts in a.sample:
            if not isinstance(sig, (int, float)):
                continue
            s = float(sig)
            if cap <= 0:
                continue
            seen += 1
            if len(all_sig) < cap:
                all_sig.append(s)
            else:
                # Reservoir replacement
                j = (hash((a.key.operator, a.key.rat, a.key.tac_lac, a.key.cell_id, int(_ts))) & 0x7FFFFFFF) % seen
                if j < cap:
                    all_sig[j] = s
        if a.stationary_count >= 10 and a.stationary_signal:
            sm = mad([float(x) for x in a.stationary_signal])
            if isinstance(sm, (int, float)):
                stat_mads.append(float(sm))
        if a.stationary_count >= 15 and a.stationary_jump_n > 0:
            stat_jump_rates.append(a.stationary_jump_gt_8db / a.stationary_jump_n)
    return {
        "signal_median": median(all_sig) if all_sig else None,
        "signal_mad": mad(all_sig) if all_sig else None,
        "mostly_lte": rats.get("LTE", 0) >= max(1, sum(rats.values()) * 0.80),
        "stationary_signal_mad_median": median(stat_mads) if stat_mads else None,
        "stationary_signal_mad_mad": mad(stat_mads) if stat_mads else None,
        "stationary_jump_rate_median": median(stat_jump_rates) if stat_jump_rates else None,
        "stationary_jump_rate_mad": mad(stat_jump_rates) if stat_jump_rates else None,
    }


def apply_stationary_param_churn(agg_list: List[TowerAgg]) -> Dict[str, Any]:
    """
    Compute dataset baselines for stationary parameter churn metrics and apply scoring bumps.

    Parameter churn here means: for the same coarse identity (operator,RAT,TAC/LAC,CellID),
    do PCI/EARFCN values change a lot while the device is stationary?
    """
    pci_rates: List[float] = []
    earfcn_rates: List[float] = []
    pci_distinct: List[float] = []
    earfcn_distinct: List[float] = []
    for a in agg_list:
        obs = a.features.get("stationary_param_obs")
        if not isinstance(obs, int) or obs < 20:
            continue
        pr = a.features.get("stationary_pci_change_rate")
        er = a.features.get("stationary_earfcn_change_rate")
        pd = a.features.get("stationary_pci_distinct")
        ed = a.features.get("stationary_earfcn_distinct")
        if isinstance(pr, (int, float)):
            pci_rates.append(float(pr))
        if isinstance(er, (int, float)):
            earfcn_rates.append(float(er))
        if isinstance(pd, (int, float)):
            pci_distinct.append(float(pd))
        if isinstance(ed, (int, float)):
            earfcn_distinct.append(float(ed))

    baselines = {
        "stationary_pci_change_rate_median": median(pci_rates) if pci_rates else None,
        "stationary_pci_change_rate_mad": mad(pci_rates) if pci_rates else None,
        "stationary_earfcn_change_rate_median": median(earfcn_rates) if earfcn_rates else None,
        "stationary_earfcn_change_rate_mad": mad(earfcn_rates) if earfcn_rates else None,
        "stationary_pci_distinct_median": median(pci_distinct) if pci_distinct else None,
        "stationary_pci_distinct_mad": mad(pci_distinct) if pci_distinct else None,
        "stationary_earfcn_distinct_median": median(earfcn_distinct) if earfcn_distinct else None,
        "stationary_earfcn_distinct_mad": mad(earfcn_distinct) if earfcn_distinct else None,
    }

    for a in agg_list:
        obs = a.features.get("stationary_param_obs")
        if not isinstance(obs, int) or obs < 20:
            a.features["stationary_pci_change_rate_z"] = None
            a.features["stationary_earfcn_change_rate_z"] = None
            a.features["stationary_pci_distinct_z"] = None
            a.features["stationary_earfcn_distinct_z"] = None
            continue

        breakdown = a.features.get("score_breakdown") or []
        # PCI churn
        pr = a.features.get("stationary_pci_change_rate")
        pr_med = baselines.get("stationary_pci_change_rate_median")
        pr_mad = baselines.get("stationary_pci_change_rate_mad")
        if isinstance(pr, (int, float)) and isinstance(pr_med, (int, float)) and isinstance(pr_mad, (int, float)) and float(pr_mad) > 1e-9:
            z = (float(pr) - float(pr_med)) / float(pr_mad)
            a.features["stationary_pci_change_rate_z"] = z
            if z >= 4.0 and obs >= 30:
                a.anomaly_score += 1.5
                a.features["anomaly_stationary_pci_churn"] = True
                breakdown.append({
                    "rule": "stationary_pci_churn",
                    "points": 1.5,
                    "because": f"pci_change_rate={round(float(pr),4)} z={round(z,2)} obs={obs}",
                })
        else:
            a.features["stationary_pci_change_rate_z"] = None

        # EARFCN churn
        er = a.features.get("stationary_earfcn_change_rate")
        er_med = baselines.get("stationary_earfcn_change_rate_median")
        er_mad = baselines.get("stationary_earfcn_change_rate_mad")
        if isinstance(er, (int, float)) and isinstance(er_med, (int, float)) and isinstance(er_mad, (int, float)) and float(er_mad) > 1e-9:
            z = (float(er) - float(er_med)) / float(er_mad)
            a.features["stationary_earfcn_change_rate_z"] = z
            if z >= 4.0 and obs >= 30:
                a.anomaly_score += 1.5
                a.features["anomaly_stationary_earfcn_churn"] = True
                breakdown.append({
                    "rule": "stationary_earfcn_churn",
                    "points": 1.5,
                    "because": f"earfcn_change_rate={round(float(er),4)} z={round(z,2)} obs={obs}",
                })
        else:
            a.features["stationary_earfcn_change_rate_z"] = None

        # Also expose distinct counts as context (no separate scoring by default; they act as explanations).
        pd = a.features.get("stationary_pci_distinct")
        pd_med = baselines.get("stationary_pci_distinct_median")
        pd_mad = baselines.get("stationary_pci_distinct_mad")
        if isinstance(pd, (int, float)) and isinstance(pd_med, (int, float)) and isinstance(pd_mad, (int, float)) and float(pd_mad) > 1e-9:
            a.features["stationary_pci_distinct_z"] = (float(pd) - float(pd_med)) / float(pd_mad)
        else:
            a.features["stationary_pci_distinct_z"] = None

        ed = a.features.get("stationary_earfcn_distinct")
        ed_med = baselines.get("stationary_earfcn_distinct_median")
        ed_mad = baselines.get("stationary_earfcn_distinct_mad")
        if isinstance(ed, (int, float)) and isinstance(ed_med, (int, float)) and isinstance(ed_mad, (int, float)) and float(ed_mad) > 1e-9:
            a.features["stationary_earfcn_distinct_z"] = (float(ed) - float(ed_med)) / float(ed_mad)
        else:
            a.features["stationary_earfcn_distinct_z"] = None

        a.features["score_breakdown"] = breakdown

    return baselines


def l1_normalize(v: List[float]) -> List[float]:
    s = sum(abs(x) for x in v) or 1.0
    return [x / s for x in v]


def logit(p: float) -> float:
    p = float(p)
    p = max(1e-6, min(1.0 - 1e-6, p))
    return math.log(p / (1.0 - p))


def logistic(x: float) -> float:
    x = float(x)
    if x >= 50:
        return 1.0
    if x <= -50:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def robust_z(x: Optional[float], med: Optional[float], mad_scale: Optional[float]) -> Optional[float]:
    if not isinstance(x, (int, float)) or not isinstance(med, (int, float)) or not isinstance(mad_scale, (int, float)):
        return None
    if float(mad_scale) <= 1e-9:
        return None
    return (float(x) - float(med)) / float(mad_scale)


def bounded_squash(z: float, scale: float = 3.0) -> float:
    """
    Map z (real line) into [-1, +1] smoothly.
    scale controls how quickly it saturates.
    """
    if not isinstance(z, (int, float)):
        return 0.0
    return math.tanh(float(z) / max(1e-6, float(scale)))


def score_pos(z: Optional[float], *, scale: float = 3.0, floor: float = 0.0) -> float:
    """
    Convert a z-like value into [0,1] evidence strength.
    """
    if not isinstance(z, (int, float)):
        return 0.0
    return max(float(floor), (bounded_squash(float(z), scale=scale) + 1.0) / 2.0) - float(floor)


def _norm01_from_range(x: Optional[float], lo: float, hi: float) -> Optional[float]:
    if not isinstance(x, (int, float)):
        return None
    if float(hi) <= float(lo):
        return None
    return clamp((float(x) - float(lo)) / (float(hi) - float(lo)), 0.0, 1.0)


def _log1p_safe(x: Optional[float]) -> Optional[float]:
    if not isinstance(x, (int, float)):
        return None
    return math.log1p(max(0.0, float(x)))


def _collect_baselines(agg_list: List["TowerAgg"]) -> Dict[str, Tuple[Optional[float], Optional[float]]]:
    """
    Median/MAD baselines across towers for Bayesian scoring (O(n_towers)).
    """

    def vals(key: str, *, transform=None, require_count: int = 0) -> List[float]:
        out: List[float] = []
        for a in agg_list:
            if require_count and a.count < require_count:
                continue
            if key == "center_drift_m":
                cd = a.features.get("center_drift") or {}
                v = cd.get("max_drift_m") if isinstance(cd, dict) else None
            elif key == "dist_outlier_frac":
                dm = a.features.get("signal_dist_model") or {}
                v = dm.get("outlier_frac") if isinstance(dm, dict) else None
            else:
                v = a.features.get(key)
            if transform is not None:
                v = transform(v)
            if isinstance(v, (int, float)):
                out.append(float(v))
        return out

    baselines: Dict[str, Tuple[Optional[float], Optional[float]]] = {}
    for k, transform, require_count in (
        ("gps_spread_m", None, 5),
        ("cluster_top2_sep_m", None, 5),
        ("stationary_cluster_top2_sep_m", None, 0),
        ("center_drift_m", None, 10),
        ("dist_outlier_frac", None, 10),
        ("local_stationary_window_frac", None, 0),
        ("change_places_frac_stationary", None, 0),
        ("change_places_frac", None, 0),
        ("place_rat_surprise", None, 0),
        ("place_entropy", None, 0),
        ("sessions", _log1p_safe, 0),
        ("max_gap_s", _log1p_safe, 0),
        ("count", _log1p_safe, 0),
        ("stationary_count", _log1p_safe, 0),
        ("days_seen", _log1p_safe, 0),
    ):
        xs = vals(k, transform=transform, require_count=require_count)
        baselines[k] = (median(xs) if xs else None, mad(xs) if xs else None)
    return baselines


def apply_bayes_scores(
    agg_list: List["TowerAgg"],
    global_stats: Dict[str, Any],
    *,
    bayes_prior: float = 1e-4,
) -> Dict[str, Any]:
    """
    Attach a Bayesian (log-odds) suspicion score to each tower.

    Goal: reduce false positives by combining multiple weak signals with a low base prior,
    and by explicitly allowing strong negative evidence (stability) to reduce suspicion.

    Model:
      logit(P(suspicious|evidence)) = logit(prior) + Σ_i Δ_i
    """

    prior_p = float(bayes_prior)
    prior_logit = logit(prior_p)
    baselines = _collect_baselines(agg_list)

    def z_from_baseline(x: Optional[float], key: str, *, transform=None) -> Optional[float]:
        med, m = baselines.get(key, (None, None))
        if transform is not None:
            x = transform(x)
        return robust_z(x, med, m)

    # Term weights are in log-odds units. Keep them modest to reduce false positives.
    W = {
        "multi_location_stationary": 2.4,
        "multi_location": 1.8,
        "center_drift": 1.2,
        "gps_spread": 1.0,
        "dist_mismatch": 1.4,
        "ephemeral_stationary_opportunity": 1.6,
        "place_change_corr": 0.9,
        "rat_transition_surprise": 0.7,
        "non_lte_when_mostly_lte": 0.8,
        "stationary_signal_mad": 1.4,
        "stationary_jump_rate": 1.0,
        "stationary_pci_churn": 1.0,
        "stationary_earfcn_churn": 1.0,
        "ml_knn": 0.5,
        "ml_lof": 0.5,
        # Negative evidence:
        "stability": 2.2,  # subtract
        "many_days": 0.9,  # subtract
    }

    def mk_term(
        *,
        term_id: str,
        title: str,
        direction: str,
        weight: float,
        inputs: List[Dict[str, Any]],
        z: Optional[float],
        norm01: Optional[float],
        delta_logodds: float,
        uses: List[str],
        why: str,
        calc: str,
        gating: str,
    ) -> Dict[str, Any]:
        return {
            "id": term_id,
            "title": title,
            "direction": direction,
            "weight": float(weight),
            "inputs": inputs,
            "z": z,
            "norm01": norm01,
            "delta_logodds": float(delta_logodds),
            "odds_mult": float(math.exp(float(delta_logodds))),
            "uses": uses,
            "why": why,
            "calc": calc,
            "gating": gating,
        }

    def inp(name: str, label: str, value: Any, *, unit: str = "", meaning: str = "") -> Dict[str, Any]:
        return {"name": name, "label": label, "value": value, "unit": unit, "meaning": meaning}

    for a in agg_list:
        m = a.features or {}
        terms: List[Dict[str, Any]] = []
        total_delta = 0.0

        # Multi-location even while stationary (strongest geo inconsistency).
        ssep = m.get("stationary_cluster_top2_sep_m")
        if isinstance(m.get("stationary_clusters"), int) and m.get("stationary_clusters") >= 2 and isinstance(ssep, (int, float)):
            n01 = _norm01_from_range(float(ssep), 800.0, 5000.0)
            if n01 is not None:
                d = W["multi_location_stationary"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="multi_location_stationary",
                    title="Multi-location even while stationary",
                    direction="up",
                    weight=W["multi_location_stationary"],
                    inputs=[
                        inp("stationary_clusters", "Stationary clusters", m.get("stationary_clusters"), meaning="Number of spatial clusters formed from stationary-only samples (greedy clustering)."),
                        inp("stationary_cluster_top2_sep_m", "Top-2 cluster separation", round(float(ssep), 1), unit="m", meaning="Distance between the two largest stationary clusters (meters)."),
                        inp("stationary_count", "Stationary samples", m.get("stationary_count"), meaning="How many samples of this tower occurred while you were detected as stationary."),
                    ],
                    z=None,
                    norm01=n01,
                    delta_logodds=d,
                    uses=["stationary_clusters", "stationary_cluster_top2_sep_m", "stationary_count"],
                    why="Stationary-only samples split into far-apart clusters; harder to explain by your movement or GPS noise.",
                    calc="norm01 = clamp((sep_m − 800) / (5000 − 800), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires stationary_clusters ≥ 2 and stationary_cluster_top2_sep_m present.",
                ))

        # Multi-location overall (weaker).
        sep = m.get("cluster_top2_sep_m")
        if isinstance(m.get("clusters"), int) and m.get("clusters") >= 2 and isinstance(sep, (int, float)):
            n01 = _norm01_from_range(float(sep), 1200.0, 6000.0)
            if n01 is not None:
                d = W["multi_location"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="multi_location",
                    title="Multi-location clusters",
                    direction="up",
                    weight=W["multi_location"],
                    inputs=[
                        inp("clusters", "All-sample clusters", m.get("clusters"), meaning="Number of spatial clusters formed from all samples (moving + stationary)."),
                        inp("cluster_top2_sep_m", "Top-2 cluster separation", round(float(sep), 1), unit="m", meaning="Distance between the two largest clusters (meters)."),
                        inp("count", "Total samples", m.get("count"), meaning="How many total log samples contained this tower."),
                    ],
                    z=None,
                    norm01=n01,
                    delta_logodds=d,
                    uses=["clusters", "cluster_top2_sep_m", "count"],
                    why="Same fingerprint appears in multiple far clusters (may indicate ID reuse or inconsistent identity).",
                    calc="norm01 = clamp((sep_m − 1200) / (6000 − 1200), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires clusters ≥ 2 and cluster_top2_sep_m present.",
                ))

        # Center drift over time.
        cd = m.get("center_drift") or {}
        md = (cd.get("max_drift_m") if isinstance(cd, dict) else None)
        if isinstance(md, (int, float)):
            n01 = _norm01_from_range(float(md), 600.0, 5000.0)
            if n01 is not None:
                d = W["center_drift"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="center_drift",
                    title="Center drift over time",
                    direction="up",
                    weight=W["center_drift"],
                    inputs=[
                        inp("center_drift_m", "Max weekly center drift", round(float(md), 1), unit="m", meaning="Max distance between weekly-binned inferred centers."),
                        inp("center_drift_bins", "Weekly bins", (cd.get("bins") if isinstance(cd, dict) else None), meaning="How many weekly bins had enough points to compute a center."),
                        inp("count", "Total samples", m.get("count"), meaning="How many total log samples contained this tower."),
                    ],
                    z=z_from_baseline(float(md), "center_drift_m"),
                    norm01=n01,
                    delta_logodds=d,
                    uses=["center_drift_m", "count"],
                    why="The inferred center changes a lot across weekly bins; can indicate ID reuse or observation corridor bias.",
                    calc="norm01 = clamp((drift_m − 600) / (5000 − 600), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires weekly drift metric available (center_drift_m present).",
                ))

        # GPS spread.
        spread = m.get("gps_spread_m")
        if isinstance(spread, (int, float)):
            n01 = _norm01_from_range(float(spread), 120.0, 800.0)
            if n01 is not None:
                d = W["gps_spread"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="gps_spread",
                    title="High location spread",
                    direction="up",
                    weight=W["gps_spread"],
                    inputs=[
                        inp("gps_spread_m", "GPS spread (median)", round(float(spread), 1), unit="m", meaning="Median distance of samples from the tower’s robust inferred center."),
                        inp("count", "Total samples", m.get("count"), meaning="How many total log samples contained this tower."),
                    ],
                    z=z_from_baseline(spread, "gps_spread_m"),
                    norm01=n01,
                    delta_logodds=d,
                    uses=["gps_spread_m", "count"],
                    why="Even after robust centering, samples are geographically inconsistent (could be ID reuse, route bias, or residual GPS noise).",
                    calc="norm01 = clamp((spread_m − 120) / (800 − 120), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires gps_spread_m present (robust center computed).",
                ))

        # Signal-vs-distance mismatch.
        dm = m.get("signal_dist_model") or {}
        out_f = (dm.get("outlier_frac") if isinstance(dm, dict) else None)
        if isinstance(out_f, (int, float)) and (dm.get("n") or 0) >= 12:
            n01 = _norm01_from_range(float(out_f), 0.12, 0.45)
            if n01 is not None:
                d = W["dist_mismatch"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="signal_distance_mismatch",
                    title="Signal vs distance mismatch",
                    direction="up",
                    weight=W["dist_mismatch"],
                    inputs=[
                        inp("dist_model_n", "Distance-model points", dm.get("n"), meaning="How many points were used for the per-tower distance→signal residual model."),
                        inp("dist_outlier_frac", "Residual outlier fraction", round(float(out_f), 3), meaning="Fraction of points whose residual is a robust outlier (relative to the tower’s own distance trend)."),
                        inp("dist_residual_mad", "Residual MAD", dm.get("residual_mad"), meaning="Robust spread (MAD) of residuals in signal units (dB-like)."),
                    ],
                    z=z_from_baseline(out_f, "dist_outlier_frac"),
                    norm01=n01,
                    delta_logodds=d,
                    uses=["dist_outlier_frac", "signal_dist_model"],
                    why="Relative to its own distance trend, this tower has many signal outliers (possible power/identity inconsistency).",
                    calc="norm01 = clamp((outlier_frac − 0.12) / (0.45 − 0.12), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires signal_dist_model.n ≥ 12 and outlier_frac present.",
                ))

        # Stationary signal instability (MAD).
        smz = m.get("stationary_signal_mad_z")
        if isinstance(smz, (int, float)) and (m.get("stationary_count") or 0) >= 15:
            p = score_pos(float(smz), scale=3.0)
            d = W["stationary_signal_mad"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="stationary_signal_mad",
                title="Signal instability while stationary (MAD)",
                direction="up",
                weight=W["stationary_signal_mad"],
                inputs=[
                    inp("stationary_signal_mad", "Stationary signal MAD", m.get("stationary_signal_mad"), meaning="Median absolute deviation of signal values, computed using stationary-only samples."),
                    inp("stationary_signal_mad_z", "MAD z-score", m.get("stationary_signal_mad_z"), meaning="Robust z-score vs the dataset baseline across towers."),
                    inp("stationary_count", "Stationary samples", m.get("stationary_count"), meaning="How many stationary-only samples were available for this tower."),
                ],
                z=float(smz),
                norm01=p,
                delta_logodds=d,
                uses=["stationary_signal_mad", "stationary_signal_mad_z", "stationary_count"],
                why="When you were not moving, the signal varied unusually strongly vs the dataset baseline.",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires stationary_count ≥ 15 and stationary_signal_mad_z present.",
            ))

        # Stationary jump rate.
        jz = m.get("stationary_jump_rate_z")
        if isinstance(jz, (int, float)) and (m.get("stationary_count") or 0) >= 15:
            p = score_pos(float(jz), scale=3.0)
            d = W["stationary_jump_rate"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="stationary_jump_rate",
                title="Large signal jumps while stationary",
                direction="up",
                weight=W["stationary_jump_rate"],
                inputs=[
                    inp("stationary_jump_rate_8db", "Jump rate (≥8 dB)", m.get("stationary_jump_rate_8db"), meaning="Fraction of consecutive stationary samples whose |Δsignal| ≥ jump threshold (default 8 dB)."),
                    inp("stationary_jump_rate_z", "Jump-rate z-score", m.get("stationary_jump_rate_z"), meaning="Robust z-score of the jump rate vs baseline across towers."),
                    inp("stationary_count", "Stationary samples", m.get("stationary_count"), meaning="How many stationary-only samples were available for this tower."),
                ],
                z=float(jz),
                norm01=p,
                delta_logodds=d,
                uses=["stationary_jump_rate_8db", "stationary_jump_rate_z", "stationary_count"],
                why="Within stationary segments, the rate of big jumps (≥8 dB) is high vs baseline.",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires stationary_count ≥ 15 and stationary_jump_rate_z present.",
            ))

        # Parameter churn (stationary-only).
        pcz = m.get("stationary_pci_change_rate_z")
        if isinstance(pcz, (int, float)) and (m.get("stationary_param_obs") or 0) >= 30:
            p = score_pos(float(pcz), scale=3.0)
            d = W["stationary_pci_churn"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="stationary_pci_churn",
                title="PCI churn while stationary",
                direction="up",
                weight=W["stationary_pci_churn"],
                inputs=[
                    inp("stationary_pci_change_rate", "PCI change rate", m.get("stationary_pci_change_rate"), meaning="Changes / stationary observations for the same coarse identity (operator,RAT,TAC/LAC,CellID)."),
                    inp("stationary_pci_change_rate_z", "Change-rate z-score", m.get("stationary_pci_change_rate_z"), meaning="Robust z-score vs dataset baseline across towers."),
                    inp("stationary_param_obs", "Stationary param obs", m.get("stationary_param_obs"), meaning="How many stationary observations existed for the coarse identity (used to avoid tiny-sample noise)."),
                ],
                z=float(pcz),
                norm01=p,
                delta_logodds=d,
                uses=["stationary_pci_change_rate", "stationary_pci_change_rate_z", "stationary_param_obs"],
                why="While you were stationary, PCI changed unusually often for the same coarse cell identity.",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires stationary_param_obs ≥ 30 and stationary_pci_change_rate_z present.",
            ))

        erz = m.get("stationary_earfcn_change_rate_z")
        if isinstance(erz, (int, float)) and (m.get("stationary_param_obs") or 0) >= 30:
            p = score_pos(float(erz), scale=3.0)
            d = W["stationary_earfcn_churn"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="stationary_earfcn_churn",
                title="EARFCN churn while stationary",
                direction="up",
                weight=W["stationary_earfcn_churn"],
                inputs=[
                    inp("stationary_earfcn_change_rate", "EARFCN change rate", m.get("stationary_earfcn_change_rate"), meaning="Changes / stationary observations for the same coarse identity (operator,RAT,TAC/LAC,CellID)."),
                    inp("stationary_earfcn_change_rate_z", "Change-rate z-score", m.get("stationary_earfcn_change_rate_z"), meaning="Robust z-score vs dataset baseline across towers."),
                    inp("stationary_param_obs", "Stationary param obs", m.get("stationary_param_obs"), meaning="How many stationary observations existed for the coarse identity (used to avoid tiny-sample noise)."),
                ],
                z=float(erz),
                norm01=p,
                delta_logodds=d,
                uses=["stationary_earfcn_change_rate", "stationary_earfcn_change_rate_z", "stationary_param_obs"],
                why="While you were stationary, EARFCN changed unusually often for the same coarse cell identity.",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires stationary_param_obs ≥ 30 and stationary_earfcn_change_rate_z present.",
            ))

        # Opportunity-aware ephemerality (avoid penalizing short sessions).
        lsw_min = m.get("local_stationary_window_min")
        lsw_frac = m.get("local_stationary_window_frac")
        stat_span = m.get("stationary_span_s")
        if (
            isinstance(lsw_min, (int, float))
            and isinstance(lsw_frac, (int, float))
            and isinstance(stat_span, (int, float))
            and (m.get("stationary_count") or 0) >= 5
        ):
            if float(lsw_min) >= max(8.0, 2.0 * (float(stat_span) / 60.0)):
                n01 = _norm01_from_range(0.35 - float(lsw_frac), 0.0, 0.30)
                if n01 is not None and n01 > 0:
                    d = W["ephemeral_stationary_opportunity"] * n01
                    total_delta += d
                    terms.append(mk_term(
                        term_id="ephemeral_stationary_opportunity",
                        title="Bursty despite stationary opportunity",
                        direction="up",
                        weight=W["ephemeral_stationary_opportunity"],
                        inputs=[
                            inp("local_stationary_window_min", "Local stationary opportunity window", lsw_min, unit="min", meaning="Minutes between first and last stationary timestamps in the same place buckets where this tower appears."),
                            inp("local_stationary_window_frac", "Stationary span / opportunity window", lsw_frac, meaning="stationary_span / local_stationary_window. Smaller means burstier even when you were stationary nearby."),
                            inp("stationary_span_min", "Tower stationary span", round(float(stat_span) / 60.0, 1), unit="min", meaning="(last_stationary_ts − first_stationary_ts) for this tower."),
                            inp("stationary_count", "Stationary samples", m.get("stationary_count"), meaning="How many stationary-only samples were available for this tower."),
                        ],
                        z=z_from_baseline(lsw_frac, "local_stationary_window_frac"),
                        norm01=n01,
                        delta_logodds=d,
                        uses=["local_stationary_window_min", "local_stationary_window_frac", "stationary_span_s"],
                        why="You were stationary in the same area for long enough, yet this tower appeared only in a small fraction of that opportunity window.",
                        calc="Only if opportunity ≥ max(8 min, 2×span). norm01 = clamp((0.35 − frac) / 0.30, 0..1); Δlog-odds = weight × norm01",
                        gating="Requires stationary_count ≥ 5, local_stationary_window_* present, and opportunity window large enough.",
                    ))

        # Place-change correlation (weak).
        cpf_s = m.get("change_places_frac_stationary")
        cpf = cpf_s if isinstance(cpf_s, (int, float)) else m.get("change_places_frac")
        if isinstance(cpf, (int, float)) and (m.get("count") or 0) >= 20:
            n01 = _norm01_from_range(float(cpf), 0.35, 0.80)
            if n01 is not None and n01 > 0:
                d = W["place_change_corr"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="place_change_correlation",
                    title="Correlates with place change buckets",
                    direction="up",
                    weight=W["place_change_corr"],
                    inputs=[
                        inp("change_places_frac_stationary", "Changed-bucket fraction (stationary)", m.get("change_places_frac_stationary"), meaning="Fraction of this tower’s samples occurring in buckets whose stationary-only signal distribution changed (KS/CUSUM)."),
                        inp("change_places_frac", "Changed-bucket fraction (all)", m.get("change_places_frac"), meaning="Same fraction computed using all samples (moving + stationary)."),
                        inp("count", "Total samples", m.get("count"), meaning="How many total log samples contained this tower."),
                    ],
                    z=z_from_baseline(float(cpf), "change_places_frac_stationary" if isinstance(cpf_s, (int, float)) else "change_places_frac"),
                    norm01=n01,
                    delta_logodds=d,
                    uses=["change_places_frac_stationary", "change_places_frac", "place_details"],
                    why="A large fraction of this tower’s samples happen in place buckets whose overall signal distribution shows change (KS/CUSUM).",
                    calc="norm01 = clamp((frac − 0.35) / (0.80 − 0.35), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires count ≥ 20 and change bucket fraction present (stationary preferred if available).",
                ))

        prs = m.get("place_rat_surprise")
        if isinstance(prs, (int, float)) and (m.get("count") or 0) >= 30:
            n01 = _norm01_from_range(float(prs), 0.9, 2.0)
            if n01 is not None and n01 > 0:
                d = W["rat_transition_surprise"] * n01
                total_delta += d
                terms.append(mk_term(
                    term_id="rat_transition_surprise",
                    title="Unusual RAT transition patterns",
                    direction="up",
                    weight=W["rat_transition_surprise"],
                    inputs=[
                        inp("place_rat_surprise", "Average RAT transition surprise", prs, meaning="Average negative log-probability of RAT transitions in the places this tower appears (higher = more chaotic transitions)."),
                        inp("count", "Total samples", m.get("count"), meaning="How many total log samples contained this tower."),
                    ],
                    z=z_from_baseline(prs, "place_rat_surprise"),
                    norm01=n01,
                    delta_logodds=d,
                    uses=["place_rat_surprise", "place_details"],
                    why="In the places where this tower appears, RAT transitions look unusually chaotic (high average surprise).",
                    calc="norm01 = clamp((surprise − 0.9) / (2.0 − 0.9), 0..1); Δlog-odds = weight × norm01",
                    gating="Requires count ≥ 30 and place_rat_surprise present.",
                ))

        rat = (a.key.rat or "").upper()
        if rat in ("GSM", "2G") and bool(global_stats.get("mostly_lte")):
            d = W["non_lte_when_mostly_lte"]
            total_delta += d
            terms.append(mk_term(
                term_id="non_lte_when_mostly_lte",
                title="Non‑LTE when dataset is mostly LTE",
                direction="up",
                weight=W["non_lte_when_mostly_lte"],
                inputs=[
                    inp("rat", "RAT", rat, meaning="Radio Access Technology label (e.g. LTE, GSM)."),
                    inp("dataset_mostly_lte", "Dataset baseline mostly LTE", True, meaning="Whether the dataset (weighted by samples) is ≥80% LTE."),
                ],
                z=None,
                norm01=1.0,
                delta_logodds=d,
                uses=["rat", "dataset_mostly_lte"],
                why="Weak evidence (some real networks still run GSM for coverage); weight kept small.",
                calc="norm01 = 1; Δlog-odds = weight × 1",
                gating="Requires RAT is GSM/2G and dataset baseline is mostly LTE.",
            ))

        # ML outliers (very weak).
        kz = m.get("ml_knn_z")
        if isinstance(kz, (int, float)) and (m.get("count") or 0) >= 15 and m.get("ml_mode") != "off":
            p = score_pos(float(kz), scale=3.0)
            d = W["ml_knn"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="ml_knn",
                title="Outlier in tower behavior space (kNN)",
                direction="up",
                weight=W["ml_knn"],
                inputs=[
                    inp("ml_knn_z", "kNN z-score", kz, meaning="Robust z-score of kNN distance in the tower-feature space."),
                    inp("ml_knn_score", "kNN distance score", m.get("ml_knn_score"), meaning="Average distance to k nearest neighbors (higher = more outlier-like)."),
                ],
                z=float(kz),
                norm01=p,
                delta_logodds=d,
                uses=["ml_knn_z", "ml_knn_score"],
                why="Weak evidence: outlier in a multi-feature tower space (can be confounded by sparse sampling).",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires count ≥ 15, ml_mode enabled, and ml_knn_z present.",
            ))

        lz = m.get("ml_lof_z")
        if isinstance(lz, (int, float)) and (m.get("count") or 0) >= 15 and m.get("ml_mode") not in ("off", "approx"):
            p = score_pos(float(lz), scale=3.0)
            d = W["ml_lof"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="ml_lof",
                title="Outlier in tower behavior space (LOF)",
                direction="up",
                weight=W["ml_lof"],
                inputs=[
                    inp("ml_lof_z", "LOF z-score", lz, meaning="Robust z-score of LOF-like outlier score in the tower-feature space."),
                    inp("ml_lof_score", "LOF-like score", m.get("ml_lof_score"), meaning="Density outlier score (higher = more outlier-like)."),
                ],
                z=float(lz),
                norm01=p,
                delta_logodds=d,
                uses=["ml_lof_z", "ml_lof_score"],
                why="Weak evidence: density outlier in tower-feature space (sensitive to sample size).",
                calc="norm01 = score_pos(z) = (tanh(z/3)+1)/2; Δlog-odds = weight × norm01",
                gating="Requires count ≥ 15, ml_mode=full, and ml_lof_z present.",
            ))

        # Negative evidence: stability bonus.
        stab = m.get("stability_bonus")
        if isinstance(stab, (int, float)) and float(stab) > 0:
            p = clamp(float(stab) / 1.5, 0.0, 1.0)
            d = -W["stability"] * p
            total_delta += d
            terms.append(mk_term(
                term_id="stability",
                title="Stability evidence (reduces suspicion)",
                direction="down",
                weight=W["stability"],
                inputs=[
                    inp("stability_bonus", "Stability bonus (rules)", stab, meaning="Legacy stability bonus points (computed from multiple consistency checks)."),
                    inp("days_seen", "Days seen", m.get("days_seen"), meaning="Number of distinct UTC days this tower was observed."),
                    inp("stationary_count", "Stationary samples", m.get("stationary_count"), meaning="How many stationary-only samples were available for this tower."),
                    inp("clusters", "All-sample clusters", m.get("clusters"), meaning="Number of clusters from all samples."),
                    inp("gps_spread_m", "GPS spread (median)", m.get("gps_spread_m"), unit="m", meaning="Median distance of samples from robust center."),
                ],
                z=None,
                norm01=p,
                delta_logodds=d,
                uses=["stability_bonus", "stationary_count", "days_seen", "clusters", "gps_spread_m"],
                why="Consistent parameters + single cluster + low spread across multiple days/stationary sessions argues against a transient simulator.",
                calc="norm01 = clamp(stability_bonus / 1.5, 0..1); Δlog-odds = −weight × norm01",
                gating="Requires stability_bonus present (legacy stability rule fired).",
            ))

        # Negative evidence: many days seen.
        days = m.get("days_seen")
        if isinstance(days, int) and days >= 2:
            n01 = clamp((float(days) - 2.0) / 8.0, 0.0, 1.0)
            d = -W["many_days"] * n01
            total_delta += d
            terms.append(mk_term(
                term_id="many_days",
                title="Seen across many days (reduces suspicion)",
                direction="down",
                weight=W["many_days"],
                inputs=[
                    inp("days_seen", "Days seen", days, meaning="Number of distinct UTC days this tower was observed."),
                ],
                z=z_from_baseline(float(days), "days_seen", transform=_log1p_safe),
                norm01=n01,
                delta_logodds=d,
                uses=["days_seen"],
                why="A long-lived tower seen repeatedly across days is less consistent with a short-lived deployment.",
                calc="norm01 = clamp((days_seen − 2) / 8, 0..1); Δlog-odds = −weight × norm01",
                gating="Requires days_seen ≥ 2.",
            ))

        post_logit = prior_logit + total_delta
        post_p = logistic(post_logit)

        ordered = sorted(terms, key=lambda t: abs(float(t.get("delta_logodds") or 0.0)), reverse=True)
        running = prior_logit
        for t in ordered:
            before_p = logistic(running)
            running += float(t["delta_logodds"])
            after_p = logistic(running)
            t["p_before"] = before_p
            t["p_after"] = after_p
            t["delta_p"] = after_p - before_p

        a.features["bayes_prior_p"] = prior_p
        a.features["bayes_prior_logit"] = prior_logit
        a.features["bayes_post_p"] = post_p
        a.features["bayes_post_logit"] = post_logit
        a.features["bayes_logodds_delta"] = total_delta
        a.features["bayes_terms"] = ordered

    return {
        "bayes_prior": prior_p,
        "bayes_weights": W,
        "bayes_baselines": {k: {"median": med, "mad": m} for k, (med, m) in baselines.items()},
    }


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


def build_dashboard(
    markers: List[Dict[str, Any]],
    center: Tuple[float, float],
    out_path: str,
    *,
    bad_gps_points: Optional[List[Dict[str, Any]]] = None,
    bad_gps_stats: Optional[Dict[str, Any]] = None,
    bayes_meta: Optional[Dict[str, Any]] = None,
) -> None:
    marker_json = json.dumps(markers, ensure_ascii=False)
    center_lat, center_lon = center
    bad_gps_json = json.dumps(bad_gps_points or [], ensure_ascii=False)
    bad_gps_stats_json = json.dumps(bad_gps_stats or {}, ensure_ascii=False)
    bayes_meta_json = json.dumps(bayes_meta or {}, ensure_ascii=False)

    bayes_prior = None
    try:
        bayes_prior = float((bayes_meta or {}).get("bayes_prior")) if isinstance((bayes_meta or {}).get("bayes_prior"), (int, float)) else None
    except Exception:
        bayes_prior = None
    bayes_weights = (bayes_meta or {}).get("bayes_weights") if isinstance(bayes_meta, dict) else None
    if not isinstance(bayes_weights, dict):
        bayes_weights = {}

    def bw(name: str) -> str:
        v = bayes_weights.get(name)
        if isinstance(v, (int, float)):
            return f"{float(v):.2f}"
        return "—"

    methods_html = f"""
<h2 style="margin:10px 0 6px 0;">Methods & scoring</h2>
<div class="muted" style="margin-bottom:10px; max-width: 980px;">
  This dashboard ranks <b>anomalous / inconsistent</b> cells for manual review. It is not attribution.
  It shows two scores:
  <ul style="margin:6px 0 0 18px; padding:0;">
    <li><b>Bayes</b>: a low-prior, bounded <b>log-odds</b> model designed to reduce false positives by combining evidence and allowing strong negative evidence.</li>
    <li><b>Rules</b>: the legacy point-based sum of triggered rules (kept for transparency / debugging).</li>
  </ul>
</div>
<div class="muted" style="margin-bottom:10px; max-width: 980px;">
  <b>Bad GPS fixes</b>: device locations that imply impossible speed jumps are <b>excluded</b> from all tower stats to avoid false anomalies.
  They are still shown on the map as an overlay: enable <span class="mono">Bad GPS fixes (excluded)</span> in the layer control.
</div>
<h3 style="margin:18px 0 6px 0;">Bayesian score (primary)</h3>
<div class="muted" style="margin-bottom:10px; max-width: 980px;">
  We compute a posterior probability using additive log-odds:
  <div class="mono" style="margin-top:6px; padding:8px; background:#f8fafc; border:1px solid #e5e7eb; border-radius:8px;">
    logit(P) = logit(prior) + Σ Δ<sub>i</sub>
  </div>
  Where each Δ<sub>i</sub> is a bounded contribution from one evidence component (some can be negative, reducing suspicion).
  Prior used in this run: <span class="mono">{(f"{bayes_prior:.6f}" if isinstance(bayes_prior,(int,float)) else "—")}</span>.
</div>
<h3 style="margin:18px 0 6px 0;">Bayes glossary (variables you see in the HTML)</h3>
<table style="width:100%; border-collapse: collapse; font-size: 13px; max-width: 980px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Name</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">prior</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Starting probability before evidence. Kept very small (e.g. 1e-4) to reduce false positives.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">posterior</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Probability after combining evidence terms in log-odds.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">logit(p)</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">log(p/(1−p)). We add evidence in logit space because independent-ish evidence adds naturally there.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">Δ log-odds</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">One term’s additive contribution to the logit. Positive raises suspicion; negative reduces it.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">odds multiplier</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">exp(Δ log-odds). Roughly: how much the odds scale due to that term alone.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">weight</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Max log-odds impact of a term (after normalization). We keep weights modest to avoid false positives.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">norm01</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Evidence strength normalized to [0,1]. 0 means “no evidence from this term”; 1 means “strong evidence”.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score vs baseline (median/MAD). Used where a dataset baseline exists (e.g. stationary instability).</td></tr>
  </tbody>
</table>

<h3 style="margin:18px 0 6px 0;">Bayes evidence terms (what raises/lowers the score)</h3>
<div class="muted" style="margin-bottom:10px; max-width: 980px;">
  Each tower’s “Explain” view shows the exact inputs, normalization, and Δ log-odds for every term that applied.
</div>
<table style="width:100%; border-collapse: collapse; font-size: 13px; max-width: 980px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Term id</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Weight</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Direction</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">What it means (plain English)</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">multi_location_stationary</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("multi_location_stationary")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Stationary-only samples split into far clusters (strong geo inconsistency).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">multi_location</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("multi_location")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">All samples split into far clusters (weaker; can be influenced by walking corridors).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">center_drift</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("center_drift")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Inferred center shifts a lot across weeks (proxy for ID reuse / inconsistent identity).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">gps_spread</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("gps_spread")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Observations are spread widely around the inferred center (residual GPS noise, route bias, or reuse).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">signal_distance_mismatch</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("dist_mismatch")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Signal has many outliers relative to its own distance trend (possible inconsistent power/identity).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_signal_mad</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("stationary_signal_mad")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While you were stationary, signal variability is an outlier vs baseline across towers.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_jump_rate</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("stationary_jump_rate")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While stationary, big signal jumps happen unusually often.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_pci_churn</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("stationary_pci_churn")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While stationary, PCI changes unusually often for the same coarse identity.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_earfcn_churn</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("stationary_earfcn_churn")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While stationary, EARFCN changes unusually often for the same coarse identity.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ephemeral_stationary_opportunity</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("ephemeral_stationary_opportunity")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Tower appears only briefly despite long stationary opportunity in the same area (reduces “walked past it” false positives).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_change_correlation</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("place_change_corr")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Tower is concentrated in place buckets whose signal distribution changed (weak/confounded; low weight).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">rat_transition_surprise</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("rat_transition_surprise")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">RAT transition patterns in its places look unusually chaotic (weak/confounded; low weight).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">non_lte_when_mostly_lte</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("non_lte_when_mostly_lte")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">RAT is GSM/2G even though dataset is mostly LTE (coarse; low weight).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_knn</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("ml_knn")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Feature-space outlier by kNN distance (very weak; low weight).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_lof</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("ml_lof")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Up</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Feature-space outlier by LOF-like density (very weak; low weight).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stability</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("stability")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Down</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Strong stability evidence reduces suspicion (explicit negative evidence to cut false positives).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">many_days</td><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">{bw("many_days")}</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Down</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Seen across many days reduces suspicion (weak negative evidence).</td></tr>
  </tbody>
</table>
<h3 style="margin:18px 0 6px 0;">Definitions (what words mean here)</h3>
<table style="width:100%; border-collapse: collapse; font-size: 13px; max-width: 980px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Term</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Meaning in this dashboard</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">log sample</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">One JSON object (one line) in the JSONL file at one timestamp. A single sample can include multiple towers in <span class="mono">towers[]</span>.</td>
    </tr>
    <tr>
      <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">tower fingerprint</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">How we identify “the same” cell across time: a key built from operator name + RAT + TAC/LAC + Cell ID (+ optional PCI/EARFCN when present). This is a heuristic identifier, not a ground-truth identity.</td>
    </tr>
    <tr>
      <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">cluster</td>
      <td style="border-bottom:1px solid #f3f4f6; padding:6px;">A group of GPS points for a given tower fingerprint built by greedy assignment: each point joins the nearest cluster center within <span class="mono">--cluster-radius-m</span>, else starts a new cluster.</td>
    </tr>
        <tr>
          <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place bucket</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">An OpenStreetMap Web Mercator tile at zoom <span class="mono">--place-zoom</span> (ID format <span class="mono">z/x/y</span>). Used to group samples by “where you were”.</td>
        </tr>
        <tr>
          <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary sample</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">A log sample where the device is considered stationary by a simple streaming detector (near an anchor within <span class="mono">--stationary-radius-m</span> and speed ≤ <span class="mono">--stationary-max-speed-mps</span> for at least <span class="mono">--stationary-min-dur-s</span>).</td>
        </tr>
        <tr>
          <td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary opportunity window</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">For a tower, the time span of stationary samples in the same place buckets where that tower appears (used to avoid scoring “ephemeral” when you never stopped nearby).</td>
        </tr>
  </tbody>
</table>
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
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">count, stationary_span_s, local_stationary_window_s</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+3.0</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Seen ≥ 5 times and with ≥2 minutes of stationary span, but only for a small fraction of the stationary time window you had opportunity in the same place buckets (stationary_span/local_stationary_window ≤ 0.25).</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>ephemeral_despite_stationary</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_count, local_stationary_window_frac</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">If ephemeral triggers and you were stationary many times (stationary_count ≥15) but the fraction is even smaller (≤0.15).</td>
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
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>stationary_signal_instability</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_signal_mad_z</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Stationary-only signal spread (MAD) is a robust z ≥ 4 vs dataset baseline (requires stationary_count ≥ 15).</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>stationary_signal_jumps</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_jump_rate_z</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Stationary-only big-jump rate (≥8 dB between consecutive stationary samples) is a robust z ≥ 4 vs baseline (requires stationary_count ≥ 15).</td>
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
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Same tower fingerprint forms ≥2 clusters separated by ≥1.5km (count ≥ 15).</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>multi_location_stationary</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_clusters, stationary_cluster_top2_sep_m</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Stationary-only samples still form ≥2 far clusters separated by ≥1.5km (stationary_count ≥ 10).</td>
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
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">change_places_frac_stationary (or change_places_frac)</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.0</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">≥50% of this tower’s samples occur in places with strong distribution change (KS/CUSUM), preferring stationary-only change metrics when available.</td>
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
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>stationary_pci_churn</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_pci_change_rate_z</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">PCI change-rate while stationary is a robust z ≥ 4 vs baseline (requires stationary_param_obs ≥ 30).</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>stationary_earfcn_churn</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stationary_earfcn_change_rate_z</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">+1.5</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">EARFCN change-rate while stationary is a robust z ≥ 4 vs baseline (requires stationary_param_obs ≥ 30).</td>
        </tr>
        <tr>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;"><b>stability_bonus</b></td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">stability_bonus</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;" class="mono">−1.5</td>
          <td style="border-bottom:1px solid #f3f4f6; padding:6px;">Subtracts points for towers that remain consistent across multiple days and stationary sessions (reduces false positives).</td>
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
<div class="muted" style="max-width: 980px; margin-bottom: 10px;">
  Reminder: a <b>log sample</b> is one JSON object (one line) in the JSONL file at one timestamp.
</div>
<table style="width:100%; border-collapse: collapse; font-size: 13px;">
  <thead>
    <tr>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Metric</th>
      <th style="text-align:left; border-bottom:1px solid #eee; padding:6px;">Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">count</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of <b>log samples</b> (JSONL lines) where this tower fingerprint was observed.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">days_seen</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distinct calendar days with ≥1 sample.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">duration_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">(last_seen - first_seen) in minutes within the dataset window.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">local_window_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Time span between first/last logging activity in the same place buckets where this tower was seen (proxy for “you were around and active”).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">local_window_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">duration / local_window (smaller = more “bursty” relative to opportunity).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_count</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;"># of tower observations that occurred while the device was detected as stationary (see --stationary-*).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_span_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">(last_stationary - first_stationary) for this tower, in minutes (stationary-only span).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">local_stationary_window_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Stationary opportunity window in the same place buckets where this tower appears (based on place stationary timestamps).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">local_stationary_window_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_span / local_stationary_window (small = tower is “bursty” even when you were stationary nearby).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">sessions</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of segments separated by gaps ≥ 6 hours (disappear/reappear proxy).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">max_gap_days</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Largest time gap between consecutive observations (days).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">signal_median</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Median of the chosen signal metric for this tower (often RSSI dBm, sometimes RSRP).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">signal_robust_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of signal_median vs global distribution (MAD scale).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_signal_mad</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust spread (MAD) of signal values observed while stationary for this tower.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_signal_mad_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of stationary_signal_mad vs dataset baseline across towers.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_jump_rate_8db</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Within stationary observations, fraction of consecutive signal samples that jump by ≥8 dB.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_jump_rate_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of stationary_jump_rate_8db vs dataset baseline.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">gps_spread_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Median distance from samples to inferred center after robust trimming (uncertainty).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">clusters</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of spatial clusters (greedy, radius 400m) for this tower fingerprint.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">cluster_top2_sep_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distance between the two biggest clusters’ centers (multi-location indicator).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">clusters_detail</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">List of the largest clusters for this tower fingerprint: each entry has a cluster center (<span class="mono">lat, lon</span>) and count <span class="mono">n</span>. Displayed in the Explain view and drawn in the Focus overlay.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_clusters</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;"># of spatial clusters computed from stationary-only GPS points for this tower.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_cluster_top2_sep_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distance between the two biggest stationary-only clusters’ centers.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_clusters_detail</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Largest stationary-only clusters (center lat/lon and n). Shown in Explain view and drawn in Focus overlay.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">center_drift_m</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Max distance between weekly-binned inferred centers (drift / ID reuse proxy).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">dist_outlier_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Fraction of big residual outliers in robust signal-vs-(proxy)distance model.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">dense_place_novelty</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;"># of dense places (≥500 samples) where this tower appears only 1–2 times.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">change_places_frac</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Fraction of this tower’s samples in places with strong distribution change using all samples (KS/CUSUM).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">change_places_frac_stationary</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Same fraction but computed using stationary-only bucket change flags when available (preferred by the place_change_correlation rule).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_rat_surprise</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Average negative log-probability of RAT transitions in its places (higher = more chaotic).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">places_n</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Number of place buckets (OSM tile at --place-zoom) where seen.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_entropy</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Entropy of place distribution (higher = more spread out).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_param_obs</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;"># of stationary observations contributing to stationary PCI/EARFCN churn metrics for the coarse key (operator,RAT,TAC/LAC,Cell ID).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_pci_distinct</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distinct PCI values observed while stationary for the same coarse key.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_earfcn_distinct</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Distinct EARFCN values observed while stationary for the same coarse key.</td></tr>
	    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_pci_change_rate</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While stationary, fraction of stationary observations where PCI changed vs the previous stationary observation for the same coarse key (resets when you leave and later re-enter a stationary segment).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_pci_change_rate_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of stationary_pci_change_rate vs dataset baseline.</td></tr>
	    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_earfcn_change_rate</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">While stationary, fraction of stationary observations where EARFCN changed for the same coarse key (resets across stationary segments).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stationary_earfcn_change_rate_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of stationary_earfcn_change_rate vs dataset baseline.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">stability_bonus</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Negative evidence points subtracted when a tower is stable across multiple checks (shown as a negative rule contribution).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_id</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">A place bucket ID in <span class="mono">z/x/y</span> format (Web Mercator tile coordinates at zoom=--place-zoom). Used to group samples by location.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">tower_count</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">For a given place bucket: how many times this tower fingerprint appears in that bucket.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_total</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Total number of log samples inside that place bucket (all towers, all time).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_dur_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Duration (minutes) between first and last logging activity recorded in that place bucket.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_stationary_total</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Total number of stationary log samples inside that place bucket.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_stationary_dur_min</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Duration (minutes) between first and last stationary logging activity recorded in that place bucket.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ks_d</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Kolmogorov–Smirnov D statistic comparing <b>early</b> vs <b>late</b> signal samples within a place bucket (higher = distributions differ more). No p-value is computed.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">cusum</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">CUSUM-like change score over the bucket’s sampled signal time series (higher = stronger evidence of a shift).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">changed</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Whether the bucket is classified as “changed” (true if ks_d≥0.25 or cusum≥8.0).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ks_d_stationary</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">KS D statistic computed from stationary-only signals in the bucket (when enough stationary samples exist).</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">cusum_stationary</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">CUSUM-like change score computed from stationary-only signals in the bucket.</td></tr>
        <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">changed_stationary</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Whether the bucket is classified as “changed” using stationary-only metrics (ks_d_stationary≥0.25 or cusum_stationary≥8.0).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">place_details</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">List of the top place buckets for this tower fingerprint, with per-bucket counts and change metrics (shown in Explain view and drawn in Focus overlay).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_mode</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">ML ranker mode used for this run: <span class="mono">off</span>, <span class="mono">approx</span>, or <span class="mono">full</span> (auto chooses based on tower count).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_knn_score</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">kNN anomaly score in scaled feature space: average distance to the k=5 nearest neighbors (higher = more outlier-like).</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_knn_z</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">Robust z-score of kNN distance outlier score in tower-feature space.</td></tr>
    <tr><td class="mono" style="border-bottom:1px solid #f3f4f6; padding:6px;">ml_lof_score</td><td style="border-bottom:1px solid #f3f4f6; padding:6px;">LOF-like density outlier score in scaled feature space (higher = more outlier-like).</td></tr>
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
          position: sticky;
          top: 0;
          z-index: 10;
          height: 14px;
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
	        <span id=\"badgps-summary\" class=\"muted mono\"></span>
	        <span id=\"pt-summary\" class=\"muted mono\"></span>
	      </div>
      <table id=\"tbl\">
        <thead>
          <tr>
            <th data-k=\"bayes_post_p\">Bayes</th>
            <th data-k=\"anomaly_score\">Rules</th>
            <th data-k=\"label\">Tower</th>
            <th data-k=\"count\">Seen</th>
            <th data-k=\"days_seen\">Days</th>
            <th data-k=\"duration_min\">Dur (min)</th>
            <th data-k=\"local_window_min\">Local win (min)</th>
            <th data-k=\"local_window_frac\">Local frac</th>
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
	            <th>Export</th>
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
	<script src=\"https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js\"></script>
<script>
  const MARKERS = {marker_json};
  const BAD_GPS = {bad_gps_json};
  const BAD_GPS_STATS = {bad_gps_stats_json};
  const BAYES_META = {bayes_meta_json};

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
	      // Keep at least a tiny sliver so the resize handle remains reachable.
	      const MIN_H = 12;
	      // Keep at least a sliver of map visible so it never looks "broken".
	      const MIN_MAP_H = 80;
	  function clamp(v, lo, hi) {{ return Math.max(lo, Math.min(hi, v)); }}

	  function setPanelHeight(px) {{
	    // No artificial ceiling: allow the panel to consume almost the whole viewport.
	    const maxH = Math.max(MIN_H, Math.floor(window.innerHeight) - MIN_MAP_H);
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
    // score here is the Bayesian posterior probability.
    if (typeof score !== 'number') return 'green';
    if (score >= 0.005) return 'red';     // ≥0.5%
    if (score >= 0.001) return 'yellow';  // ≥0.1%
    return 'green';
  }}

  function fmtBayes(p) {{
    if (typeof p !== 'number') return '—';
    const pct = p * 100.0;
    if (pct >= 0.01) return pct.toFixed(2) + '%';
    if (pct >= 0.001) return pct.toFixed(3) + '%';
    if (pct >= 0.0001) return pct.toFixed(4) + '%';
    const ppm = p * 1e6;
    return ppm.toFixed(ppm >= 10 ? 1 : 2) + ' ppm';
  }}

  function fmtSigned(x, digits=2) {{
    if (typeof x !== 'number' || !isFinite(x)) return '—';
    const s = x >= 0 ? '+' : '';
    return s + x.toFixed(digits);
  }}

  function safeFilename(s) {{
    const t = String(s ?? 'tower')
      .replaceAll(/[^a-zA-Z0-9._-]+/g, '_')
      .replaceAll(/_+/g, '_')
      .replaceAll(/^_+|_+$/g, '');
    return t ? t.slice(0, 140) : 'tower';
  }}

  function downloadBlob(blob, filename) {{
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2500);
  }}

  function downloadText(text, filename, mime='text/plain;charset=utf-8') {{
    const blob = new Blob([text], {{ type: mime }});
    downloadBlob(blob, filename);
  }}

  function kvLines(obj, keys) {{
    const out = [];
    for (const k of keys) {{
      const v = obj[k];
      out.push(`- **${{k}}**: ${{(v==null) ? '—' : String(v)}}`);
    }}
    return out.join('\\n');
  }}

  function buildTowerReportMd(m) {{
    const now = new Date().toISOString();
    const idParts = [
      m.operator ? `op=${{m.operator}}` : null,
      m.rat ? `rat=${{m.rat}}` : null,
      (m.tac_lac!=null) ? `tac_lac=${{m.tac_lac}}` : null,
      (m.cell_id!=null) ? `cell_id=${{m.cell_id}}` : null,
      (m.pci!=null) ? `pci=${{m.pci}}` : null,
      (m.earfcn!=null) ? `earfcn=${{m.earfcn}}` : null,
    ].filter(Boolean);
    const towerId = idParts.join(' · ');

    const lines = [];
    lines.push(`# Tower report`);
    lines.push('');
    lines.push(`**Tower:** ${{m.label}}`);
    lines.push(`**Generated:** ${{now}}`);
    lines.push(`**Tower id:** ${{towerId || '—'}}`);
    lines.push('');
    lines.push('## Summary');
    lines.push(`- **Bayes posterior (primary):** ${{fmtBayes(m.bayes_post_p)}}`);
    lines.push(`- **Bayes prior:** ${{fmtBayes(m.bayes_prior_p)}}`);
    lines.push(`- **Bayes Δ log-odds:** ${{(typeof m.bayes_logodds_delta==='number') ? fmtSigned(m.bayes_logodds_delta, 3) : '—'}}`);
    lines.push(`- **Bayes posterior logit:** ${{(typeof m.bayes_post_logit==='number') ? m.bayes_post_logit.toFixed(3) : '—'}}`);
    lines.push(`- **Rules score (legacy):** ${{(typeof m.anomaly_score==='number') ? m.anomaly_score.toFixed(1) : '—'}}`);
    lines.push('');
    lines.push('## Key values');
    lines.push(kvLines(m, [
      'first_seen','last_seen','count','days_seen','duration_min','sessions','max_gap_days',
      'lat','lon','gps_spread_m','clusters','cluster_top2_sep_m','stationary_clusters','stationary_cluster_top2_sep_m',
      'center_drift_m','dist_outlier_frac','signal_median','signal_robust_z',
      'stationary_count','stationary_span_min','stationary_signal_mad','stationary_signal_mad_z',
      'stationary_jump_rate_8db','stationary_jump_rate_z',
      'change_places_frac','change_places_frac_stationary','place_rat_surprise','place_entropy','places_n',
      'stationary_param_obs','stationary_pci_change_rate','stationary_pci_change_rate_z',
      'stationary_earfcn_change_rate','stationary_earfcn_change_rate_z',
    ]));
    lines.push('');
    lines.push('## Bayesian score model');
    lines.push('');
    lines.push('We compute a posterior probability using additive log-odds:');
    lines.push('');
    lines.push('`logit(P) = logit(prior) + Σ Δ_i`');
    lines.push('');
    lines.push('Where each `Δ_i` is one evidence term’s contribution (positive raises suspicion; negative reduces it).');
    lines.push('');
    lines.push('## Bayesian term breakdown (XAI)');
    const terms = Array.isArray(m.bayes_terms) ? m.bayes_terms : [];
    if (!terms.length) {{
      lines.push('');
      lines.push('_No Bayes terms applied (insufficient evidence)._');
    }} else {{
      for (const t of terms) {{
        lines.push('');
        lines.push(`### ${{
          (t.title ? t.title : t.id)
        }}  \\`(${{
          t.id ?? 'term'
        }})\\``);
        lines.push('');
        lines.push(`- **Direction:** ${{t.direction ?? '—'}}`);
        lines.push(`- **Applies when:** ${{t.gating ?? '—'}}`);
        lines.push(`- **Why:** ${{t.why ?? '—'}}`);
        lines.push(`- **Calculation:** ${{t.calc ?? '—'}}`);
        lines.push(`- **Weight:** ${{(typeof t.weight==='number') ? t.weight.toFixed(3) : '—'}}`);
        lines.push(`- **norm01:** ${{(typeof t.norm01==='number') ? t.norm01.toFixed(4) : '—'}}`);
        lines.push(`- **z:** ${{(typeof t.z==='number') ? t.z.toFixed(3) : '—'}}`);
        lines.push(`- **Δ log-odds:** ${{(typeof t.delta_logodds==='number') ? fmtSigned(t.delta_logodds, 4) : '—'}}`);
        lines.push(`- **Odds multiplier:** ${{(typeof t.odds_mult==='number') ? t.odds_mult.toFixed(3) : '—'}}`);
        lines.push(`- **ΔP:** ${{(typeof t.delta_p==='number') ? fmtSigned(t.delta_p*100.0, 6) + '%' : '—'}}`);
        lines.push(`- **P before → after:** ${{fmtBayes(t.p_before)}} → ${{fmtBayes(t.p_after)}}`);
        lines.push('');
        lines.push('**Inputs:**');
        const inps = Array.isArray(t.inputs) ? t.inputs : [];
        if (!inps.length) {{
          lines.push('- —');
        }} else {{
          for (const inp of inps) {{
            const lab = inp.label ?? inp.name ?? 'value';
            const val = (inp.value==null) ? '—' : String(inp.value);
            const unit = inp.unit ? (' ' + inp.unit) : '';
            const meaning = inp.meaning ? String(inp.meaning) : '';
            lines.push(`- **${{lab}}**: ${{val}}${{unit}}${{meaning ? ` — ${{meaning}}` : ''}}`);
          }}
        }}
      }}
    }}

    lines.push('');
    lines.push('## Rules breakdown (legacy, for transparency)');
    const x = buildXai(m);
    const triggered = (x.rows || []).filter(r => r.pts !== 0);
    if (!triggered.length) {{
      lines.push('');
      lines.push('_No rule contributions triggered._');
    }} else {{
      for (const r of triggered) {{
        lines.push('');
        lines.push(`### ${{r.title}}  \\`(${{r.id}})\\``);
        lines.push('');
        lines.push(`- **Points:** ${{(r.pts>=0?'+':'') + r.pts.toFixed(1)}}`);
        lines.push(`- **Decision:** ${{r.because ?? '—'}}`);
        lines.push(`- **Uses:** ${{Array.isArray(r.uses) ? r.uses.join(', ') : '—'}}`);
        lines.push(`- **Description:** ${{r.desc ?? '—'}}`);
      }}
    }}

    lines.push('');
    lines.push('## Spatial evidence');
    lines.push('');
    lines.push('### Clusters (all samples)');
    const cl = Array.isArray(m.clusters_detail) ? m.clusters_detail : [];
    if (!cl.length) lines.push('- —');
    for (const [i,c] of cl.entries()) {{
      lines.push(`- Cluster #${{i+1}}: n=${{c.n ?? '—'}} at lat=${{c.lat ?? '—'}}, lon=${{c.lon ?? '—'}}`);
    }}
    lines.push('');
    lines.push('### Clusters (stationary-only)');
    const scl = Array.isArray(m.stationary_clusters_detail) ? m.stationary_clusters_detail : [];
    if (!scl.length) lines.push('- —');
    for (const [i,c] of scl.entries()) {{
      lines.push(`- Stationary cluster #${{i+1}}: n=${{c.n ?? '—'}} at lat=${{c.lat ?? '—'}}, lon=${{c.lon ?? '—'}}`);
    }}

    lines.push('');
    lines.push('### Place buckets (top)');
    const ps = Array.isArray(m.place_details) ? m.place_details : [];
    if (!ps.length) lines.push('- —');
    for (const p of ps) {{
      lines.push(`- place_id=${{p.place_id ?? '—'}} · tower_count=${{p.tower_count ?? '—'}}/${{p.place_total ?? '—'}} · ks_d=${{p.ks_d ?? '—'}} · cusum=${{p.cusum ?? '—'}} · changed=${{p.changed ?? '—'}} · ks_d_stationary=${{p.ks_d_stationary ?? '—'}} · cusum_stationary=${{p.cusum_stationary ?? '—'}} · changed_stationary=${{p.changed_stationary ?? '—'}}`);
    }}

    lines.push('');
    lines.push('## Flags');
    const flags = Array.isArray(m.flags) ? m.flags : [];
    lines.push(flags.length ? flags.map(f => `- ${{f}}`).join('\\n') : '- —');
    lines.push('');

    return lines.join('\\n');
  }}

  function exportTowerMd(m) {{
    const md = buildTowerReportMd(m);
    const base = safeFilename(`${{m.operator ?? 'op'}}_${{m.rat ?? 'rat'}}_tac${{m.tac_lac ?? 'na'}}_cell${{m.cell_id ?? 'na'}}`);
    downloadText(md, `${{base}}.md`, 'text/markdown;charset=utf-8');
  }}

  function xmlEscape(s) {{
    return String(s ?? '')
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('\"','&quot;');
  }}

  async function exportTowerDocx(m) {{
    if (typeof JSZip === 'undefined') {{
      alert('JSZip not loaded; cannot export .docx. Check your network connection.');
      return;
    }}
    const md = buildTowerReportMd(m);
    const text = md; // keep markdown as text inside the docx (auditable, exact).
    const lines = text.split(/\\r?\\n/);

    const paras = lines.map(line => {{
      const t = xmlEscape(line);
      // Preserve leading spaces by using xml:space="preserve".
      return `<w:p><w:r><w:t xml:space=\"preserve\">${{t}}</w:t></w:r></w:p>`;
    }}).join('');

    const documentXml = `<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>` +
`<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">` +
`<w:body>${{paras}}<w:sectPr/></w:body></w:document>`;

    const contentTypes = `<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>` +
`<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">` +
`<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>` +
`<Default Extension=\"xml\" ContentType=\"application/xml\"/>` +
`<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>` +
`</Types>`;

    const rels = `<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>` +
`<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">` +
`<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>` +
`</Relationships>`;

    const zip = new JSZip();
    zip.file('[Content_Types].xml', contentTypes);
    zip.folder('_rels').file('.rels', rels);
    zip.folder('word').file('document.xml', documentXml);

    const blob = await zip.generateAsync({{type:'blob', mimeType:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}});
    const base = safeFilename(`${{m.operator ?? 'op'}}_${{m.rat ?? 'rat'}}_tac${{m.tac_lac ?? 'na'}}_cell${{m.cell_id ?? 'na'}}`);
    downloadBlob(blob, `${{base}}.docx`);
  }}

	  const layer = L.layerGroup().addTo(map);
	  const focusLayer = L.layerGroup().addTo(map);
	  let lastFocusId = null;
	  // Separate layers for per-tower raw points so they persist even after closing the modal.
	  const towerPtsLayer = L.layerGroup();
	  const statPtsLayer = L.layerGroup();
	  const badGpsLayer = L.layerGroup();
  if (Array.isArray(BAD_GPS) && BAD_GPS.length) {{
    for (const p of BAD_GPS) {{
      if (p.lat==null || p.lon==null) continue;
      const m = L.circleMarker([p.lat, p.lon], {{
        radius: 5,
        color: '#ef4444',
        weight: 2,
        fillColor: '#ef4444',
        fillOpacity: 0.25,
      }});
      const sp = (p.speed_mps!=null) ? `speed=${{p.speed_mps}} m/s` : '';
      m.bindPopup(`<div class=\"mono\">BAD GPS<br/>${{esc(p.ts ?? '')}}<br/>${{esc(sp)}}<br/>lat=${{esc(p.lat)}} lon=${{esc(p.lon)}}</div>`);
      m.addTo(badGpsLayer);
    }}
  }}

	  // Layer control (lets you toggle overlays on/off)
	  L.control.layers({{}}, {{
	    'Bad GPS fixes (excluded)': badGpsLayer,
	    'Focus (clusters/buckets)': focusLayer,
	    'Tower points (selected)': towerPtsLayer,
	    'Stationary points (selected)': statPtsLayer,
	  }}).addTo(map);

	  // Show bad-GPS summary (excluded points)
	  try {{
	    const s = document.getElementById('badgps-summary');
    if (s && BAD_GPS_STATS && (BAD_GPS_STATS.excluded_total || BAD_GPS.length)) {{
      const excl = BAD_GPS_STATS.excluded_total ?? 0;
      const shown = BAD_GPS.length ?? 0;
      const thr = BAD_GPS_STATS.gps_max_speed_mps ?? '';
      s.textContent = 'bad_gps_excluded=' + excl + ' shown=' + shown + ' speed_thr_mps=' + thr;
    }}
	  }} catch (e) {{}}

	  function setPtSummary(text) {{
	    try {{
	      const el = document.getElementById('pt-summary');
	      if (el) el.textContent = text ? String(text) : '';
	    }} catch (e) {{}}
	  }}

	      function setFocus(m) {{
	        focusLayer.clearLayers();
	        lastFocusId = m && (m.id ?? null);
	        // Clusters: centers from greedy online clustering (radius defined in CLI).
	        const clusters = Array.isArray(m.clusters_detail) ? m.clusters_detail : [];
        for (let i=0;i<clusters.length;i++) {{
      const c = clusters[i];
      if (c.lat==null || c.lon==null) continue;
      const n = c.n ?? 0;
      const r = Math.max(4, Math.min(16, 3 + Math.sqrt(Math.max(1,n))));
      const cm = L.circleMarker([c.lat, c.lon], {{
        radius: r,
        color: '#7c3aed',
        weight: 2,
        fillColor: '#a78bfa',
        fillOpacity: 0.35,
      }});
      const chtml = '<div class=\"mono\">cluster #' + (i+1) +
        '<br/>n=' + esc(n) +
        '<br/>lat=' + esc(c.lat) + ' lon=' + esc(c.lon) +
        '</div>';
      cm.bindPopup(chtml);
          cm.addTo(focusLayer);
        }}

        // Stationary-only clusters: computed from samples where the device was stationary.
        const sClusters = Array.isArray(m.stationary_clusters_detail) ? m.stationary_clusters_detail : [];
        for (let i=0;i<sClusters.length;i++) {{
          const c = sClusters[i];
          if (c.lat==null || c.lon==null) continue;
          const n = c.n ?? 0;
          const r = Math.max(4, Math.min(16, 3 + Math.sqrt(Math.max(1,n))));
          const cm = L.circleMarker([c.lat, c.lon], {{
            radius: r,
            color: '#16a34a',
            weight: 2,
            fillColor: '#4ade80',
            fillOpacity: 0.30,
          }});
          const chtml = '<div class=\"mono\">stationary cluster #' + (i+1) +
            '<br/>n=' + esc(n) +
            '<br/>lat=' + esc(c.lat) + ' lon=' + esc(c.lon) +
            '</div>';
          cm.bindPopup(chtml);
          cm.addTo(focusLayer);
        }}

	        // Place buckets: OSM tiles at --place-zoom; show top buckets for this tower.
	        const places = Array.isArray(m.place_details) ? m.place_details : [];
	        for (const p of places) {{
          const bb = p.bbox;
          if (!bb) continue;
          const changedAll = !!p.changed;
          const changedStat = (p.changed_stationary === true);
          const col = changedStat ? '#f59e0b' : (changedAll ? '#ef4444' : '#94a3b8');
          const rect = L.rectangle([[bb.south, bb.west],[bb.north, bb.east]], {{
            color: col,
            weight: (changedStat || changedAll) ? 3 : 1,
            fillOpacity: (changedStat || changedAll) ? 0.08 : 0.04,
          }});
          const why = 'place=' + (p.place_id ?? '') +
            ' tower_count=' + (p.tower_count ?? '') + '/' + (p.place_total ?? '') +
            ' place_stationary=' + (p.place_stationary_total ?? '') +
            ' ks_d=' + (p.ks_d ?? '—') +
            ' cusum=' + (p.cusum ?? '—') +
            ' changed=' + (p.changed ? 'true' : 'false') +
            ' ks_d_stationary=' + (p.ks_d_stationary ?? '—') +
            ' cusum_stationary=' + (p.cusum_stationary ?? '—') +
            ' changed_stationary=' + ((p.changed_stationary==null) ? '—' : (p.changed_stationary ? 'true' : 'false'));
          rect.bindPopup(`<div class=\"mono\">${{esc(why)}}</div>`);
	          rect.addTo(focusLayer);
	        }}
	      }}

	      function showPointsFor(m, which) {{
	        if (!m) return;
	        const needEmbedMsg = 'no embedded points (re-run with --embed-points-top / --embed-points-per-tower)';
	        function drawPts(layer, list, color, fillColor, label) {{
	          layer.clearLayers();
	          if (!Array.isArray(list) || !list.length) return [];
	          const latlngs = [];
	          for (const p of list) {{
	            if (p.lat==null || p.lon==null) continue;
	            latlngs.push([p.lat, p.lon]);
	            const cm = L.circleMarker([p.lat, p.lon], {{
	              radius: 6,
	              color,
	              weight: 2,
	              fillColor,
	              fillOpacity: 0.70,
	            }});
	            const ts = p.ts ? `ts=${{p.ts}}` : '';
	            const sig = (p.sig!=null) ? `sig=${{p.sig}}` : '';
	            cm.bindPopup(`<div class=\"mono\">${{esc(label)}}<br/>${{esc(ts)}}<br/>${{esc(sig)}}<br/>lat=${{esc(p.lat)}} lon=${{esc(p.lon)}}</div>`);
	            cm.addTo(layer);
	          }}
	          return latlngs;
	        }}

	        if (which === 'all') {{
	          const pts = Array.isArray(m.points_all) ? m.points_all : [];
	          if (!pts.length) {{ setPtSummary(needEmbedMsg); return; }}
	          statPtsLayer.clearLayers();
	          const latlngs = drawPts(towerPtsLayer, pts, '#0ea5e9', '#38bdf8', 'tower point');
	          towerPtsLayer.addTo(map);
	          if (latlngs.length) map.fitBounds(L.latLngBounds(latlngs).pad(0.15), {{ maxZoom: 19 }});
	          setPtSummary('tower_points=' + latlngs.length + ' (selected)');
	        }} else if (which === 'stationary') {{
	          const pts = Array.isArray(m.points_stationary) ? m.points_stationary : [];
	          if (!pts.length) {{ setPtSummary(needEmbedMsg); return; }}
	          towerPtsLayer.clearLayers();
	          const latlngs = drawPts(statPtsLayer, pts, '#a855f7', '#c084fc', 'stationary point');
	          statPtsLayer.addTo(map);
	          if (latlngs.length) map.fitBounds(L.latLngBounds(latlngs).pad(0.15), {{ maxZoom: 19 }});
	          setPtSummary('stationary_points=' + latlngs.length + ' (selected)');
	        }} else {{
	          towerPtsLayer.clearLayers();
	          statPtsLayer.clearLayers();
	          setPtSummary('');
	        }}
	        try {{ setFocus(m); }} catch (e) {{}}
	      }}

      function clustersTable(m) {{
        const all = Array.isArray(m.clusters_detail) ? m.clusters_detail : [];
        const stat = Array.isArray(m.stationary_clusters_detail) ? m.stationary_clusters_detail : [];

        function tableFor(list) {{
          if (!list.length) return '<div class=\"muted\">—</div>';
          const rows = [];
          rows.push('<table style=\"width:100%; border-collapse:collapse; font-size:12px;\">');
          rows.push('<thead><tr>' +
            '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">#</th>' +
            '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">n</th>' +
            '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">lat</th>' +
            '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">lon</th>' +
            '</tr></thead><tbody>');
          for (let i=0;i<list.length;i++) {{
            const c = list[i];
            rows.push('<tr>' +
              `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(i+1)}}</td>` +
              `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(c.n ?? '')}}</td>` +
              `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc((c.lat==null?'':Number(c.lat).toFixed(6)))}}</td>` +
              `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc((c.lon==null?'':Number(c.lon).toFixed(6)))}}</td>` +
            '</tr>');
          }}
          rows.push('</tbody></table>');
          return rows.join('');
        }}

        const parts = [];
        parts.push('<div><b>All samples</b>' + tableFor(all) + '</div>');
        parts.push('<div style=\"margin-top:10px;\"><b>Stationary-only samples</b>' + tableFor(stat) + '</div>');
        parts.push('<div class=\"muted\" style=\"margin-top:8px;\">Clusters are formed by greedy online assignment: each GPS sample goes to the nearest existing cluster within the configured radius, else starts a new cluster.</div>');
        return parts.join('');
      }}

      function placesTable(m) {{
        const places = Array.isArray(m.place_details) ? m.place_details : [];
        if (!places.length) return '<div class=\"muted\">No place buckets recorded for this tower (place tracking disabled or capped).</div>';
        const rows = [];
        rows.push('<table style=\"width:100%; border-collapse:collapse; font-size:12px;\">');
        rows.push('<thead><tr>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">place_id (z/x/y)</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">tower_count</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">place_total</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">place_dur_min</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">place_stationary_total</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">place_stationary_dur_min</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">ks_d</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">cusum</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">changed</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">ks_d_stationary</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">cusum_stationary</th>' +
          '<th style=\"text-align:left; border-bottom:1px solid #eee; padding:6px;\">changed_stationary</th>' +
          '</tr></thead><tbody>');
        for (const p of places) {{
          const changed = !!p.changed;
          const bg = changed ? ' style=\"background:#fee2e2;\"' : '';
          rows.push(`<tr${{bg}}>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.place_id)}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.tower_count ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.place_total ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.place_duration_min ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.place_stationary_total ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.place_stationary_dur_min ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.ks_d ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.cusum ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{changed ? 'yes' : 'no'}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.ks_d_stationary ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{esc(p.cusum_stationary ?? '')}}</td>` +
            `<td class=\"mono\" style=\"border-bottom:1px solid #f3f4f6; padding:6px;\">${{p.changed_stationary==null ? '—' : (p.changed_stationary ? 'yes' : 'no')}}</td>` +
          `</tr>`);
        }}
    rows.push('</tbody></table>');
        rows.push('<div class=\"muted\" style=\"margin-top:8px;\">' +
          'A “place bucket” is an OpenStreetMap Web Mercator tile at <span class=\"mono\">--place-zoom</span>. ' +
          '<span class=\"mono\">place_total</span>=all log samples in that tile; <span class=\"mono\">place_dur_min</span>=first→last activity span in that tile. ' +
          '<span class=\"mono\">place_stationary_total</span>/<span class=\"mono\">place_stationary_dur_min</span>=same but only for samples where the device was stationary. ' +
          '<span class=\"mono\">ks_d</span>/<span class=\"mono\">cusum</span>=change metrics for all samples; <span class=\"mono\">ks_d_stationary</span>/<span class=\"mono\">cusum_stationary</span>=stationary-only. ' +
          'Red rows indicate <span class=\"mono\">changed</span>=true (ks_d≥0.25 or cusum≥8.0). ' +
          'These buckets are drawn on the map in the Focus overlay.' +
        '</div>');
    return rows.join('');
  }}
  const byId = new Map();

  // Rule schema for XAI: points, description, thresholds, and feature usage.
  // The explanation UI will show pass/fail and what values contributed.
  const RULES = [
        {{
          id: 'ephemeral',
          points: 3.0,
          title: 'Ephemeral burst',
          desc: 'Seen ≥5 times, but only for a small fraction of the time you were stationary (had opportunity) in the same place buckets.',
          uses: ['count', 'stationary_count', 'stationary_span_min', 'local_stationary_window_min', 'local_stationary_window_frac'],
          eval: (m) => {{
            const statCount = (m.stationary_count ?? 0);
            const span = (typeof m.stationary_span_min === 'number') ? m.stationary_span_min : null;
            const win = (typeof m.local_stationary_window_min === 'number') ? m.local_stationary_window_min : null;
            const frac = (typeof m.local_stationary_window_frac === 'number') ? m.local_stationary_window_frac : null;
            const ok =
              (m.count ?? 0) >= 5 &&
              statCount >= 5 &&
              (span == null ? false : span >= 2) &&
              (win == null ? false : win >= Math.max(10, 3 * (span ?? 0))) &&
              (frac == null ? false : frac <= 0.25);
            return {{ ok, because: `count=${{m.count}} (≥5), stationary_count=${{statCount}} (≥5), stationary_span_min=${{m.stationary_span_min}} (≥2), local_stationary_window_min=${{m.local_stationary_window_min}} (≥max(10,3×span)), local_stationary_window_frac=${{m.local_stationary_window_frac}} (≤0.25)` }};
          }}
        }},
        {{
          id: 'ephemeral_despite_stationary',
          points: 1.0,
          title: 'Ephemeral despite stationary opportunity',
          desc: 'Extra bump when the ephemeral fraction is very small even though you were stationary many times.',
          uses: ['stationary_count', 'local_stationary_window_frac', 'flags'],
          eval: (m) => {{
            const isEphemeral = Array.isArray(m.flags) && m.flags.includes('ephemeral');
            const ok = isEphemeral && (m.stationary_count ?? 0) >= 15 && (typeof m.local_stationary_window_frac === 'number') && m.local_stationary_window_frac <= 0.15;
            return {{ ok, because: `ephemeral=${{isEphemeral}} and stationary_count=${{m.stationary_count}} (≥15) and local_stationary_window_frac=${{m.local_stationary_window_frac}} (≤0.15)` }};
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
      desc: 'GPS samples for this tower fingerprint group into ≥2 spatial clusters far apart (clusters built by greedy radius assignment).',
      uses: ['clusters','cluster_top2_sep_m','count','clusters_detail'],
      eval: (m) => {{
        const ok = (m.clusters ?? 0) >= 2 && (typeof m.cluster_top2_sep_m === 'number') && m.cluster_top2_sep_m >= 1500 && (m.count ?? 0) >= 15;
        return {{ ok, because: `clusters=${{m.clusters}}, top2_sep_m=${{m.cluster_top2_sep_m}} (needs clusters≥2, sep≥1500m, count≥15)` }};
          }}
        }},
        {{
          id: 'stationary_signal_instability',
          points: 1.5,
          title: 'Signal instability while stationary',
          desc: 'Within stationary segments (you not moving), signal varies much more than the dataset baseline (MAD z).',
          uses: ['stationary_signal_mad','stationary_signal_mad_z','stationary_count'],
          eval: (m) => {{
            const ok = (m.stationary_count ?? 0) >= 15 && (typeof m.stationary_signal_mad_z === 'number') && m.stationary_signal_mad_z >= 4.0;
            return {{ ok, because: `stationary_count=${{m.stationary_count}} (needs ≥15), stationary_signal_mad=${{m.stationary_signal_mad}}, stationary_signal_mad_z=${{m.stationary_signal_mad_z}} (needs ≥4.0)` }};
          }}
        }},
        {{
          id: 'stationary_signal_jumps',
          points: 1.0,
          title: 'Large signal jumps while stationary',
          desc: 'Within stationary segments, the rate of big jumps (≥8 dB) is an outlier vs baseline.',
          uses: ['stationary_jump_rate_8db','stationary_jump_rate_z','stationary_count'],
          eval: (m) => {{
            const ok = (m.stationary_count ?? 0) >= 15 && (typeof m.stationary_jump_rate_z === 'number') && m.stationary_jump_rate_z >= 4.0;
            return {{ ok, because: `stationary_count=${{m.stationary_count}} (needs ≥15), jump_rate_8db=${{m.stationary_jump_rate_8db}}, jump_rate_z=${{m.stationary_jump_rate_z}} (needs ≥4.0)` }};
          }}
        }},
        {{
          id: 'multi_location_stationary',
          points: 1.5,
          title: 'Multi-location even while stationary',
          desc: 'Stationary-only samples still split into ≥2 far-apart clusters. Stronger evidence than multi-location while moving.',
          uses: ['stationary_clusters','stationary_cluster_top2_sep_m','stationary_count','stationary_clusters_detail'],
          eval: (m) => {{
            const ok = (m.stationary_clusters ?? 0) >= 2 && (typeof m.stationary_cluster_top2_sep_m === 'number') && m.stationary_cluster_top2_sep_m >= 1500 && (m.stationary_count ?? 0) >= 10;
            return {{ ok, because: `stationary_clusters=${{m.stationary_clusters}}, stationary_top2_sep_m=${{m.stationary_cluster_top2_sep_m}} (needs ≥1500m), stationary_count=${{m.stationary_count}} (needs ≥10)` }};
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
          desc: 'Most sightings occur in place buckets whose distributions show change (KS/CUSUM). Prefers stationary-only change metrics when available.',
          uses: ['change_places_frac','change_places_frac_stationary','count','place_details'],
          eval: (m) => {{
            const cpf = (typeof m.change_places_frac_stationary === 'number') ? m.change_places_frac_stationary : m.change_places_frac;
            const which = (typeof m.change_places_frac_stationary === 'number') ? 'stationary' : 'all';
            const ok = (typeof cpf === 'number') && cpf >= 0.5 && (m.count ?? 0) >= 20;
            const places = Array.isArray(m.place_details) ? m.place_details : [];
            const changed = places.filter(p => p && (which==='stationary' ? p.changed_stationary : p.changed)).slice(0,3).map(p => p.place_id).join(', ');
            return {{ ok, because: `change_places_frac_${{which}}=${{cpf}} (needs ≥0.5) with count=${{m.count}} (needs ≥20). changed_buckets_top=${{changed || '—'}}` }};
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
          id: 'stationary_pci_churn',
          points: 1.5,
          title: 'PCI churn while stationary',
          desc: 'For the same (operator,RAT,TAC/LAC,Cell ID), PCI changes unusually often while you are stationary.',
          uses: ['stationary_param_obs','stationary_pci_change_rate','stationary_pci_change_rate_z'],
          eval: (m) => {{
            const ok = (m.stationary_param_obs ?? 0) >= 30 && (typeof m.stationary_pci_change_rate_z === 'number') && m.stationary_pci_change_rate_z >= 4.0;
            return {{ ok, because: `stationary_param_obs=${{m.stationary_param_obs}} (needs ≥30), pci_change_rate=${{m.stationary_pci_change_rate}}, pci_change_rate_z=${{m.stationary_pci_change_rate_z}} (needs ≥4.0)` }};
          }}
        }},
        {{
          id: 'stationary_earfcn_churn',
          points: 1.5,
          title: 'EARFCN churn while stationary',
          desc: 'For the same (operator,RAT,TAC/LAC,Cell ID), EARFCN changes unusually often while you are stationary.',
          uses: ['stationary_param_obs','stationary_earfcn_change_rate','stationary_earfcn_change_rate_z'],
          eval: (m) => {{
            const ok = (m.stationary_param_obs ?? 0) >= 30 && (typeof m.stationary_earfcn_change_rate_z === 'number') && m.stationary_earfcn_change_rate_z >= 4.0;
            return {{ ok, because: `stationary_param_obs=${{m.stationary_param_obs}} (needs ≥30), earfcn_change_rate=${{m.stationary_earfcn_change_rate}}, earfcn_change_rate_z=${{m.stationary_earfcn_change_rate_z}} (needs ≥4.0)` }};
          }}
        }},
        {{
          id: 'stability_bonus',
          points: -1.5,
          title: 'Stability bonus (negative evidence)',
          desc: 'Subtracts points for towers that are consistently stable across multiple days and stationary sessions.',
          uses: ['stability_bonus','stationary_count','stationary_span_min','stationary_signal_mad','clusters','stationary_clusters'],
          eval: (m) => {{
            const ok = (typeof m.stability_bonus === 'number') && m.stability_bonus > 0;
            return {{ ok, because: ok ? `stability_bonus=${{m.stability_bonus}} applied (stable across multiple checks)` : 'not stable enough for bonus' }};
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

      function xaiTotalText(m) {{
        const x = buildXai(m);
        const jsTotal = x.total;
        const pyTotal = (typeof m.anomaly_score === 'number') ? m.anomaly_score : null;
        if (pyTotal == null) return `js_sum=${{jsTotal.toFixed(1)}}`;
        const diff = Math.abs(jsTotal - pyTotal);
        if (diff <= 0.05) return `rules=${{pyTotal.toFixed(1)}}`;
        return `rules=${{pyTotal.toFixed(1)}} (js_sum=${{jsTotal.toFixed(1)}})`; // should match; show if not
      }}

	  function driverSummary(m, posN=3, negN=1) {{
	    const x = buildXai(m);
	    const pos = x.rows.filter(r => r.pts > 0).slice(0, posN);
	    const neg = x.rows.filter(r => r.pts < 0).sort((a,b) => a.pts - b.pts).slice(0, negN);
	    const parts = [];
	    if (pos.length) parts.push(pos.map(r => `${{r.id}} +${{r.pts}}`).join(' | '));
	    if (neg.length) parts.push(neg.map(r => `${{r.id}} ${{r.pts}}`).join(' | '));
	    return parts.length ? parts.join(' | ') : '—';
	  }}

	  function allTriggeredDrivers(m) {{
	    const x = buildXai(m);
	    const on = x.rows.filter(r => r.pts !== 0);
	    if (!on.length) return '—';
	    return on.map(r => `${{r.id}} ${{(r.pts >= 0 ? '+' : '') + r.pts}}`).join(' | ');
	  }}

	  function bayesTerms(m) {{
	    return Array.isArray(m.bayes_terms) ? m.bayes_terms : [];
	  }}

	  function bayesDriverSummary(m, posN=3, negN=1) {{
	    const ts = bayesTerms(m).slice().sort((a,b) => Math.abs((b.delta_logodds||0)) - Math.abs((a.delta_logodds||0)));
	    const pos = ts.filter(t => (t.delta_logodds||0) > 0).slice(0, posN);
	    const neg = ts.filter(t => (t.delta_logodds||0) < 0).slice(0, negN);
	    const parts = [];
	    const name = (t) => (t.id ?? '');
	    if (pos.length) parts.push(pos.map(t => `${{name(t)}} ${{fmtSigned(t.delta_logodds,2)}}`).join(' | '));
	    if (neg.length) parts.push(neg.map(t => `${{name(t)}} ${{fmtSigned(t.delta_logodds,2)}}`).join(' | '));
	    return parts.length ? parts.join(' | ') : '—';
	  }}

	  function bayesWaterfall(m) {{
	    const ts = bayesTerms(m);
	    const priorP = (typeof m.bayes_prior_p === 'number') ? m.bayes_prior_p : null;
	    const postP = (typeof m.bayes_post_p === 'number') ? m.bayes_post_p : null;
	    const priorLogit = (typeof m.bayes_prior_logit === 'number') ? m.bayes_prior_logit : null;
	    const postLogit = (typeof m.bayes_post_logit === 'number') ? m.bayes_post_logit : null;
	    const totalDelta = (typeof m.bayes_logodds_delta === 'number') ? m.bayes_logodds_delta : null;

	    const head = `
	      <div class="why-row">
	        <div class="why-box"><div class="muted">Prior</div><div class="mono">${{fmtBayes(priorP)}}</div></div>
	        <div class="why-box"><div class="muted">Posterior</div><div class="mono">${{fmtBayes(postP)}}</div></div>
	        <div class="why-box"><div class="muted">Δ log-odds</div><div class="mono">${{(typeof totalDelta==='number') ? fmtSigned(totalDelta,2) : '—'}}</div></div>
	        <div class="why-box"><div class="muted">Posterior logit</div><div class="mono">${{(typeof postLogit==='number') ? postLogit.toFixed(2) : '—'}}</div></div>
	      </div>
	      <div class="muted" style="margin-top:8px;">Each row shows how one evidence component moves the probability (positive = more suspicious, negative = less). Terms are ordered by absolute impact.</div>
	    `;
	    if (!ts.length) return head + '<div class="muted" style="margin-top:10px;">No Bayes terms were applicable (not enough evidence).</div>';

		    const rows = ts.map(t => {{
	      const dir = (t.delta_logodds||0) >= 0 ? 'up' : 'down';
	      const pill = dir === 'up'
	        ? '<span class="pill on">raises</span>'
	        : '<span class="pill off">reduces</span>';
	      const uses = (t.uses||[]).map(u => `<span class="pill mono">${{esc(u)}}</span>`).join(' ');
	      const ztxt = (typeof t.z === 'number') ? t.z.toFixed(2) : '—';
	      const n01 = (typeof t.norm01 === 'number') ? t.norm01.toFixed(3) : '—';
	      const dlog = fmtSigned(t.delta_logodds||0, 2);
	      const dp = (typeof t.delta_p === 'number') ? fmtSigned((t.delta_p*100.0), 4) + '%' : '—';
	      const pb = (typeof t.p_before === 'number') ? fmtBayes(t.p_before) : '—';
	      const pa = (typeof t.p_after === 'number') ? fmtBayes(t.p_after) : '—';
	      const calc = (typeof t.calc === 'string' && t.calc) ? t.calc : '—';
		      const gating = (typeof t.gating === 'string' && t.gating) ? t.gating : '—';
		      let actions = '';
		      if (t.id === 'multi_location') {{
		        actions = `<div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
		          <button class="btn" type="button" onclick="window.__SHOW_TOWER_POINTS(${{m.id}}, 'all')">Show tower points</button>
		          <button class="btn" type="button" onclick="window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')">Hide points</button>
		        </div>`;
		      }} else if (t.id === 'multi_location_stationary') {{
		        actions = `<div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
		          <button class="btn" type="button" onclick="window.__SHOW_TOWER_POINTS(${{m.id}}, 'stationary')">Show stationary points</button>
		          <button class="btn" type="button" onclick="window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')">Hide points</button>
		        </div>`;
		      }}
	      const inps = Array.isArray(t.inputs) ? t.inputs : [];
	      const inputsHtml = inps.length ? inps.map(inp => {{
	        const lab = inp.label ?? inp.name ?? '';
	        const val = (inp.value==null) ? '—' : String(inp.value);
	        const unit = inp.unit ? (' ' + inp.unit) : '';
	        const meaning = (typeof inp.meaning === 'string' && inp.meaning) ? inp.meaning : '';
	        return `
	          <div class="why-box" title="${{esc(meaning)}}">
	            <div class="muted">${{esc(lab)}}</div>
	            <div class="mono">${{esc(val)}}${{esc(unit)}}</div>
	          </div>
	        `;
	      }}).join('') : '<div class="muted">—</div>';
	      return `
	        <div class="rule">
	          <div class="rule-title">
	            <span class="name">${{esc(t.title || t.id)}}</span>
	            ${{pill}}
	            <span class="points mono">${{dlog}}</span>
	          </div>
	          <div class="rule-desc">${{esc(t.why || '')}}</div>
		          <div class="rule-why">
	            <div class="muted">Uses:</div>
	            <div class="why-row">${{uses}}</div>
	            <div class="muted" style="margin-top:6px;">Applies when:</div>
	            <div class="mono">${{esc(gating)}}</div>
	            <div class="muted" style="margin-top:6px;">Inputs (hover for definitions):</div>
	            <div class="why-row">${{inputsHtml}}</div>
	            <div class="muted" style="margin-top:6px;">Calculation:</div>
	            <div class="mono">${{esc(calc)}}</div>
		            <div class="muted" style="margin-top:6px;">Effect:</div>
		            <div class="why-row">
		              <div class="why-box"><div class="muted">z</div><div class="mono">${{esc(ztxt)}}</div></div>
		              <div class="why-box"><div class="muted">norm01</div><div class="mono">${{esc(n01)}}</div></div>
		              <div class="why-box"><div class="muted">ΔP</div><div class="mono">${{esc(dp)}}</div></div>
		              <div class="why-box"><div class="muted">P before→after</div><div class="mono">${{esc(pb)}} → ${{esc(pa)}}</div></div>
		            </div>
		            ${{actions}}
		          </div>
		        </div>
		      `;
		    }}).join('');

	    return head + `<div style="margin-top:10px;">${{rows}}</div>`;
	  }}

  function openExplain(m) {{
    const modal = document.getElementById('modal');
    const body = document.getElementById('modal-body');

    document.getElementById('modal-title').textContent = m.label;
    document.getElementById('modal-sub').textContent =
      `bayes=${{fmtBayes(m.bayes_post_p)}}  rules=${{(typeof m.anomaly_score==='number') ? m.anomaly_score.toFixed(1) : '—'}}  count=${{m.count}}  days=${{m.days_seen}}  first=${{m.first_seen}}  last=${{m.last_seen}}`;

    const metricBox = (k, v) =>
      `<div class=\"why-box\"><div class=\"muted\">${{esc(k)}}</div><div class=\"mono\">${{esc(v ?? '—')}}</div></div>`;

    const summary = `
      <div class=\"grid2\">
        <div class=\"card\">
          <div class=\"k\">Bayes posterior (primary)</div>
          <div class=\"v mono\" style=\"font-size:18px; margin-top:4px;\">${{fmtBayes(m.bayes_post_p)}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">prior=${{fmtBayes(m.bayes_prior_p)}} · Δlog-odds=${{(typeof m.bayes_logodds_delta==='number') ? fmtSigned(m.bayes_logodds_delta,2) : '—'}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">drivers: ${{bayesDriverSummary(m, 5, 2)}}</div>
        </div>
        <div class=\"card\">
          <div class=\"k\">Rules score (legacy)</div>
          <div class=\"v mono\" style=\"font-size:18px; margin-top:4px;\">${{(typeof m.anomaly_score==='number') ? m.anomaly_score.toFixed(1) : '—'}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">${{xaiTotalText(m)}}</div>
          <div class=\"muted\" style=\"margin-top:6px;\">drivers: ${{driverSummary(m, 5, 2)}}</div>
        </div>
      </div>
    `;

    const metrics = `
      <div class=\"card\" style=\"margin-top:10px;\">
            <div class=\"k\">Key metrics (inputs)</div>
            <div class=\"why-row\">
                ${{metricBox('duration_min', m.duration_min)}}
                ${{metricBox('local_window_min', m.local_window_min)}}
                ${{metricBox('local_window_frac', m.local_window_frac)}}
                ${{metricBox('stationary_count', m.stationary_count)}}
                ${{metricBox('stationary_span_min', m.stationary_span_min)}}
                ${{metricBox('local_stationary_window_min', m.local_stationary_window_min)}}
                ${{metricBox('local_stationary_window_frac', m.local_stationary_window_frac)}}
                ${{metricBox('sessions', m.sessions)}}
                ${{metricBox('max_gap_days', m.max_gap_days)}}
                ${{metricBox('signal_median', m.signal_median)}}
              ${{metricBox('signal_robust_z', m.signal_robust_z)}}
              ${{metricBox('stationary_signal_mad', m.stationary_signal_mad)}}
              ${{metricBox('stationary_signal_mad_z', m.stationary_signal_mad_z)}}
              ${{metricBox('stationary_jump_rate_8db', m.stationary_jump_rate_8db)}}
              ${{metricBox('stationary_jump_rate_z', m.stationary_jump_rate_z)}}
              ${{metricBox('gps_spread_m', m.gps_spread_m)}}
              ${{metricBox('clusters', m.clusters)}}
              ${{metricBox('cluster_top2_sep_m', m.cluster_top2_sep_m)}}
              ${{metricBox('stationary_clusters', m.stationary_clusters)}}
              ${{metricBox('stationary_cluster_top2_sep_m', m.stationary_cluster_top2_sep_m)}}
              ${{metricBox('center_drift_m', m.center_drift_m)}}
              ${{metricBox('dist_outlier_frac', m.dist_outlier_frac)}}
              ${{metricBox('dense_place_novelty', m.dense_place_novelty)}}
              ${{metricBox('change_places_frac', m.change_places_frac)}}
              ${{metricBox('change_places_frac_stationary', m.change_places_frac_stationary)}}
              ${{metricBox('place_rat_surprise', m.place_rat_surprise)}}
              ${{metricBox('place_entropy', m.place_entropy)}}
              ${{metricBox('places_n', m.places_n)}}
              ${{metricBox('stationary_param_obs', m.stationary_param_obs)}}
              ${{metricBox('stationary_pci_change_rate', m.stationary_pci_change_rate)}}
              ${{metricBox('stationary_pci_change_rate_z', m.stationary_pci_change_rate_z)}}
              ${{metricBox('stationary_earfcn_change_rate', m.stationary_earfcn_change_rate)}}
              ${{metricBox('stationary_earfcn_change_rate_z', m.stationary_earfcn_change_rate_z)}}
              ${{metricBox('stability_bonus', m.stability_bonus)}}
              ${{metricBox('ml_knn_z', m.ml_knn_z)}}
              ${{metricBox('ml_lof_z', m.ml_lof_z)}}
              ${{metricBox('ml_mode', m.ml_mode)}}
          ${{metricBox('dataset_mostly_lte', m.dataset_mostly_lte)}}
        </div>
      </div>
    `;

	    const explainMore = `
	      <div class=\"card\" style=\"margin-top:10px;\">
	        <div class=\"k\">Clusters (where + how)</div>
	        <div style=\"margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;\">
	          <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'all')\">Show tower points</button>
	          <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'stationary')\">Show stationary points</button>
	          <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')\">Hide points</button>
	        </div>
	        <div style=\"margin-top:8px;\">${{clustersTable(m)}}</div>
	      </div>
      <div class=\"card\" style=\"margin-top:10px;\">
        <div class=\"k\">Place buckets (which ones)</div>
        <div style=\"margin-top:8px;\">${{placesTable(m)}}</div>
      </div>
    `;

	    const x = buildXai(m);
	        const rulesHtml = x.rows.map(r => {{
	          const pill = r.ok ? '<span class=\"pill on\">triggered</span>' : '<span class=\"pill off\">not triggered</span>';
	          const pts = r.ok ? `${{(r.pts >= 0 ? '+' : '') + r.pts.toFixed(1)}}` : '+0.0';
	          const uses = (r.uses||[]).map(u => `<span class=\"pill mono\">${{esc(u)}}</span>`).join(' ');
	          let actions = '';
	          if (r.id === 'multi_location') {{
	            actions = `<div style=\"margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;\">
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'all')\">Show tower points</button>
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')\">Hide points</button>
	            </div>`;
	          }} else if (r.id === 'multi_location_stationary') {{
	            actions = `<div style=\"margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;\">
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'stationary')\">Show stationary points</button>
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')\">Hide points</button>
	            </div>`;
	          }} else if (r.id === 'location_spread') {{
	            actions = `<div style=\"margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;\">
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'all')\">Show tower points</button>
	              <button class=\"btn\" type=\"button\" onclick=\"window.__SHOW_TOWER_POINTS(${{m.id}}, 'off')\">Hide points</button>
	            </div>`;
	          }}
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
	            ${{actions}}
	          </div>
	        </div>
	      `;
	    }}).join('');

    // Draw clusters/place-buckets overlay for this tower.
    try {{ setFocus(m); }} catch (e) {{}}

    body.innerHTML = summary + metrics + explainMore +
      `<div class=\"card\" style=\"margin-top:10px;\"><div class=\"k\">Bayesian score breakdown (XAI)</div><div style=\"margin-top:8px;\">${{bayesWaterfall(m)}}</div></div>` +
      `<div class=\"card\" style=\"margin-top:10px;\"><div class=\"k\">Rules breakdown (for transparency)</div>${{rulesHtml}}</div>`;
    modal.classList.add('open');
  }}

  document.getElementById('modal-close').addEventListener('click', () => document.getElementById('modal').classList.remove('open'));
  document.getElementById('modal').addEventListener('click', (ev) => {{ if (ev.target && ev.target.id === 'modal') ev.currentTarget.classList.remove('open'); }});

  for (const m of MARKERS) {{
    if (m.lat == null || m.lon == null) continue;
    const cls = scoreClass(m.bayes_post_p);
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
		    const driverText = bayesDriverSummary(m, 4, 2);
    const popup = `
      <div style="min-width:280px">
        <div class="badge ${{cls}}"><b>Bayes</b>: ${{fmtBayes(m.bayes_post_p)}} <span class="muted">(rules=${{(typeof m.anomaly_score==='number') ? m.anomaly_score.toFixed(1) : '—'}})</span></div>
        <div style="margin-top:6px"><b>${{esc(m.label)}}</b></div>
        <div class="muted" style="margin-top:6px">center from ${{m.n_used}} / ${{m.n_points}} GPS points</div>
        <div style="margin-top:6px" class="mono">lat=${{m.lat.toFixed(6)}} lon=${{m.lon.toFixed(6)}}</div>
        <div style="margin-top:6px">
          <div><b>Seen</b>: ${{m.count}} samples across ${{m.days_seen}} day(s)</div>
          <div><b>First</b>: ${{esc(m.first_seen)}}</div>
          <div><b>Last</b>: ${{esc(m.last_seen)}}</div>
          <div><b>Duration</b>: ${{m.duration_min ?? ''}} min</div>
          <div><b>Local window</b>: ${{m.local_window_min ?? ''}} min (frac=${{m.local_window_frac ?? ''}})</div>
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
	        <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
	          <button class="btn" onclick="window.__OPEN_EXPLAIN(${{m.id}})">Explain</button>
	          <button class="btn" onclick="window.__EXPORT_MD(${{m.id}})">Export MD</button>
	          <button class="btn" onclick="window.__EXPORT_DOCX(${{m.id}})">Export DOCX</button>
	        </div>
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
  window.__EXPORT_MD = (id) => {{
    const rec = byId.get(id);
    if (rec) exportTowerMd(rec.m);
  }};
  window.__EXPORT_DOCX = (id) => {{
    const rec = byId.get(id);
    if (rec) exportTowerDocx(rec.m);
  }};
  window.__SHOW_TOWER_POINTS = (id, which) => {{
    const rec = byId.get(id);
    if (rec) showPointsFor(rec.m, which);
  }};

  // Table
  const tbody = document.querySelector('#tbl tbody');
  let sortKey = 'bayes_post_p';
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
      const cls = scoreClass(r.bayes_post_p);
      const tr = document.createElement('tr');
		      const drivers = bayesDriverSummary(r, 4, 2);
		      const driversRules = allTriggeredDrivers(r);
	      tr.innerHTML = `
	        <td><span class="badge ${{cls}} mono" title="posterior=${{r.bayes_post_p ?? '—'}}">${{fmtBayes(r.bayes_post_p)}}</span></td>
	        <td><span class="badge mono" title="Legacy rule points (kept for transparency)">${{(typeof r.anomaly_score==='number') ? r.anomaly_score.toFixed(1) : '—'}}</span></td>
	        <td>${{esc(r.label)}}</td>
        <td class="mono">${{r.count}}</td>
        <td class="mono">${{r.days_seen}}</td>
        <td class="mono">${{r.duration_min ?? ''}}</td>
        <td class="mono">${{r.local_window_min ?? ''}}</td>
        <td class="mono">${{r.local_window_frac ?? ''}}</td>
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
			        <td class="mono" title="rules: ${{esc(driversRules)}}">${{esc(drivers)}}</td>
	        <td><button class="btn" type="button" data-act="explain">Explain</button></td>
	        <td>
	          <button class="btn" type="button" data-act="md">MD</button>
	          <button class="btn" type="button" data-act="docx">DOCX</button>
	        </td>
	        <td>${{(r.flags||[]).map(f=>`<span class="badge">${{esc(f)}}</span>`).join(' ')}}</td>
	      `;
	      tr.querySelector('button[data-act=\"explain\"]').addEventListener('click', (ev) => {{
	        ev.stopPropagation();
	        openExplain(r);
	      }});
	      tr.querySelector('button[data-act=\"md\"]').addEventListener('click', (ev) => {{
	        ev.stopPropagation();
	        exportTowerMd(r);
	      }});
	      tr.querySelector('button[data-act=\"docx\"]').addEventListener('click', (ev) => {{
	        ev.stopPropagation();
	        exportTowerDocx(r);
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
    ap = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("jsonl", help="Path to hack-wanderer JSONL")
    ap.add_argument("--out", default="towers-dashboard.html", help="Output HTML path")
    ap.add_argument("--min-count", type=int, default=1, help="Hide towers seen fewer than N times")
    ap.add_argument("--place-zoom", type=int, default=17, help="OSM tile zoom for place bucketing (higher => smaller buckets)")
    ap.add_argument("--max-lines", type=int, default=0, help="Read at most N lines from the JSONL (0 = no limit)")
    ap.add_argument("--tail-lines", type=int, default=0, help="Read at most N lines from the end of the JSONL (0 = disabled). Speeds up huge files.")
    ap.add_argument("--after", default="", help="Only include samples at/after this datetime (ISO8601, e.g. 2026-05-01T00:00:00Z or 2026-05-01)")
    ap.add_argument("--before", default="", help="Only include samples before this datetime (ISO8601, e.g. 2026-05-10T00:00:00Z or 2026-05-10)")
    ap.add_argument("--ml-mode", choices=["auto", "off", "approx", "full"], default="auto", help="ML-style rankers mode (kNN/LOF). 'auto' disables heavy modes for large tower counts.")
    ap.add_argument("--ml-ref-size", type=int, default=800, help="Reference subset size for --ml-mode approx (kNN)")
    ap.add_argument("--global-signal-sample-size", type=int, default=100000, help="Reservoir size for global signal distribution stats (memory bound).")
    ap.add_argument("--sample-size", type=int, default=400, help="Max per-tower reservoir samples kept for robust stats (memory bound).")
    ap.add_argument("--place-sample-size", type=int, default=400, help="Max per-place reservoir samples kept for distribution/change estimation (memory bound).")
    ap.add_argument("--place-bitmap-bits", type=int, default=2048, help="Bitmap size for approximate distinct-tower counts per place (memory bound).")
    ap.add_argument("--max-places", type=int, default=8000, help="Max number of distinct place buckets to track (0 = unlimited). Limits memory for very long logs.")
    ap.add_argument("--device-sample-size", type=int, default=5000, help="Reservoir size for device GPS points used only to center the map (0 = center on first tower marker).")
    ap.add_argument("--gps-max-speed-mps", type=float, default=60.0, help="Device GPS jump filter: if implied speed exceeds this, treat the fix as bad and exclude it from tower stats (still shown on map).")
    ap.add_argument("--bad-gps-sample-size", type=int, default=2000, help="Max number of bad GPS fixes to keep for display (memory bound).")
    ap.add_argument("--stationary-radius-m", type=float, default=25.0, help="Stationary detection: max distance from anchor (m) to consider device stationary.")
    ap.add_argument("--stationary-max-speed-mps", type=float, default=1.0, help="Stationary detection: max implied speed (m/s) to consider device stationary.")
    ap.add_argument("--stationary-min-dur-s", type=float, default=60.0, help="Stationary detection: minimum duration (s) before a stationary segment counts.")
    ap.add_argument("--stationary-signal-sample-size", type=int, default=400, help="Per-tower reservoir size for stationary-only signal stats (memory bound).")
    ap.add_argument("--stationary-pts-sample-size", type=int, default=400, help="Per-tower reservoir size for stationary-only GPS points (memory bound).")
    ap.add_argument("--stationary-jump-db", type=float, default=8.0, help="Stationary signal instability: count a jump when |signal_t - signal_{t-1}| >= this threshold.")
    ap.add_argument("--cluster-radius-m", type=float, default=400.0, help="Radius (m) for online multi-location clustering.")
    ap.add_argument("--max-clusters", type=int, default=30, help="Max number of online clusters stored per tower (memory bound).")
    ap.add_argument("--session-gap-s", type=float, default=6*3600.0, help="Gap (seconds) that starts a new session.")
    ap.add_argument("--bayes-prior", type=float, default=1e-4, help="Bayesian suspicion prior probability used for the Bayes score (lower => fewer false positives).")
    ap.add_argument("--embed-points-top", type=int, default=250, help="Embed per-tower sample GPS points into the HTML for the top N towers by Bayes score (0 = disable). Used by the Explain view 'Show points' buttons.")
    ap.add_argument("--embed-points-per-tower", type=int, default=350, help="Max number of per-tower GPS points embedded for visualization (cap per tower).")
    args = ap.parse_args()

    if not os.path.exists(args.jsonl):
        raise SystemExit(f"No such file: {args.jsonl}")

    aggs: Dict[TowerKey, TowerAgg] = {}
    places: Dict[str, PlaceAgg] = {}
    base_aggs: Dict[BaseKey, BaseAgg] = {}
    # Memory-bounded reservoir of device locations to center the map.
    device_pts: List[Tuple[float, float]] = []
    device_pts_seen = 0
    device_pts_cap = max(0, int(args.device_sample_size))
    # Memory-bounded reservoir of bad GPS fixes (jump filter) to visualize but exclude.
    bad_gps: List[Dict[str, Any]] = []
    bad_gps_seen = 0
    bad_gps_cap = max(0, int(args.bad_gps_sample_size))
    last_fix: Optional[Tuple[float, float, float]] = None  # lat, lon, ts

    # Stationary segment tracker (simple, streaming)
    stat_anchor: Optional[Tuple[float, float]] = None
    stat_start_ts: Optional[float] = None
    stat_last_ts: Optional[float] = None
    stat_seg_id: int = 0

    rng = random.Random(1)
    max_lines = args.max_lines if args.max_lines and args.max_lines > 0 else None
    tail_lines = int(args.tail_lines) if args.tail_lines and int(args.tail_lines) > 0 else None
    after_dt = parse_time_arg(args.after)
    before_dt = parse_time_arg(args.before)
    after_ts = to_epoch_seconds(after_dt) if after_dt else None
    before_ts = to_epoch_seconds(before_dt) if before_dt else None
    src_iter: Iterable[Dict[str, Any]]
    if tail_lines is not None:
        src_iter = iter_jsonl_tail(args.jsonl, tail_lines)
    else:
        src_iter = iter_jsonl(args.jsonl, max_lines=max_lines)

    for obj in src_iter:
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
        # GPS jump filter: exclude fixes that imply impossible speeds (common when GPS has poor lock).
        bad_fix = False
        speed_mps = None
        prev_fix = last_fix
        if last_fix is not None:
            speed_mps = implied_speed_mps(last_fix[0], last_fix[1], last_fix[2], lat, lon, when_ts)
            if isinstance(speed_mps, (int, float)) and speed_mps > float(args.gps_max_speed_mps):
                bad_fix = True

        if bad_fix:
            bad_gps_seen += 1
            if bad_gps_cap > 0:
                rec = {
                    "ts": epoch_to_iso(when_ts),
                    "lat": lat,
                    "lon": lon,
                    "speed_mps": round(float(speed_mps or 0.0), 2) if speed_mps is not None else None,
                }
                if len(bad_gps) < bad_gps_cap:
                    bad_gps.append(rec)
                else:
                    j = rng.randrange(bad_gps_seen)
                    if j < bad_gps_cap:
                        bad_gps[j] = rec
            continue

        # Stationary detection update (based on anchor proximity + speed).
        if stat_anchor is None or stat_start_ts is None or stat_last_ts is None:
            stat_anchor = (lat, lon)
            stat_start_ts = when_ts
            stat_last_ts = when_ts
        else:
            d_anchor = haversine_m(stat_anchor[0], stat_anchor[1], lat, lon)
            v = speed_mps if isinstance(speed_mps, (int, float)) else None
            if d_anchor <= float(args.stationary_radius_m) and (v is None or v <= float(args.stationary_max_speed_mps)):
                stat_last_ts = when_ts
            else:
                stat_anchor = (lat, lon)
                stat_start_ts = when_ts
                stat_last_ts = when_ts
                stat_seg_id += 1

        stationary = False
        if stat_start_ts is not None and stat_last_ts is not None:
            stationary = (stat_last_ts - stat_start_ts) >= float(args.stationary_min_dur_s)

        last_fix = (lat, lon, when_ts)

        if device_pts_cap > 0:
            device_pts_seen += 1
            if len(device_pts) < device_pts_cap:
                device_pts.append((lat, lon))
            else:
                j = rng.randrange(device_pts_seen)
                if j < device_pts_cap:
                    device_pts[j] = (lat, lon)

        x, y = latlon_to_tile(lat, lon, args.place_zoom)
        place_id = f"{args.place_zoom}/{x}/{y}"
        if args.max_places and args.max_places > 0 and place_id not in places and len(places) >= int(args.max_places):
            place_id = None

        for cell in iter_observed_cells(obj):
            operator = extract_operator(obj, cell)
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
                max_clusters=max(0, int(args.max_clusters)),
                session_gap_s=float(args.session_gap_s),
                rng=rng,
            )
            if stationary:
                aggs[key].add_stationary(
                    when_ts,
                    lat,
                    lon,
                    sig,
                    segment_id=stat_seg_id,
                    signal_sample_size=max(0, int(args.stationary_signal_sample_size)),
                    pts_sample_size=max(0, int(args.stationary_pts_sample_size)),
                    rng=rng,
                    jump_db=float(args.stationary_jump_db),
                )

                bkey = base_key_from_cell(operator, cell)
                bagg = base_aggs.get(bkey)
                if bagg is None:
                    bagg = BaseAgg(key=bkey)
                    base_aggs[bkey] = bagg
                bagg.add_stationary(pci=key.pci, earfcn=key.earfcn, segment_id=stat_seg_id)

            if place_id is not None:
                p = places.get(place_id)
                if p is None:
                    p = PlaceAgg(
                        place_id=place_id,
                        signal_sample_size=max(0, int(args.place_sample_size)),
                        distinct_bitmap_bits=max(256, int(args.place_bitmap_bits)),
                    )
                    places[place_id] = p
                p.add(when_ts, key, sig, stationary=stationary)

    if not aggs:
        raise SystemExit("No tower observations found (need location + towers/registration in JSONL).")

    # Compute robust centers
    agg_list = list(aggs.values())
    for a in agg_list:
        lat, lon, meta = robust_center([(lat, lon, sig) for (lat, lon, sig, _ts) in a.sample])
        a.center_lat = lat
        a.center_lon = lon
        a.center_meta = meta

    global_stats = compute_global_stats(agg_list, global_signal_sample_size=int(args.global_signal_sample_size))
    global_stats["cluster_radius_m"] = float(args.cluster_radius_m)
    for a in agg_list:
        feats, score = compute_features(a, global_stats)
        a.features = feats
        a.anomaly_score = score

        # Parameter churn while stationary (PCI/EARFCN variability for same (operator,RAT,TAC,CellID)).
        bkey = BaseKey(operator=a.key.operator, rat=a.key.rat, tac_lac=a.key.tac_lac, cell_id=a.key.cell_id)
        bagg = base_aggs.get(bkey)
        if bagg is not None and bagg.stationary_obs > 0:
            a.features["stationary_param_obs"] = int(bagg.stationary_obs)
            a.features["stationary_pci_distinct"] = len(bagg.distinct_pci)
            a.features["stationary_earfcn_distinct"] = len(bagg.distinct_earfcn)
            a.features["stationary_pci_change_rate"] = bagg.pci_changes / max(1, bagg.stationary_obs)
            a.features["stationary_earfcn_change_rate"] = bagg.earfcn_changes / max(1, bagg.stationary_obs)
        else:
            a.features["stationary_param_obs"] = None
            a.features["stationary_pci_distinct"] = None
            a.features["stationary_earfcn_distinct"] = None
            a.features["stationary_pci_change_rate"] = None
            a.features["stationary_earfcn_change_rate"] = None
    # Place-level distribution & change metrics
    place_metrics: Dict[str, Dict[str, Any]] = {}
    for pid, p in places.items():
        st = sorted(p.signal_sample, key=lambda x: x[0])
        series = [v for _, v in st]
        st_s = sorted(p.signal_sample_stationary, key=lambda x: x[0])
        series_s = [v for _, v in st_s]
        km = {}
        if len(series) >= 60:
            split = int(len(series) * 0.7)
            early = series[:split]
            late = series[split:]
            km["ks_d"] = ks_2samp(early, late)
            km["mw_u_norm"] = mann_whitney_u(early, late)
            km["cusum"] = cusum_change_score(series, drift=0.05)
            if len(series_s) >= 60:
                split = int(len(series_s) * 0.7)
                early = series_s[:split]
                late = series_s[split:]
                km["ks_d_stationary"] = ks_2samp(early, late)
                km["cusum_stationary"] = cusum_change_score(series_s, drift=0.05)
            km["count"] = p.count
            km["first_ts"] = p.first_seen_ts
            km["last_ts"] = p.last_seen_ts
            if isinstance(p.first_seen_ts, (int, float)) and isinstance(p.last_seen_ts, (int, float)) and p.last_seen_ts >= p.first_seen_ts:
                km["duration_s"] = float(p.last_seen_ts - p.first_seen_ts)
            else:
                km["duration_s"] = None
            km["stationary_count"] = int(p.stationary_count)
            km["first_stationary_ts"] = p.first_stationary_ts
            km["last_stationary_ts"] = p.last_stationary_ts
            if isinstance(p.first_stationary_ts, (int, float)) and isinstance(p.last_stationary_ts, (int, float)) and p.last_stationary_ts >= p.first_stationary_ts:
                km["stationary_duration_s"] = float(p.last_stationary_ts - p.first_stationary_ts)
            else:
                km["stationary_duration_s"] = None
            km["distinct_towers"] = p.distinct_towers_est()
            km["rat_surprise"] = p.rat_surprise()
            place_metrics[pid] = km
    # Add place-aware features to each tower
    for a in agg_list:
        dense_novel = 0
        change_weight = 0
        change_weight_stationary = 0
        stationary_bucket_weight = 0
        surprise_weighted = 0.0
        surprise_w = 0
        total = a.count or 1

        local_first = None
        local_last = None
        local_stat_first = None
        local_stat_last = None
        place_details = []

        for pid, c in a.places.items():
            pm = place_metrics.get(pid) or {}

            ft = pm.get('first_ts')
            lt = pm.get('last_ts')
            if isinstance(ft, (int, float)):
                if local_first is None or float(ft) < local_first:
                    local_first = float(ft)
            if isinstance(lt, (int, float)):
                if local_last is None or float(lt) > local_last:
                    local_last = float(lt)

            ft_s = pm.get('first_stationary_ts')
            lt_s = pm.get('last_stationary_ts')
            if isinstance(ft_s, (int, float)):
                if local_stat_first is None or float(ft_s) < local_stat_first:
                    local_stat_first = float(ft_s)
            if isinstance(lt_s, (int, float)):
                if local_stat_last is None or float(lt_s) > local_stat_last:
                    local_stat_last = float(lt_s)

            if pm.get('count', 0) >= 500 and c <= 2:
                dense_novel += 1

            ks = pm.get('ks_d')
            cus = pm.get('cusum')
            changed = (isinstance(ks, (int, float)) and ks >= 0.25) or (isinstance(cus, (int, float)) and cus >= 8.0)
            if changed:
                change_weight += c

            ks_s = pm.get('ks_d_stationary')
            cus_s = pm.get('cusum_stationary')
            changed_s = None
            if isinstance(ks_s, (int, float)) or isinstance(cus_s, (int, float)):
                changed_s = (isinstance(ks_s, (int, float)) and ks_s >= 0.25) or (isinstance(cus_s, (int, float)) and cus_s >= 8.0)
                stationary_bucket_weight += c
                if changed_s:
                    change_weight_stationary += c

            rs = pm.get('rat_surprise')
            if isinstance(rs, (int, float)):
                surprise_weighted += rs * c
                surprise_w += c

            place_details.append({
                'place_id': pid,
                'tower_count': int(c),
                'place_total': int(pm.get('count') or 0),
                'place_duration_min': round(float(pm.get('duration_s') or 0.0) / 60.0, 1) if isinstance(pm.get('duration_s'), (int, float)) else None,
                'place_stationary_total': int(pm.get('stationary_count') or 0),
                'place_stationary_dur_min': round(float(pm.get('stationary_duration_s') or 0.0) / 60.0, 1) if isinstance(pm.get('stationary_duration_s'), (int, float)) else None,
                'ks_d': round(float(ks), 3) if isinstance(ks, (int, float)) else None,
                'cusum': round(float(cus), 3) if isinstance(cus, (int, float)) else None,
                'ks_d_stationary': round(float(ks_s), 3) if isinstance(ks_s, (int, float)) else None,
                'cusum_stationary': round(float(cus_s), 3) if isinstance(cus_s, (int, float)) else None,
                'rat_surprise': round(float(rs), 3) if isinstance(rs, (int, float)) else None,
                'changed': bool(changed),
                'changed_stationary': (bool(changed_s) if isinstance(changed_s, bool) else None),
            })

        a.features['dense_place_novelty'] = dense_novel
        a.features['change_places_frac'] = change_weight / max(1, total)
        a.features['change_places_frac_stationary'] = (change_weight_stationary / stationary_bucket_weight) if stationary_bucket_weight > 0 else None
        a.features['place_rat_surprise'] = (surprise_weighted / surprise_w) if surprise_w else None

        if local_first is not None and local_last is not None and local_last >= local_first:
            local_window_s = float(local_last - local_first)
            a.features['local_window_s'] = local_window_s
            a.features['local_window_min'] = round(local_window_s / 60.0, 1)
            dur_s = a.features.get('duration_s')
            a.features['local_window_frac'] = (float(dur_s) / local_window_s) if isinstance(dur_s, (int, float)) and local_window_s > 0 else None
        else:
            a.features['local_window_s'] = None
            a.features['local_window_min'] = None
            a.features['local_window_frac'] = None

        if local_stat_first is not None and local_stat_last is not None and local_stat_last >= local_stat_first:
            local_stat_window_s = float(local_stat_last - local_stat_first)
            a.features['local_stationary_window_s'] = local_stat_window_s
            a.features['local_stationary_window_min'] = round(local_stat_window_s / 60.0, 1)
            stat_span_s = a.features.get('stationary_span_s')
            a.features['local_stationary_window_frac'] = (float(stat_span_s) / local_stat_window_s) if isinstance(stat_span_s, (int, float)) and local_stat_window_s > 0 else None
        else:
            a.features['local_stationary_window_s'] = None
            a.features['local_stationary_window_min'] = None
            a.features['local_stationary_window_frac'] = None

        place_details.sort(key=lambda d: (-int(d.get('tower_count') or 0), -int(d.get('place_total') or 0), str(d.get('place_id') or '')))
        top_places = place_details[:12]
        for d in top_places:
            pid = str(d.get('place_id') or '')
            try:
                z_str, x_str, y_str = pid.split('/', 2)
                z = int(z_str)
                x = int(x_str)
                y = int(y_str)
                s, w, n, e = tile_bounds_latlon(z, x, y)
                d['bbox'] = {'south': s, 'west': w, 'north': n, 'east': e}
                d['tile'] = {'z': z, 'x': x, 'y': y}
            except Exception:
                d['bbox'] = None
                d['tile'] = None
        a.features['place_details'] = top_places

        breakdown = a.features.get('score_breakdown') or []

        stat_span_s = a.features.get('stationary_span_s')
        lsw_s = a.features.get('local_stationary_window_s')
        lsw_frac = a.features.get('local_stationary_window_frac')
        if (
            a.count >= 5
            and a.stationary_count >= 5
            and isinstance(stat_span_s, (int, float))
            and float(stat_span_s) >= 120.0
            and isinstance(lsw_s, (int, float))
            and lsw_s >= max(10 * 60, 3.0 * float(stat_span_s))
            and isinstance(lsw_frac, (int, float))
            and lsw_frac <= 0.25
        ):
            a.anomaly_score += 3.0
            a.features['anomaly_ephemeral'] = True
            breakdown.append({
                'rule': 'ephemeral',
                'points': 3.0,
                'because': f"count={a.count} stationary_span_min={round(float(stat_span_s)/60.0,1)} local_stationary_window_min={a.features.get('local_stationary_window_min')} stationary_frac={round(float(lsw_frac),4)} stationary_count={a.stationary_count}",
            })

        if a.features.get('anomaly_ephemeral') and a.stationary_count >= 15 and isinstance(lsw_frac, (int, float)) and lsw_frac <= 0.15:
            a.anomaly_score += 1.0
            a.features['anomaly_ephemeral_despite_stationary'] = True
            breakdown.append({
                'rule': 'ephemeral_despite_stationary',
                'points': 1.0,
                'because': f"stationary_count={a.stationary_count} local_stationary_window_frac={round(float(lsw_frac),4)} (≤0.15)",
            })

        if isinstance(dense_novel, int) and dense_novel >= 2 and a.count >= 10:
            a.anomaly_score += 1.5
            a.features['anomaly_novel_in_dense_places'] = True
            breakdown.append({'rule': 'novel_in_dense_places', 'points': 1.5, 'because': f"dense_place_novelty={dense_novel} count={a.count}"})

        cpf_s = a.features.get('change_places_frac_stationary')
        cpf = cpf_s if isinstance(cpf_s, (int, float)) else a.features.get('change_places_frac')
        if isinstance(cpf, (int, float)) and cpf >= 0.5 and a.count >= 20:
            a.anomaly_score += 1.0
            a.features['anomaly_correlates_with_place_change'] = True
            breakdown.append({'rule': 'place_change_correlation', 'points': 1.0, 'because': f"change_places_frac={'stationary' if isinstance(cpf_s,(int,float)) else 'all'}={round(cpf,3)}"})

        prs = a.features.get('place_rat_surprise')
        if isinstance(prs, (int, float)) and prs >= 1.2 and a.count >= 30:
            a.anomaly_score += 1.0
            a.features['anomaly_rat_transition_surprise'] = True
            breakdown.append({'rule': 'rat_transition_surprise', 'points': 1.0, 'because': f"avg_neglogp={round(prs,3)}"})

        a.features['score_breakdown'] = breakdown

    churn_stats = apply_stationary_param_churn(agg_list)
    global_stats.update(churn_stats)

    # Pure-Python ML-ish rankers over tower feature vectors (kNN + LOF).
    # WARNING: full LOF is O(n^2) memory/time and can be killed by the OS for large n.
    #
    # IMPORTANT: build the ML feature matrix only when ML is enabled; otherwise keep memory bounded.
    n_towers = len(agg_list)
    ml_mode = args.ml_mode
    if ml_mode == "auto":
        # Safe defaults: for large N, avoid O(n^2) LOF and even the O(n) matrix build.
        ml_mode = "full" if n_towers <= 1200 else ("approx" if n_towers <= 6000 else "off")

    if ml_mode == "off":
        knn_scores = {a.key: 0.0 for a in agg_list}
        lof_scores = {a.key: 1.0 for a in agg_list}
    else:
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

        if ml_mode == "approx":
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

    # Bayesian (log-odds) suspicion score. This is designed to reduce false positives by:
    # - starting from a low prior
    # - using bounded contributions
    # - allowing strong negative evidence (stability) to reduce suspicion
    for a in agg_list:
        a.features["ml_mode"] = ml_mode
    bayes_meta = apply_bayes_scores(agg_list, global_stats, bayes_prior=float(args.bayes_prior))

    # Build markers
    markers: List[Dict[str, Any]] = []
    for i, a in enumerate(sorted(agg_list, key=lambda x: (-(x.features.get("bayes_post_p") or 0.0), -x.anomaly_score, -x.count, x.key.label()))):
        if a.count < args.min_count:
            continue
        if a.center_lat is None or a.center_lon is None:
            continue

        flags = []
        for k in (
            'anomaly_ephemeral',
            'anomaly_ephemeral_despite_stationary',
            'anomaly_strong_signal',
            'anomaly_location_spread',
            'anomaly_multi_location',
            'anomaly_multi_location_stationary',
            'anomaly_moving_or_reused_id',
            'anomaly_non_lte',
            'anomaly_reappears',
            'anomaly_long_absence',
            'anomaly_signal_distance_mismatch',
            'anomaly_stationary_signal_instability',
            'anomaly_stationary_signal_jumps',
            'anomaly_stationary_pci_churn',
            'anomaly_stationary_earfcn_churn',
            'anomaly_novel_in_dense_places',
            'anomaly_correlates_with_place_change',
            'anomaly_rat_transition_surprise',
            'anomaly_wide_area',
            'anomaly_ml_knn',
            'anomaly_ml_lof',
        ):
            if a.features.get(k):
                flags.append(k.replace('anomaly_', ''))
        if a.features.get('anomaly_rare') and flags:
            flags.append('rare')

        search = ' '.join([
            a.key.operator,
            a.key.rat,
            str(a.key.tac_lac or ''),
            str(a.key.cell_id or ''),
            str(a.key.earfcn or ''),
            str(a.key.pci or ''),
        ]).strip().lower()

        embed_pts = int(args.embed_points_top) > 0 and len(markers) < int(args.embed_points_top)
        per_tower_cap = max(0, int(args.embed_points_per_tower))
        points_all = []
        points_stationary = []
        if embed_pts and per_tower_cap > 0:
            # Use the per-tower reservoir samples (bounded by --sample-size / --stationary-pts-sample-size).
            for (plat, plon, psig, pts) in a.sample[:per_tower_cap]:
                points_all.append({
                    "lat": round(float(plat), 7),
                    "lon": round(float(plon), 7),
                    "ts": epoch_to_iso(float(pts)) if isinstance(pts, (int, float)) else None,
                    "sig": float(psig) if isinstance(psig, (int, float)) else None,
                })
            for (plat, plon) in a.stationary_pts[:per_tower_cap]:
                points_stationary.append({
                    "lat": round(float(plat), 7),
                    "lon": round(float(plon), 7),
                })

        markers.append({
            'id': i,
            'label': a.key.label(),
            'operator': a.key.operator,
            'rat': a.key.rat,
            'tac_lac': a.key.tac_lac,
            'cell_id': a.key.cell_id,
            'earfcn': a.key.earfcn,
            'pci': a.key.pci,
            'lat': a.center_lat,
            'lon': a.center_lon,
            'count': a.count,
            'first_seen': epoch_to_iso(a.first_seen_ts),
            'last_seen': epoch_to_iso(a.last_seen_ts),
            'days_seen': a.features.get('days_seen'),
            'duration_min': round((a.features.get('duration_s') or 0.0) / 60.0, 1) if a.features.get('duration_s') is not None else None,
            'sessions': a.features.get('sessions'),
            'max_gap_days': round((a.features.get('max_gap_s') or 0.0) / (24.0 * 3600.0), 2) if a.features.get('max_gap_s') is not None else None,
            'signal_median': a.features.get('signal_median'),
            'signal_robust_z': round(a.features.get('signal_robust_z'), 2) if isinstance(a.features.get('signal_robust_z'), (int, float)) else None,
            'gps_spread_m': a.features.get('gps_spread_m'),
            'clusters': a.features.get('clusters'),
            'cluster_top2_sep_m': round(a.features.get('cluster_top2_sep_m'), 1) if isinstance(a.features.get('cluster_top2_sep_m'), (int, float)) else None,
            'clusters_detail': a.features.get('clusters_detail') or [],
            'stationary_count': a.features.get('stationary_count'),
            'stationary_span_min': round(float(a.features.get('stationary_span_s') or 0.0) / 60.0, 1) if isinstance(a.features.get('stationary_span_s'), (int, float)) else None,
            'stationary_signal_mad': round(a.features.get('stationary_signal_mad'), 3) if isinstance(a.features.get('stationary_signal_mad'), (int, float)) else None,
            'stationary_signal_mad_z': round(a.features.get('stationary_signal_mad_z'), 2) if isinstance(a.features.get('stationary_signal_mad_z'), (int, float)) else None,
            'stationary_jump_rate_8db': round(a.features.get('stationary_jump_rate_8db'), 4) if isinstance(a.features.get('stationary_jump_rate_8db'), (int, float)) else None,
            'stationary_jump_rate_z': round(a.features.get('stationary_jump_rate_z'), 2) if isinstance(a.features.get('stationary_jump_rate_z'), (int, float)) else None,
            'stationary_clusters': a.features.get('stationary_clusters'),
            'stationary_cluster_top2_sep_m': round(a.features.get('stationary_cluster_top2_sep_m'), 1) if isinstance(a.features.get('stationary_cluster_top2_sep_m'), (int, float)) else None,
            'stationary_clusters_detail': a.features.get('stationary_clusters_detail') or [],
            'stability_bonus': a.features.get('stability_bonus'),
            'center_drift_m': round(((a.features.get('center_drift') or {}).get('max_drift_m') or 0.0), 1) if isinstance(((a.features.get('center_drift') or {}).get('max_drift_m')), (int, float)) else None,
            'dist_outlier_frac': round((((a.features.get('signal_dist_model') or {}).get('outlier_frac')) or 0.0), 3) if isinstance(((a.features.get('signal_dist_model') or {}).get('outlier_frac')), (int, float)) else None,
            'anomaly_score': a.anomaly_score,
            'score_breakdown': a.features.get('score_breakdown') or [],
            'bayes_prior_p': a.features.get('bayes_prior_p'),
            'bayes_prior_logit': a.features.get('bayes_prior_logit'),
            'bayes_post_p': a.features.get('bayes_post_p'),
            'bayes_post_logit': a.features.get('bayes_post_logit'),
            'bayes_logodds_delta': a.features.get('bayes_logodds_delta'),
            'bayes_terms': a.features.get('bayes_terms') or [],
            'points_all': points_all,
            'points_stationary': points_stationary,
            'flags': flags,
            'local_window_min': a.features.get('local_window_min'),
            'local_window_frac': round(a.features.get('local_window_frac'), 4) if isinstance(a.features.get('local_window_frac'), (int, float)) else None,
            'local_stationary_window_min': a.features.get('local_stationary_window_min'),
            'local_stationary_window_frac': round(a.features.get('local_stationary_window_frac'), 4) if isinstance(a.features.get('local_stationary_window_frac'), (int, float)) else None,
            'place_details': a.features.get('place_details') or [],
            'dense_place_novelty': a.features.get('dense_place_novelty'),
            'change_places_frac': round(a.features.get('change_places_frac'), 3) if isinstance(a.features.get('change_places_frac'), (int, float)) else None,
            'change_places_frac_stationary': round(a.features.get('change_places_frac_stationary'), 3) if isinstance(a.features.get('change_places_frac_stationary'), (int, float)) else None,
            'place_rat_surprise': round(a.features.get('place_rat_surprise'), 3) if isinstance(a.features.get('place_rat_surprise'), (int, float)) else None,
            'place_entropy': round(a.features.get('place_entropy'), 3) if isinstance(a.features.get('place_entropy'), (int, float)) else None,
            'places_n': a.features.get('places_n'),
            'stationary_param_obs': a.features.get('stationary_param_obs'),
            'stationary_pci_distinct': a.features.get('stationary_pci_distinct'),
            'stationary_earfcn_distinct': a.features.get('stationary_earfcn_distinct'),
            'stationary_pci_change_rate': round(a.features.get('stationary_pci_change_rate'), 5) if isinstance(a.features.get('stationary_pci_change_rate'), (int, float)) else None,
            'stationary_earfcn_change_rate': round(a.features.get('stationary_earfcn_change_rate'), 5) if isinstance(a.features.get('stationary_earfcn_change_rate'), (int, float)) else None,
            'stationary_pci_change_rate_z': round(a.features.get('stationary_pci_change_rate_z'), 2) if isinstance(a.features.get('stationary_pci_change_rate_z'), (int, float)) else None,
            'stationary_earfcn_change_rate_z': round(a.features.get('stationary_earfcn_change_rate_z'), 2) if isinstance(a.features.get('stationary_earfcn_change_rate_z'), (int, float)) else None,
            'stationary_pci_distinct_z': round(a.features.get('stationary_pci_distinct_z'), 2) if isinstance(a.features.get('stationary_pci_distinct_z'), (int, float)) else None,
            'stationary_earfcn_distinct_z': round(a.features.get('stationary_earfcn_distinct_z'), 2) if isinstance(a.features.get('stationary_earfcn_distinct_z'), (int, float)) else None,
            'ml_knn_score': round(a.features.get('ml_knn_score'), 4) if isinstance(a.features.get('ml_knn_score'), (int, float)) else None,
            'ml_lof_score': round(a.features.get('ml_lof_score'), 4) if isinstance(a.features.get('ml_lof_score'), (int, float)) else None,
            'ml_knn_z': round(a.features.get('ml_knn_z'), 2) if isinstance(a.features.get('ml_knn_z'), (int, float)) else None,
            'ml_lof_z': round(a.features.get('ml_lof_z'), 2) if isinstance(a.features.get('ml_lof_z'), (int, float)) else None,
            'ml_mode': ml_mode,
            'dataset_mostly_lte': bool(global_stats.get('mostly_lte')),
            'n_points': a.center_meta.get('n'),
            'n_used': a.center_meta.get('n_used'),
            'search': search,
        })

    # Center map
    if device_pts:
        c_lat = median([p[0] for p in device_pts]) or markers[0]["lat"]
        c_lon = median([p[1] for p in device_pts]) or markers[0]["lon"]
    else:
        c_lat = markers[0]["lat"]
        c_lon = markers[0]["lon"]

    bad_stats = {
        "excluded_total": int(bad_gps_seen),
        "shown": int(len(bad_gps)),
        "gps_max_speed_mps": float(args.gps_max_speed_mps),
    }

    build_dashboard(markers, (c_lat, c_lon), args.out, bad_gps_points=bad_gps, bad_gps_stats=bad_stats, bayes_meta=bayes_meta)
    print(f"Wrote {args.out} (towers: {len(markers)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
