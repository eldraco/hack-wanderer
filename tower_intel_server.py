#!/usr/bin/env python3
"""Persistent local tower intelligence dashboard.

This is the live SQLite/FastAPI successor to the static one-shot
`tower_anomaly_dashboard.py` workflow.  It stores raw observations durably,
recomputes derived evidence with editable method settings, and serves a local
Leaflet dashboard for exploration.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import hashlib
import html
import io
import json
import math
import os
import random
import re
import sqlite3
import statistics
import sys
import threading
import time
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from starlette.requests import Request as StarletteRequest
except Exception:  # Keep CLI usable without FastAPI/Starlette installed.
    class StarletteRequest:  # type: ignore[no-redef]
        pass

from tower_anomaly_dashboard import (
    BaseAgg,
    BaseKey,
    PlaceAgg,
    TowerAgg,
    TowerKey,
    apply_stationary_param_churn,
    cluster_centers_simple,
    compute_features,
    compute_global_stats,
    cusum_change_score,
    extract_operator,
    haversine_m,
    implied_speed_mps,
    iter_observed_cells,
    ks_2samp,
    latlon_to_tile,
    logistic,
    logit,
    mad,
    median,
    observation_signal,
    parse_time,
    pick_location,
    robust_center,
    safe_int,
    tile_bounds_latlon,
    to_epoch_seconds,
    tower_key_from_cell,
    base_key_from_cell,
)


DEFAULT_DB = "tower_intel.sqlite"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8890
PLACE_ZOOM = 17
BAD_GPS_SPEED_MPS = 60.0
STATIONARY_RADIUS_M = 25.0
STATIONARY_MAX_SPEED_MPS = 1.0
STATIONARY_MAX_REPORTED_SPEED_MPS = 1.2
STATIONARY_MIN_DUR_S = 60.0
ALTITUDE_BASELINE_QUANTILE = 0.25
ALTITUDE_NOISE_BUFFER_M = 6.0
ALTITUDE_HIGH_POINT_M = 10.0
ALTITUDE_DISCOUNT_SCALE_M = 18.0
ALTITUDE_MIN_CONFIDENCE = 0.35

GLOBAL_CONFIG_DEFAULTS: Dict[str, Any] = {
    "altitude_floor_iqr_k": 1.5,
    "altitude_no_discount_until_m": 2.0,
    "altitude_half_value_height_m": 8.0,
    "altitude_high_point_m": 10.0,
    "altitude_min_confidence": 0.20,
}

GLOBAL_CONFIG_HELP: Dict[str, str] = {
    "altitude_floor_iqr_k": "Robust-ground estimator: when computing a local ground/floor baseline inside each place bucket, low altitude values below Q1 - k*IQR are treated as outliers and ignored. Then the baseline is the minimum remaining altitude.",
    "altitude_no_discount_until_m": "Relative altitude above the local ground baseline that receives no penalty. Ground-level points should stay near full value; small GPS altitude noise should not matter.",
    "altitude_half_value_height_m": "Extra relative altitude needed to halve geo-based evidence after the no-discount buffer. With the default settings, about 10 m above local ground gives roughly half evidence.",
    "altitude_high_point_m": "Threshold used for summary features such as high_altitude_obs_frac. Points above this relative height are counted as clearly elevated.",
    "altitude_min_confidence": "Lower clamp for the altitude multiplier. Even at high altitude we soften evidence instead of dropping it to zero.",
}

ANALYSIS_STATUS_VALUES = ("", "under analysis", "analyzed", "benign", "suspicious", "CSS")
WIGLE_CELL_SEARCH_URL = "https://api.wigle.net/api/v2/cell/search"
WIGLE_OPERATOR_ALIASES = {
    "tesco mobile": "23002",
    "o2 czech": "23002",
}

# SQLite allows only one writer. Imports and recompute are write-heavy, so we
# serialize them at the app layer to avoid "database is locked" crashes.
WRITE_TASK_LOCK = threading.Lock()
IMPORT_STATUS_LOCK = threading.Lock()
IMPORT_STATUS: Dict[str, Any] = {
    "active": False,
    "phase": "idle",
    "message": "Ready to import JSONL files.",
    "started_at": None,
    "updated_at": utc_now() if "utc_now" in globals() else None,  # placeholder overwritten after function definition
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


IMPORT_STATUS["updated_at"] = utc_now()


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_loads(text: Optional[str], default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def load_local_env(path: Optional[Path] = None) -> None:
    env_path = path or (Path(__file__).resolve().parent / ".env")
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


def infer_wigle_cell_op(operator: Any) -> Optional[str]:
    text = str(operator or "").strip()
    numeric = re.search(r"(?<!\d)(\d{5,6})(?!\d)", text)
    if numeric:
        return numeric.group(1)
    lowered = text.lower()
    for alias, cell_op in WIGLE_OPERATOR_ALIASES.items():
        if alias in lowered:
            return cell_op
    return None


def get_wigle_enrichment(con: sqlite3.Connection, tower_id: int) -> Optional[Dict[str, Any]]:
    row = con.execute(
        "SELECT checked_at,result_json FROM wigle_enrichments WHERE tower_id=?",
        (int(tower_id),),
    ).fetchone()
    if not row:
        return None
    result = json_loads(row["result_json"], {})
    if not isinstance(result, dict):
        return None
    result["checked_at"] = row["checked_at"]
    result["cached"] = True
    return result


def apply_wigle_features(features: Dict[str, Any], enrichment: Optional[Dict[str, Any]]) -> None:
    features["wigle_checked"] = bool(enrichment)
    features["wigle_exists"] = bool(enrichment and enrichment.get("exists"))
    features["wigle_match_count"] = int(enrichment.get("match_count") or 0) if enrichment else 0
    features["wigle_first_seen"] = None
    features["wigle_last_seen"] = None
    features["wigle_first_seen_age_days"] = None
    features["wigle_last_seen_age_days"] = None
    if not enrichment or not enrichment.get("exists"):
        return
    checked = parse_time(str(enrichment.get("checked_at") or ""))
    checked_ts = to_epoch_seconds(checked) if checked else None
    first_values: List[Tuple[float, str]] = []
    last_values: List[Tuple[float, str]] = []
    for result in enrichment.get("results") or []:
        if not isinstance(result, dict):
            continue
        first_text = str(result.get("firsttime") or "")
        first = parse_time(first_text) if first_text else None
        first_ts = to_epoch_seconds(first) if first else None
        if isinstance(first_ts, (int, float)):
            first_values.append((float(first_ts), first_text))
        last_text = str(result.get("lasttime") or result.get("lastupdt") or "")
        last = parse_time(last_text) if last_text else None
        last_ts = to_epoch_seconds(last) if last else None
        if isinstance(last_ts, (int, float)):
            last_values.append((float(last_ts), last_text))
    if first_values:
        first_ts, first_text = min(first_values)
        features["wigle_first_seen"] = first_text
        if isinstance(checked_ts, (int, float)):
            features["wigle_first_seen_age_days"] = max(0.0, (float(checked_ts) - first_ts) / 86400.0)
    if last_values:
        last_ts, last_text = max(last_values)
        features["wigle_last_seen"] = last_text
        if isinstance(checked_ts, (int, float)):
            features["wigle_last_seen_age_days"] = max(0.0, (float(checked_ts) - last_ts) / 86400.0)


def wigle_enrich_tower(db_path: str, tower_id: int, *, refresh: bool = False) -> Dict[str, Any]:
    load_local_env()
    with connect_db(db_path) as con:
        if not refresh:
            cached = get_wigle_enrichment(con, tower_id)
            if cached is not None:
                return cached
        tower = con.execute(
            "SELECT id,operator,rat,tac_lac,cell_id,pci,earfcn FROM towers WHERE id=?",
            (int(tower_id),),
        ).fetchone()
    if not tower:
        raise KeyError("tower not found")
    if tower["tac_lac"] is None or tower["cell_id"] is None:
        raise ValueError("WiGLE enrichment requires TAC/LAC and Cell ID.")
    api_name = os.environ.get("WIGLE_API_NAME") or os.environ.get("WIGLE_NAME")
    api_token = os.environ.get("WIGLE_API_TOKEN") or os.environ.get("WIGLE_KEY")
    if not api_name or not api_token:
        raise RuntimeError("WiGLE enrichment is not configured. Set WIGLE_API_NAME and WIGLE_API_TOKEN in .env.")

    cell_op = infer_wigle_cell_op(tower["operator"])
    params = {
        "cell_net": str(tower["tac_lac"]),
        "cell_id": str(tower["cell_id"]),
        "resultsPerPage": "100",
    }
    if cell_op:
        params["cell_op"] = cell_op
    url = f"{WIGLE_CELL_SEARCH_URL}?{urllib.parse.urlencode(params)}"
    basic = base64.b64encode(f"{api_name}:{api_token}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": f"Basic {basic}"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"WiGLE request failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"WiGLE request failed: {exc.reason}") from exc

    results = payload.get("results") if isinstance(payload, dict) else []
    if not isinstance(results, list):
        results = []
    expected_id = f"{cell_op}_{tower['tac_lac']}_{tower['cell_id']}" if cell_op else None
    exact_results = [result for result in results if not expected_id or str(result.get("id") or "") == expected_id]
    checked_at = utc_now()
    result = {
        "configured": True,
        "exists": bool(exact_results),
        "match_count": len(exact_results),
        "wigle_total_results": int(payload.get("totalResults") or len(results)),
        "query": {
            "cell_op": cell_op,
            "cell_net": tower["tac_lac"],
            "cell_id": tower["cell_id"],
        },
        "results": exact_results,
        "checked_at": checked_at,
        "cached": False,
    }
    with connect_db(db_path) as con:
        con.execute(
            """
            INSERT INTO wigle_enrichments(tower_id,checked_at,result_json)
            VALUES (?,?,?)
            ON CONFLICT(tower_id) DO UPDATE SET
              checked_at=excluded.checked_at,
              result_json=excluded.result_json
            """,
            (int(tower_id), checked_at, json_dumps(result)),
        )
        con.commit()
    return result


def import_status_snapshot() -> Dict[str, Any]:
    with IMPORT_STATUS_LOCK:
        return dict(IMPORT_STATUS)


def set_import_status(**updates: Any) -> Dict[str, Any]:
    with IMPORT_STATUS_LOCK:
        IMPORT_STATUS.update(updates)
        IMPORT_STATUS["updated_at"] = utc_now()
        return dict(IMPORT_STATUS)


def reset_import_status(message: str = "Ready to import JSONL files.") -> Dict[str, Any]:
    return set_import_status(
        active=False,
        phase="idle",
        task=None,
        message=message,
        started_at=None,
        finished_at=None,
        total_files=0,
        file_index=0,
        current_path="",
        current_file_size=0,
        current_file_bytes=0,
        current_file_percent=0.0,
        current_rows=0,
        current_observations=0,
        current_errors=0,
        imported_rows=0,
        tower_observations=0,
        files_imported=0,
        files_skipped=0,
        errors=0,
        result=None,
        detail=None,
    )


def format_import_progress(progress: Dict[str, Any]) -> str:
    phase = str(progress.get("phase") or "")
    total_files = int(progress.get("total_files") or 0)
    file_index = int(progress.get("file_index") or 0)
    current_path = Path(str(progress.get("current_path") or "")).name or "-"
    current_rows = int(progress.get("current_rows") or 0)
    current_obs = int(progress.get("current_observations") or 0)
    current_errors = int(progress.get("current_errors") or 0)
    imported_rows = int(progress.get("imported_rows") or 0)
    files_imported = int(progress.get("files_imported") or 0)
    files_skipped = int(progress.get("files_skipped") or 0)
    percent = progress.get("current_file_percent")
    percent_text = ""
    if isinstance(percent, (int, float)) and percent > 0:
        percent_text = f" {float(percent):.1f}%"
    if phase == "starting":
        return f"Preparing import of {total_files} file(s)…"
    if phase == "skipped":
        return f"Skipping {current_path} ({file_index}/{total_files}); already imported."
    if phase == "finalizing":
        return f"Finalizing import after {files_imported} imported file(s), {imported_rows} rows total…"
    if phase == "finalizing_stationary_scan":
        done = int(progress.get("finalize_scan_done") or 0)
        total = int(progress.get("finalize_scan_total") or 0)
        return f"Finalizing: scanning GPS samples for stationary segments ({done}/{total})…"
    if phase == "finalizing_stationary_apply":
        done = int(progress.get("finalize_apply_done") or 0)
        total = int(progress.get("finalize_apply_total") or 0)
        return f"Finalizing: writing stationary flags ({done}/{total})…"
    if phase == "done":
        result = progress.get("result") or {}
        return (
            f"Import complete: {int(result.get('files_imported') or 0)} file(s) imported, "
            f"{int(result.get('files_skipped') or 0)} skipped, "
            f"{int(result.get('new_towers') or 0)} new towers added."
        )
    if phase == "error":
        return str(progress.get("detail") or progress.get("message") or "Import failed.")
    if current_path and file_index and total_files:
        return (
            f"Importing {current_path} ({file_index}/{total_files}){percent_text} "
            f"rows={current_rows} obs={current_obs} errors={current_errors} "
            f"total_rows={imported_rows} imported={files_imported} skipped={files_skipped}"
        )
    return str(progress.get("message") or "Import in progress…")


def emit_import_progress(
    callback: Optional[Callable[[Dict[str, Any]], None]],
    progress: Dict[str, Any],
) -> None:
    if callback is None:
        return
    payload = dict(progress)
    payload["message"] = format_import_progress(payload)
    callback(payload)


def _iter_chunks(items: Sequence[Any], size: int = 500) -> Iterable[Sequence[Any]]:
    step = max(1, int(size))
    for idx in range(0, len(items), step):
        yield items[idx:idx + step]


def set_app_setting(con: sqlite3.Connection, key: str, value: Any) -> None:
    now = utc_now()
    con.execute(
        """
        INSERT INTO app_settings(key, value_json, updated_at)
        VALUES (?,?,?)
        ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (str(key), json_dumps(value), now),
    )


def get_app_setting(con: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = con.execute("SELECT value_json FROM app_settings WHERE key=?", (str(key),)).fetchone()
    if not row:
        return default
    return json_loads(row["value_json"], default)


def file_sha256(path: str, block_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def stable_uid(*parts: Any) -> str:
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, bytes):
            data = part
        else:
            data = str(part).encode("utf-8", "replace")
        h.update(data)
        h.update(b"\x1f")
    return h.hexdigest()


def timestamp_from_obj(obj: Dict[str, Any]) -> Optional[str]:
    for key in ("timestamp_utc", "timestamp", "timestamp_local"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    gpsd = obj.get("gps_device") or {}
    val = gpsd.get("timestamp_utc")
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def parse_obj_ts(obj: Dict[str, Any]) -> Optional[float]:
    ts = timestamp_from_obj(obj)
    parsed = parse_time(ts) if ts else None
    return to_epoch_seconds(parsed) if parsed else None


def _day_id_to_datestr(day_id: Optional[int]) -> Optional[str]:
    if not isinstance(day_id, int) or day_id <= 0:
        return None
    y = day_id // 10000
    m = (day_id // 100) % 100
    d = day_id % 100
    try:
        return dt.date(int(y), int(m), int(d)).isoformat()
    except Exception:
        return None


def tower_identity_dict(key: TowerKey) -> Dict[str, Any]:
    return {
        "operator": key.operator or "",
        "rat": key.rat or "",
        "tac_lac": key.tac_lac,
        "cell_id": key.cell_id,
        "pci": key.pci,
        "earfcn": key.earfcn,
    }


def tower_identity_key(key: TowerKey) -> str:
    return json_dumps(tower_identity_dict(key))


def base_identity_key(key: BaseKey) -> str:
    return json_dumps({
        "operator": key.operator or "",
        "rat": key.rat or "",
        "tac_lac": key.tac_lac,
        "cell_id": key.cell_id,
    })


def tower_label(row_or_key: Any) -> str:
    if isinstance(row_or_key, TowerKey):
        return row_or_key.label()
    parts = [row_or_key["operator"] or "(unknown op)", row_or_key["rat"] or "(unknown rat)"]
    if row_or_key["tac_lac"] is not None:
        parts.append(f"TAC/LAC {row_or_key['tac_lac']}")
    if row_or_key["cell_id"] is not None:
        parts.append(f"Cell {row_or_key['cell_id']}")
    if row_or_key["pci"] is not None:
        parts.append(f"PCI {row_or_key['pci']}")
    if row_or_key["earfcn"] is not None:
        parts.append(f"EARFCN {row_or_key['earfcn']}")
    return " | ".join(parts)


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, tb):  # type: ignore[override]
        result = super().__exit__(exc_type, exc, tb)
        self.close()
        return result


def connect_db(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, factory=ClosingConnection)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    # Avoid immediate failures when imports/recompute are writing.
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA foreign_keys=ON")
    return con


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS import_files (
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime REAL NOT NULL,
  sha256 TEXT NOT NULL,
  imported_rows INTEGER NOT NULL DEFAULT 0,
  new_samples INTEGER NOT NULL DEFAULT 0,
  tower_fingerprints INTEGER NOT NULL DEFAULT 0,
  new_towers INTEGER NOT NULL DEFAULT 0,
  observation_rows INTEGER NOT NULL DEFAULT 0,
  new_observations INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  imported_at TEXT NOT NULL,
  UNIQUE(path, size, mtime, sha256)
);

CREATE TABLE IF NOT EXISTS raw_samples (
  id INTEGER PRIMARY KEY,
  sample_uid TEXT NOT NULL UNIQUE,
  content_hash TEXT NOT NULL UNIQUE,
  import_id INTEGER,
  line_no INTEGER,
  ts REAL,
  ts_iso TEXT,
  lat REAL,
  lon REAL,
  alt_m REAL,
  gps_source TEXT,
  gps_status TEXT,
  hdop REAL,
  bad_gps INTEGER NOT NULL DEFAULT 0,
  stationary INTEGER NOT NULL DEFAULT 0,
  stationary_segment INTEGER,
  place_id TEXT,
  raw_json TEXT NOT NULL,
  FOREIGN KEY(import_id) REFERENCES import_files(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS towers (
  id INTEGER PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  coarse_identity_key TEXT NOT NULL,
  operator TEXT NOT NULL DEFAULT '',
  rat TEXT NOT NULL DEFAULT '',
  tac_lac INTEGER,
  cell_id INTEGER,
  pci INTEGER,
  earfcn INTEGER,
  label TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  analysis_status TEXT NOT NULL DEFAULT '',
  known INTEGER NOT NULL DEFAULT 0,
  ignored INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tower_observations (
  id INTEGER PRIMARY KEY,
  obs_uid TEXT NOT NULL UNIQUE,
  sample_uid TEXT NOT NULL,
  tower_id INTEGER NOT NULL,
  coarse_identity_key TEXT NOT NULL,
  ts REAL,
  lat REAL,
  lon REAL,
  place_id TEXT,
  signal REAL,
  raw_cell_json TEXT NOT NULL,
  bad_gps INTEGER NOT NULL DEFAULT 0,
  ignored INTEGER NOT NULL DEFAULT 0,
  stationary INTEGER NOT NULL DEFAULT 0,
  stationary_segment INTEGER,
  FOREIGN KEY(sample_uid) REFERENCES raw_samples(sample_uid) ON DELETE CASCADE,
  FOREIGN KEY(tower_id) REFERENCES towers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tower_features (
  tower_id INTEGER PRIMARY KEY,
  computed_at TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  center_lat REAL,
  center_lon REAL,
  first_seen_ts REAL,
  last_seen_ts REAL,
  rule_score REAL NOT NULL DEFAULT 0,
  bayes_post_p REAL NOT NULL DEFAULT 0,
  features_json TEXT NOT NULL,
  methods_json TEXT NOT NULL,
  bayes_json TEXT NOT NULL,
  FOREIGN KEY(tower_id) REFERENCES towers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wigle_enrichments (
  tower_id INTEGER PRIMARY KEY,
  checked_at TEXT NOT NULL,
  result_json TEXT NOT NULL,
  FOREIGN KEY(tower_id) REFERENCES towers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS anomaly_methods (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  direction TEXT NOT NULL,
  default_weight REAL NOT NULL,
  default_thresholds_json TEXT NOT NULL,
  variables_json TEXT NOT NULL,
  equation TEXT NOT NULL,
  help TEXT NOT NULL,
  map_layers_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS method_settings (
  method_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL,
  weight REAL NOT NULL,
  thresholds_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(method_id) REFERENCES anomaly_methods(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_samples_ts ON raw_samples(ts);
CREATE INDEX IF NOT EXISTS idx_obs_tower_ts ON tower_observations(tower_id, ts);
CREATE INDEX IF NOT EXISTS idx_obs_place ON tower_observations(place_id);
CREATE INDEX IF NOT EXISTS idx_towers_cell ON towers(cell_id, tac_lac, pci, earfcn);
CREATE INDEX IF NOT EXISTS idx_features_score ON tower_features(bayes_post_p DESC, rule_score DESC);
"""


VARIABLE_GLOSSARY: Dict[str, str] = {
    "log_sample": "One JSONL line recorded by hack-wanderer at one time. It may contain GPS, network registration, and one or more cell/tower observations.",
    "tower_observation": "One cell/tower seen inside one log sample. If one JSONL line contains serving and neighbor cells, each becomes a separate observation.",
    "fingerprint": "The stable tower identity used here: operator, RAT, TAC/LAC, cell_id, PCI, and EARFCN.",
    "coarse_identity": "A broader identity: operator, RAT, TAC/LAC, and cell_id. It is used to study PCI/EARFCN churn.",
    "count": "Number of tower observations for this exact fingerprint after ingest. One observation means one tower seen in one log sample.",
    "days_seen": "Number of distinct UTC calendar days on which this fingerprint was observed.",
    "stationary_count": "Number of tower observations that happened while the device was classified as stationary.",
    "stationary_span_s": "Seconds between the first and last stationary observation of this tower in the current dataset.",
    "rat": "Radio Access Technology, for example LTE, GSM/2G, UMTS/3G, or NR/5G.",
    "tac_lac": "LTE/5G Tracking Area Code or 2G/3G Location Area Code.",
    "cell_id": "Network cell identifier reported by the modem. In LTE this is usually ECI/Cell Identifier and can be shown differently by databases.",
    "pci": "Physical Cell ID. It identifies radio-layer identity within a local LTE area and helps distinguish sectors.",
    "earfcn": "LTE frequency channel number. It helps distinguish frequency layers/sectors.",
    "signal": "Best available signal proxy from the log: per-cell RSRP/RSSI/RSRQ/RSSNR when present, otherwise CSQ RSSI dBm.",
    "bad_gps": "A GPS fix excluded from anomaly calculations because the source reports an invalid/no-fix state (e.g. gps_device fix_quality==0/status!=A, or modem fix_status==0) or because consecutive fixes imply an impossible speed jump.",
    "stationary": "A sample marked stationary because the device stayed within a small radius long enough, with low implied speed between fixes and low GPS-reported speed when that direct speed was available from the log.",
    "alt_m": "Altitude in meters attached to the sample when available from GPS. For external NMEA GPS this often comes from the GGA sentence.",
    "place_id": "A Web-Mercator map-tile bucket at zoom 17. It groups nearby samples into a local place without needing external geocoding.",
    "gps_spread_m": "Median distance in meters from this tower's points to its robust inferred center after bad GPS exclusion.",
    "clusters": "Greedy spatial clusters made from all valid GPS points for the same tower fingerprint.",
    "cluster_top2_sep_m": "Distance between the two largest all-point cluster centers.",
    "stationary_clusters": "Greedy spatial clusters made only from stationary points for the same fingerprint.",
    "stationary_cluster_top2_sep_m": "Distance between the two largest stationary-only cluster centers.",
    "center_drift": "Weekly center-drift summary for this fingerprint.",
    "center_drift.max_drift_m": "Maximum distance between inferred weekly centers for this fingerprint.",
    "center_drift.bins": "How many weekly time bins had enough points to compute a center.",
    "center_drift_m": "Maximum distance between inferred centers from weekly time bins.",
    "max_weekly_center_drift_m": "Maximum distance between inferred weekly centers for this fingerprint.",
    "signal_dist_model": "Signal-vs-distance model summary for this fingerprint.",
    "signal_dist_model.n": "Number of observations used in the signal-vs-distance residual model.",
    "signal_dist_model.outlier_frac": "Fraction of model residuals marked as outliers for this fingerprint.",
    "signal_dist_model.residual_mad": "Robust median absolute deviation of residuals in the signal-vs-distance model.",
    "dist_outlier_frac": "Fraction of points whose signal is a robust residual outlier compared with this tower's own signal-vs-distance trend.",
    "stationary_signal_mad": "Median absolute deviation of signal while stationary.",
    "stationary_signal_mad_z": "Robust z-score of stationary signal MAD compared with the dataset-wide tower baseline.",
    "stationary_jump_rate_8db": "Fraction of consecutive stationary signal readings that jump by at least 8 dB-like units.",
    "stationary_jump_rate_z": "Robust z-score of the large-jump rate compared with the dataset-wide tower baseline.",
    "stationary_param_obs": "Stationary observations for a coarse identity; used for PCI/EARFCN churn.",
    "stationary_pci_change_rate": "Rate of PCI changes while stationary for the same coarse identity.",
    "stationary_pci_change_rate_z": "Robust z-score of stationary PCI change rate versus the dataset baseline.",
    "stationary_earfcn_change_rate": "Rate of EARFCN changes while stationary for the same coarse identity.",
    "stationary_earfcn_change_rate_z": "Robust z-score of stationary EARFCN change rate versus the dataset baseline.",
    "local_stationary_window_min": "Minutes between first and last stationary observations in the same place buckets where this tower appeared.",
    "local_stationary_window_frac": "Tower's stationary span divided by local stationary opportunity window. Small means bursty despite nearby stationary time.",
    "change_places_frac": "Fraction of this tower's observations that fall in place buckets flagged as \"changed\" (the signal levels in that local area shifted over time).",
    "change_places_frac_stationary": "Same as change_places_frac, but preferring place buckets whose stationary-only distributions changed when that evidence exists.",
    "changed_bucket_fraction": "Fraction of this tower's observations that fall in place buckets marked as changed. Uses stationary-only change fraction when available, otherwise overall change fraction.",
    "place_details": "List of local place buckets used by the place-change method. Each item summarizes one bucket with fields such as count, place_total, ks_d, cusum, changed, and changed_stationary.",
    "new_place_id": "The place bucket (tile at zoom 17) where this tower fingerprint was most often observed.",
    "new_place_count": "How many observations of this tower were in new_place_id (the tower's main place bucket).",
    "new_place_prior_count": "How many total (good-GPS) tower observations existed in new_place_id before this tower was first seen there. Higher implies better coverage and higher confidence the tower is genuinely new.",
    "new_place_prior_days": "How many distinct UTC days had any (good-GPS) observations in new_place_id before this tower was first seen there.",
    "new_place_prior_stationary_count": "How many stationary (good-GPS) observations existed in new_place_id before this tower was first seen there.",
    "new_place_prior_stationary_days": "How many distinct UTC days had any stationary observations in new_place_id before this tower was first seen there.",
    "new_place_first_seen_ts": "Epoch seconds (UTC) when this tower fingerprint was first observed in its main place bucket.",
    "new_place_first_seen_local": "Local time (machine running the server) when this tower fingerprint was first observed in its main place bucket.",
    "new_place_prior_range": "Human-readable date range of prior coverage in new_place_id before the tower first appeared there.",
    "new_area_code_prior_same_rat_count": "How many prior good-GPS observations in this tower's main place bucket had the same operator and RAT and also reported any TAC/LAC value before this tower first appeared there.",
    "new_area_code_prior_same_rat_days": "How many distinct UTC days contributed prior same-operator/RAT TAC/LAC observations in this tower's main place bucket.",
    "new_area_code_prior_same_code_count": "How many prior same-operator/RAT observations in this place already used this exact TAC/LAC before the tower first appeared there. Zero means the area code was locally unseen.",
    "new_area_code_prior_distinct_codes": "How many distinct TAC/LAC values were already seen for the same operator and RAT in this place before the tower first appeared there.",
    "new_area_code_prior_dominant_code": "The most common prior TAC/LAC value for the same operator and RAT in this place before the tower first appeared there.",
    "new_area_code_prior_dominant_frac": "Fraction of prior same-operator/RAT observations in this place that used the dominant TAC/LAC. Higher means the local area-code pattern was more stable before the new tower appeared.",
    "new_area_code_prior_range": "Human-readable date range of prior same-operator/RAT TAC/LAC coverage in this place before the tower first appeared there.",
    "new_place_post_count": "How many total (good-GPS) tower observations existed in new_place_id after this tower was last seen there. Higher implies more opportunity to have seen it again if it still existed.",
    "new_place_post_days": "How many distinct UTC days had any (good-GPS) observations in new_place_id after this tower was last seen there.",
    "new_place_post_stationary_count": "How many stationary (good-GPS) observations existed in new_place_id after this tower was last seen there.",
    "new_place_post_stationary_days": "How many distinct UTC days had any stationary observations in new_place_id after this tower was last seen there.",
    "place_total": "Total number of log samples in that place bucket, across all towers.",
    "place_dur_min": "Total duration in minutes covered by samples inside that place bucket.",
    "ks_d": "KS distance between earlier vs later signal-strength samples in this bucket. Near 0 means \"looks the same\"; larger means \"shape changed\".",
    "cusum": "CUSUM change score: gets large when signal shifts and stays shifted over time in this bucket.",
    "changed": "True when this place bucket was flagged as changed (KS/CUSUM indicate the signal behavior changed over time).",
    "changed_stationary": "Boolean flag saying the place bucket was marked as changed using stationary-only samples.",
    "rat_surprise": "How surprising the RAT transition pattern is inside a place bucket. Higher means more unusual.",
    "place_rat_surprise": "Average negative log probability of RAT transitions in the place buckets where this tower appeared.",
    "stability_bonus": "Negative-evidence score awarded when a tower looks stable across days, location, and stationary behavior.",
    "dataset_mostly_lte": "True when the overall dataset is mostly LTE observations. Used only as weak contextual evidence for non-LTE towers.",
    "altitude_samples": "Number of observations for this tower that had usable altitude and could therefore be altitude-adjusted.",
    "stationary_altitude_samples": "Number of stationary observations for this tower that had usable altitude.",
    "altitude_rel_median_m": "Median height of this tower's observations above the local place-floor baseline. Higher means you often saw it from elevated positions.",
    "altitude_rel_p90_m": "90th percentile of relative altitude above the local place-floor baseline.",
    "stationary_altitude_rel_median_m": "Median relative altitude above the local place-floor baseline, using stationary observations only.",
    "stationary_altitude_rel_p90_m": "90th percentile of relative altitude above the local place-floor baseline, using stationary observations only.",
    "high_altitude_obs_frac": "Fraction of this tower's observations that were clearly elevated above the local place-floor baseline.",
    "stationary_high_altitude_obs_frac": "Fraction of stationary observations that were clearly elevated above the local place-floor baseline.",
    "geo_altitude_confidence": "Multiplier in [0,1] that discounts geo/distance anomalies when many observations were made from elevated positions where farther towers are easier to hear.",
    "stationary_geo_altitude_confidence": "Same as geo_altitude_confidence, but computed from stationary observations only when available.",
    "relative_altitude_m": "Observation altitude above the locally estimated ground/floor baseline for that place bucket. This is the quantity used for altitude discounting, not sea-level altitude.",
    "local_ground_altitude_m": "Robust local ground/floor baseline for a place bucket. It is estimated as a robust minimum altitude after ignoring low outliers.",
    "altitude_floor_iqr_k": "Low-outlier rejection strength for the local ground estimator. Larger values trust lower points more; smaller values reject suspicious low GPS altitude glitches more aggressively.",
    "altitude_no_discount_until_m": "Relative altitude above local ground that keeps full evidence weight.",
    "altitude_half_value_height_m": "Extra height after the no-discount buffer needed to reduce geo evidence by half.",
    "altitude_high_point_m": "Relative altitude used when counting clearly elevated points.",
    "altitude_min_confidence": "Minimum discount multiplier allowed for geo-based methods.",
    "known": "Manual user flag marking the tower as known/verified. It lowers ranking but does not erase anomalies.",
    "ignored": "Manual user flag hiding the tower from default anomaly views. The raw data stays in the database.",
    "bayes_prior": "Starting probability before evidence. Kept low to reduce false positives.",
    "bayes_post_p": "Posterior probability after adding enabled evidence terms in log-odds space.",
    "delta_logodds": "How much one method changes log-odds. Positive raises suspicion; negative lowers it.",
    "odds_multiplier": "exp(delta_logodds). It tells how much this method alone multiplies suspicious odds at its current strength.",
    "p_before": "Posterior probability immediately before this method's contribution is applied in the explanation ordering.",
    "p_after": "Posterior probability immediately after this method's contribution is applied in the explanation ordering.",
    "delta_p": "Change in posterior probability caused by this method at that point in the explanation ordering.",
    "weight": "Maximum absolute log-odds contribution this method can add once its normalized evidence reaches 1.",
    "triggered": "Whether this method's gating conditions were satisfied and the computed evidence strength was above zero.",
    "base_norm01": "Raw normalized evidence before any altitude discount is applied.",
    "altitude_factor": "Altitude discount multiplier applied to some methods. Elevated observation points reduce the effective strength because they can hear farther towers.",
    "norm01": "Evidence strength normalized to 0..1 before multiplying by a method weight.",
    "sep_start_m": "Lower distance threshold in meters. Below this separation, the method gives zero separation evidence.",
    "sep_full_m": "Upper distance threshold in meters. At or above this separation, the method reaches full normalized evidence.",
    "spread_start_m": "Lower GPS-spread threshold in meters. Below this spread, the spread method gives zero evidence.",
    "spread_full_m": "Upper GPS-spread threshold in meters. At or above this spread, the spread method reaches full normalized evidence.",
    "drift_start_m": "Lower weekly-drift threshold in meters. Below this drift, the drift method gives zero evidence.",
    "drift_full_m": "Upper weekly-drift threshold in meters. At or above this drift, the drift method reaches full normalized evidence.",
    "frac_start": "Lower fraction threshold. Below this fraction, the method gives zero normalized evidence.",
    "frac_full": "Upper fraction threshold. At or above this fraction, the method reaches full normalized evidence.",
    "z_start": "Lower robust z-score threshold. Below this z-score, the method gives zero evidence.",
    "z_full": "Upper robust z-score threshold. At or above this z-score, the method reaches full normalized evidence.",
    "min_clusters": "Minimum number of spatial clusters required before this method can trigger.",
    "min_stationary_count": "Minimum number of stationary observations required before this method can trigger.",
    "min_count": "Minimum number of observations required before this method can trigger.",
    "min_bins": "Minimum number of weekly bins required before weekly drift is considered valid.",
    "min_model_n": "Minimum number of observations required before fitting the signal-vs-distance residual model.",
    "min_obs": "Minimum number of stationary coarse-identity observations required before churn methods can trigger.",
    "min_window_min": "Minimum stationary opportunity window, in minutes, required before the bursty-opportunity method can trigger.",
    "max_frac": "Upper local-window fraction used by the bursty-opportunity method. Above this, the burst signal weakens toward zero.",
    "full_frac": "Lower local-window fraction used by the bursty-opportunity method. At or below this, the method reaches full normalized evidence.",
    "prior_count_start": "Lower prior-coverage threshold. Below this count, the local novelty methods give zero normalized evidence.",
    "prior_count_full": "Upper prior-coverage threshold. At or above this count, the local novelty methods reach full normalized evidence.",
    "post_count_start": "Lower post-coverage threshold. Below this, the disappearance method gives zero evidence.",
    "post_count_full": "Upper post-coverage threshold. At or above this count, the disappearance method reaches full normalized evidence.",
    "dominant_frac_start": "Lower dominant-area-code fraction threshold. Below this, the TAC/LAC stability term gives zero evidence.",
    "dominant_frac_full": "Upper dominant-area-code fraction threshold. At or above this fraction, the TAC/LAC stability term reaches full normalized evidence.",
    "min_prior_days": "Minimum number of distinct prior days required before the new local novelty methods can trigger.",
    "min_post_days": "Minimum number of distinct later-coverage days required before the disappearance method can trigger.",
    "min_tower_count_in_place": "Minimum number of observations this tower must have in its main place bucket before local place-based novelty methods can trigger.",
    "surprise_start": "Lower RAT-surprise threshold. Below this, the RAT surprise method gives zero evidence.",
    "surprise_full": "Upper RAT-surprise threshold. At or above this, the RAT surprise method reaches full normalized evidence.",
    "stable_spread_m": "GPS spread threshold used when awarding negative stability evidence.",
    "min_days": "Minimum number of distinct days required before the stability method can lower suspicion.",
    "days_start": "Distinct-day count where the many-days negative evidence starts to reduce suspicion.",
    "days_full": "Distinct-day count where the many-days negative evidence reaches full configured strength.",
    "wigle_checked": "Whether this tower has been explicitly checked against WiGLE and stored locally.",
    "wigle_exists": "Whether the stored WiGLE lookup found an exact PLMN/TAC-LAC/Cell-ID match.",
    "wigle_match_count": "Number of exact WiGLE records stored for this tower.",
    "wigle_first_seen": "Earliest first-seen timestamp among exact stored WiGLE matches.",
    "wigle_last_seen": "Most recent last-seen timestamp among exact stored WiGLE matches.",
    "wigle_first_seen_age_days": "Days between the WiGLE check and the earliest stored WiGLE first-seen timestamp. Older records are stronger normality evidence.",
    "wigle_last_seen_age_days": "Days between the WiGLE check and the most recent stored WiGLE last-seen timestamp. Smaller values are stronger normality evidence.",
    "first_age_start_days": "WiGLE first-seen age where historical-presence normality evidence starts.",
    "first_age_full_days": "WiGLE first-seen age where the historical-age component reaches full strength.",
    "last_age_full_days": "WiGLE last-seen recency at or below which the recency component has full strength.",
    "last_age_max_days": "WiGLE last-seen age at or above which the recency component contributes no normality evidence.",
}


METHOD_REGISTRY: List[Dict[str, Any]] = [
    {
        "id": "new_in_well_covered_place",
        "label": "New tower in a well-covered place",
        "direction": "up",
        "weight": 1.6,
        "thresholds": {
            "prior_count_start": 120,
            "prior_count_full": 1200,
            "min_tower_count_in_place": 6,
            "min_prior_days": 2,
        },
        "variables": [
            "new_place_prior_count",
            "new_place_prior_days",
            "new_place_prior_stationary_count",
            "new_place_prior_stationary_days",
            "new_place_count",
        ],
        "equation": "norm01 = clamp((new_place_prior_count - prior_count_start) / (prior_count_full - prior_count_start), 0, 1) if new_place_prior_days >= min_prior_days",
        "help": "If a tower first appears inside a place bucket that previously had lots of good observations, we have higher confidence it was not simply missed earlier. This flags new deployments in well-covered areas (still probabilistic).",
        "map_layers": ["place_buckets", "points"],
    },
    {
        "id": "disappears_despite_coverage",
        "label": "Disappears despite later coverage",
        "direction": "up",
        "weight": 1.2,
        "thresholds": {
            "post_count_start": 120,
            "post_count_full": 1200,
            "min_post_days": 2,
            "min_tower_count_in_place": 6,
        },
        "variables": [
            "new_place_post_count",
            "new_place_post_days",
            "new_place_post_stationary_count",
            "new_place_post_stationary_days",
            "new_place_count",
            "new_place_id",
        ],
        "equation": "norm01 = clamp((new_place_post_count - post_count_start) / (post_count_full - post_count_start), 0, 1) if new_place_post_days >= min_post_days",
        "help": "If a tower is observed in a place bucket, and then later we spend lots of time in that same bucket (seeing other towers), but never see this tower again, that is evidence it was short-lived or inconsistent. This is still probabilistic: phones do not observe every tower on every pass.",
        "map_layers": ["place_buckets", "points"],
    },
    {
        "id": "new_area_code_in_well_covered_place",
        "label": "New TAC/LAC in a well-covered place",
        "direction": "up",
        "weight": 1.2,
        "thresholds": {
            "prior_count_start": 40,
            "prior_count_full": 300,
            "dominant_frac_start": 0.65,
            "dominant_frac_full": 0.90,
            "min_tower_count_in_place": 4,
            "min_prior_days": 2,
        },
        "variables": [
            "tac_lac",
            "new_area_code_prior_same_rat_count",
            "new_area_code_prior_same_rat_days",
            "new_area_code_prior_same_code_count",
            "new_area_code_prior_distinct_codes",
            "new_area_code_prior_dominant_code",
            "new_area_code_prior_dominant_frac",
            "new_place_count",
        ],
        "equation": "coverage_norm = clamp((new_area_code_prior_same_rat_count - prior_count_start) / (prior_count_full - prior_count_start), 0, 1); stability_norm = clamp((new_area_code_prior_dominant_frac - dominant_frac_start) / (dominant_frac_full - dominant_frac_start), 0, 1); norm01 = coverage_norm * stability_norm when this TAC/LAC was unseen before in that same place for the same operator and RAT.",
        "help": "Conservative local-context evidence only. LTE/5G uses TAC; older RATs use LAC in the same field. If a tower first appears in a place where the same operator and RAT were already well covered, and this TAC/LAC was not seen there before, that is mildly suspicious. The signal is stronger only when the previous local TAC/LAC pattern was itself stable.",
        "map_layers": ["place_buckets", "points"],
    },
    {
        "id": "multi_location_stationary",
        "label": "Multi-location even while stationary",
        "direction": "up",
        "weight": 2.4,
        "thresholds": {"sep_start_m": 800, "sep_full_m": 5000, "min_clusters": 2, "min_stationary_count": 10},
        "variables": ["stationary_clusters", "stationary_cluster_top2_sep_m", "stationary_count"],
        "equation": "norm01 = clamp((stationary_cluster_top2_sep_m - sep_start_m) / (sep_full_m - sep_start_m), 0, 1)",
        "help": "If the device is stationary, your own movement should not split one tower fingerprint into far-apart places. This is strong inconsistency evidence.",
        "map_layers": ["stationary_points", "stationary_clusters"],
    },
    {
        "id": "multi_location",
        "label": "Multi-location clusters",
        "direction": "up",
        "weight": 1.8,
        "thresholds": {"sep_start_m": 1200, "sep_full_m": 6000, "min_clusters": 2, "min_count": 15},
        "variables": ["clusters", "cluster_top2_sep_m", "count"],
        "equation": "norm01 = clamp((cluster_top2_sep_m - sep_start_m) / (sep_full_m - sep_start_m), 0, 1)",
        "help": "The same full fingerprint appears in multiple distant clusters. This can be ID reuse, route bias, bad data, or something worth reviewing.",
        "map_layers": ["points", "clusters"],
    },
    {
        "id": "gps_spread",
        "label": "High location spread",
        "direction": "up",
        "weight": 1.0,
        "thresholds": {"spread_start_m": 120, "spread_full_m": 800, "min_count": 5},
        "variables": ["gps_spread_m", "count"],
        "equation": "norm01 = clamp((gps_spread_m - spread_start_m) / (spread_full_m - spread_start_m), 0, 1)",
        "help": "After removing impossible GPS jumps and robustly centering, points are still very spread out.",
        "map_layers": ["points", "center"],
    },
    {
        "id": "center_drift",
        "label": "Center drift over time",
        "direction": "up",
        "weight": 1.2,
        "thresholds": {"drift_start_m": 600, "drift_full_m": 5000, "min_bins": 2},
        "variables": ["center_drift.max_drift_m", "center_drift.bins"],
        "equation": "norm01 = clamp((max_weekly_center_drift_m - drift_start_m) / (drift_full_m - drift_start_m), 0, 1)",
        "help": "Weekly inferred centers for the same fingerprint move far apart. This may indicate cell ID reuse or changing observation geometry.",
        "map_layers": ["points", "center"],
    },
    {
        "id": "signal_distance_mismatch",
        "label": "Signal vs distance mismatch",
        "direction": "up",
        "weight": 1.4,
        "thresholds": {"frac_start": 0.12, "frac_full": 0.45, "min_model_n": 12},
        "variables": ["signal_dist_model.n", "signal_dist_model.outlier_frac", "signal_dist_model.residual_mad"],
        "equation": "norm01 = clamp((dist_outlier_frac - frac_start) / (frac_full - frac_start), 0, 1)",
        "help": "Models this tower's signal as a function of distance from its inferred center, then counts large residual outliers.",
        "map_layers": ["points", "center"],
    },
    {
        "id": "stationary_signal_mad",
        "label": "Signal instability while stationary",
        "direction": "up",
        "weight": 1.4,
        "thresholds": {"z_start": 2.0, "z_full": 6.0, "min_stationary_count": 15},
        "variables": ["stationary_signal_mad", "stationary_signal_mad_z", "stationary_count"],
        "equation": "norm01 = clamp((stationary_signal_mad_z - z_start) / (z_full - z_start), 0, 1)",
        "help": "When you are standing still, distance-to-tower is roughly fixed. Signal should not jump around far beyond dataset baseline.",
        "map_layers": ["stationary_points"],
    },
    {
        "id": "stationary_jump_rate",
        "label": "Large signal jumps while stationary",
        "direction": "up",
        "weight": 1.0,
        "thresholds": {"z_start": 2.0, "z_full": 6.0, "min_stationary_count": 15},
        "variables": ["stationary_jump_rate_8db", "stationary_jump_rate_z", "stationary_count"],
        "equation": "norm01 = clamp((stationary_jump_rate_z - z_start) / (z_full - z_start), 0, 1)",
        "help": "Counts how often consecutive stationary signal readings jump by at least 8 dB-like units and compares to baseline.",
        "map_layers": ["stationary_points"],
    },
    {
        "id": "stationary_pci_churn",
        "label": "PCI churn while stationary",
        "direction": "up",
        "weight": 1.0,
        "thresholds": {"z_start": 2.0, "z_full": 6.0, "min_obs": 30},
        "variables": ["stationary_pci_change_rate", "stationary_pci_change_rate_z", "stationary_param_obs"],
        "equation": "norm01 = clamp((stationary_pci_change_rate_z - z_start) / (z_full - z_start), 0, 1)",
        "help": "For the same coarse identity, PCI should be comparatively stable while you are stationary. High churn is suspicious context.",
        "map_layers": ["stationary_points"],
    },
    {
        "id": "stationary_earfcn_churn",
        "label": "EARFCN churn while stationary",
        "direction": "up",
        "weight": 1.0,
        "thresholds": {"z_start": 2.0, "z_full": 6.0, "min_obs": 30},
        "variables": ["stationary_earfcn_change_rate", "stationary_earfcn_change_rate_z", "stationary_param_obs"],
        "equation": "norm01 = clamp((stationary_earfcn_change_rate_z - z_start) / (z_full - z_start), 0, 1)",
        "help": "For the same coarse identity, frequency channel should be comparatively stable while stationary. High churn is suspicious context.",
        "map_layers": ["stationary_points"],
    },
    {
        "id": "ephemeral_stationary_opportunity",
        "label": "Bursty despite stationary opportunity",
        "direction": "up",
        "weight": 1.6,
        "thresholds": {"min_stationary_count": 5, "min_window_min": 8, "max_frac": 0.35, "full_frac": 0.05},
        "variables": ["local_stationary_window_min", "local_stationary_window_frac", "stationary_span_s"],
        "equation": "norm01 = clamp((max_frac - local_stationary_window_frac) / (max_frac - full_frac), 0, 1)",
        "help": "This fixes the old false-positive problem: a tower is only bursty if you had stationary opportunity nearby and it still appeared briefly.",
        "map_layers": ["stationary_points", "place_buckets"],
    },
    {
        "id": "place_change_correlation",
        "label": "Correlates with changed place buckets",
        "direction": "up",
        "weight": 0.9,
        "thresholds": {"frac_start": 0.35, "frac_full": 0.80, "min_count": 20},
        "variables": ["change_places_frac_stationary", "change_places_frac", "place_details"],
        "equation": "norm01 = clamp((changed_bucket_fraction - frac_start) / (frac_full - frac_start), 0, 1)",
        "help": "Weak evidence: this tower is seen mostly in place buckets where the signal you recorded in that same area changed over time. We mark a bucket as \"changed\" when simple change tests say the earlier vs later signal-strength distribution looks different (KS) or there is a sustained shift (CUSUM).",
        "map_layers": ["place_buckets"],
    },
    {
        "id": "rat_transition_surprise",
        "label": "Unusual RAT transition patterns",
        "direction": "up",
        "weight": 0.7,
        "thresholds": {"surprise_start": 0.9, "surprise_full": 2.0, "min_count": 30},
        "variables": ["place_rat_surprise", "count"],
        "equation": "norm01 = clamp((place_rat_surprise - surprise_start) / (surprise_full - surprise_start), 0, 1)",
        "help": "Weak evidence: RAT transitions in the places where this tower appears are unusually chaotic.",
        "map_layers": ["place_buckets"],
    },
    {
        "id": "non_lte_when_mostly_lte",
        "label": "Non-LTE when dataset is mostly LTE",
        "direction": "up",
        "weight": 0.8,
        "thresholds": {},
        "variables": ["rat", "dataset_mostly_lte"],
        "equation": "norm01 = 1 when RAT is GSM/2G and the dataset is at least 80% LTE.",
        "help": "A small bump only. Real networks can still use GSM/2G, so this is context rather than proof.",
        "map_layers": [],
    },
    {
        "id": "wigle_absent",
        "label": "Absent from checked WiGLE records",
        "direction": "up",
        "weight": 1.5,
        "thresholds": {},
        "variables": ["wigle_checked", "wigle_exists", "wigle_match_count"],
        "equation": "norm01 = 1 when WiGLE was checked and returned no exact PLMN/TAC-LAC/Cell-ID match.",
        "help": "External-database evidence. After an explicit WiGLE lookup, an exact-match absence raises suspicion. WiGLE coverage is incomplete, so this is evidence rather than proof.",
        "map_layers": [],
    },
    {
        "id": "wigle_historical_presence",
        "label": "Historical WiGLE presence",
        "direction": "down",
        "weight": 2.0,
        "thresholds": {
            "first_age_start_days": 90,
            "first_age_full_days": 730,
            "last_age_full_days": 90,
            "last_age_max_days": 730,
        },
        "variables": [
            "wigle_checked",
            "wigle_exists",
            "wigle_match_count",
            "wigle_first_seen",
            "wigle_last_seen",
            "wigle_first_seen_age_days",
            "wigle_last_seen_age_days",
        ],
        "equation": "norm01 = clamp((wigle_first_seen_age_days - first_age_start_days) / (first_age_full_days - first_age_start_days), 0, 1) * clamp((last_age_max_days - wigle_last_seen_age_days) / (last_age_max_days - last_age_full_days), 0, 1); contribution is negative.",
        "help": "External-database normality evidence. An exact WiGLE match lowers suspicion more when it was first recorded long ago and was also seen recently.",
        "map_layers": [],
    },
    {
        "id": "stability",
        "label": "Stability evidence",
        "direction": "down",
        "weight": 2.2,
        "thresholds": {"stable_spread_m": 120, "min_stationary_count": 30, "min_days": 2},
        "variables": ["stability_bonus", "days_seen", "stationary_count", "clusters", "gps_spread_m"],
        "equation": "norm01 = clamp(stability_bonus / 1.5, 0, 1); contribution is negative.",
        "help": "Negative evidence. Repeated stable observations across days lower suspicion to reduce false positives.",
        "map_layers": ["points", "stationary_points"],
    },
    {
        "id": "many_days",
        "label": "Seen across many days",
        "direction": "down",
        "weight": 0.9,
        "thresholds": {"days_start": 2, "days_full": 10},
        "variables": ["days_seen"],
        "equation": "norm01 = clamp((days_seen - days_start) / (days_full - days_start), 0, 1); contribution is negative.",
        "help": "Negative evidence. A tower seen across many days is less like a short-lived deployment.",
        "map_layers": [],
    },
]

METHOD_XAI_SPECS: Dict[str, Dict[str, Any]] = {
    "new_in_well_covered_place": {
        "trigger_summary": "Requires enough tower observations in its main place bucket and substantial prior coverage (count and days) in that place before the tower first appeared there.",
        "rows": [
            ("Gate", "new_place_count"),
            ("Gate", "min_tower_count_in_place"),
            ("Context", "new_place_first_seen_local"),
            ("Gate", "new_place_prior_days"),
            ("Gate", "min_prior_days"),
            ("Equation", "new_place_prior_count"),
            ("Equation", "prior_count_start"),
            ("Equation", "prior_count_full"),
            ("Context", "new_place_id"),
            ("Context", "new_place_prior_range"),
            ("Context", "new_place_prior_stationary_count"),
            ("Context", "new_place_prior_stationary_days"),
        ],
    },
    "disappears_despite_coverage": {
        "trigger_summary": "Requires enough tower observations in its main place bucket, and substantial post-coverage (count and days) in that place after the tower's last sighting.",
        "rows": [
            ("Gate", "new_place_count"),
            ("Gate", "min_tower_count_in_place"),
            ("Gate", "new_place_post_days"),
            ("Gate", "min_post_days"),
            ("Equation", "new_place_post_count"),
            ("Equation", "post_count_start"),
            ("Equation", "post_count_full"),
            ("Context", "new_place_id"),
            ("Context", "new_place_post_stationary_count"),
            ("Context", "new_place_post_stationary_days"),
        ],
    },
    "new_area_code_in_well_covered_place": {
        "trigger_summary": "Requires enough observations in the tower's main place bucket, enough prior same-operator/RAT coverage days in that bucket, this TAC/LAC to have been unseen there before, and the prior local TAC/LAC pattern to have been fairly stable.",
        "rows": [
            ("Context", "tac_lac"),
            ("Gate", "new_place_count"),
            ("Gate", "min_tower_count_in_place"),
            ("Gate", "new_area_code_prior_same_rat_days"),
            ("Gate", "min_prior_days"),
            ("Gate", "new_area_code_prior_same_code_count"),
            ("Equation", "new_area_code_prior_same_rat_count"),
            ("Equation", "prior_count_start"),
            ("Equation", "prior_count_full"),
            ("Equation", "new_area_code_prior_dominant_frac"),
            ("Equation", "dominant_frac_start"),
            ("Equation", "dominant_frac_full"),
            ("Context", "new_area_code_prior_distinct_codes"),
            ("Context", "new_area_code_prior_dominant_code"),
            ("Context", "new_area_code_prior_range"),
            ("Context", "new_place_id"),
        ],
    },
    "multi_location_stationary": {
        "trigger_summary": "Requires at least 2 stationary clusters, enough stationary observations, and separation above the start threshold.",
        "rows": [
            ("Gate", "stationary_clusters"),
            ("Gate", "min_clusters"),
            ("Gate", "stationary_count"),
            ("Gate", "min_stationary_count"),
            ("Equation", "stationary_cluster_top2_sep_m"),
            ("Equation", "sep_start_m"),
            ("Equation", "sep_full_m"),
        ],
    },
    "multi_location": {
        "trigger_summary": "Requires at least 2 all-sample clusters, enough observations, and separation above the start threshold.",
        "rows": [
            ("Gate", "clusters"),
            ("Gate", "min_clusters"),
            ("Gate", "count"),
            ("Gate", "min_count"),
            ("Equation", "cluster_top2_sep_m"),
            ("Equation", "sep_start_m"),
            ("Equation", "sep_full_m"),
        ],
    },
    "gps_spread": {
        "trigger_summary": "Requires enough observations and GPS spread above the start threshold.",
        "rows": [
            ("Gate", "count"),
            ("Gate", "min_count"),
            ("Equation", "gps_spread_m"),
            ("Equation", "spread_start_m"),
            ("Equation", "spread_full_m"),
        ],
    },
    "center_drift": {
        "trigger_summary": "Requires at least the minimum number of weekly bins and weekly drift above the start threshold.",
        "rows": [
            ("Gate", "center_drift.bins"),
            ("Gate", "min_bins"),
            ("Equation", "max_weekly_center_drift_m"),
            ("Equation", "drift_start_m"),
            ("Equation", "drift_full_m"),
        ],
    },
    "signal_distance_mismatch": {
        "trigger_summary": "Requires enough observations for the distance model and an outlier fraction above the start threshold.",
        "rows": [
            ("Gate", "signal_dist_model.n"),
            ("Gate", "min_model_n"),
            ("Context", "signal_dist_model.residual_mad"),
            ("Equation", "dist_outlier_frac"),
            ("Equation", "frac_start"),
            ("Equation", "frac_full"),
        ],
    },
    "wigle_absent": {
        "trigger_summary": "Requires an explicit stored WiGLE lookup with no exact PLMN/TAC-LAC/Cell-ID match.",
        "rows": [
            ("Gate", "wigle_checked"),
            ("Gate", "wigle_exists"),
            ("Context", "wigle_match_count"),
        ],
    },
    "wigle_historical_presence": {
        "trigger_summary": "Requires an explicit stored WiGLE lookup with an exact match. Older first appearance and more recent last appearance increase the normality evidence.",
        "rows": [
            ("Gate", "wigle_checked"),
            ("Gate", "wigle_exists"),
            ("Context", "wigle_match_count"),
            ("Context", "wigle_first_seen"),
            ("Context", "wigle_last_seen"),
            ("Equation", "wigle_first_seen_age_days"),
            ("Equation", "first_age_start_days"),
            ("Equation", "first_age_full_days"),
            ("Equation", "wigle_last_seen_age_days"),
            ("Equation", "last_age_full_days"),
            ("Equation", "last_age_max_days"),
        ],
    },
    "stationary_signal_mad": {
        "trigger_summary": "Requires enough stationary observations and a stationary-signal MAD z-score above the start threshold.",
        "rows": [
            ("Gate", "stationary_count"),
            ("Gate", "min_stationary_count"),
            ("Context", "stationary_signal_mad"),
            ("Equation", "stationary_signal_mad_z"),
            ("Equation", "z_start"),
            ("Equation", "z_full"),
        ],
    },
    "stationary_jump_rate": {
        "trigger_summary": "Requires enough stationary observations and a stationary jump-rate z-score above the start threshold.",
        "rows": [
            ("Gate", "stationary_count"),
            ("Gate", "min_stationary_count"),
            ("Context", "stationary_jump_rate_8db"),
            ("Equation", "stationary_jump_rate_z"),
            ("Equation", "z_start"),
            ("Equation", "z_full"),
        ],
    },
    "stationary_pci_churn": {
        "trigger_summary": "Requires enough stationary coarse-identity observations and a PCI-churn z-score above the start threshold.",
        "rows": [
            ("Gate", "stationary_param_obs"),
            ("Gate", "min_obs"),
            ("Context", "stationary_pci_change_rate"),
            ("Equation", "stationary_pci_change_rate_z"),
            ("Equation", "z_start"),
            ("Equation", "z_full"),
        ],
    },
    "stationary_earfcn_churn": {
        "trigger_summary": "Requires enough stationary coarse-identity observations and an EARFCN-churn z-score above the start threshold.",
        "rows": [
            ("Gate", "stationary_param_obs"),
            ("Gate", "min_obs"),
            ("Context", "stationary_earfcn_change_rate"),
            ("Equation", "stationary_earfcn_change_rate_z"),
            ("Equation", "z_start"),
            ("Equation", "z_full"),
        ],
    },
    "ephemeral_stationary_opportunity": {
        "trigger_summary": "Requires enough stationary observations, enough local stationary opportunity, and a small local-window fraction.",
        "rows": [
            ("Gate", "stationary_count"),
            ("Gate", "min_stationary_count"),
            ("Gate", "local_stationary_window_min"),
            ("Gate", "min_window_min"),
            ("Context", "stationary_span_s"),
            ("Equation", "local_stationary_window_frac"),
            ("Equation", "max_frac"),
            ("Equation", "full_frac"),
        ],
    },
    "place_change_correlation": {
        "trigger_summary": "Requires enough observations and a changed-bucket fraction above the start threshold.",
        "rows": [
            ("Gate", "count"),
            ("Gate", "min_count"),
            ("Context", "change_places_frac_stationary"),
            ("Context", "change_places_frac"),
            ("Context", "place_details"),
            ("Equation", "changed_bucket_fraction"),
            ("Equation", "frac_start"),
            ("Equation", "frac_full"),
        ],
    },
    "rat_transition_surprise": {
        "trigger_summary": "Requires enough observations and place-level RAT surprise above the start threshold.",
        "rows": [
            ("Gate", "count"),
            ("Gate", "min_count"),
            ("Equation", "place_rat_surprise"),
            ("Equation", "surprise_start"),
            ("Equation", "surprise_full"),
        ],
    },
    "non_lte_when_mostly_lte": {
        "trigger_summary": "Triggers only when this tower is GSM/2G and the overall dataset is mostly LTE.",
        "rows": [
            ("Gate", "rat"),
            ("Gate", "dataset_mostly_lte"),
            ("Equation", "norm01"),
        ],
    },
    "stability": {
        "trigger_summary": "Negative evidence: stronger stability bonus lowers suspicion.",
        "rows": [
            ("Gate", "days_seen"),
            ("Gate", "min_days"),
            ("Gate", "stationary_count"),
            ("Gate", "min_stationary_count"),
            ("Gate", "gps_spread_m"),
            ("Gate", "stable_spread_m"),
            ("Context", "clusters"),
            ("Equation", "stability_bonus"),
            ("Equation", "norm01"),
        ],
    },
    "many_days": {
        "trigger_summary": "Negative evidence: once distinct days seen exceeds the start threshold, suspicion is reduced.",
        "rows": [
            ("Equation", "days_seen"),
            ("Equation", "days_start"),
            ("Equation", "days_full"),
        ],
    },
    "known_tower": {
        "trigger_summary": "Applies because you manually marked this tower as known/verified.",
        "rows": [
            ("Gate", "known"),
        ],
    },
}

COMMON_EFFECT_ROWS: List[Tuple[str, str]] = [
    ("Effect", "base_norm01"),
    ("Effect", "altitude_factor"),
    ("Effect", "norm01"),
    ("Effect", "weight"),
    ("Effect", "delta_logodds"),
    ("Effect", "odds_multiplier"),
    ("Effect", "p_before"),
    ("Effect", "p_after"),
    ("Effect", "delta_p"),
    ("Effect", "triggered"),
]

METHOD_VALUE_ALIASES: Dict[str, Dict[str, Any]] = {
    "center_drift": {
        "max_weekly_center_drift_m": lambda features, _method: get_path(features, "center_drift.max_drift_m"),
    },
    "signal_distance_mismatch": {
        "dist_outlier_frac": lambda features, _method: get_path(features, "signal_dist_model.outlier_frac"),
    },
    "place_change_correlation": {
        "changed_bucket_fraction": lambda features, _method: (
            features.get("change_places_frac_stationary")
            if isinstance(features.get("change_places_frac_stationary"), (int, float))
            else features.get("change_places_frac")
        ),
    },
}


def glossary_definition(name: str) -> str:
    if name in VARIABLE_GLOSSARY:
        return VARIABLE_GLOSSARY[name]
    base = name.split(".")[0]
    return VARIABLE_GLOSSARY.get(base, "")


def resolve_method_term_value(method: Dict[str, Any], features: Dict[str, Any], name: str) -> Any:
    thresholds = method.get("thresholds") or {}
    if name in thresholds:
        return thresholds.get(name)
    if name in method:
        return method.get(name)
    for item in method.get("inputs") or []:
        if item.get("name") == name:
            return item.get("value")
    alias = METHOD_VALUE_ALIASES.get(method.get("id"), {}).get(name)
    if callable(alias):
        return alias(features, method)
    if "." in name:
        return get_path(features, name)
    return features.get(name)


def method_equation_note(equation: str) -> str:
    if "clamp(" in equation:
        return "clamp(x, 0, 1) means values below 0 become 0 and values above 1 become 1."
    return ""


def build_method_xai_rows(method: Dict[str, Any], features: Dict[str, Any]) -> List[Dict[str, Any]]:
    spec = METHOD_XAI_SPECS.get(method.get("id"), {})
    rows: List[Tuple[str, str]] = list(spec.get("rows", []))
    seen = {(role, name) for role, name in rows}
    altitude_factor_name = str(method.get("altitude_factor_name") or "")
    altitude_extra: List[Tuple[str, str]] = []
    if altitude_factor_name == "geo_altitude_confidence":
        altitude_extra = [
            ("Altitude", "geo_altitude_confidence"),
            ("Altitude", "altitude_samples"),
            ("Altitude", "altitude_rel_median_m"),
            ("Altitude", "altitude_rel_p90_m"),
            ("Altitude", "high_altitude_obs_frac"),
        ]
    elif altitude_factor_name == "stationary_geo_altitude_confidence":
        altitude_extra = [
            ("Altitude", "stationary_geo_altitude_confidence"),
            ("Altitude", "stationary_altitude_samples"),
            ("Altitude", "stationary_altitude_rel_median_m"),
            ("Altitude", "stationary_altitude_rel_p90_m"),
            ("Altitude", "stationary_high_altitude_obs_frac"),
        ]
    for role, name in altitude_extra:
        if (role, name) not in seen:
            rows.append((role, name))
            seen.add((role, name))
    for role, name in COMMON_EFFECT_ROWS:
        if (role, name) not in seen:
            rows.append((role, name))
    out: List[Dict[str, Any]] = []
    for role, name in rows:
        out.append({
            "role": role,
            "name": name,
            "value": resolve_method_term_value(method, features, name),
            "definition": glossary_definition(name),
        })
    return out


def enrich_method_result(method: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(method)
    enriched["inputs"] = [
        {
            "name": item.get("name"),
            "value": item.get("value"),
            "definition": glossary_definition(str(item.get("name") or "")),
        }
        for item in (method.get("inputs") or [])
    ]
    spec = METHOD_XAI_SPECS.get(method.get("id"), {})
    enriched["trigger_summary"] = spec.get("trigger_summary", "")
    enriched["equation_note"] = method_equation_note(str(method.get("equation") or ""))
    if str(method.get("altitude_factor_name") or ""):
        note = "Elevated observation points reduce this method because towers are easier to hear from higher places."
        enriched["equation_note"] = f"{enriched['equation_note']} {note}".strip()
    enriched["xai_rows"] = build_method_xai_rows(enriched, features)
    return enriched


def init_db(db_path: str, *, seed_reference_data: bool = True) -> None:
    with connect_db(db_path) as con:
        con.executescript(SCHEMA_SQL)
        migrate_db(con)
        if seed_reference_data:
            seed_methods_if_missing(con)
            seed_app_settings_if_missing(con)


def ensure_column(con: sqlite3.Connection, table: str, column: str, spec: str) -> None:
    cols = {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {spec}")


def migrate_db(con: sqlite3.Connection) -> None:
    ensure_column(con, "raw_samples", "alt_m", "REAL")
    ensure_column(con, "tower_observations", "ignored", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "import_files", "new_samples", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "import_files", "tower_fingerprints", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "import_files", "new_towers", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "import_files", "observation_rows", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "import_files", "new_observations", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(con, "towers", "analysis_status", "TEXT NOT NULL DEFAULT ''")
    con.commit()


def normalize_analysis_status(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    lowered = text.lower()
    for allowed in ANALYSIS_STATUS_VALUES:
        if allowed and lowered == allowed.lower():
            return allowed
    raise ValueError(f"Invalid analysis_status '{text}'. Allowed values: {', '.join(v for v in ANALYSIS_STATUS_VALUES if v)}")


def seed_methods(con: sqlite3.Connection) -> None:
    for method in METHOD_REGISTRY:
        con.execute(
            """
            INSERT INTO anomaly_methods
            (id,label,direction,default_weight,default_thresholds_json,variables_json,equation,help,map_layers_json)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              label=excluded.label,
              direction=excluded.direction,
              default_weight=excluded.default_weight,
              default_thresholds_json=excluded.default_thresholds_json,
              variables_json=excluded.variables_json,
              equation=excluded.equation,
              help=excluded.help,
              map_layers_json=excluded.map_layers_json
            """,
            (
                method["id"],
                method["label"],
                method["direction"],
                method["weight"],
                json_dumps(method["thresholds"]),
                json_dumps(method["variables"]),
                method["equation"],
                method["help"],
                json_dumps(method["map_layers"]),
            ),
        )
        con.execute(
            """
            INSERT OR IGNORE INTO method_settings
            (method_id,enabled,weight,thresholds_json,updated_at)
            VALUES (?,?,?,?,?)
            """,
            (method["id"], 1, method["weight"], json_dumps(method["thresholds"]), utc_now()),
        )
    con.commit()


def seed_methods_if_missing(con: sqlite3.Connection) -> None:
    existing_methods = {str(row["id"]) for row in con.execute("SELECT id FROM anomaly_methods").fetchall()}
    existing_settings = {str(row["method_id"]) for row in con.execute("SELECT method_id FROM method_settings").fetchall()}
    required = {str(method["id"]) for method in METHOD_REGISTRY}
    if required.issubset(existing_methods) and required.issubset(existing_settings):
        return
    seed_methods(con)


def seed_app_settings(con: sqlite3.Connection) -> None:
    now = utc_now()
    for key, value in GLOBAL_CONFIG_DEFAULTS.items():
        con.execute(
            """
            INSERT OR IGNORE INTO app_settings(key, value_json, updated_at)
            VALUES (?,?,?)
            """,
            (key, json_dumps(value), now),
        )
    con.commit()


def seed_app_settings_if_missing(con: sqlite3.Connection) -> None:
    existing = {str(row["key"]) for row in con.execute("SELECT key FROM app_settings").fetchall()}
    required = set(GLOBAL_CONFIG_DEFAULTS.keys())
    if required.issubset(existing):
        return
    seed_app_settings(con)


def get_app_config(con: sqlite3.Connection) -> Dict[str, Any]:
    cfg = dict(GLOBAL_CONFIG_DEFAULTS)
    rows = con.execute("SELECT key, value_json FROM app_settings").fetchall()
    for row in rows:
        key = str(row["key"])
        value = json_loads(row["value_json"])
        if key in cfg and value is not None:
            cfg[key] = value
    return cfg


def update_app_config(con: sqlite3.Connection, updates: Dict[str, Any]) -> Dict[str, Any]:
    now = utc_now()
    merged = get_app_config(con)
    for key, value in updates.items():
        if key not in GLOBAL_CONFIG_DEFAULTS:
            continue
        merged[key] = value
        con.execute(
            """
            INSERT INTO app_settings(key, value_json, updated_at)
            VALUES (?,?,?)
            ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
            """,
            (key, json_dumps(value), now),
        )
    con.commit()
    return get_app_config(con)


def get_method_settings(con: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    rows = con.execute(
        """
        SELECT m.*, s.enabled, s.weight, s.thresholds_json
        FROM anomaly_methods m
        JOIN method_settings s ON s.method_id = m.id
        ORDER BY m.id
        """
    ).fetchall()
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        out[row["id"]] = {
            "id": row["id"],
            "label": row["label"],
            "direction": row["direction"],
            "enabled": bool(row["enabled"]),
            "weight": float(row["weight"]),
            "thresholds": json_loads(row["thresholds_json"], {}),
            "default_weight": float(row["default_weight"]),
            "default_thresholds": json_loads(row["default_thresholds_json"], {}),
            "variables": json_loads(row["variables_json"], []),
            "equation": row["equation"],
            "help": row["help"],
            "map_layers": json_loads(row["map_layers_json"], []),
        }
    return out


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def norm_range(value: Any, start: float, full: float) -> float:
    if not isinstance(value, (int, float)) or full == start:
        return 0.0
    return clamp01((float(value) - float(start)) / (float(full) - float(start)))


def z_norm(value: Any, start: float, full: float) -> float:
    return norm_range(value, start, full)


def get_path(obj: Dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def method_input(name: str, features: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "value": get_path(features, name) if "." in name else features.get(name),
        "definition": glossary_definition(name),
    }


def add_method_result(
    results: List[Dict[str, Any]],
    method: Dict[str, Any],
    context: Dict[str, Any],
    norm01: float,
    triggered: bool,
    why: str,
    *,
    altitude_factor: float = 1.0,
    altitude_factor_name: Optional[str] = None,
) -> float:
    weight = float(method["weight"])
    direction = method["direction"]
    base_norm01 = clamp01(norm01)
    altitude_factor = clamp01(altitude_factor)
    effective_norm01 = base_norm01 * altitude_factor if triggered else 0.0
    delta = weight * effective_norm01
    if direction == "down":
        delta = -delta
    if not method["enabled"]:
        delta = 0.0
        triggered = False
        effective_norm01 = 0.0
    result = {
        "id": method["id"],
        "label": method["label"],
        "enabled": method["enabled"],
        "triggered": bool(triggered),
        "direction": direction,
        "weight": weight,
        "thresholds": method["thresholds"],
        "variables": method["variables"],
        "inputs": [method_input(v, context) for v in method["variables"]],
        "equation": method["equation"],
        "why": why,
        "base_norm01": base_norm01,
        "altitude_factor": altitude_factor,
        "altitude_factor_name": altitude_factor_name,
        "norm01": effective_norm01,
        "delta_logodds": delta,
        "odds_multiplier": math.exp(delta),
        "help": method["help"],
        "map_layers": method["map_layers"],
    }
    results.append(result)
    return delta


def evaluate_methods(
    features: Dict[str, Any],
    settings: Dict[str, Dict[str, Any]],
    *,
    mostly_lte: bool,
    known: bool,
    ignored: bool,
    prior: float = 1e-4,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], float, float]:
    results: List[Dict[str, Any]] = []
    total_delta = 0.0
    context = dict(features)
    context["dataset_mostly_lte"] = mostly_lte
    context["known"] = known
    context["ignored"] = ignored

    def m(mid: str) -> Dict[str, Any]:
        return settings[mid]

    def th(mid: str, key: str, default: Any) -> Any:
        return m(mid)["thresholds"].get(key, default)

    def geo_altitude_factor() -> float:
        val = features.get("geo_altitude_confidence")
        return clamp01(val) if isinstance(val, (int, float)) else 1.0

    def stationary_altitude_factor() -> float:
        val = features.get("stationary_geo_altitude_confidence")
        if not isinstance(val, (int, float)):
            val = features.get("geo_altitude_confidence")
        return clamp01(val) if isinstance(val, (int, float)) else 1.0

    sc = features.get("stationary_clusters")
    ssep = features.get("stationary_cluster_top2_sep_m")
    mid = "multi_location_stationary"
    n = norm_range(ssep, th(mid, "sep_start_m", 800), th(mid, "sep_full_m", 5000))
    total_delta += add_method_result(results, m(mid), context, n, bool(sc and sc >= th(mid, "min_clusters", 2) and (features.get("stationary_count") or 0) >= th(mid, "min_stationary_count", 10) and n > 0), "Stationary samples form separated geographic clusters.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "multi_location"
    n = norm_range(features.get("cluster_top2_sep_m"), th(mid, "sep_start_m", 1200), th(mid, "sep_full_m", 6000))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("clusters") or 0) >= th(mid, "min_clusters", 2) and (features.get("count") or 0) >= th(mid, "min_count", 15) and n > 0), "All valid samples form separated geographic clusters.", altitude_factor=geo_altitude_factor(), altitude_factor_name="geo_altitude_confidence")

    mid = "gps_spread"
    n = norm_range(features.get("gps_spread_m"), th(mid, "spread_start_m", 120), th(mid, "spread_full_m", 800))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("count") or 0) >= th(mid, "min_count", 5) and n > 0), "Points are spread around the robust center.", altitude_factor=geo_altitude_factor(), altitude_factor_name="geo_altitude_confidence")

    mid = "center_drift"
    drift = (features.get("center_drift") or {}).get("max_drift_m") if isinstance(features.get("center_drift"), dict) else None
    n = norm_range(drift, th(mid, "drift_start_m", 600), th(mid, "drift_full_m", 5000))
    total_delta += add_method_result(results, m(mid), context, n, bool(((features.get("center_drift") or {}).get("bins") or 0) >= th(mid, "min_bins", 2) and n > 0), "Weekly inferred centers drift apart.", altitude_factor=geo_altitude_factor(), altitude_factor_name="geo_altitude_confidence")

    mid = "signal_distance_mismatch"
    dm = features.get("signal_dist_model") or {}
    n = norm_range(dm.get("outlier_frac") if isinstance(dm, dict) else None, th(mid, "frac_start", 0.12), th(mid, "frac_full", 0.45))
    model_n = dm.get("n") if isinstance(dm, dict) and isinstance(dm.get("n"), (int, float)) else 0
    total_delta += add_method_result(results, m(mid), context, n, bool(model_n >= th(mid, "min_model_n", 12) and n > 0), "Signal has too many residual outliers for its own distance trend.", altitude_factor=geo_altitude_factor(), altitude_factor_name="geo_altitude_confidence")

    mid = "stationary_signal_mad"
    n = z_norm(features.get("stationary_signal_mad_z"), th(mid, "z_start", 2.0), th(mid, "z_full", 6.0))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("stationary_count") or 0) >= th(mid, "min_stationary_count", 15) and n > 0), "Stationary signal variability is high vs baseline.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "stationary_jump_rate"
    n = z_norm(features.get("stationary_jump_rate_z"), th(mid, "z_start", 2.0), th(mid, "z_full", 6.0))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("stationary_count") or 0) >= th(mid, "min_stationary_count", 15) and n > 0), "Stationary signal jumps are high vs baseline.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "stationary_pci_churn"
    n = z_norm(features.get("stationary_pci_change_rate_z"), th(mid, "z_start", 2.0), th(mid, "z_full", 6.0))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("stationary_param_obs") or 0) >= th(mid, "min_obs", 30) and n > 0), "PCI changes often while stationary for the same coarse identity.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "stationary_earfcn_churn"
    n = z_norm(features.get("stationary_earfcn_change_rate_z"), th(mid, "z_start", 2.0), th(mid, "z_full", 6.0))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("stationary_param_obs") or 0) >= th(mid, "min_obs", 30) and n > 0), "EARFCN changes often while stationary for the same coarse identity.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "ephemeral_stationary_opportunity"
    frac = features.get("local_stationary_window_frac")
    window = features.get("local_stationary_window_min")
    stat_count = features.get("stationary_count") or 0
    max_frac = float(th(mid, "max_frac", 0.35))
    full_frac = float(th(mid, "full_frac", 0.05))
    n = 0.0
    if isinstance(frac, (int, float)) and full_frac != max_frac:
        n = clamp01((max_frac - float(frac)) / (max_frac - full_frac))
    total_delta += add_method_result(results, m(mid), context, n, bool(stat_count >= th(mid, "min_stationary_count", 5) and isinstance(window, (int, float)) and window >= th(mid, "min_window_min", 8) and n > 0), "Tower appeared briefly despite stationary nearby opportunity.", altitude_factor=stationary_altitude_factor(), altitude_factor_name="stationary_geo_altitude_confidence")

    mid = "new_in_well_covered_place"
    prior_count = features.get("new_place_prior_count")
    prior_days = features.get("new_place_prior_days")
    tower_place_n = features.get("new_place_count") or 0
    n = norm_range(prior_count, th(mid, "prior_count_start", 120), th(mid, "prior_count_full", 1200))
    triggered = bool(
        isinstance(prior_days, (int, float))
        and prior_days >= th(mid, "min_prior_days", 2)
        and (tower_place_n >= th(mid, "min_tower_count_in_place", 6))
        and n > 0
    )
    total_delta += add_method_result(
        results,
        m(mid),
        context,
        n,
        triggered,
        (
            "Tower first appears in a well-covered place bucket. "
            + (f"First seen: {features.get('new_place_first_seen_local')}. " if features.get("new_place_first_seen_local") else "")
            + (
                f"Prior coverage in this bucket: {features.get('new_place_prior_range')} ({int(prior_days)} distinct days with data). "
                if features.get("new_place_prior_range") and isinstance(prior_days, (int, float))
                else ""
            )
            + (f"Prior good-GPS obs in bucket: {int(prior_count)}. " if isinstance(prior_count, (int, float)) else "")
        ).strip(),
        altitude_factor=geo_altitude_factor(),
        altitude_factor_name="geo_altitude_confidence",
    )

    mid = "new_area_code_in_well_covered_place"
    prior_rr_count = features.get("new_area_code_prior_same_rat_count")
    prior_rr_days = features.get("new_area_code_prior_same_rat_days")
    prior_same_code_count = features.get("new_area_code_prior_same_code_count")
    prior_dom_frac = features.get("new_area_code_prior_dominant_frac")
    tower_place_n3 = features.get("new_place_count") or 0
    coverage_n = norm_range(prior_rr_count, th(mid, "prior_count_start", 40), th(mid, "prior_count_full", 300))
    stability_n = norm_range(prior_dom_frac, th(mid, "dominant_frac_start", 0.65), th(mid, "dominant_frac_full", 0.90))
    n = coverage_n * stability_n
    triggered = bool(
        features.get("tac_lac") is not None
        and isinstance(prior_same_code_count, (int, float))
        and float(prior_same_code_count) <= 0.0
        and isinstance(prior_rr_days, (int, float))
        and prior_rr_days >= th(mid, "min_prior_days", 2)
        and tower_place_n3 >= th(mid, "min_tower_count_in_place", 4)
        and n > 0
    )
    total_delta += add_method_result(
        results,
        m(mid),
        context,
        n,
        triggered,
        (
            "This tower's TAC/LAC first appears in a locally well-covered place for the same operator and RAT. "
            + (f"Current TAC/LAC: {features.get('tac_lac')}. " if features.get("tac_lac") is not None else "")
            + (
                f"Prior same-operator/RAT TAC/LAC coverage in this bucket: {int(prior_rr_count)} obs across {int(prior_rr_days)} day(s). "
                if isinstance(prior_rr_count, (int, float)) and isinstance(prior_rr_days, (int, float))
                else ""
            )
            + (
                f"Dominant prior TAC/LAC: {features.get('new_area_code_prior_dominant_code')} ({float(prior_dom_frac) * 100.0:.1f}% of prior same-operator/RAT observations). "
                if features.get("new_area_code_prior_dominant_code") is not None and isinstance(prior_dom_frac, (int, float))
                else ""
            )
            + (
                f"Prior same-operator/RAT coverage window: {features.get('new_area_code_prior_range')}. "
                if features.get("new_area_code_prior_range")
                else ""
            )
        ).strip(),
        altitude_factor=geo_altitude_factor(),
        altitude_factor_name="geo_altitude_confidence",
    )

    mid = "disappears_despite_coverage"
    post_count = features.get("new_place_post_count")
    post_days = features.get("new_place_post_days")
    tower_place_n2 = features.get("new_place_count") or 0
    n = norm_range(post_count, th(mid, "post_count_start", 120), th(mid, "post_count_full", 1200))
    triggered = bool(
        isinstance(post_days, (int, float))
        and post_days >= th(mid, "min_post_days", 2)
        and (tower_place_n2 >= th(mid, "min_tower_count_in_place", 6))
        and n > 0
    )
    total_delta += add_method_result(
        results,
        m(mid),
        context,
        n,
        triggered,
        "Tower stops appearing even though later coverage exists in its main place bucket.",
        altitude_factor=geo_altitude_factor(),
        altitude_factor_name="geo_altitude_confidence",
    )

    mid = "place_change_correlation"
    frac2 = features.get("change_places_frac_stationary")
    if not isinstance(frac2, (int, float)):
        frac2 = features.get("change_places_frac")
    n = norm_range(frac2, th(mid, "frac_start", 0.35), th(mid, "frac_full", 0.80))
    total_delta += add_method_result(
        results,
        m(mid),
        context,
        n,
        bool((features.get("count") or 0) >= th(mid, "min_count", 20) and n > 0),
        "Tower is concentrated in place buckets where the local signal behavior changed over time (earlier vs later looks different).",
    )

    mid = "rat_transition_surprise"
    n = norm_range(features.get("place_rat_surprise"), th(mid, "surprise_start", 0.9), th(mid, "surprise_full", 2.0))
    total_delta += add_method_result(results, m(mid), context, n, bool((features.get("count") or 0) >= th(mid, "min_count", 30) and n > 0), "Place-level RAT transitions are unusually surprising.")

    mid = "non_lte_when_mostly_lte"
    rat = str(features.get("rat") or "").upper()
    n = 1.0 if rat in {"GSM", "2G"} and mostly_lte else 0.0
    total_delta += add_method_result(results, m(mid), context, n, n > 0, "This is a non-LTE tower in a mostly-LTE dataset.")

    mid = "wigle_absent"
    checked = bool(features.get("wigle_checked"))
    exists = bool(features.get("wigle_exists"))
    n = 1.0 if checked and not exists else 0.0
    total_delta += add_method_result(results, m(mid), context, n, n > 0, "An explicit WiGLE lookup found no exact PLMN/TAC-LAC/Cell-ID match.")

    mid = "wigle_historical_presence"
    first_age = features.get("wigle_first_seen_age_days")
    last_age = features.get("wigle_last_seen_age_days")
    historical_n = norm_range(first_age, th(mid, "first_age_start_days", 90), th(mid, "first_age_full_days", 730))
    recent_n = 0.0
    last_age_full = float(th(mid, "last_age_full_days", 90))
    last_age_max = float(th(mid, "last_age_max_days", 730))
    if isinstance(last_age, (int, float)) and last_age_max != last_age_full:
        recent_n = clamp01((last_age_max - float(last_age)) / (last_age_max - last_age_full))
    n = historical_n * recent_n
    total_delta += add_method_result(
        results,
        m(mid),
        context,
        n,
        bool(checked and exists and n > 0),
        "An exact WiGLE record lowers suspicion more when its first appearance is older and its latest appearance is recent.",
    )

    mid = "stability"
    n = clamp01(float(features.get("stability_bonus") or 0.0) / 1.5)
    total_delta += add_method_result(results, m(mid), context, n, n > 0, "Stable repeated evidence lowers suspicion.")

    mid = "many_days"
    days = features.get("days_seen")
    n = 0.0
    if isinstance(days, (int, float)):
        n = norm_range(days, th(mid, "days_start", 2), th(mid, "days_full", 10))
    total_delta += add_method_result(results, m(mid), context, n, n > 0, "Long-lived cells seen across days lower suspicion.")

    if known:
        total_delta -= 2.0
        results.append({
            "id": "known_tower",
            "label": "Known/verified tower",
            "enabled": True,
            "triggered": True,
            "direction": "down",
            "weight": 2.0,
            "thresholds": {},
            "variables": ["known"],
            "inputs": [{"name": "known", "value": True, "definition": "User-marked verified/known tower."}],
            "equation": "Δlogodds = -2.0",
            "why": "You marked this tower known; it should still show anomalies but rank lower.",
            "base_norm01": 1.0,
            "altitude_factor": 1.0,
            "altitude_factor_name": None,
            "norm01": 1.0,
            "delta_logodds": -2.0,
            "odds_multiplier": math.exp(-2.0),
            "help": "Manual negative evidence to reduce false positives.",
            "map_layers": [],
        })
    if ignored:
        total_delta -= 4.0

    prior_logit = logit(prior)
    post = logistic(prior_logit + total_delta)
    running = prior_logit
    for item in sorted(results, key=lambda x: abs(float(x.get("delta_logodds") or 0)), reverse=True):
        item["p_before"] = logistic(running)
        running += float(item["delta_logodds"])
        item["p_after"] = logistic(running)
        item["delta_p"] = item["p_after"] - item["p_before"]

    rule_score = sum(abs(float(r["delta_logodds"])) for r in results if r.get("triggered") and r.get("direction") == "up")
    bayes = {
        "prior": prior,
        "prior_logit": prior_logit,
        "total_delta_logodds": total_delta,
        "posterior": post,
        "explanation": "logit(posterior) = logit(prior) + sum(enabled method Δ log-odds). Negative evidence lowers the final probability.",
    }
    return results, bayes, rule_score, post


def upsert_tower(con: sqlite3.Connection, key: TowerKey) -> int:
    identity = tower_identity_key(key)
    coarse = base_identity_key(BaseKey(key.operator, key.rat, key.tac_lac, key.cell_id))
    now = utc_now()
    con.execute(
        """
        INSERT INTO towers
        (identity_key,coarse_identity_key,operator,rat,tac_lac,cell_id,pci,earfcn,label,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(identity_key) DO UPDATE SET updated_at=excluded.updated_at
        """,
        (identity, coarse, key.operator or "", key.rat or "", key.tac_lac, key.cell_id, key.pci, key.earfcn, key.label(), now, now),
    )
    return int(con.execute("SELECT id FROM towers WHERE identity_key=?", (identity,)).fetchone()["id"])


def gps_meta(obj: Dict[str, Any]) -> Tuple[str, str, Optional[float]]:
    gpsd = obj.get("gps_device") or {}
    source = gpsd.get("location_source") or ("gps_device" if gpsd else "modem")
    status = gpsd.get("status") or ""
    hdop = None
    for path in (("hdop",), ("gga", "hdop"), ("gsa", "hdop")):
        cur: Any = gpsd
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, (int, float)):
            hdop = float(cur)
            break
    return str(source or ""), str(status or ""), hdop


def _gps_device_has_valid_fix(gpsd: Dict[str, Any]) -> bool:
    status = str(gpsd.get("status") or ((gpsd.get("rmc") or {}).get("status") or "")).upper()
    fix_quality = gpsd.get("fix_quality")
    fix_type = gpsd.get("fix_type")
    return bool(
        status == "A"
        or (isinstance(fix_quality, (int, float)) and float(fix_quality) > 0)
        or (isinstance(fix_type, (int, float)) and float(fix_type) >= 2)
    )


def _modem_has_valid_fix(gps: Dict[str, Any]) -> bool:
    cgns = gps.get("cgnsinf") or {}
    fix_status = cgns.get("fix_status")
    return bool(isinstance(fix_status, (int, float)) and float(fix_status) > 0)


def sample_alt_m(obj: Dict[str, Any]) -> Optional[float]:
    if not isinstance(obj, dict):
        return None
    location = obj.get("location") or {}
    source = str(location.get("source") or "").lower() if isinstance(location, dict) else ""
    gpsd = obj.get("gps_device") or {}
    if source == "gps_device" and isinstance(gpsd, dict):
        valid = _gps_device_has_valid_fix(gpsd)
        if valid and isinstance(location, dict) and isinstance(location.get("alt_m"), (int, float)):
            return float(location["alt_m"])
        dloc = gpsd.get("location") or {}
        if valid and isinstance(dloc, dict) and isinstance(dloc.get("alt_m"), (int, float)):
            return float(dloc["alt_m"])
        gga = gpsd.get("gga") or {}
        if valid and isinstance(gga, dict) and isinstance(gga.get("alt_m"), (int, float)):
            return float(gga["alt_m"])
        return None
    if isinstance(gpsd, dict):
        valid = _gps_device_has_valid_fix(gpsd)
        dloc = gpsd.get("location") or {}
        if valid and isinstance(dloc, dict) and isinstance(dloc.get("alt_m"), (int, float)):
            return float(dloc["alt_m"])
        gga = gpsd.get("gga") or {}
        if valid and isinstance(gga, dict) and isinstance(gga.get("alt_m"), (int, float)):
            return float(gga["alt_m"])
    gps = obj.get("gps") or obj.get("gps_lte_modem") or {}
    if source == "lte_modem" and isinstance(gps, dict):
        valid = _modem_has_valid_fix(gps)
        if valid and isinstance(location, dict) and isinstance(location.get("alt_m"), (int, float)):
            return float(location["alt_m"])
        cgns = gps.get("cgnsinf") or {}
        if valid and isinstance(cgns, dict) and isinstance(cgns.get("alt_m"), (int, float)):
            return float(cgns["alt_m"])
        return None
    if isinstance(gps, dict):
        valid = _modem_has_valid_fix(gps)
        cgns = gps.get("cgnsinf") or {}
        if valid and isinstance(cgns, dict) and isinstance(cgns.get("alt_m"), (int, float)):
            return float(cgns["alt_m"])
    if isinstance(location, dict) and source not in {"gps_device", "lte_modem"} and isinstance(location.get("alt_m"), (int, float)):
        return float(location["alt_m"])
    return None


def sample_has_valid_location_fix(obj: Dict[str, Any]) -> bool:
    """
    Best-effort validity check for the location fix used by hack-wanderer.

    We intentionally keep this conservative: if the location source is explicit
    (gps_device / lte_modem), require that source to report a valid fix.
    Otherwise, assume "valid enough" and let the speed-jump heuristic catch
    implausible points.
    """
    if not isinstance(obj, dict):
        return True
    loc = obj.get("location") or {}
    source = str(loc.get("source") or "").lower() if isinstance(loc, dict) else ""
    if source == "gps_device":
        gpsd = obj.get("gps_device") or {}
        return _gps_device_has_valid_fix(gpsd) if isinstance(gpsd, dict) else False
    if source == "lte_modem":
        gps = obj.get("gps") or obj.get("gps_lte_modem") or {}
        return _modem_has_valid_fix(gps) if isinstance(gps, dict) else False
    return True


def quantile(values: Sequence[float], q: float) -> Optional[float]:
    if not values:
        return None
    xs = sorted(float(v) for v in values)
    if len(xs) == 1:
        return xs[0]
    q = max(0.0, min(1.0, float(q)))
    pos = q * (len(xs) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return xs[lo]
    frac = pos - lo
    return xs[lo] * (1.0 - frac) + xs[hi] * frac


def robust_ground_altitude(values: Sequence[float], *, iqr_k: float) -> Optional[float]:
    if not values:
        return None
    xs = sorted(float(v) for v in values)
    if len(xs) < 4:
        return min(xs)
    q1 = quantile(xs, 0.25)
    q3 = quantile(xs, 0.75)
    if not isinstance(q1, (int, float)) or not isinstance(q3, (int, float)):
        return min(xs)
    iqr = max(0.0, float(q3) - float(q1))
    lower_fence = float(q1) - max(0.0, float(iqr_k)) * iqr
    kept = [x for x in xs if x >= lower_fence]
    return min(kept) if kept else min(xs)


def altitude_confidence_weight(relative_alt_m: float, config: Optional[Dict[str, Any]] = None) -> float:
    cfg = config or GLOBAL_CONFIG_DEFAULTS
    rel = max(0.0, float(relative_alt_m))
    no_discount = float(cfg.get("altitude_no_discount_until_m", GLOBAL_CONFIG_DEFAULTS["altitude_no_discount_until_m"]))
    half_height = max(0.1, float(cfg.get("altitude_half_value_height_m", GLOBAL_CONFIG_DEFAULTS["altitude_half_value_height_m"])))
    min_conf = clamp01(float(cfg.get("altitude_min_confidence", GLOBAL_CONFIG_DEFAULTS["altitude_min_confidence"])))
    if rel <= no_discount:
        return 1.0
    exponent = (rel - no_discount) / half_height
    return max(min_conf, 0.5 ** exponent)


def altitude_discount_examples(config: Dict[str, Any]) -> List[Dict[str, float]]:
    no_discount = float(config.get("altitude_no_discount_until_m", GLOBAL_CONFIG_DEFAULTS["altitude_no_discount_until_m"]))
    half_height = float(config.get("altitude_half_value_height_m", GLOBAL_CONFIG_DEFAULTS["altitude_half_value_height_m"]))
    marks = sorted({0.0, no_discount, no_discount + half_height, no_discount + 2.0 * half_height, float(config.get("altitude_high_point_m", GLOBAL_CONFIG_DEFAULTS["altitude_high_point_m"]))})
    out: List[Dict[str, float]] = []
    for rel in marks:
        out.append({"relative_altitude_m": rel, "altitude_factor": altitude_confidence_weight(rel, config)})
    return out


def _speed_to_mps(value: Any, unit: str) -> Optional[float]:
    if not isinstance(value, (int, float)):
        return None
    speed = float(value)
    if unit == "knots":
        return speed * 0.514444
    if unit == "kph":
        return speed / 3.6
    if unit == "mps":
        return speed
    return None


def _gps_device_speed_mps(obj: Dict[str, Any]) -> Optional[float]:
    gpsd = obj.get("gps_device") or {}
    if not isinstance(gpsd, dict):
        return None
    if not _gps_device_has_valid_fix(gpsd):
        return None
    loc = gpsd.get("location") or {}
    if not isinstance(loc, dict):
        return None
    for key, unit in (("speed_mps", "mps"), ("speed_knots", "knots"), ("speed_kph", "kph")):
        speed = _speed_to_mps(loc.get(key), unit)
        if speed is not None:
            return speed
    return None


def _modem_speed_mps(obj: Dict[str, Any]) -> Optional[float]:
    gps = obj.get("gps") or obj.get("gps_lte_modem") or {}
    if not isinstance(gps, dict):
        return None
    if not _modem_has_valid_fix(gps):
        return None
    cgns = gps.get("cgnsinf") or {}
    if not isinstance(cgns, dict):
        return None
    for key, unit in (("speed_mps", "mps"), ("speed_kph", "kph"), ("speed_knots", "knots")):
        speed = _speed_to_mps(cgns.get(key), unit)
        if speed is not None:
            return speed
    return None


def sample_direct_speed_mps(obj: Dict[str, Any]) -> Optional[float]:
    if not isinstance(obj, dict):
        return None
    location = obj.get("location") or {}
    source = str(location.get("source") or "").lower() if isinstance(location, dict) else ""
    if source == "gps_device":
        gpsd = obj.get("gps_device")
        if isinstance(gpsd, dict) and gpsd:
            return _gps_device_speed_mps(obj)
    elif source == "lte_modem":
        gps = obj.get("gps") or obj.get("gps_lte_modem")
        if isinstance(gps, dict) and gps:
            return _modem_speed_mps(obj)
    for key, unit in (("speed_mps", "mps"), ("speed_knots", "knots"), ("speed_kph", "kph")):
        if isinstance(location, dict):
            speed = _speed_to_mps(location.get(key), unit)
            if speed is not None:
                return speed
    speed = _gps_device_speed_mps(obj)
    if speed is not None:
        return speed
    return _modem_speed_mps(obj)


def backfill_raw_sample_altitudes(con: sqlite3.Connection, *, batch_size: int = 1000) -> int:
    updated = 0
    pending: List[Tuple[float, str]] = []
    rows = con.execute("SELECT sample_uid, raw_json FROM raw_samples WHERE alt_m IS NULL")
    for row in rows:
        obj = json_loads(row["raw_json"], {})
        alt_m = sample_alt_m(obj) if isinstance(obj, dict) else None
        if not isinstance(alt_m, (int, float)):
            continue
        pending.append((float(alt_m), str(row["sample_uid"])))
        if len(pending) >= batch_size:
            con.executemany("UPDATE raw_samples SET alt_m=? WHERE sample_uid=?", pending)
            updated += len(pending)
            pending = []
    if pending:
        con.executemany("UPDATE raw_samples SET alt_m=? WHERE sample_uid=?", pending)
        updated += len(pending)
    return updated


def _multipart_boundary(content_type: str) -> Optional[bytes]:
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type or "", flags=re.I)
    if not match:
        return None
    boundary = (match.group(1) or match.group(2) or "").strip()
    return boundary.encode("utf-8") if boundary else None


def _parse_content_disposition(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            out.setdefault("type", part.lower())
            continue
        key, raw = part.split("=", 1)
        raw = raw.strip()
        if raw.startswith('"') and raw.endswith('"'):
            raw = raw[1:-1].replace('\\"', '"')
        out[key.strip().lower()] = raw
    return out


def parse_multipart_paths(content_type: str, body: bytes, upload_dir: Path) -> List[str]:
    """
    Dependency-free multipart/form-data parser for the local upload form.

    Starlette's `request.form()` requires `python-multipart`. This fallback keeps
    the "Upload + import" button working even when that package is missing.
    It is intentionally narrow: it extracts fields named `files` and optional
    text fields named `paths`.
    """
    boundary = _multipart_boundary(content_type)
    if not boundary:
        raise ValueError("multipart boundary missing")
    upload_dir.mkdir(exist_ok=True)
    paths: List[str] = []
    marker = b"--" + boundary
    for part in body.split(marker):
        if not part or part in (b"--", b"--\r\n"):
            continue
        part = part.strip(b"\r\n")
        if part.endswith(b"--"):
            part = part[:-2].rstrip(b"\r\n")
        if b"\r\n\r\n" not in part:
            continue
        raw_headers, data = part.split(b"\r\n\r\n", 1)
        headers: Dict[str, str] = {}
        for line in raw_headers.decode("utf-8", "replace").split("\r\n"):
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
        disp = _parse_content_disposition(headers.get("content-disposition", ""))
        name = disp.get("name")
        filename = disp.get("filename")
        if name == "paths":
            text = data.decode("utf-8", "replace").strip()
            if text:
                paths.append(text)
            continue
        if name != "files" or not filename:
            continue
        safe_name = Path(filename).name or "upload.jsonl"
        target = upload_dir / safe_name
        if target.exists():
            stem = target.stem
            suffix = target.suffix
            target = upload_dir / f"{stem}-{stable_uid(filename, len(data))[:10]}{suffix}"
        target.write_bytes(data)
        paths.append(str(target))
    return paths


def ingest_files(
    db_path: str,
    paths: Sequence[str],
    *,
    max_lines: Optional[int] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    init_db(db_path, seed_reference_data=False)
    summary = {
        "files": [],
        "imported_rows": 0,
        "new_samples": 0,
        "tower_fingerprints": 0,
        "new_towers": 0,
        "tower_observations": 0,
        "new_observations": 0,
        "errors": 0,
        "skipped": 0,
        "files_imported": 0,
        "files_skipped": 0,
    }
    progress_state: Dict[str, Any] = {
        "active": True,
        "task": "import",
        "phase": "starting",
        "started_at": utc_now(),
        "total_files": len(paths),
        "file_index": 0,
        "current_path": "",
        "current_file_size": 0,
        "current_file_bytes": 0,
        "current_file_percent": 0.0,
        "current_rows": 0,
        "current_observations": 0,
        "current_errors": 0,
        "imported_rows": 0,
        "tower_observations": 0,
        "files_imported": 0,
        "files_skipped": 0,
        "errors": 0,
        "result": None,
        "detail": None,
    }
    emit_import_progress(progress_callback, progress_state)
    with connect_db(db_path) as con:
        db_before = _count_db_entities(con)
        for file_index, path0 in enumerate(paths, 1):
            path = str(Path(path0).expanduser().resolve())
            st = os.stat(path)
            digest = file_sha256(path)
            progress_state.update({
                "phase": "checking",
                "file_index": file_index,
                "current_path": path,
                "current_file_size": int(st.st_size),
                "current_file_bytes": 0,
                "current_file_percent": 0.0,
                "current_rows": 0,
                "current_observations": 0,
                "current_errors": 0,
                "files_imported": summary["files_imported"] if "files_imported" in summary else 0,
                "files_skipped": summary["skipped"],
                "errors": summary["errors"],
            })
            emit_import_progress(progress_callback, progress_state)
            existing = con.execute(
                """
                SELECT id, imported_rows, new_samples, tower_fingerprints, new_towers, observation_rows, new_observations, errors
                FROM import_files WHERE path=? AND size=? AND mtime=? AND sha256=?
                """,
                (path, int(st.st_size), float(st.st_mtime), digest),
            ).fetchone()
            if existing:
                summary["skipped"] += 1
                summary["files"].append({
                    "path": path,
                    "status": "skipped",
                    "rows": existing["imported_rows"],
                    "new_samples": existing["new_samples"],
                    "tower_fingerprints": existing["tower_fingerprints"],
                    "new_towers": existing["new_towers"],
                    "tower_observations": existing["observation_rows"],
                    "new_observations": existing["new_observations"],
                    "errors": existing["errors"],
                })
                progress_state.update({
                    "phase": "skipped",
                    "files_skipped": summary["skipped"],
                    "errors": summary["errors"],
                })
                emit_import_progress(progress_callback, progress_state)
                continue
            counts_before_file = _count_db_entities(con)
            cur = con.execute(
                "INSERT INTO import_files(path,size,mtime,sha256,imported_at) VALUES (?,?,?,?,?)",
                (path, int(st.st_size), float(st.st_mtime), digest, utc_now()),
            )
            import_id = int(cur.lastrowid)
            imported_rows = 0
            fingerprints_seen: set[str] = set()
            observation_rows = 0
            errors = 0
            prev_fix: Optional[Tuple[float, float, float]] = None
            bytes_read = 0
            last_progress_emit = time.monotonic()
            progress_state.update({"phase": "importing"})
            emit_import_progress(progress_callback, progress_state)
            with open(path, "rb") as f:
                for line_no, raw in enumerate(f, 1):
                    if max_lines is not None and line_no > max_lines:
                        break
                    bytes_read += len(raw)
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line.decode("utf-8", "replace"))
                        if not isinstance(obj, dict):
                            continue
                    except Exception:
                        errors += 1
                        continue
                    ts = parse_obj_ts(obj)
                    ts_iso = timestamp_from_obj(obj)
                    loc = pick_location(obj)
                    lat = lon = None
                    place_id = None
                    bad_gps = 0
                    if loc is not None:
                        lat, lon = loc
                        if not sample_has_valid_location_fix(obj):
                            bad_gps = 1
                        if ts is not None and prev_fix is not None:
                            speed = implied_speed_mps(prev_fix[0], prev_fix[1], prev_fix[2], lat, lon, ts)
                            if speed is not None and speed > BAD_GPS_SPEED_MPS:
                                bad_gps = 1
                        if ts is not None and not bad_gps:
                            prev_fix = (lat, lon, ts)
                        try:
                            x, y = latlon_to_tile(lat, lon, PLACE_ZOOM)
                            place_id = f"z{PLACE_ZOOM}/{x}/{y}"
                        except Exception:
                            place_id = None
                    content_hash = stable_uid(ts_iso or "", line)
                    sample_uid = stable_uid(digest, line_no, ts_iso or "", content_hash)
                    gps_source, gps_status, hdop = gps_meta(obj)
                    alt_m = sample_alt_m(obj)
                    con.execute(
                        """
                        INSERT OR IGNORE INTO raw_samples
                        (sample_uid,content_hash,import_id,line_no,ts,ts_iso,lat,lon,alt_m,gps_source,gps_status,hdop,bad_gps,place_id,raw_json)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (sample_uid, content_hash, import_id, line_no, ts, ts_iso, lat, lon, alt_m, gps_source, gps_status, hdop, bad_gps, place_id, json_dumps(obj)),
                    )
                    operator = extract_operator(obj)
                    obs_count = 0
                    for cell in iter_observed_cells(obj):
                        key = tower_key_from_cell(operator, cell)
                        if key.cell_id is None and key.tac_lac is None and key.pci is None and key.earfcn is None:
                            continue
                        fingerprints_seen.add(tower_identity_key(key))
                        observation_rows += 1
                        tower_id = upsert_tower(con, key)
                        signal = observation_signal(obj, cell)
                        obs_uid = stable_uid(content_hash, tower_identity_key(key), obs_count)
                        obs_count += 1
                        con.execute(
                            """
                            INSERT OR IGNORE INTO tower_observations
                            (obs_uid,sample_uid,tower_id,coarse_identity_key,ts,lat,lon,place_id,signal,raw_cell_json,bad_gps)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)
                            """,
                            (obs_uid, sample_uid, tower_id, base_identity_key(BaseKey(key.operator, key.rat, key.tac_lac, key.cell_id)), ts, lat, lon, place_id, signal, json_dumps(cell), bad_gps),
                        )
                    imported_rows += 1
                    now_mono = time.monotonic()
                    if imported_rows == 1 or imported_rows % 200 == 0 or (now_mono - last_progress_emit) >= 0.75:
                        progress_state.update({
                            "phase": "importing",
                            "current_file_bytes": bytes_read,
                            "current_file_percent": (100.0 * bytes_read / max(1, int(st.st_size))),
                            "current_rows": imported_rows,
                            "current_observations": observation_rows,
                            "current_errors": errors,
                            "imported_rows": summary["imported_rows"] + imported_rows,
                            "tower_observations": summary["tower_observations"] + observation_rows,
                            "files_imported": summary.get("files_imported", 0),
                            "files_skipped": summary["skipped"],
                            "errors": summary["errors"] + errors,
                        })
                        emit_import_progress(progress_callback, progress_state)
                        last_progress_emit = now_mono
                    # Commit in smaller batches to reduce long-held write locks,
                    # so the UI can still perform small updates (e.g. ignore a point).
                    if imported_rows % 200 == 0:
                        con.commit()
            counts_after_file = _count_db_entities(con)
            file_summary = {
                "path": path,
                "status": "imported",
                "rows": imported_rows,
                "new_samples": counts_after_file["raw_samples"] - counts_before_file["raw_samples"],
                "tower_fingerprints": len(fingerprints_seen),
                "new_towers": counts_after_file["towers"] - counts_before_file["towers"],
                "tower_observations": observation_rows,
                "new_observations": counts_after_file["tower_observations"] - counts_before_file["tower_observations"],
                "errors": errors,
            }
            con.execute(
                """
                UPDATE import_files
                SET imported_rows=?, new_samples=?, tower_fingerprints=?, new_towers=?, observation_rows=?, new_observations=?, errors=?
                WHERE id=?
                """,
                (
                    file_summary["rows"],
                    file_summary["new_samples"],
                    file_summary["tower_fingerprints"],
                    file_summary["new_towers"],
                    file_summary["tower_observations"],
                    file_summary["new_observations"],
                    file_summary["errors"],
                    import_id,
                ),
            )
            con.commit()
            summary["files"].append(file_summary)
            summary["imported_rows"] += file_summary["rows"]
            summary["new_samples"] += file_summary["new_samples"]
            summary["tower_fingerprints"] += file_summary["tower_fingerprints"]
            summary["new_towers"] += file_summary["new_towers"]
            summary["tower_observations"] += file_summary["tower_observations"]
            summary["new_observations"] += file_summary["new_observations"]
            summary["errors"] += file_summary["errors"]
            summary["files_imported"] = summary.get("files_imported", 0) + 1
            progress_state.update({
                "phase": "file_done",
                "current_file_bytes": int(st.st_size),
                "current_file_percent": 100.0,
                "current_rows": imported_rows,
                "current_observations": observation_rows,
                "current_errors": errors,
                "imported_rows": summary["imported_rows"],
                "tower_observations": summary["tower_observations"],
                "files_imported": summary["files_imported"],
                "files_skipped": summary["skipped"],
                "errors": summary["errors"],
            })
            emit_import_progress(progress_callback, progress_state)
        progress_state.update({
            "phase": "finalizing",
            "files_imported": summary.get("files_imported", 0),
            "files_skipped": summary["skipped"],
            "errors": summary["errors"],
            "imported_rows": summary["imported_rows"],
            "tower_observations": summary["tower_observations"],
        })
        emit_import_progress(progress_callback, progress_state)
        refresh_stationary_flags(con, progress_callback=progress_callback)
        con.commit()
        db_after = _count_db_entities(con)
    summary["db_before"] = db_before
    summary["db_after"] = db_after
    summary["db_delta"] = {key: db_after[key] - db_before[key] for key in db_before.keys()}
    summary["files_imported"] = sum(1 for item in summary["files"] if item.get("status") == "imported")
    summary["files_skipped"] = sum(1 for item in summary["files"] if item.get("status") == "skipped")
    progress_state.update({
        "active": False,
        "phase": "done",
        "finished_at": utc_now(),
        "files_imported": summary["files_imported"],
        "files_skipped": summary["files_skipped"],
        "errors": summary["errors"],
        "imported_rows": summary["imported_rows"],
        "tower_observations": summary["tower_observations"],
        "result": summary,
    })
    emit_import_progress(progress_callback, progress_state)
    return summary


def refresh_stationary_flags(
    con: sqlite3.Connection,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> None:
    total_rows = int(con.execute(
        "SELECT COUNT(*) FROM raw_samples WHERE ts IS NOT NULL AND lat IS NOT NULL AND lon IS NOT NULL"
    ).fetchone()[0] or 0)
    segments: List[List[sqlite3.Row]] = []
    cur: List[sqlite3.Row] = []
    anchor: Optional[sqlite3.Row] = None
    prev: Optional[sqlite3.Row] = None
    processed = 0
    last_progress_emit = time.monotonic()

    def report_scan(force: bool = False) -> None:
        nonlocal last_progress_emit
        now_mono = time.monotonic()
        if not force and processed and processed % 1000 != 0 and (now_mono - last_progress_emit) < 0.75:
            return
        emit_import_progress(progress_callback, {
            "phase": "finalizing_stationary_scan",
            "finalize_scan_done": processed,
            "finalize_scan_total": total_rows,
        })
        last_progress_emit = now_mono

    def flush() -> None:
        nonlocal cur
        if len(cur) < 2:
            cur = []
            return
        start = cur[0]["ts"]
        end = cur[-1]["ts"]
        if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end - start >= STATIONARY_MIN_DUR_S:
            segments.append(list(cur))
        cur = []

    cursor = con.execute(
        "SELECT sample_uid, ts, lat, lon, bad_gps, raw_json FROM raw_samples WHERE ts IS NOT NULL AND lat IS NOT NULL AND lon IS NOT NULL ORDER BY ts, id"
    )
    for row in cursor:
        processed += 1
        if row["bad_gps"]:
            flush()
            anchor = None
            prev = None
            report_scan()
            continue
        ok = False
        if anchor is None:
            ok = True
        else:
            dist_anchor = haversine_m(anchor["lat"], anchor["lon"], row["lat"], row["lon"])
            implied_speed = None
            if prev is not None:
                implied_speed = implied_speed_mps(prev["lat"], prev["lon"], prev["ts"], row["lat"], row["lon"], row["ts"])
            try:
                raw_obj = json.loads(row["raw_json"]) if row["raw_json"] else {}
            except Exception:
                raw_obj = {}
            direct_speed = sample_direct_speed_mps(raw_obj)
            ok = (
                dist_anchor <= STATIONARY_RADIUS_M
                and (implied_speed is None or implied_speed <= STATIONARY_MAX_SPEED_MPS)
                and (direct_speed is None or direct_speed <= STATIONARY_MAX_REPORTED_SPEED_MPS)
            )
        if not ok:
            flush()
            anchor = row
            cur = [row]
        else:
            if anchor is None:
                anchor = row
            cur.append(row)
        prev = row
        report_scan()
    flush()
    report_scan(force=True)
    con.execute("UPDATE raw_samples SET stationary=0, stationary_segment=NULL")
    con.execute("UPDATE tower_observations SET stationary=0, stationary_segment=NULL")

    total_apply = sum(len(seg) for seg in segments)
    applied = 0
    last_apply_emit = time.monotonic()

    def report_apply(force: bool = False) -> None:
        nonlocal last_apply_emit
        now_mono = time.monotonic()
        if not force and applied and applied % 1000 != 0 and (now_mono - last_apply_emit) < 0.75:
            return
        emit_import_progress(progress_callback, {
            "phase": "finalizing_stationary_apply",
            "finalize_apply_done": applied,
            "finalize_apply_total": total_apply,
        })
        last_apply_emit = now_mono

    report_apply(force=True)
    for seg_id, seg in enumerate(segments, 1):
        uids = [str(r["sample_uid"]) for r in seg]
        for chunk in _iter_chunks(uids, 500):
            placeholders = ",".join("?" for _ in chunk)
            params = [seg_id, *chunk]
            con.execute(
                f"UPDATE raw_samples SET stationary=1, stationary_segment=? WHERE sample_uid IN ({placeholders})",
                params,
            )
            con.execute(
                f"UPDATE tower_observations SET stationary=1, stationary_segment=? WHERE sample_uid IN ({placeholders})",
                params,
            )
            applied += len(chunk)
            report_apply()
    report_apply(force=True)


def row_to_tower_key(row: sqlite3.Row) -> TowerKey:
    return TowerKey(
        operator=row["operator"] or "",
        rat=row["rat"] or "",
        tac_lac=row["tac_lac"],
        cell_id=row["cell_id"],
        pci=row["pci"],
        earfcn=row["earfcn"],
    )


def compute_place_metrics(place_aggs: Dict[str, PlaceAgg]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for pid, p in place_aggs.items():
        sample = sorted(p.signal_sample, key=lambda x: x[0])
        stat_sample = sorted(p.signal_sample_stationary, key=lambda x: x[0])
        def change(vals: List[Tuple[float, float]]) -> Dict[str, Any]:
            if len(vals) < 40:
                return {"changed": False, "n": len(vals)}
            mid = len(vals) // 2
            a = [x[1] for x in vals[:mid]]
            b = [x[1] for x in vals[mid:]]
            ks = ks_2samp(a, b)
            cus = cusum_change_score([x[1] for x in vals])
            changed = bool((isinstance(ks, (int, float)) and ks >= 0.35) or (isinstance(cus, (int, float)) and cus >= 12))
            return {"changed": changed, "n": len(vals), "ks_d": ks, "cusum": cus}
        all_change = change(sample)
        stat_change = change(stat_sample)
        out[pid] = {
            "place_total": p.count,
            "place_dur_min": ((p.last_seen_ts or 0) - (p.first_seen_ts or 0)) / 60.0 if p.first_seen_ts and p.last_seen_ts else None,
            "stationary_total": p.stationary_count,
            "stationary_dur_min": ((p.last_stationary_ts or 0) - (p.first_stationary_ts or 0)) / 60.0 if p.first_stationary_ts and p.last_stationary_ts else None,
            "changed": all_change.get("changed"),
            "ks_d": all_change.get("ks_d"),
            "cusum": all_change.get("cusum"),
            "changed_stationary": stat_change.get("changed"),
            "ks_d_stationary": stat_change.get("ks_d"),
            "cusum_stationary": stat_change.get("cusum"),
            "rat_surprise": p.rat_surprise(),
            "distinct_towers_est": p.distinct_towers_est(),
            "bounds": _place_bounds(pid),
        }
    return out


def _place_bounds(place_id: str) -> Optional[Dict[str, float]]:
    try:
        zpart, xpart, ypart = place_id.split("/")
        z = int(zpart[1:])
        x = int(xpart)
        y = int(ypart)
        south, west, north, east = tile_bounds_latlon(z, x, y)
        return {"south": south, "west": west, "north": north, "east": east}
    except Exception:
        return None


def compute_place_altitude_floors(con: sqlite3.Connection, config: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    cfg = config or GLOBAL_CONFIG_DEFAULTS
    place_values: Dict[str, List[float]] = defaultdict(list)
    rows = con.execute(
        "SELECT place_id, alt_m FROM raw_samples WHERE place_id IS NOT NULL AND alt_m IS NOT NULL AND bad_gps=0"
    )
    for row in rows:
        place_values[str(row["place_id"])].append(float(row["alt_m"]))
    floors: Dict[str, float] = {}
    for place_id, values in place_values.items():
        floor = robust_ground_altitude(values, iqr_k=float(cfg.get("altitude_floor_iqr_k", GLOBAL_CONFIG_DEFAULTS["altitude_floor_iqr_k"])))
        if isinstance(floor, (int, float)):
            floors[place_id] = float(floor)
    return floors


def make_altitude_acc() -> Dict[str, Any]:
    return {
        "count": 0,
        "high_count": 0,
        "weight_sum": 0.0,
        "sample_seen": 0,
        "sample": [],
        "stationary_count": 0,
        "stationary_high_count": 0,
        "stationary_weight_sum": 0.0,
        "stationary_seen": 0,
        "stationary_sample": [],
    }


def _reservoir_add(sample: List[float], seen: int, value: float, sample_size: int, rng: random.Random) -> None:
    if sample_size <= 0:
        return
    if len(sample) < sample_size:
        sample.append(float(value))
        return
    j = rng.randrange(seen)
    if j < sample_size:
        sample[j] = float(value)


def add_altitude_obs(acc: Dict[str, Any], relative_alt_m: float, *, stationary: bool, rng: random.Random, config: Optional[Dict[str, Any]] = None, sample_size: int = 512) -> None:
    cfg = config or GLOBAL_CONFIG_DEFAULTS
    rel = max(0.0, float(relative_alt_m))
    weight = altitude_confidence_weight(rel, cfg)
    high_point_m = float(cfg.get("altitude_high_point_m", GLOBAL_CONFIG_DEFAULTS["altitude_high_point_m"]))
    acc["count"] += 1
    acc["weight_sum"] += weight
    if rel >= high_point_m:
        acc["high_count"] += 1
    acc["sample_seen"] += 1
    _reservoir_add(acc["sample"], int(acc["sample_seen"]), rel, sample_size, rng)
    if stationary:
        acc["stationary_count"] += 1
        acc["stationary_weight_sum"] += weight
        if rel >= high_point_m:
            acc["stationary_high_count"] += 1
        acc["stationary_seen"] += 1
        _reservoir_add(acc["stationary_sample"], int(acc["stationary_seen"]), rel, sample_size, rng)


def recompute(
    db_path: str,
    *,
    sample_size: int = 2500,
    refresh_stationary: bool = False,
    backfill_altitudes: bool = True,
) -> Dict[str, Any]:
    init_db(db_path)
    rng = random.Random(1)
    with connect_db(db_path) as con:
        if backfill_altitudes:
            backfill_raw_sample_altitudes(con)
        if refresh_stationary:
            refresh_stationary_flags(con)
        if backfill_altitudes or refresh_stationary:
            con.commit()
        settings = get_method_settings(con)
        app_config = get_app_config(con)
        tower_rows = {int(r["id"]): r for r in con.execute("SELECT * FROM towers").fetchall()}
        aggs: Dict[int, TowerAgg] = {}
        base_aggs: Dict[str, BaseAgg] = {}
        place_aggs: Dict[str, PlaceAgg] = {}

        # For "new tower in well-covered place" we need to know how much a place
        # was observed before a given tower first appeared there. Because rows
        # are ordered by timestamp, we can compute these as running counters.
        place_seen_total: Dict[str, int] = defaultdict(int)
        place_seen_stationary: Dict[str, int] = defaultdict(int)
        place_day_count: Dict[str, int] = defaultdict(int)
        place_last_day: Dict[str, int] = {}
        place_first_day: Dict[str, int] = {}
        place_stationary_day_count: Dict[str, int] = defaultdict(int)
        place_stationary_last_day: Dict[str, int] = {}
        place_rr_seen_total: Dict[Tuple[str, str, str], int] = defaultdict(int)
        place_rr_day_count: Dict[Tuple[str, str, str], int] = defaultdict(int)
        place_rr_last_day: Dict[Tuple[str, str, str], int] = {}
        place_rr_first_day: Dict[Tuple[str, str, str], int] = {}
        place_rr_code_counts: Dict[Tuple[str, str, str], Counter] = defaultdict(Counter)

        first_seen_in_place: set[Tuple[int, str]] = set()
        tower_place_prior: Dict[Tuple[int, str], Dict[str, Any]] = {}
        tower_place_area_prior: Dict[Tuple[int, str], Dict[str, Any]] = {}
        tower_main_place: Dict[int, str] = {}

        def day_id_utc(ts: float) -> int:
            d = dt.datetime.fromtimestamp(float(ts), dt.timezone.utc)
            return d.year * 10000 + d.month * 100 + d.day

        place_altitude_floor = compute_place_altitude_floors(con, app_config)
        altitude_aggs: Dict[int, Dict[str, Any]] = defaultdict(make_altitude_acc)
        rows = con.execute(
            """
            SELECT o.*, t.operator,t.rat,t.tac_lac,t.cell_id,t.pci,t.earfcn, r.alt_m
            FROM tower_observations o
            JOIN towers t ON t.id=o.tower_id
            LEFT JOIN raw_samples r ON r.sample_uid=o.sample_uid
            WHERE o.ts IS NOT NULL AND o.lat IS NOT NULL AND o.lon IS NOT NULL AND COALESCE(o.ignored,0)=0
            ORDER BY o.ts, o.id
            """
        )
        for row in rows:
            tid = int(row["tower_id"])
            key = row_to_tower_key(row)
            if tid not in aggs:
                aggs[tid] = TowerAgg(key=key, first_seen_ts=float(row["ts"]), last_seen_ts=float(row["ts"]))
            agg = aggs[tid]
            if row["bad_gps"]:
                agg.bad_gps_skipped += 1
                continue
            place_id = row["place_id"]
            ts = float(row["ts"])
            if place_id:
                pid = str(place_id)
                # Record prior place coverage the first time we ever see this tower in this place.
                tp = (tid, pid)
                if tp not in first_seen_in_place:
                    tower_place_prior[tp] = {
                        "prior_count": int(place_seen_total.get(pid, 0)),
                        "prior_stationary_count": int(place_seen_stationary.get(pid, 0)),
                        "prior_days": int(place_day_count.get(pid, 0)),
                        "prior_stationary_days": int(place_stationary_day_count.get(pid, 0)),
                        "prior_first_day": place_first_day.get(pid),
                        "prior_last_day": place_last_day.get(pid),
                        "first_seen_ts": ts,
                    }
                    if key.tac_lac is not None:
                        rr_key = (pid, key.operator or "", key.rat or "")
                        rr_counts = place_rr_code_counts.get(rr_key) or Counter()
                        dominant_code = None
                        dominant_count = 0
                        if rr_counts:
                            dominant_code, dominant_count = max(
                                rr_counts.items(),
                                key=lambda kv: (int(kv[1]), str(kv[0])),
                            )
                        rr_total = int(place_rr_seen_total.get(rr_key, 0))
                        tower_place_area_prior[tp] = {
                            "prior_same_rat_count": rr_total,
                            "prior_same_rat_days": int(place_rr_day_count.get(rr_key, 0)),
                            "prior_same_code_count": int(rr_counts.get(key.tac_lac, 0)),
                            "prior_distinct_codes": int(len(rr_counts)),
                            "prior_dominant_code": dominant_code,
                            "prior_dominant_frac": (float(dominant_count) / float(rr_total)) if rr_total > 0 else None,
                            "prior_first_day": place_rr_first_day.get(rr_key),
                            "prior_last_day": place_rr_last_day.get(rr_key),
                        }
                    first_seen_in_place.add(tp)
            alt_m = float(row["alt_m"]) if isinstance(row["alt_m"], (int, float)) else None
            place_floor = place_altitude_floor.get(str(place_id)) if place_id else None
            relative_alt_m = max(0.0, alt_m - place_floor) if isinstance(alt_m, (int, float)) and isinstance(place_floor, (int, float)) else None
            if isinstance(relative_alt_m, (int, float)):
                add_altitude_obs(altitude_aggs[tid], float(relative_alt_m), stationary=bool(row["stationary"]), rng=rng, config=app_config)
            signal = row["signal"]
            agg.add(
                ts,
                float(row["lat"]),
                float(row["lon"]),
                float(signal) if isinstance(signal, (int, float)) else None,
                place_id,
                sample_size=sample_size,
                cluster_radius_m=400.0,
                max_clusters=64,
                session_gap_s=6 * 3600.0,
                rng=rng,
            )
            if row["stationary"]:
                seg = int(row["stationary_segment"] or 0)
                agg.add_stationary(
                    ts,
                    float(row["lat"]),
                    float(row["lon"]),
                    float(signal) if isinstance(signal, (int, float)) else None,
                    segment_id=seg,
                    signal_sample_size=1000,
                    pts_sample_size=1000,
                    rng=rng,
                )
                bkey = BaseKey(key.operator, key.rat, key.tac_lac, key.cell_id)
                bidentity = base_identity_key(bkey)
                base_aggs.setdefault(bidentity, BaseAgg(bkey)).add_stationary(key.pci, key.earfcn, segment_id=seg)
            if place_id:
                # Update per-place running coverage counters AFTER processing the row.
                pid = str(place_id)
                # Track the current best "main" place bucket for this tower (highest count).
                # Used later for prior/post coverage features.
                if tid not in tower_main_place:
                    tower_main_place[tid] = pid
                else:
                    cur = tower_main_place[tid]
                    if (agg.places.get(pid, 0) > agg.places.get(cur, 0)) or (
                        agg.places.get(pid, 0) == agg.places.get(cur, 0) and str(pid) > str(cur)
                    ):
                        tower_main_place[tid] = pid
                day = day_id_utc(ts)
                if pid not in place_first_day:
                    place_first_day[pid] = day
                if place_last_day.get(pid) != day:
                    place_last_day[pid] = day
                    place_day_count[pid] += 1
                place_seen_total[pid] += 1
                if row["stationary"]:
                    if place_stationary_last_day.get(pid) != day:
                        place_stationary_last_day[pid] = day
                        place_stationary_day_count[pid] += 1
                    place_seen_stationary[pid] += 1
                if key.tac_lac is not None:
                    rr_key = (pid, key.operator or "", key.rat or "")
                    if rr_key not in place_rr_first_day:
                        place_rr_first_day[rr_key] = day
                    if place_rr_last_day.get(rr_key) != day:
                        place_rr_last_day[rr_key] = day
                        place_rr_day_count[rr_key] += 1
                    place_rr_seen_total[rr_key] += 1
                    place_rr_code_counts[rr_key][key.tac_lac] += 1
                place_aggs.setdefault(place_id, PlaceAgg(place_id)).add(ts, key, signal, stationary=bool(row["stationary"]))

        # Post-coverage ("disappears despite coverage") stats per tower's main place bucket.
        # We define "later coverage" as valid observations on subsequent UTC days after the
        # tower's last-seen day. This matches the intended question: "I was in that area on
        # later days and saw other towers, but never saw this one again."
        tower_place_post: Dict[Tuple[int, str], Dict[str, Any]] = {}
        if tower_main_place:
            need_pids = sorted(set(tower_main_place.values()))
            qmarks = ",".join(["?"] * len(need_pids))
            # Precompute per-(place_id, day) totals once, then each tower can slice by its last day.
            day_rows = con.execute(
                f"""
                SELECT
                  o.place_id,
                  CAST(strftime('%Y%m%d', o.ts, 'unixepoch') AS INT) AS day_id,
                  COUNT(*) AS c,
                  SUM(CASE WHEN o.stationary THEN 1 ELSE 0 END) AS sc
                FROM tower_observations o
                WHERE o.ts IS NOT NULL
                  AND o.place_id IN ({qmarks})
                  AND o.bad_gps=0
                  AND COALESCE(o.ignored,0)=0
                GROUP BY o.place_id, day_id
                """,
                tuple(need_pids),
            ).fetchall()
            per_pid_days: Dict[str, List[Tuple[int, int, int]]] = defaultdict(list)
            for r in day_rows:
                per_pid_days[str(r["place_id"])].append((int(r["day_id"]), int(r["c"]), int(r["sc"] or 0)))
            for pid in per_pid_days.keys():
                per_pid_days[pid].sort(key=lambda t: t[0])

            for tid, pid in tower_main_place.items():
                a = aggs.get(int(tid))
                if not a or not isinstance(a.last_seen_ts, (int, float)):
                    continue
                last_day = day_id_utc(float(a.last_seen_ts))
                post_count = 0
                post_days = 0
                post_stationary_count = 0
                post_stationary_days = 0
                for day_id, c, sc in per_pid_days.get(str(pid), []):
                    if day_id <= last_day:
                        continue
                    post_count += int(c)
                    if c:
                        post_days += 1
                    post_stationary_count += int(sc)
                    if sc:
                        post_stationary_days += 1
                tower_place_post[(int(tid), str(pid))] = {
                    "post_count": int(post_count),
                    "post_days": int(post_days),
                    "post_stationary_count": int(post_stationary_count),
                    "post_stationary_days": int(post_stationary_days),
                }

        agg_list = list(aggs.values())
        for a in agg_list:
            points = [(lat, lon, sig) for (lat, lon, sig, _ts) in a.sample]
            a.center_lat, a.center_lon, a.center_meta = robust_center(points) if points else (None, None, {"n": 0, "n_used": 0})
        global_stats = compute_global_stats(agg_list)
        global_stats["cluster_radius_m"] = 400.0
        # Cache global stats so we can do fast single-tower recomputes without
        # rescanning the entire dataset.
        set_app_setting(con, "global_stats_cache", {"computed_at": utc_now(), "stats": global_stats})

        for tid, a in aggs.items():
            a.features, a.anomaly_score = compute_features(a, global_stats)
            a.features["rat"] = a.key.rat
            a.features["tac_lac"] = a.key.tac_lac
            coarse = base_identity_key(BaseKey(a.key.operator, a.key.rat, a.key.tac_lac, a.key.cell_id))
            ba = base_aggs.get(coarse)
            if ba and ba.stationary_obs > 0:
                a.features["stationary_param_obs"] = ba.stationary_obs
                a.features["stationary_pci_distinct"] = len(ba.distinct_pci)
                a.features["stationary_earfcn_distinct"] = len(ba.distinct_earfcn)
                a.features["stationary_pci_change_rate"] = ba.pci_changes / max(1, ba.stationary_obs)
                a.features["stationary_earfcn_change_rate"] = ba.earfcn_changes / max(1, ba.stationary_obs)
            aalt = altitude_aggs.get(tid)
            if aalt:
                a.features["altitude_samples"] = aalt["count"]
                a.features["altitude_rel_median_m"] = median(aalt["sample"]) if aalt["sample"] else None
                a.features["altitude_rel_p90_m"] = quantile(aalt["sample"], 0.90) if aalt["sample"] else None
                a.features["high_altitude_obs_frac"] = (aalt["high_count"] / aalt["count"]) if aalt["count"] else None
                a.features["geo_altitude_confidence"] = max(ALTITUDE_MIN_CONFIDENCE, min(1.0, aalt["weight_sum"] / aalt["count"])) if aalt["count"] else 1.0
                a.features["stationary_altitude_samples"] = aalt["stationary_count"]
                a.features["stationary_altitude_rel_median_m"] = median(aalt["stationary_sample"]) if aalt["stationary_sample"] else None
                a.features["stationary_altitude_rel_p90_m"] = quantile(aalt["stationary_sample"], 0.90) if aalt["stationary_sample"] else None
                a.features["stationary_high_altitude_obs_frac"] = (aalt["stationary_high_count"] / aalt["stationary_count"]) if aalt["stationary_count"] else None
                if aalt["stationary_count"]:
                    a.features["stationary_geo_altitude_confidence"] = max(ALTITUDE_MIN_CONFIDENCE, min(1.0, aalt["stationary_weight_sum"] / aalt["stationary_count"]))
                else:
                    a.features["stationary_geo_altitude_confidence"] = a.features["geo_altitude_confidence"]
            else:
                a.features["altitude_samples"] = 0
                a.features["altitude_rel_median_m"] = None
                a.features["altitude_rel_p90_m"] = None
                a.features["high_altitude_obs_frac"] = None
                a.features["geo_altitude_confidence"] = 1.0
                a.features["stationary_altitude_samples"] = 0
                a.features["stationary_altitude_rel_median_m"] = None
                a.features["stationary_altitude_rel_p90_m"] = None
                a.features["stationary_high_altitude_obs_frac"] = None
                a.features["stationary_geo_altitude_confidence"] = 1.0
            a.features["altitude_model"] = {
                "ground_estimator": "robust_min_after_low_outlier_rejection",
                "altitude_floor_iqr_k": app_config["altitude_floor_iqr_k"],
                "altitude_no_discount_until_m": app_config["altitude_no_discount_until_m"],
                "altitude_half_value_height_m": app_config["altitude_half_value_height_m"],
                "altitude_high_point_m": app_config["altitude_high_point_m"],
                "altitude_min_confidence": app_config["altitude_min_confidence"],
                "examples": altitude_discount_examples(app_config),
            }
        churn_baselines = apply_stationary_param_churn(agg_list)
        place_metrics = compute_place_metrics(place_aggs)

        for tid, a in aggs.items():
            pdetails = []
            changed_count = 0
            changed_count_stationary = 0
            rat_surprises = []
            stationary_firsts = []
            stationary_lasts = []
            for pid, count in a.places.items():
                pm = place_metrics.get(pid, {})
                if pm.get("changed"):
                    changed_count += count
                if pm.get("changed_stationary"):
                    changed_count_stationary += count
                if isinstance(pm.get("rat_surprise"), (int, float)):
                    rat_surprises.append(float(pm["rat_surprise"]))
                pa = place_aggs.get(pid)
                if pa and pa.first_stationary_ts is not None and pa.last_stationary_ts is not None:
                    stationary_firsts.append(pa.first_stationary_ts)
                    stationary_lasts.append(pa.last_stationary_ts)
                pdetails.append({"place_id": pid, "count": count, **pm})
            # New tower in well-covered place: attach prior coverage features for the tower's
            # most common place bucket.
            if a.places:
                top_pid, top_cnt = max(a.places.items(), key=lambda kv: (kv[1], str(kv[0])))
                a.features["new_place_id"] = str(top_pid)
                a.features["new_place_count"] = int(top_cnt)
                prior = tower_place_prior.get((tid, str(top_pid))) or {}
                a.features["new_place_prior_count"] = prior.get("prior_count")
                a.features["new_place_prior_days"] = prior.get("prior_days")
                a.features["new_place_prior_stationary_count"] = prior.get("prior_stationary_count")
                a.features["new_place_prior_stationary_days"] = prior.get("prior_stationary_days")
                fst = prior.get("first_seen_ts")
                if isinstance(fst, (int, float)):
                    a.features["new_place_first_seen_ts"] = float(fst)
                    # Render a human-friendly local timestamp (machine timezone).
                    try:
                        a.features["new_place_first_seen_local"] = dt.datetime.fromtimestamp(float(fst), dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                    except Exception:
                        a.features["new_place_first_seen_local"] = None
                d0 = _day_id_to_datestr(prior.get("prior_first_day"))
                d1 = _day_id_to_datestr(prior.get("prior_last_day"))
                if d0 and d1:
                    a.features["new_place_prior_range"] = f"{d0} .. {d1}"
                elif d0:
                    a.features["new_place_prior_range"] = f"{d0}"
                else:
                    a.features["new_place_prior_range"] = None
                area_prior = tower_place_area_prior.get((tid, str(top_pid))) or {}
                a.features["new_area_code_prior_same_rat_count"] = area_prior.get("prior_same_rat_count")
                a.features["new_area_code_prior_same_rat_days"] = area_prior.get("prior_same_rat_days")
                a.features["new_area_code_prior_same_code_count"] = area_prior.get("prior_same_code_count")
                a.features["new_area_code_prior_distinct_codes"] = area_prior.get("prior_distinct_codes")
                a.features["new_area_code_prior_dominant_code"] = area_prior.get("prior_dominant_code")
                a.features["new_area_code_prior_dominant_frac"] = area_prior.get("prior_dominant_frac")
                d0 = _day_id_to_datestr(area_prior.get("prior_first_day"))
                d1 = _day_id_to_datestr(area_prior.get("prior_last_day"))
                if d0 and d1:
                    a.features["new_area_code_prior_range"] = f"{d0} .. {d1}"
                elif d0:
                    a.features["new_area_code_prior_range"] = f"{d0}"
                else:
                    a.features["new_area_code_prior_range"] = None
                post = tower_place_post.get((tid, str(top_pid))) or {}
                a.features["new_place_post_count"] = post.get("post_count")
                a.features["new_place_post_days"] = post.get("post_days")
                a.features["new_place_post_stationary_count"] = post.get("post_stationary_count")
                a.features["new_place_post_stationary_days"] = post.get("post_stationary_days")
            a.features["place_details"] = pdetails[:30]
            if a.count:
                a.features["change_places_frac"] = changed_count / max(1, a.count)
                a.features["change_places_frac_stationary"] = changed_count_stationary / max(1, a.count)
            if rat_surprises:
                a.features["place_rat_surprise"] = statistics.mean(rat_surprises)
            if stationary_firsts and stationary_lasts:
                window_s = max(stationary_lasts) - min(stationary_firsts)
                a.features["local_stationary_window_min"] = window_s / 60.0
                span = a.features.get("stationary_span_s")
                a.features["local_stationary_window_frac"] = (float(span) / window_s) if isinstance(span, (int, float)) and window_s > 0 else None
            a.features["bad_gps_skipped"] = a.bad_gps_skipped

        mostly_lte = bool(global_stats.get("mostly_lte"))
        con.execute("DELETE FROM tower_features")
        now = utc_now()
        updated = 0
        for tid, agg in aggs.items():
            tower_row = tower_rows.get(tid)
            known = bool(tower_row["known"]) if tower_row else False
            ignored = bool(tower_row["ignored"]) if tower_row else False
            apply_wigle_features(agg.features, get_wigle_enrichment(con, tid))
            methods, bayes, rule_score, post = evaluate_methods(agg.features, settings, mostly_lte=mostly_lte, known=known, ignored=ignored)
            con.execute(
                """
                INSERT INTO tower_features
                (tower_id,computed_at,count,center_lat,center_lon,first_seen_ts,last_seen_ts,rule_score,bayes_post_p,features_json,methods_json,bayes_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tid,
                    now,
                    agg.count,
                    agg.center_lat,
                    agg.center_lon,
                    agg.first_seen_ts,
                    agg.last_seen_ts,
                    rule_score,
                    post,
                    json_dumps(agg.features),
                    json_dumps(methods),
                    json_dumps(bayes),
                ),
            )
            updated += 1
        con.commit()
        return {"updated_towers": updated, "computed_at": now, "global_stats": global_stats, "churn_baselines": churn_baselines}


def _count_db_entities(con: sqlite3.Connection) -> Dict[str, int]:
    return {
        "imports": int(con.execute("SELECT COUNT(*) c FROM import_files").fetchone()["c"]),
        "raw_samples": int(con.execute("SELECT COUNT(*) c FROM raw_samples").fetchone()["c"]),
        "tower_observations": int(con.execute("SELECT COUNT(*) c FROM tower_observations").fetchone()["c"]),
        "towers": int(con.execute("SELECT COUNT(*) c FROM towers").fetchone()["c"]),
        "features": int(con.execute("SELECT COUNT(*) c FROM tower_features").fetchone()["c"]),
    }


def _global_stats_cached(con: sqlite3.Connection) -> Dict[str, Any]:
    cached = get_app_setting(con, "global_stats_cache", {}) or {}
    if isinstance(cached, dict) and isinstance(cached.get("stats"), dict):
        return dict(cached["stats"])
    return {}


def _compute_churn_baselines_from_features(con: sqlite3.Connection) -> Dict[str, Any]:
    """
    Compute churn baselines from existing tower_features rows.
    Used to support fast single-tower recompute without building all aggs.
    """
    pci_rates: List[float] = []
    earfcn_rates: List[float] = []
    rows = con.execute("SELECT features_json FROM tower_features").fetchall()
    for r in rows:
        feats = json_loads(r["features_json"], {}) or {}
        obs = feats.get("stationary_param_obs")
        if not isinstance(obs, (int, float)) or int(obs) < 20:
            continue
        pr = feats.get("stationary_pci_change_rate")
        er = feats.get("stationary_earfcn_change_rate")
        if isinstance(pr, (int, float)):
            pci_rates.append(float(pr))
        if isinstance(er, (int, float)):
            earfcn_rates.append(float(er))
    return {
        "stationary_pci_change_rate_median": median(pci_rates) if pci_rates else None,
        "stationary_pci_change_rate_mad": mad(pci_rates) if pci_rates else None,
        "stationary_earfcn_change_rate_median": median(earfcn_rates) if earfcn_rates else None,
        "stationary_earfcn_change_rate_mad": mad(earfcn_rates) if earfcn_rates else None,
    }


def recompute_one_tower(db_path: str, tower_id: int, *, sample_size: int = 2500) -> Dict[str, Any]:
    """
    Fast-ish recompute for a single tower.

    Uses cached global stats from the last full recompute for z-score baselines.
    Recomputes this tower's own features from its (non-ignored, non-bad-gps) observations,
    and updates just its row in tower_features.
    """
    init_db(db_path)
    rng = random.Random(1)
    with connect_db(db_path) as con:
        settings = get_method_settings(con)
        app_config = get_app_config(con)
        tower_row = con.execute("SELECT * FROM towers WHERE id=?", (int(tower_id),)).fetchone()
        if not tower_row:
            raise ValueError("tower not found")
        global_stats = _global_stats_cached(con)
        if "cluster_radius_m" not in global_stats:
            global_stats["cluster_radius_m"] = 400.0

        # Build TowerAgg for this tower from non-bad-gps, non-ignored observations.
        key = TowerKey(
            operator=tower_row["operator"] or "",
            rat=tower_row["rat"] or "",
            tac_lac=tower_row["tac_lac"],
            cell_id=tower_row["cell_id"],
            pci=tower_row["pci"],
            earfcn=tower_row["earfcn"],
        )
        rows = con.execute(
            """
            SELECT o.*, r.alt_m
            FROM tower_observations o
            LEFT JOIN raw_samples r ON r.sample_uid=o.sample_uid
            WHERE o.tower_id=?
              AND o.ts IS NOT NULL AND o.lat IS NOT NULL AND o.lon IS NOT NULL
              AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
            ORDER BY o.ts, o.id
            """,
            (int(tower_id),),
        ).fetchall()
        if not rows:
            # Still create an empty-ish features row so the UI doesn't break.
            now = utc_now()
            con.execute(
                """
                INSERT INTO tower_features
                (tower_id,computed_at,count,center_lat,center_lon,first_seen_ts,last_seen_ts,rule_score,bayes_post_p,features_json,methods_json,bayes_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(tower_id) DO UPDATE SET
                  computed_at=excluded.computed_at,
                  count=excluded.count,
                  center_lat=excluded.center_lat,
                  center_lon=excluded.center_lon,
                  first_seen_ts=excluded.first_seen_ts,
                  last_seen_ts=excluded.last_seen_ts,
                  rule_score=excluded.rule_score,
                  bayes_post_p=excluded.bayes_post_p,
                  features_json=excluded.features_json,
                  methods_json=excluded.methods_json,
                  bayes_json=excluded.bayes_json
                """,
                (int(tower_id), now, 0, None, None, None, None, 0.0, 0.0, json_dumps({}), json_dumps([]), json_dumps({})),
            )
            con.commit()
            return {"updated_towers": 1, "computed_at": now}

        agg = TowerAgg(key=key, first_seen_ts=float(rows[0]["ts"]), last_seen_ts=float(rows[-1]["ts"]))

        # Altitude floors for only the places this tower uses.
        place_ids = sorted({str(r["place_id"]) for r in rows if r["place_id"]})
        floors: Dict[str, float] = {}
        if place_ids:
            qmarks = ",".join(["?"] * len(place_ids))
            alt_rows = con.execute(
                f"SELECT place_id, alt_m FROM raw_samples WHERE place_id IN ({qmarks}) AND alt_m IS NOT NULL AND bad_gps=0",
                tuple(place_ids),
            ).fetchall()
            by_place: Dict[str, List[float]] = defaultdict(list)
            for r in alt_rows:
                by_place[str(r["place_id"])].append(float(r["alt_m"]))
            for pid, vals in by_place.items():
                floor = robust_ground_altitude(vals, iqr_k=float(app_config.get("altitude_floor_iqr_k", GLOBAL_CONFIG_DEFAULTS["altitude_floor_iqr_k"])))
                if isinstance(floor, (int, float)):
                    floors[pid] = float(floor)
        alt_acc = make_altitude_acc()

        # Populate agg.
        for r in rows:
            ts = float(r["ts"])
            lat = float(r["lat"])
            lon = float(r["lon"])
            sig = float(r["signal"]) if isinstance(r["signal"], (int, float)) else None
            pid = r["place_id"]
            agg.add(
                ts,
                lat,
                lon,
                sig,
                pid,
                sample_size=sample_size,
                cluster_radius_m=400.0,
                max_clusters=64,
                session_gap_s=6 * 3600.0,
                rng=rng,
            )
            if r["stationary"]:
                seg = int(r["stationary_segment"] or 0)
                agg.add_stationary(
                    ts,
                    lat,
                    lon,
                    sig,
                    segment_id=seg,
                    signal_sample_size=1000,
                    pts_sample_size=1000,
                    rng=rng,
                )
            alt_m = float(r["alt_m"]) if isinstance(r["alt_m"], (int, float)) else None
            if isinstance(alt_m, (int, float)) and pid and str(pid) in floors:
                rel = max(0.0, float(alt_m) - float(floors[str(pid)]))
                add_altitude_obs(alt_acc, rel, stationary=bool(r["stationary"]), rng=rng, config=app_config)

        # Center + per-tower features.
        pts = [(lat, lon, sig) for (lat, lon, sig, _ts) in agg.sample]
        agg.center_lat, agg.center_lon, agg.center_meta = robust_center(pts) if pts else (None, None, {"n": 0, "n_used": 0})
        feats, rule_score = compute_features(agg, global_stats)
        agg.features = feats
        agg.anomaly_score = rule_score
        agg.features["rat"] = agg.key.rat
        agg.features["tac_lac"] = agg.key.tac_lac

        # Altitude features (same shape as full recompute).
        agg.features["altitude_samples"] = alt_acc["count"]
        agg.features["altitude_rel_median_m"] = median(alt_acc["sample"]) if alt_acc["sample"] else None
        agg.features["altitude_rel_p90_m"] = quantile(alt_acc["sample"], 0.90) if alt_acc["sample"] else None
        agg.features["high_altitude_obs_frac"] = (alt_acc["high_count"] / alt_acc["count"]) if alt_acc["count"] else None
        agg.features["geo_altitude_confidence"] = max(ALTITUDE_MIN_CONFIDENCE, min(1.0, alt_acc["weight_sum"] / alt_acc["count"])) if alt_acc["count"] else 1.0
        agg.features["stationary_altitude_samples"] = alt_acc["stationary_count"]
        agg.features["stationary_altitude_rel_median_m"] = median(alt_acc["stationary_sample"]) if alt_acc["stationary_sample"] else None
        agg.features["stationary_altitude_rel_p90_m"] = quantile(alt_acc["stationary_sample"], 0.90) if alt_acc["stationary_sample"] else None
        agg.features["stationary_high_altitude_obs_frac"] = (alt_acc["stationary_high_count"] / alt_acc["stationary_count"]) if alt_acc["stationary_count"] else None
        if alt_acc["stationary_count"]:
            agg.features["stationary_geo_altitude_confidence"] = max(ALTITUDE_MIN_CONFIDENCE, min(1.0, alt_acc["stationary_weight_sum"] / alt_acc["stationary_count"]))
        else:
            agg.features["stationary_geo_altitude_confidence"] = agg.features["geo_altitude_confidence"]

        # Churn baselines from existing features.
        churn_base = _compute_churn_baselines_from_features(con)
        obs = agg.features.get("stationary_param_obs")
        if isinstance(obs, int) and obs >= 20:
            pr = agg.features.get("stationary_pci_change_rate")
            pr_med = churn_base.get("stationary_pci_change_rate_median")
            pr_mad = churn_base.get("stationary_pci_change_rate_mad")
            if isinstance(pr, (int, float)) and isinstance(pr_med, (int, float)) and isinstance(pr_mad, (int, float)) and float(pr_mad) > 1e-9:
                agg.features["stationary_pci_change_rate_z"] = (float(pr) - float(pr_med)) / float(pr_mad)
            er = agg.features.get("stationary_earfcn_change_rate")
            er_med = churn_base.get("stationary_earfcn_change_rate_median")
            er_mad = churn_base.get("stationary_earfcn_change_rate_mad")
            if isinstance(er, (int, float)) and isinstance(er_med, (int, float)) and isinstance(er_mad, (int, float)) and float(er_mad) > 1e-9:
                agg.features["stationary_earfcn_change_rate_z"] = (float(er) - float(er_med)) / float(er_mad)

        # Place-aware features for this tower: compute place metrics only for this tower's places.
        place_aggs: Dict[str, PlaceAgg] = {}
        if place_ids:
            qmarks = ",".join(["?"] * len(place_ids))
            prow = con.execute(
                f"""
                SELECT o.ts, o.signal, o.stationary, o.place_id, t.operator,t.rat,t.tac_lac,t.cell_id,t.pci,t.earfcn
                FROM tower_observations o
                JOIN towers t ON t.id=o.tower_id
                WHERE o.place_id IN ({qmarks})
                  AND o.ts IS NOT NULL AND o.lat IS NOT NULL AND o.lon IS NOT NULL
                  AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                ORDER BY o.ts
                """,
                tuple(place_ids),
            ).fetchall()
            for r in prow:
                pid = str(r["place_id"])
                k = TowerKey(operator=r["operator"] or "", rat=r["rat"] or "", tac_lac=r["tac_lac"], cell_id=r["cell_id"], pci=r["pci"], earfcn=r["earfcn"])
                place_aggs.setdefault(pid, PlaceAgg(pid)).add(float(r["ts"]), k, r["signal"], stationary=bool(r["stationary"]))
            place_metrics = compute_place_metrics(place_aggs)
            pdetails = []
            changed_count = 0
            changed_count_stationary = 0
            rat_surprises = []
            stationary_firsts = []
            stationary_lasts = []
            for pid, count in agg.places.items():
                pm = place_metrics.get(pid, {})
                if pm.get("changed"):
                    changed_count += count
                if pm.get("changed_stationary"):
                    changed_count_stationary += count
                if isinstance(pm.get("rat_surprise"), (int, float)):
                    rat_surprises.append(float(pm["rat_surprise"]))
                pa = place_aggs.get(pid)
                if pa and pa.first_stationary_ts is not None and pa.last_stationary_ts is not None:
                    stationary_firsts.append(pa.first_stationary_ts)
                    stationary_lasts.append(pa.last_stationary_ts)
                pdetails.append({"place_id": pid, "count": count, **pm})
            agg.features["place_details"] = pdetails[:30]
            if agg.count:
                agg.features["change_places_frac"] = changed_count / max(1, agg.count)
                agg.features["change_places_frac_stationary"] = changed_count_stationary / max(1, agg.count)
            if rat_surprises:
                agg.features["place_rat_surprise"] = statistics.mean(rat_surprises)
            if stationary_firsts and stationary_lasts:
                window_s = max(stationary_lasts) - min(stationary_firsts)
                agg.features["local_stationary_window_min"] = window_s / 60.0
                span = agg.features.get("stationary_span_s")
                agg.features["local_stationary_window_frac"] = (float(span) / window_s) if isinstance(span, (int, float)) and window_s > 0 else None

        # New-in-well-covered-place features for top place.
        if agg.places:
            top_pid, top_cnt = max(agg.places.items(), key=lambda kv: (kv[1], str(kv[0])))
            agg.features["new_place_id"] = str(top_pid)
            agg.features["new_place_count"] = int(top_cnt)
            first_ts = con.execute(
                "SELECT MIN(ts) AS m FROM tower_observations WHERE tower_id=? AND place_id=? AND bad_gps=0 AND COALESCE(ignored,0)=0",
                (int(tower_id), str(top_pid)),
            ).fetchone()["m"]
            if isinstance(first_ts, (int, float)):
                agg.features["new_place_first_seen_ts"] = float(first_ts)
                try:
                    agg.features["new_place_first_seen_local"] = dt.datetime.fromtimestamp(float(first_ts), dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    agg.features["new_place_first_seen_local"] = None
                row = con.execute(
                    "SELECT COUNT(*) c FROM tower_observations WHERE place_id=? AND ts<? AND bad_gps=0 AND COALESCE(ignored,0)=0",
                    (str(top_pid), float(first_ts)),
                ).fetchone()
                agg.features["new_place_prior_count"] = int(row["c"])
                row = con.execute(
                    "SELECT COUNT(DISTINCT CAST(ts/86400 AS INT)) d FROM tower_observations WHERE place_id=? AND ts<? AND bad_gps=0 AND COALESCE(ignored,0)=0",
                    (str(top_pid), float(first_ts)),
                ).fetchone()
                agg.features["new_place_prior_days"] = int(row["d"] or 0)
                rrange = con.execute(
                    """
                    SELECT
                      MIN(CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT)) AS mn,
                      MAX(CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT)) AS mx
                    FROM tower_observations
                    WHERE place_id=? AND ts<? AND bad_gps=0 AND COALESCE(ignored,0)=0
                    """,
                    (str(top_pid), float(first_ts)),
                ).fetchone()
                d0 = _day_id_to_datestr(rrange["mn"] if rrange else None)
                d1 = _day_id_to_datestr(rrange["mx"] if rrange else None)
                if d0 and d1:
                    agg.features["new_place_prior_range"] = f"{d0} .. {d1}"
                elif d0:
                    agg.features["new_place_prior_range"] = f"{d0}"
                else:
                    agg.features["new_place_prior_range"] = None
                if key.tac_lac is not None:
                    row = con.execute(
                        """
                        SELECT COUNT(*) c
                        FROM tower_observations o
                        JOIN towers t ON t.id=o.tower_id
                        WHERE o.place_id=? AND o.ts<? AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                          AND COALESCE(t.operator,'')=? AND COALESCE(t.rat,'')=?
                          AND t.tac_lac IS NOT NULL
                        """,
                        (str(top_pid), float(first_ts), key.operator or "", key.rat or ""),
                    ).fetchone()
                    agg.features["new_area_code_prior_same_rat_count"] = int(row["c"] or 0)
                    row = con.execute(
                        """
                        SELECT COUNT(DISTINCT CAST(o.ts/86400 AS INT)) d
                        FROM tower_observations o
                        JOIN towers t ON t.id=o.tower_id
                        WHERE o.place_id=? AND o.ts<? AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                          AND COALESCE(t.operator,'')=? AND COALESCE(t.rat,'')=?
                          AND t.tac_lac IS NOT NULL
                        """,
                        (str(top_pid), float(first_ts), key.operator or "", key.rat or ""),
                    ).fetchone()
                    agg.features["new_area_code_prior_same_rat_days"] = int(row["d"] or 0)
                    row = con.execute(
                        """
                        SELECT COUNT(*) c
                        FROM tower_observations o
                        JOIN towers t ON t.id=o.tower_id
                        WHERE o.place_id=? AND o.ts<? AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                          AND COALESCE(t.operator,'')=? AND COALESCE(t.rat,'')=?
                          AND t.tac_lac=?
                        """,
                        (str(top_pid), float(first_ts), key.operator or "", key.rat or "", key.tac_lac),
                    ).fetchone()
                    agg.features["new_area_code_prior_same_code_count"] = int(row["c"] or 0)
                    code_rows = con.execute(
                        """
                        SELECT t.tac_lac, COUNT(*) c
                        FROM tower_observations o
                        JOIN towers t ON t.id=o.tower_id
                        WHERE o.place_id=? AND o.ts<? AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                          AND COALESCE(t.operator,'')=? AND COALESCE(t.rat,'')=?
                          AND t.tac_lac IS NOT NULL
                        GROUP BY t.tac_lac
                        """,
                        (str(top_pid), float(first_ts), key.operator or "", key.rat or ""),
                    ).fetchall()
                    agg.features["new_area_code_prior_distinct_codes"] = int(len(code_rows))
                    if code_rows:
                        dominant_row = max(code_rows, key=lambda r: (int(r["c"] or 0), str(r["tac_lac"])))
                        dominant_count = int(dominant_row["c"] or 0)
                        dominant_code = dominant_row["tac_lac"]
                        total_count = int(agg.features.get("new_area_code_prior_same_rat_count") or 0)
                        agg.features["new_area_code_prior_dominant_code"] = dominant_code
                        agg.features["new_area_code_prior_dominant_frac"] = (float(dominant_count) / float(total_count)) if total_count > 0 else None
                    rrange = con.execute(
                        """
                        SELECT
                          MIN(CAST(strftime('%Y%m%d', o.ts, 'unixepoch') AS INT)) AS mn,
                          MAX(CAST(strftime('%Y%m%d', o.ts, 'unixepoch') AS INT)) AS mx
                        FROM tower_observations o
                        JOIN towers t ON t.id=o.tower_id
                        WHERE o.place_id=? AND o.ts<? AND o.bad_gps=0 AND COALESCE(o.ignored,0)=0
                          AND COALESCE(t.operator,'')=? AND COALESCE(t.rat,'')=?
                          AND t.tac_lac IS NOT NULL
                        """,
                        (str(top_pid), float(first_ts), key.operator or "", key.rat or ""),
                    ).fetchone()
                    d0 = _day_id_to_datestr(rrange["mn"] if rrange else None)
                    d1 = _day_id_to_datestr(rrange["mx"] if rrange else None)
                    if d0 and d1:
                        agg.features["new_area_code_prior_range"] = f"{d0} .. {d1}"
                    elif d0:
                        agg.features["new_area_code_prior_range"] = f"{d0}"
                    else:
                        agg.features["new_area_code_prior_range"] = None
                row = con.execute(
                    "SELECT COUNT(*) c FROM tower_observations WHERE place_id=? AND ts<? AND bad_gps=0 AND COALESCE(ignored,0)=0 AND stationary=1",
                    (str(top_pid), float(first_ts)),
                ).fetchone()
                agg.features["new_place_prior_stationary_count"] = int(row["c"])
                row = con.execute(
                    "SELECT COUNT(DISTINCT CAST(ts/86400 AS INT)) d FROM tower_observations WHERE place_id=? AND ts<? AND bad_gps=0 AND COALESCE(ignored,0)=0 AND stationary=1",
                    (str(top_pid), float(first_ts)),
                ).fetchone()
                agg.features["new_place_prior_stationary_days"] = int(row["d"] or 0)

            # Post-coverage after the tower's last-seen day in its main place bucket.
            if isinstance(agg.last_seen_ts, (int, float)):
                d = dt.datetime.fromtimestamp(float(agg.last_seen_ts), dt.timezone.utc)
                last_day = d.year * 10000 + d.month * 100 + d.day
                row = con.execute(
                    """
                    SELECT COUNT(*) c,
                           COUNT(DISTINCT CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT)) d
                    FROM tower_observations
                    WHERE place_id=? AND bad_gps=0 AND COALESCE(ignored,0)=0
                      AND CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT) > ?
                    """,
                    (str(top_pid), int(last_day)),
                ).fetchone()
                agg.features["new_place_post_count"] = int(row["c"] or 0)
                agg.features["new_place_post_days"] = int(row["d"] or 0)
                row = con.execute(
                    """
                    SELECT COUNT(*) c,
                           COUNT(DISTINCT CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT)) d
                    FROM tower_observations
                    WHERE place_id=? AND bad_gps=0 AND COALESCE(ignored,0)=0 AND stationary=1
                      AND CAST(strftime('%Y%m%d', ts, 'unixepoch') AS INT) > ?
                    """,
                    (str(top_pid), int(last_day)),
                ).fetchone()
                agg.features["new_place_post_stationary_count"] = int(row["c"] or 0)
                agg.features["new_place_post_stationary_days"] = int(row["d"] or 0)

        mostly_lte = bool(global_stats.get("mostly_lte"))
        known = bool(tower_row["known"])
        ignored = bool(tower_row["ignored"])
        apply_wigle_features(agg.features, get_wigle_enrichment(con, tower_id))
        methods, bayes, rule_score2, post = evaluate_methods(agg.features, settings, mostly_lte=mostly_lte, known=known, ignored=ignored)

        now = utc_now()
        con.execute(
            """
            INSERT INTO tower_features
            (tower_id,computed_at,count,center_lat,center_lon,first_seen_ts,last_seen_ts,rule_score,bayes_post_p,features_json,methods_json,bayes_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tower_id) DO UPDATE SET
              computed_at=excluded.computed_at,
              count=excluded.count,
              center_lat=excluded.center_lat,
              center_lon=excluded.center_lon,
              first_seen_ts=excluded.first_seen_ts,
              last_seen_ts=excluded.last_seen_ts,
              rule_score=excluded.rule_score,
              bayes_post_p=excluded.bayes_post_p,
              features_json=excluded.features_json,
              methods_json=excluded.methods_json,
              bayes_json=excluded.bayes_json
            """,
            (
                int(tower_id),
                now,
                agg.count,
                agg.center_lat,
                agg.center_lon,
                agg.first_seen_ts,
                agg.last_seen_ts,
                rule_score2,
                post,
                json_dumps(agg.features),
                json_dumps(methods),
                json_dumps(bayes),
            ),
        )
        con.commit()
        return {"updated_towers": 1, "computed_at": now}


def db_stats(db_path: str) -> Dict[str, Any]:
    init_db(db_path)
    with connect_db(db_path) as con:
        stats = _count_db_entities(con)
    stats["db"] = str(Path(db_path).resolve())
    return stats


def tower_payload(row: sqlite3.Row, *, enrich_methods: bool = False) -> Dict[str, Any]:
    features = json_loads(row["features_json"] if "features_json" in row.keys() else None, {})
    methods = json_loads(row["methods_json"] if "methods_json" in row.keys() else None, [])
    bayes = json_loads(row["bayes_json"] if "bayes_json" in row.keys() else None, {})
    if enrich_methods:
        method_context = dict(features)
        method_context.update({
            "known": bool(row["known"]) if "known" in row.keys() else None,
            "ignored": bool(row["ignored"]) if "ignored" in row.keys() else None,
            "count": row["count"] if "count" in row.keys() else features.get("count"),
            "rat": row["rat"] if "rat" in row.keys() else features.get("rat"),
        })
        methods = [enrich_method_result(method, method_context) for method in methods]
    label = row["label"] or tower_label(row)
    notes = row["notes"] or ""
    analysis_status = normalize_analysis_status(row["analysis_status"] if "analysis_status" in row.keys() else "")
    return {
        "id": row["id"],
        "label": label,
        "notes": notes,
        "has_note": bool(str(notes).strip()),
        "analysis_status": analysis_status,
        "known": bool(row["known"]),
        "ignored": bool(row["ignored"]),
        "operator": row["operator"],
        "rat": row["rat"],
        "tac_lac": row["tac_lac"],
        "cell_id": row["cell_id"],
        "pci": row["pci"],
        "earfcn": row["earfcn"],
        "count": row["count"] if "count" in row.keys() else 0,
        "center_lat": row["center_lat"] if "center_lat" in row.keys() else None,
        "center_lon": row["center_lon"] if "center_lon" in row.keys() else None,
        "first_seen_ts": row["first_seen_ts"] if "first_seen_ts" in row.keys() else None,
        "last_seen_ts": row["last_seen_ts"] if "last_seen_ts" in row.keys() else None,
        "rule_score": row["rule_score"] if "rule_score" in row.keys() else 0,
        "bayes_post_p": row["bayes_post_p"] if "bayes_post_p" in row.keys() else 0,
        "features": features,
        "methods": methods,
        "bayes": bayes,
    }


def altitude_view_payload(methods: Sequence[Dict[str, Any]], features: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    affected = []
    for method in methods:
        factor_name = method.get("altitude_factor_name")
        if not factor_name:
            continue
        factor_value = method.get("altitude_factor")
        affected.append({
            "id": method.get("id"),
            "label": method.get("label"),
            "direction": method.get("direction"),
            "base_norm01": method.get("base_norm01"),
            "altitude_factor_name": factor_name,
            "altitude_factor": factor_value,
            "final_norm01": method.get("norm01"),
            "delta_logodds": method.get("delta_logodds"),
            "why": method.get("why"),
        })
    return {
        "summary": {
            "altitude_samples": features.get("altitude_samples"),
            "altitude_rel_median_m": features.get("altitude_rel_median_m"),
            "altitude_rel_p90_m": features.get("altitude_rel_p90_m"),
            "high_altitude_obs_frac": features.get("high_altitude_obs_frac"),
            "geo_altitude_confidence": features.get("geo_altitude_confidence"),
            "stationary_altitude_samples": features.get("stationary_altitude_samples"),
            "stationary_altitude_rel_median_m": features.get("stationary_altitude_rel_median_m"),
            "stationary_altitude_rel_p90_m": features.get("stationary_altitude_rel_p90_m"),
            "stationary_high_altitude_obs_frac": features.get("stationary_high_altitude_obs_frac"),
            "stationary_geo_altitude_confidence": features.get("stationary_geo_altitude_confidence"),
        },
        "config": config,
        "examples": altitude_discount_examples(config),
        "affected_methods": affected,
        "notes": [
            "Sea-level altitude is not used directly. The model first estimates local ground/floor altitude inside each place bucket, then uses height above that local baseline.",
            "Ground-level points stay at full value up to the no-discount buffer. After that, evidence halves every configured half-value height.",
        ],
    }


def export_markdown(con: sqlite3.Connection, tower_id: int) -> str:
    row = con.execute(
        """
        SELECT t.*, f.* FROM towers t
        LEFT JOIN tower_features f ON f.tower_id=t.id
        WHERE t.id=?
        """,
        (tower_id,),
    ).fetchone()
    if not row:
        raise KeyError("tower not found")
    payload = tower_payload(row, enrich_methods=True)
    pts = con.execute(
        "SELECT COUNT(*) c, SUM(stationary) stat, SUM(bad_gps) bad, MIN(ts) first_ts, MAX(ts) last_ts FROM tower_observations WHERE tower_id=?",
        (tower_id,),
    ).fetchone()
    lines = [
        f"# Tower report: {payload['label']}",
        "",
        "## Identity",
        f"- ID: `{tower_id}`",
        f"- Operator: `{payload['operator']}`",
        f"- RAT: `{payload['rat']}`",
        f"- TAC/LAC: `{payload['tac_lac']}`",
        f"- Cell ID: `{payload['cell_id']}`",
        f"- PCI: `{payload['pci']}`",
        f"- EARFCN: `{payload['earfcn']}`",
        f"- Analysis status: `{payload['analysis_status'] or ''}`",
        f"- Known: `{payload['known']}`",
        f"- Ignored: `{payload['ignored']}`",
        f"- Notes: `{payload['notes'] or ''}`",
        "",
        "## Scores",
        f"- Bayes posterior: `{payload['bayes_post_p']:.6f}`",
        f"- Rule score: `{payload['rule_score']:.3f}`",
        f"- Bayes equation: `{payload['bayes'].get('explanation', '')}`",
        "",
        "## Observation summary",
        f"- Observations: `{pts['c'] or 0}`",
        f"- Stationary observations: `{pts['stat'] or 0}`",
        f"- Bad GPS observations (excluded from features): `{pts['bad'] or 0}`",
        f"- First timestamp: `{pts['first_ts']}`",
        f"- Last timestamp: `{pts['last_ts']}`",
        f"- Robust center: `{payload['center_lat']}, {payload['center_lon']}`",
        "",
        "## Evidence terms",
    ]
    for method in payload["methods"]:
        lines += [
            f"### {method['label']} (`{method['id']}`)",
            f"- Enabled / triggered: `{method.get('enabled')}` / `{method.get('triggered')}`",
            f"- Direction: `{method.get('direction')}`",
            f"- Δ log-odds: `{method.get('delta_logodds')}`",
            f"- Normalized evidence: `{method.get('norm01')}`",
            f"- Equation: `{method.get('equation')}`",
            f"- Equation note: {method.get('equation_note') or '—'}",
            f"- Applies when: {method.get('trigger_summary') or '—'}",
            f"- Meaning: {method.get('help')}",
            f"- This tower: {method.get('why')}",
            "- Variables and values used:",
        ]
        for inp in method.get("xai_rows", []):
            lines.append(f"  - **{inp.get('role','')}** `{inp.get('name')}` = `{inp.get('value')}` — {inp.get('definition','')}")
        lines.append("")
    lines += ["## Feature values", "```json", json.dumps(payload["features"], indent=2, ensure_ascii=False), "```"]
    return "\n".join(lines) + "\n"


def _xml(text: Any) -> str:
    return html.escape("" if text is None else str(text), quote=True)


def _w_run(text: Any, *, bold: bool = False, color: str = "111827", size: int = 22, italic: bool = False) -> str:
    props = [f'<w:color w:val="{color}"/>', f'<w:sz w:val="{size}"/>', '<w:rFonts w:ascii="Arial" w:hAnsi="Arial"/>']
    if bold:
        props.append("<w:b/>")
    if italic:
        props.append("<w:i/>")
    return f'<w:r><w:rPr>{"".join(props)}</w:rPr><w:t xml:space="preserve">{_xml(text)}</w:t></w:r>'


def _w_para(
    *runs: str,
    align: str = "left",
    before: int = 80,
    after: int = 80,
    shading: Optional[str] = None,
    border_color: Optional[str] = None,
) -> str:
    jc = {"left": "left", "center": "center", "right": "right"}.get(align, "left")
    shade = f'<w:shd w:val="clear" w:color="auto" w:fill="{shading}"/>' if shading else ""
    border = ""
    if border_color:
        border = f'<w:pBdr><w:left w:val="single" w:sz="16" w:space="4" w:color="{border_color}"/></w:pBdr>'
    return (
        "<w:p><w:pPr>"
        f'<w:jc w:val="{jc}"/><w:spacing w:before="{before}" w:after="{after}"/>'
        f"{shade}{border}</w:pPr>{''.join(runs)}</w:p>"
    )


def _w_heading(text: str, level: int = 1) -> str:
    if level == 1:
        return _w_para(_w_run(text, bold=True, color="0F172A", size=34), before=260, after=140)
    return _w_para(_w_run(text, bold=True, color="1E3A8A", size=28), before=220, after=100)


def _w_cell(content: str, width: int, *, fill: str = "FFFFFF") -> str:
    borders = (
        '<w:tcBorders><w:top w:val="single" w:sz="4" w:color="D1D5DB"/>'
        '<w:left w:val="single" w:sz="4" w:color="D1D5DB"/>'
        '<w:bottom w:val="single" w:sz="4" w:color="D1D5DB"/>'
        '<w:right w:val="single" w:sz="4" w:color="D1D5DB"/></w:tcBorders>'
    )
    margins = '<w:tcMar><w:top w:w="100" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/><w:left w:w="140" w:type="dxa"/><w:right w:w="140" w:type="dxa"/></w:tcMar>'
    return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>{borders}{margins}</w:tcPr>{content}</w:tc>'


def _w_table(rows: List[List[str]], widths: List[int], *, header: bool = True, fills: Optional[List[str]] = None) -> str:
    total = sum(widths)
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    out = [
        '<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblLook w:firstRow="1" w:noHBand="0" w:noVBand="1"/></w:tblPr><w:tblGrid>%s</w:tblGrid>' % (total, grid)
    ]
    for i, row in enumerate(rows):
        fill = "E0F2FE" if header and i == 0 else (fills[i] if fills and i < len(fills) else ("F8FAFC" if i % 2 == 0 else "FFFFFF"))
        cells = []
        for j, value in enumerate(row):
            para = _w_para(_w_run(value, bold=bool(header and i == 0), color="0F172A", size=20), before=0, after=0)
            cells.append(_w_cell(para, widths[j], fill=fill))
        out.append(f'<w:tr>{"".join(cells)}</w:tr>')
    out.append("</w:tbl>")
    return "".join(out)


def _fmt_num(value: Any, digits: int = 3) -> str:
    if isinstance(value, (int, float)):
        return f"{float(value):.{digits}f}"
    return "" if value is None else str(value)


def _score_fill(probability: float) -> str:
    if probability >= 0.20:
        return "FEE2E2"
    if probability >= 0.03:
        return "FEF3C7"
    return "DCFCE7"


def export_docx(con: sqlite3.Connection, tower_id: int) -> bytes:
    row = con.execute(
        """
        SELECT t.*, f.* FROM towers t
        LEFT JOIN tower_features f ON f.tower_id=t.id
        WHERE t.id=?
        """,
        (tower_id,),
    ).fetchone()
    if not row:
        raise KeyError("tower not found")
    payload = tower_payload(row, enrich_methods=True)
    pts = con.execute(
        "SELECT COUNT(*) c, SUM(stationary) stat, SUM(bad_gps) bad, MIN(ts) first_ts, MAX(ts) last_ts FROM tower_observations WHERE tower_id=?",
        (tower_id,),
    ).fetchone()

    score = float(payload.get("bayes_post_p") or 0.0)
    features = payload.get("features") or {}
    methods = sorted(payload.get("methods") or [], key=lambda x: abs(float(x.get("delta_logodds") or 0)), reverse=True)
    triggered = [m for m in methods if m.get("triggered")]
    if not triggered:
        triggered = methods[:8]

    children: List[str] = []
    children.append(_w_para(_w_run("Tower Intelligence Report", bold=True, color="FFFFFF", size=42), align="center", before=180, after=40, shading="0F172A"))
    children.append(_w_para(_w_run(payload["label"], bold=True, color="1E3A8A", size=30), align="center", before=80, after=160))
    children.append(_w_para(_w_run("Ranking only — not attribution. This report explains why this tower fingerprint was ranked as anomalous or stable.", italic=True, color="64748B", size=20), align="center", before=0, after=180))

    children.append(_w_table(
        [
            ["Bayes posterior", "Rule score", "Observation count"],
            [f"{score * 100:.4f}%", _fmt_num(payload.get("rule_score"), 2), str(payload.get("count") or 0)],
        ],
        [3120, 3120, 3120],
        fills=["E0F2FE", _score_fill(score)],
    ))

    children.append(_w_heading("Identity", 1))
    children.append(_w_table(
        [
            ["Field", "Value", "Meaning"],
            ["Operator", payload.get("operator"), "Network/operator string from the modem."],
            ["RAT", payload.get("rat"), VARIABLE_GLOSSARY["rat"]],
            ["TAC/LAC", payload.get("tac_lac"), VARIABLE_GLOSSARY["tac_lac"]],
            ["Cell ID", payload.get("cell_id"), VARIABLE_GLOSSARY["cell_id"]],
            ["PCI", payload.get("pci"), VARIABLE_GLOSSARY["pci"]],
            ["EARFCN", payload.get("earfcn"), VARIABLE_GLOSSARY["earfcn"]],
            ["Analysis status", payload.get("analysis_status") or "", "Manual review tag stored in the DB."],
            ["Known / ignored", f"{payload.get('known')} / {payload.get('ignored')}", "Manual DB flags that affect ranking/visibility."],
            ["Notes", payload.get("notes") or "", "Manual note stored in the DB for this tower."],
        ],
        [2200, 2500, 4660],
    ))

    children.append(_w_heading("Observation Summary", 1))
    children.append(_w_table(
        [
            ["Metric", "Value"],
            ["Raw tower observations", pts["c"] or 0],
            ["Stationary observations", pts["stat"] or 0],
            ["Bad GPS observations excluded from features", pts["bad"] or 0],
            ["First timestamp", pts["first_ts"]],
            ["Last timestamp", pts["last_ts"]],
            ["Robust center", f"{payload.get('center_lat')}, {payload.get('center_lon')}"],
            ["GPS spread (m)", _fmt_num(features.get("gps_spread_m"), 1)],
            ["All clusters / top separation", f"{features.get('clusters')} / {_fmt_num(features.get('cluster_top2_sep_m'), 1)} m"],
            ["Stationary clusters / top separation", f"{features.get('stationary_clusters')} / {_fmt_num(features.get('stationary_cluster_top2_sep_m'), 1)} m"],
        ],
        [4200, 5160],
    ))

    children.append(_w_heading("Bayesian Score Explanation", 1))
    bayes = payload.get("bayes") or {}
    children.append(_w_para(_w_run(bayes.get("explanation") or "logit(posterior) = logit(prior) + Σ method Δ log-odds", color="334155", size=22), before=40, after=80, shading="F8FAFC", border_color="2563EB"))
    children.append(_w_table(
        [
            ["Quantity", "Value", "Meaning"],
            ["Prior", _fmt_num(bayes.get("prior"), 6), VARIABLE_GLOSSARY["bayes_prior"]],
            ["Total Δ log-odds", _fmt_num(bayes.get("total_delta_logodds"), 3), "Sum of all enabled method contributions."],
            ["Posterior", f"{score * 100:.4f}%", VARIABLE_GLOSSARY["bayes_post_p"]],
        ],
        [2600, 2100, 4660],
    ))

    children.append(_w_heading("Evidence Terms", 1))
    evidence_rows = [["Method", "Dir", "Triggered", "Δ log-odds", "norm01", "Explanation"]]
    fills = ["E0F2FE"]
    for m in methods:
        direction = "Raises" if m.get("direction") == "up" else "Lowers"
        evidence_rows.append([
            m.get("label"),
            direction,
            str(bool(m.get("triggered"))),
            _fmt_num(m.get("delta_logodds"), 3),
            _fmt_num(m.get("norm01"), 3),
            m.get("why") or m.get("help"),
        ])
        fills.append("FEE2E2" if m.get("direction") == "up" and m.get("triggered") else "DCFCE7" if m.get("direction") == "down" and m.get("triggered") else "F8FAFC")
    children.append(_w_table(evidence_rows, [2200, 900, 1000, 1100, 900, 3260], fills=fills))

    children.append(_w_heading("Method Details", 1))
    for m in triggered[:12]:
        color = "DC2626" if m.get("direction") == "up" else "16A34A"
        shade = "FEF2F2" if m.get("direction") == "up" else "F0FDF4"
        children.append(_w_para(
            _w_run(m.get("label"), bold=True, color=color, size=26),
            _w_run(f"  Δ={_fmt_num(m.get('delta_logodds'), 3)}", bold=True, color="111827", size=22),
            before=180,
            after=60,
            shading=shade,
            border_color=color,
        ))
        children.append(_w_para(_w_run(m.get("help"), color="334155", size=20), before=0, after=40))
        children.append(_w_para(_w_run("Equation: ", bold=True, color="0F172A", size=20), _w_run(m.get("equation"), color="334155", size=20), before=0, after=40))
        if m.get("equation_note"):
            children.append(_w_para(_w_run("Equation note: ", bold=True, color="0F172A", size=20), _w_run(m.get("equation_note"), color="334155", size=20), before=0, after=40))
        if m.get("trigger_summary"):
            children.append(_w_para(_w_run("Applies when: ", bold=True, color="0F172A", size=20), _w_run(m.get("trigger_summary"), color="334155", size=20), before=0, after=40))
        input_rows = [["Role", "Variable", "This tower", "Meaning"]]
        for inp in m.get("xai_rows", []):
            input_rows.append([inp.get("role"), inp.get("name"), inp.get("value"), inp.get("definition")])
        children.append(_w_table(input_rows, [1200, 2200, 1800, 4160]))

    children.append(_w_heading("Important Feature Values", 1))
    keys = [
        "count",
        "days_seen",
        "stationary_count",
        "gps_spread_m",
        "clusters",
        "cluster_top2_sep_m",
        "stationary_clusters",
        "stationary_cluster_top2_sep_m",
        "stationary_signal_mad",
        "stationary_signal_mad_z",
        "stationary_jump_rate_8db",
        "stationary_jump_rate_z",
        "stationary_param_obs",
        "stationary_pci_change_rate_z",
        "stationary_earfcn_change_rate_z",
        "local_stationary_window_min",
        "local_stationary_window_frac",
        "change_places_frac_stationary",
        "place_rat_surprise",
        "stability_bonus",
        "bad_gps_skipped",
        "altitude_samples",
        "altitude_rel_median_m",
        "altitude_rel_p90_m",
        "high_altitude_obs_frac",
        "geo_altitude_confidence",
        "stationary_altitude_samples",
        "stationary_altitude_rel_median_m",
        "stationary_altitude_rel_p90_m",
        "stationary_high_altitude_obs_frac",
        "stationary_geo_altitude_confidence",
    ]
    rows = [["Variable", "Value", "Meaning"]]
    for key in keys:
        if key in features:
            rows.append([key, _fmt_num(features.get(key), 4), VARIABLE_GLOSSARY.get(key, "")])
    children.append(_w_table(rows, [2800, 2000, 4560]))

    children.append(_w_heading("Limitations", 1))
    for line in [
        "This report ranks anomalies for manual review; it does not identify an operator or prove IMSI-catcher activity.",
        "Bad GPS points are stored and visible in the dashboard, but excluded from derived anomaly calculations by default.",
        "Threshold changes affect only derived evidence and scores, never raw observations.",
    ]:
        children.append(_w_para(_w_run(line, color="475569", size=20), before=20, after=40))

    sect = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="900" w:right="900" w:bottom="900" w:left="900" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>'
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{''.join(children)}{sect}</w:body></w:document>"""
    styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="22"/></w:rPr></w:style></w:styles>"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"""
    doc_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"""
    types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/styles.xml", styles)
        z.writestr("word/document.xml", document)
    return out.getvalue()


def index_html() -> str:
    return r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tower Intelligence</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    :root{--bg:#0f172a;--panel:#111827;--card:#ffffff;--muted:#64748b;--line:#e5e7eb;--accent:#2563eb;--good:#16a34a;--bad:#dc2626;--warn:#d97706;--drawer-width:min(760px,92vw);--drawer-font-size:16px}
    *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:#0f172a;background:#f8fafc}
    .app{display:grid;grid-template-columns:82px 1fr;height:100vh;overflow:hidden}.nav{background:var(--bg);color:#cbd5e1;display:flex;flex-direction:column;gap:8px;padding:14px 8px}
    .nav button{background:transparent;border:0;color:inherit;border-radius:14px;padding:10px 6px;cursor:pointer;font-weight:700}.nav button.active,.nav button:hover{background:#1e293b;color:#fff}
    .main{position:relative;overflow:hidden}.view{display:none;height:100%;overflow:auto}.view.active{display:block}.toolbar{display:flex;gap:10px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);background:white;flex-wrap:wrap}
    input,select,textarea,button{font:inherit} input,select,textarea{border:1px solid #cbd5e1;border-radius:10px;padding:8px 10px;background:white} button.primary{background:var(--accent);color:white;border:0;border-radius:10px;padding:9px 12px;font-weight:800;cursor:pointer}
    button.ghost{background:white;border:1px solid #cbd5e1;border-radius:10px;padding:8px 10px;cursor:pointer}.small{font-size:12px;color:var(--muted)}.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-weight:800;background:#e0f2fe}
    #map{height:calc(100vh - 58px);width:100%}.drawer{position:absolute;right:18px;top:76px;bottom:18px;width:var(--drawer-width);max-width:95vw;min-width:420px;background:white;border:1px solid var(--line);border-radius:18px;box-shadow:0 18px 60px #0003;z-index:900;display:none;overflow:hidden;font-size:var(--drawer-font-size)}
    .drawer.open{display:block}.drawer-scroll{position:absolute;inset:0;overflow:auto}.drawer header{position:sticky;top:0;background:white;padding:16px;border-bottom:1px solid var(--line);z-index:20}.drawer .body{padding:16px}.drawer .body h3{margin-top:14px}.drawer-top{display:flex;gap:12px;justify-content:space-between;align-items:flex-start}.drawer-tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;justify-content:flex-end}.drawer-resizer{position:absolute;left:0;top:0;bottom:0;width:14px;cursor:ew-resize;z-index:30;touch-action:none}.drawer-resizer:before{content:'';position:absolute;left:4px;top:50%;transform:translateY(-50%);width:4px;height:72px;border-radius:999px;background:#cbd5e1}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;padding:16px}
    .card{background:white;border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:0 1px 2px #0000000a}.card h3{margin:0 0 8px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
    table{width:100%;border-collapse:collapse;background:white} th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top} th{background:#f8fafc}
    .table-wrap{height:calc(100vh - 66px);overflow:auto}.table-wrap th{position:sticky;top:0;z-index:1}.score{font-family:ui-monospace,monospace}.term{border:1px solid var(--line);border-radius:14px;margin:10px 0;padding:12px;overflow:hidden}.term.up{border-left:5px solid var(--bad)}.term.down{border-left:5px solid var(--good)} code{background:#f1f5f9;border-radius:6px;padding:1px 5px;white-space:normal;word-break:break-word}
    th.sortable{cursor:pointer;user-select:none} th.sortable:hover{background:#e0f2fe}
    .term-table-wrap{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:12px}.term table{min-width:760px;table-layout:fixed}.term td,.term th{word-break:break-word;overflow-wrap:anywhere}.mini-json{margin:0;max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:8px;font-size:12px}.value-lines{white-space:pre-wrap;line-height:1.35}
    .feature-table{table-layout:fixed}.feature-table td,.feature-table th{overflow-wrap:anywhere;word-break:break-word}.feature-table code{display:inline-block;max-width:100%}
    .score-filter{display:flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:12px;padding:6px 8px;background:#f8fafc}.score-filter input[type=range]{width:180px}.score-filter input[type=number]{width:82px;padding:5px 7px}
    .help{max-width:1100px;padding:22px}.method-row textarea{width:100%;min-height:70px;font-family:ui-monospace,monospace}.pillbar{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
    .imports-shell{padding:16px;display:flex;flex-direction:column;gap:14px}.imports-grid{display:grid;grid-template-columns:minmax(420px,2.2fr) minmax(340px,1.5fr) minmax(280px,1fr);gap:14px;align-items:start}.span-all{grid-column:1/-1}
    .status-line{border:1px solid var(--line);border-radius:14px;padding:12px 14px;background:white;font-weight:600}.status-line.idle{color:#334155}.status-line.working{background:#eff6ff;border-color:#bfdbfe;color:#1d4ed8}.status-line.success{background:#ecfdf5;border-color:#bbf7d0;color:#15803d}.status-line.warn{background:#fffbeb;border-color:#fde68a;color:#a16207}.status-line.error{background:#fef2f2;border-color:#fecaca;color:#b91c1c}
    .inline-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.upload-stack{display:flex;flex-direction:column;gap:10px}.upload-stack input[type=file]{width:100%;max-width:100%}
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.stat-card{border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:#f8fafc}.stat-card .k{font-size:12px;color:var(--muted);margin-bottom:4px}.stat-card .v{font-size:22px;font-weight:800;line-height:1.1}
    .config-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}.config-field label{display:block;font-weight:700;margin-bottom:6px}.config-field input{width:100%}
    .table-wrap.compact{height:auto;max-height:360px}.table-wrap.compact table{min-width:100%}.path-cell code{display:block;white-space:normal;overflow-wrap:anywhere}.status-tag{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:800;text-transform:capitalize}.status-tag.imported{background:#dcfce7;color:#166534}.status-tag.skipped{background:#e2e8f0;color:#334155}.status-tag.error{background:#fee2e2;color:#991b1b}
    .toolbar-note{margin-left:auto}
    .meta-editor{border:1px solid var(--line);border-radius:14px;padding:14px;background:#f8fafc}.meta-editor textarea{width:100%;min-height:120px;resize:vertical}.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.meta-grid label{display:flex;gap:8px;align-items:center}.note-indicator{font-weight:700}.note-indicator.yes{color:#1d4ed8}.note-indicator.no{color:#64748b}.tag-badge{display:inline-flex;align-items:center;border:1px solid #cbd5e1;border-radius:999px;padding:3px 8px;background:#f8fafc;font-size:12px;font-weight:700}.leaflet-tooltip.point-raw-tooltip,.leaflet-popup.point-raw-tooltip{max-width:min(720px,92vw);min-width:min(320px,92vw);white-space:normal}.point-tooltip{max-width:min(700px,92vw)}.point-tooltip pre{margin:6px 0 0;max-height:180px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:8px;font-size:11px}.obs-table td,.obs-table th{vertical-align:top}.obs-table tr.obs-ignored{background:#f8fafc}.obs-table tr.obs-bad{background:#fff7ed}
    .area-legend{background:#fffffff2;border:1px solid #cbd5e1;border-radius:10px;box-shadow:0 2px 12px #0002;padding:9px 10px;min-width:130px;max-width:220px}.area-legend-title{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:12px;font-weight:800;margin-bottom:6px}.area-legend-close{border:0;background:transparent;color:#64748b;cursor:pointer;font-size:18px;line-height:14px;padding:0 1px}.area-legend-close:hover{color:#0f172a}.area-legend-items{display:flex;flex-direction:column;gap:4px;max-height:240px;overflow:auto}.area-legend-row{display:flex;align-items:center;gap:7px;font-size:12px;white-space:nowrap}.area-legend-swatch{width:12px;height:12px;border:1px solid #fff;border-radius:50%;box-shadow:0 0 0 1px #0003;flex:0 0 auto}.area-legend-count{color:#64748b;margin-left:auto;padding-left:8px}
    @media (max-width: 1180px){.imports-grid{grid-template-columns:1fr 1fr}.imports-grid .stats-card-col,.imports-grid .span-all{grid-column:1/-1}}
    @media (max-width: 860px){.imports-grid{grid-template-columns:1fr}.imports-grid > *{grid-column:1/-1}.toolbar-note{margin-left:0}}
  </style>
</head>
<body>
<div class="app">
  <nav class="nav">
    <button data-view="mapView" class="active">🗺️<br>Map</button>
    <button data-view="towersView">📡<br>Towers</button>
    <button data-view="anomaliesView">⚠️<br>Anomalies</button>
    <button data-view="methodsView">⚙️<br>Methods</button>
    <button data-view="importsView">⬆️<br>Imports</button>
    <button data-view="adminView">🧰<br>Admin</button>
    <button data-view="helpView">❔<br>Help</button>
  </nav>
  <main class="main">
    <section id="mapView" class="view active">
      <div class="toolbar">
        <input id="mapSearch" placeholder="Search cell/TAC/PCI/operator/notes" style="min-width:280px">
        <label class="score-filter">Min Bayes <input id="scoreSlider" type="range" min="0" max="100" step="0.01" value="0" oninput="syncScoreFilter('slider')"><input id="scoreMin" type="number" min="0" max="100" step="0.01" value="0" oninput="syncScoreFilter('number')"><span>%</span></label>
        <label>Last seen from <input id="lastSeenFrom" type="date" onchange="changeLastSeenFilter('from')"></label>
        <label>through <input id="lastSeenTo" type="date" onchange="changeLastSeenFilter('to')"></label>
        <button class="ghost" onclick="clearLastSeenFilter()">Clear dates</button>
        <label><input id="showNormal" type="checkbox" checked onchange="renderMapTowers(false)"> normal</label>
        <label><input id="showAnom" type="checkbox" checked onchange="renderMapTowers(false)"> anomalous</label>
        <label><input id="showKnown" type="checkbox" checked onchange="renderMapTowers(false)"> known</label>
        <label><input id="showIgnored" type="checkbox" onchange="renderMapTowers(false)"> ignored</label>
        <label><input id="showAreaLegend" type="checkbox" checked onchange="toggleAreaLegend()"> TAC/LAC legend</label>
        <button class="ghost" onclick="loadTowers()">Refresh</button>
        <span id="mapStatus" class="small"></span>
      </div>
      <div id="map"></div>
      <aside id="drawer" class="drawer"><div class="drawer-resizer" title="Drag to resize"></div><div class="drawer-scroll"><header><div class="drawer-top"><div><button class="ghost" onclick="closeDrawer()">Close</button><h2 id="drawerTitle"></h2><div id="drawerSub" class="small"></div></div><div class="drawer-tools"><button class="ghost" onclick="changeDrawerFont(-1)">A−</button><button class="ghost" onclick="resetDrawerFont()">A</button><button class="ghost" onclick="changeDrawerFont(1)">A+</button><span id="drawerFontLabel" class="small"></span></div></div></header><div class="body" id="drawerBody"></div></div></aside>
    </section>
    <section id="towersView" class="view"><div class="toolbar"><input id="towerSearch" placeholder="Search identifiers, notes, tags"><button class="ghost" onclick="loadTowerTable()">Search</button></div><div class="table-wrap"><table id="towerTable"></table></div></section>
    <section id="anomaliesView" class="view"><div class="toolbar"><input id="anomalySearch" placeholder="Search identifiers, notes, tags"><select id="anomalyMethod" onchange="loadAnomalyTable()"><option value="">All triggered anomalies</option></select><label><input id="anomalyIgnored" type="checkbox" onchange="loadAnomalyTable()"> include ignored</label><button class="ghost" onclick="loadAnomalyTable()">Search</button><span id="anomalyStatus" class="small"></span></div><div class="table-wrap"><table id="anomalyTable"></table></div></section>
    <section id="methodsView" class="view"><div class="toolbar"><button class="primary" onclick="saveMethods()">Save settings</button><button class="ghost" onclick="saveAppConfig()">Save altitude config</button><button class="ghost" onclick="recompute('methods')">Recompute scores</button><span class="small">Method thresholds and altitude discount settings are editable for experiments.</span><span id="methodsStatus" class="small toolbar-note"></span></div><div class="cards"><div class="card span-all"><h3>Altitude discount configuration</h3><p class="small">These settings control how much elevated positions soften geo-heavy evidence. Ground-level points remain full strength; higher positions are discounted using local ground/floor baselines per place bucket.</p><div id="appConfigBox" class="config-grid"></div><div id="appConfigCurve" class="table-wrap compact" style="margin-top:12px"><table id="appConfigCurveTable"></table></div></div></div><div id="methodsList" class="cards"></div></section>
    <section id="importsView" class="view"><div class="imports-shell"><div id="importsStatus" class="status-line idle">Ready to import JSONL files.</div><div id="importsProgressMeta" class="small toolbar-note" style="margin:8px 0 14px 0"></div><div class="imports-grid"><div class="card"><h3>Import by path</h3><p class="small">Local server reads files from this machine. Separate multiple paths with newlines.</p><textarea id="importPaths" style="width:100%;min-height:140px" placeholder="logs/14-5-2026.jsonl"></textarea><div class="inline-actions"><button class="primary" onclick="doImport()">Import</button><button class="ghost" onclick="recompute('imports')">Recompute</button></div></div><div class="card"><h3>Upload JSONL</h3><div class="upload-stack"><input id="uploadFiles" type="file" multiple><div id="uploadSelection" class="small">No files selected.</div><button class="primary" onclick="uploadImport()">Upload + import</button></div></div><div class="card stats-card-col"><h3>DB Stats</h3><div class="inline-actions" style="margin-top:0"><button class="ghost" onclick="loadStats()">Refresh stats</button></div><div id="statsBox" class="stats-grid" style="margin-top:12px"></div><div id="statsMeta" class="small" style="margin-top:10px"></div></div><div class="card span-all"><h3>Last import result</h3><p class="small">Every import shows a compact status line plus per-file counts. No popup windows; results stay here for review.</p><div id="importSummaryMetrics" class="stats-grid" style="margin-top:12px"></div><div class="table-wrap compact" style="margin-top:12px"><table id="importResultTable"></table></div></div><div class="card span-all"><h3>Imported files history</h3><p class="small">Persistent list from the SQLite <code>import_files</code> table. Manual path imports and browser uploads both appear here.</p><div class="inline-actions" style="margin-top:0"><button class="ghost" onclick="loadImports()">Refresh imported files</button></div><div class="table-wrap compact" style="margin-top:12px"><table id="importsTable"></table></div></div></div></div></section>
    <section id="adminView" class="view"><div class="toolbar"><input id="adminSearch" placeholder="Search DB, notes, tags"><button class="ghost" onclick="loadAdmin()">Search</button></div><div class="table-wrap"><table id="adminTable"></table></div></section>
    <section id="helpView" class="view"><div class="help" id="helpBox"></div></section>
  </main>
</div>
<script>
let map, towerLayer, estimateLayer, pointLayer, clusterLayer, badLayer, placeLayer, centerLayer, areaLegend;
let allTowers=[];
let towerTableItems=[], anomalyTableItems=[], adminTableItems=[];
let tableSort={towerTable:{key:'bayes_post_p',dir:-1},anomalyTable:{key:'bayes_post_p',dir:-1},adminTable:{key:'bayes_post_p',dir:-1}};
let appConfig={}, appConfigHelp={};
let currentTowerData=null, drawerShowAllMethods=false;
let obsMarkers=new Map(); // obs_uid -> {layer, point}
let currentPointsMode='';
let currentObsList=null;
const ANOMALY_CATEGORY_CUTOFF=0.001;
const ANALYSIS_STATUS_VALUES=['','under analysis','analyzed','benign','suspicious','CSS'];
function initMap(){
  map=L.map('map',{minZoom:1,maxZoom:22}).setView([50.061,14.40],15);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:22,attribution:'© OpenStreetMap'}).addTo(map);
  estimateLayer=L.layerGroup().addTo(map); towerLayer=L.layerGroup().addTo(map); pointLayer=L.layerGroup().addTo(map); clusterLayer=L.layerGroup().addTo(map); badLayer=L.layerGroup().addTo(map); placeLayer=L.layerGroup().addTo(map); centerLayer=L.layerGroup().addTo(map);
  L.control.layers(null,{"Tower estimate circles":estimateLayer,"Tower points":pointLayer,"Clusters":clusterLayer,"Bad GPS":badLayer,"Place buckets":placeLayer,"Center":centerLayer}).addTo(map);
  areaLegend=L.control({position:'bottomright'});
  areaLegend.onAdd=()=>{
    const div=L.DomUtil.create('div','area-legend');
    div.innerHTML='<div class="area-legend-title"><span>TAC/LAC colors</span><button class="area-legend-close" type="button" title="Hide legend" aria-label="Hide TAC/LAC legend" onclick="setAreaLegendVisible(false)">×</button></div><div id="areaLegendItems" class="area-legend-items"><span class="small">No towers shown</span></div>';
    L.DomEvent.disableClickPropagation(div); L.DomEvent.disableScrollPropagation(div);
    return div;
  };
  areaLegend.addTo(map);
  let showLegend=true;
  try{showLegend=localStorage.getItem('towerShowAreaLegend')!=='false';}catch(_e){}
  setAreaLegendVisible(showLegend,false);
}
async function api(url, opts={}){const r=await fetch(url, opts); if(!r.ok) throw new Error(await r.text()); const ct=r.headers.get('content-type')||''; return ct.includes('json')?r.json():r.text();}
function pct(x){return ((x||0)*100).toFixed(3)+'%'} function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function prettyJson(value){return esc(JSON.stringify(value??{},null,2))}
function noteIndicatorHtml(text){
  const has=Boolean(String(text??'').trim());
  return `<span class="note-indicator ${has?'yes':'no'}">${has?'yes':'—'}</span>`;
}
function analysisTagHtml(value){
  const text=String(value??'').trim();
  return text?`<span class="tag-badge">${esc(text)}</span>`:'—';
}
function pointTooltipHtml(point, mode){
  const canToggle = Boolean(point && point.obs_uid);
  const bits=[
    `<div><b>Mode</b>: ${esc(mode)}</div>`,
    `<div><b>Time</b>: ${esc(point.ts_iso||point.ts||'')}</div>`,
    `<div><b>Lat/Lon</b>: ${esc(point.lat)}, ${esc(point.lon)}</div>`,
    `<div><b>Altitude</b>: ${point.alt_m==null?'—':`${Number(point.alt_m).toFixed(1)} m`}</div>`,
    `<div><b>Signal</b>: ${point.signal==null?'—':esc(point.signal)}</div>`,
    `<div><b>Place</b>: ${esc(point.place_id||'')}</div>`,
    `<div><b>Stationary</b>: ${esc(Boolean(point.stationary))}</div>`,
    `<div><b>Bad GPS</b>: ${esc(Boolean(point.bad_gps))}</div>`,
    `<div><b>Ignored</b>: ${esc(Boolean(point.ignored))}</div>`,
    point.sample_uid?`<div><b>Sample UID</b>: <code>${esc(point.sample_uid)}</code></div>`:'',
    point.obs_uid?`<div><b>Obs UID</b>: <code>${esc(point.obs_uid)}</code></div>`:'',
    `<div><b>Raw cell</b></div><pre>${prettyJson(point.raw_cell||{})}</pre>`,
    `<div><b>Raw sample</b></div><pre>${prettyJson(point.raw_sample||{})}</pre>`
  ].filter(Boolean);
  const action = canToggle ? `
    <div style="margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <button class="ghost" onclick="toggleObsIgnored('${esc(String(point.obs_uid))}', ${point.ignored?0:1})">${point.ignored?'Mark used':'Ignore this observation'}</button>
      <span class="small">${point.ignored?'Ignored: excluded from recompute.':'Used: included in recompute.'}</span>
    </div>` : '';
  return `<div class="point-tooltip">${bits.join('')}${action}</div>`;
}
function bindPointTooltip(layer, point, mode){
  // Use a click-open popup (not a hover tooltip) so you can move the mouse into
  // it (e.g. to scroll) without it disappearing.
  layer.bindPopup(pointTooltipHtml(point, mode), {
    maxWidth: 720,
    autoClose: true,
    closeOnClick: true,
    autoPan: true,
    className: 'point-raw-tooltip',
  });
  layer.on('click', () => layer.openPopup());
}
function analysisStatusOptionsHtml(selected){
  return ANALYSIS_STATUS_VALUES.map(v=>`<option value="${esc(v)}" ${String(selected||'')===String(v)?'selected':''}>${esc(v||'unassigned')}</option>`).join('');
}
	function formatValue(value){
	  if(value===null||value===undefined) return '<span class="small">—</span>';
	  if(typeof value==='number') return Number.isInteger(value)?String(value):String(Number(value.toFixed(6)));
	  if(typeof value==='string'||typeof value==='boolean') return esc(value);
  if(Array.isArray(value)){
    if(value.length===0) return '<span class="small">empty</span>';
    if(value.every(v=>v&&typeof v==='object')){
      const lines=value.slice(0,18).map((v,i)=>{
        const place=v.place_id?`${v.place_id}`:`item ${i+1}`;
        const bits=[];
        if(v.count!==undefined) bits.push(`count=${v.count}`);
        if(v.place_total!==undefined) bits.push(`place_total=${v.place_total}`);
        if(v.changed!==undefined) bits.push(`changed=${v.changed}`);
        if(v.changed_stationary!==undefined) bits.push(`stationary_changed=${v.changed_stationary}`);
        if(v.ks_d!==undefined&&v.ks_d!==null) bits.push(`ks_d=${Number(v.ks_d).toFixed(3)}`);
        if(v.cusum!==undefined&&v.cusum!==null) bits.push(`cusum=${Number(v.cusum).toFixed(2)}`);
        return `${place}${bits.length?' — '+bits.join(', '):''}`;
      });
      if(value.length>18) lines.push(`… ${value.length-18} more`);
      return `<div class="value-lines">${esc(lines.join('\\n'))}</div>`;
    }
    return `<pre class="mini-json">${esc(JSON.stringify(value,null,2))}</pre>`;
  }
  if(typeof value==='object') return `<pre class="mini-json">${esc(JSON.stringify(value,null,2))}</pre>`;
  return esc(value);
}
function formatInt(n){const x=Number(n)||0; return x.toLocaleString('en-US')}
function formatBytes(n){
  const x=Number(n)||0;
  if(x<1024) return `${formatInt(x)} B`;
  if(x<1024**2) return `${(x/1024).toFixed(1)} KB`;
  if(x<1024**3) return `${(x/1024**2).toFixed(1)} MB`;
  return `${(x/1024**3).toFixed(2)} GB`;
}
function renderStatsGrid(items){
  return items.map(([label,value])=>`<div class="stat-card"><div class="k">${esc(label)}</div><div class="v">${esc(value)}</div></div>`).join('');
}
function setStatusLine(id, kind, text){
  const el=document.getElementById(id); if(!el) return;
  el.className=`status-line ${kind||'idle'}`;
  el.textContent=text||'';
}
function setMethodsStatus(kind, text){
  const el=document.getElementById('methodsStatus'); if(!el) return;
  el.textContent=text||'';
  el.style.color = kind==='error' ? '#b91c1c' : kind==='success' ? '#15803d' : kind==='working' ? '#1d4ed8' : '#64748b';
}
function renderEmptyTable(tableId, headers, message){
  document.getElementById(tableId).innerHTML=`<tr>${headers.map(h=>`<th>${h}</th>`).join('')}</tr><tr><td colspan="${headers.length}" class="small">${esc(message)}</td></tr>`;
}
function renderImportResult(result){
  const metricsEl=document.getElementById('importSummaryMetrics');
  const tableEl=document.getElementById('importResultTable');
  if(!result || result.error){
    metricsEl.innerHTML='';
    renderEmptyTable('importResultTable',['Path','Status','Rows','New samples','Tower IDs in file','New towers','Obs in file','New obs','Errors'], result&&result.error ? result.error : 'No import has been run yet.');
    return;
  }
  metricsEl.innerHTML=renderStatsGrid([
    ['Files imported', formatInt(result.files_imported||0)],
    ['Files skipped', formatInt(result.files_skipped||0)],
    ['Rows read', formatInt(result.imported_rows||0)],
    ['New samples', formatInt(result.new_samples||0)],
    ['Tower IDs in file(s)', formatInt(result.tower_fingerprints||0)],
    ['New towers', formatInt(result.new_towers||0)],
    ['Obs in file(s)', formatInt(result.tower_observations||0)],
    ['New obs', formatInt(result.new_observations||0)],
    ['Line errors', formatInt(result.errors||0)]
  ]);
  const rows=result.files||[];
  if(!rows.length){
    renderEmptyTable('importResultTable',['Path','Status','Rows','New samples','Tower IDs in file','New towers','Obs in file','New obs','Errors'],'No file results returned.');
    return;
  }
  tableEl.innerHTML=`<tr><th>Path</th><th>Status</th><th>Rows</th><th>New samples</th><th>Tower IDs in file</th><th>New towers</th><th>Obs in file</th><th>New obs</th><th>Errors</th></tr>`+rows.map(r=>`<tr><td class="path-cell"><code>${esc(r.path||'')}</code></td><td><span class="status-tag ${esc(r.status||'')}">${esc(r.status||'')}</span></td><td>${formatInt(r.rows)}</td><td>${formatInt(r.new_samples)}</td><td>${formatInt(r.tower_fingerprints)}</td><td>${formatInt(r.new_towers)}</td><td>${formatInt(r.tower_observations)}</td><td>${formatInt(r.new_observations)}</td><td>${formatInt(r.errors)}</td></tr>`).join('');
}
function renderStatsBox(stats){
  const box=document.getElementById('statsBox');
  const meta=document.getElementById('statsMeta');
  box.innerHTML=renderStatsGrid([
    ['Imports', formatInt(stats.imports)],
    ['Raw samples', formatInt(stats.raw_samples)],
    ['Tower observations', formatInt(stats.tower_observations)],
    ['Towers', formatInt(stats.towers)],
    ['Feature rows', formatInt(stats.features)]
  ]);
  meta.innerHTML=`<b>DB</b><br><code>${esc(stats.db||'')}</code>`;
}
function renderImportsHistory(items){
  if(!items.length){
    renderEmptyTable('importsTable',['Imported at','Rows','New samples','Tower IDs','New towers','Obs','New obs','Errors','Size','Path','SHA-256'],'No imported files recorded yet.');
    return;
  }
  document.getElementById('importsTable').innerHTML=`<tr><th>Imported at</th><th>Rows</th><th>New samples</th><th>Tower IDs</th><th>New towers</th><th>Obs</th><th>New obs</th><th>Errors</th><th>Size</th><th>Path</th><th>SHA-256</th></tr>`+items.map(r=>`<tr><td>${esc(r.imported_at)}</td><td>${formatInt(r.imported_rows)}</td><td>${formatInt(r.new_samples)}</td><td>${formatInt(r.tower_fingerprints)}</td><td>${formatInt(r.new_towers)}</td><td>${formatInt(r.observation_rows)}</td><td>${formatInt(r.new_observations)}</td><td>${formatInt(r.errors)}</td><td>${formatBytes(r.size)}</td><td class="path-cell"><code>${esc(r.path)}</code></td><td><code>${esc((r.sha256||'').slice(0,16))}…</code></td></tr>`).join('');
}
function renderAppConfigPanel(config, help){
  appConfig={...(config||{})}; appConfigHelp={...(help||{})};
  const fields=[
    ['altitude_floor_iqr_k','Ground outlier rejection (IQR×k)',0.1],
    ['altitude_no_discount_until_m','No discount until (m)',0.1],
    ['altitude_half_value_height_m','Half-value height (m)',0.1],
    ['altitude_high_point_m','High-point threshold (m)',0.1],
    ['altitude_min_confidence','Minimum confidence',0.01],
  ];
  const box=document.getElementById('appConfigBox');
  box.innerHTML=fields.map(([key,label,step])=>`<div class="config-field"><label for="cfg_${key}" title="${esc(help&&help[key]||'')}">${esc(label)}</label><input id="cfg_${key}" data-config-key="${key}" type="number" step="${step}" value="${Number((config&&config[key]) ?? 0)}"><div class="small">${esc(help&&help[key]||'')}</div></div>`).join('');
  renderAppConfigCurve(config||{});
}
function renderAppConfigCurve(config){
  const noDiscount=Number(config.altitude_no_discount_until_m||0);
  const half=Number(config.altitude_half_value_height_m||1);
  const minConf=Number(config.altitude_min_confidence||0);
  const points=[0,noDiscount,noDiscount+half,noDiscount+2*half,Number(config.altitude_high_point_m||0)];
  const uniq=[...new Set(points.filter(v=>Number.isFinite(v)).map(v=>Number(v.toFixed(3))))].sort((a,b)=>a-b);
  function factor(rel){
    if(rel<=noDiscount) return 1;
    return Math.max(minConf, Math.pow(0.5, (rel-noDiscount)/Math.max(0.1,half)));
  }
  document.getElementById('appConfigCurveTable').innerHTML=`<tr><th>Relative height above local ground</th><th>Altitude factor</th><th>Meaning</th></tr>`+uniq.map(rel=>`<tr><td>${rel.toFixed(1)} m</td><td>${factor(rel).toFixed(3)}</td><td>${rel<=noDiscount?'full value':`geo evidence × ${factor(rel).toFixed(3)}`}</td></tr>`).join('');
}
function renderAltitudeView(view){
  if(!view) return '';
  const s=view.summary||{};
  const affected=view.affected_methods||[];
  const examples=view.examples||[];
  const metrics=renderStatsGrid([
    ['Altitude samples', formatInt(s.altitude_samples)],
    ['Median rel. height', s.altitude_rel_median_m==null?'—':`${Number(s.altitude_rel_median_m).toFixed(1)} m`],
    ['P90 rel. height', s.altitude_rel_p90_m==null?'—':`${Number(s.altitude_rel_p90_m).toFixed(1)} m`],
    ['High-altitude frac', s.high_altitude_obs_frac==null?'—':`${(100*Number(s.high_altitude_obs_frac)).toFixed(1)}%`],
    ['Geo altitude confidence', s.geo_altitude_confidence==null?'—':Number(s.geo_altitude_confidence).toFixed(3)],
    ['Stationary altitude confidence', s.stationary_geo_altitude_confidence==null?'—':Number(s.stationary_geo_altitude_confidence).toFixed(3)]
  ]);
  const exampleRows=examples.length?examples.map(x=>`<tr><td>${Number(x.relative_altitude_m).toFixed(1)} m</td><td>${Number(x.altitude_factor).toFixed(3)}</td></tr>`).join(''):`<tr><td colspan="2" class="small">No curve examples.</td></tr>`;
  const affectedRows=affected.length?affected.map(m=>`<tr><td>${esc(m.label)}</td><td>${m.base_norm01==null?'—':Number(m.base_norm01).toFixed(3)}</td><td>${m.altitude_factor==null?'—':Number(m.altitude_factor).toFixed(3)}</td><td>${m.final_norm01==null?'—':Number(m.final_norm01).toFixed(3)}</td><td>${Number(m.delta_logodds||0).toFixed(3)}</td></tr>`).join(''):`<tr><td colspan="5" class="small">This tower has no altitude-discounted methods in its current explanation.</td></tr>`;
  return `<h3>Altitude discount</h3><p class="small">${esc((view.notes||[]).join(' '))}</p><div class="stats-grid">${metrics}</div><div class="grid2" style="margin-top:12px"><div class="term-table-wrap"><table><tr><th>Curve point</th><th>Altitude factor</th></tr>${exampleRows}</table></div><div class="term-table-wrap"><table><tr><th>Config</th><th>Value</th><th>Meaning</th></tr>${Object.entries(view.config||{}).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${typeof v==='number'?Number(v).toFixed(3):esc(v)}</td><td>${esc(appConfigHelp[k]||'')}</td></tr>`).join('')}</table></div></div><div class="term-table-wrap" style="margin-top:12px"><table><tr><th>Method</th><th>Base norm01</th><th>Altitude factor</th><th>Final norm01</th><th>Δ log-odds</th></tr>${affectedRows}</table></div>`;
}
function renderFeatureTable(features){
  const rows=pickFeatures(features);
  const glossary=window.__helpGlossary||{};
  const data=Object.entries(rows).map(([name,value])=>({name,value,definition:glossary[name]||''}));
  if(!data.length) return '<p class="small">No feature values available.</p>';
  return `<div class="term-table-wrap"><table class="feature-table"><colgroup><col style="width:24%"><col style="width:28%"><col style="width:48%"></colgroup><tr><th>Variable</th><th>Value</th><th>Meaning</th></tr>${data.map(r=>`<tr><td><code>${esc(r.name)}</code></td><td>${formatValue(r.value)}</td><td>${esc(r.definition)}</td></tr>`).join('')}</table></div>`;
}
function currentDrawerFontSize(){
  const raw=getComputedStyle(document.documentElement).getPropertyValue('--drawer-font-size').trim()||'16px';
  return Number(raw.replace('px',''))||16;
}
function updateDrawerFontLabel(){const el=document.getElementById('drawerFontLabel'); if(el) el.textContent=`${currentDrawerFontSize()}px`;}
function setDrawerFontSize(px){const clamped=Math.max(12,Math.min(28,Number(px)||16)); document.documentElement.style.setProperty('--drawer-font-size',`${clamped}px`); try{localStorage.setItem('towerDrawerFontPx', String(clamped));}catch(_e){} updateDrawerFontLabel();}
function changeDrawerFont(delta){setDrawerFontSize(currentDrawerFontSize()+delta);}
function resetDrawerFont(){setDrawerFontSize(16);}
function currentDrawerWidthPx(){
  const raw=getComputedStyle(document.documentElement).getPropertyValue('--drawer-width').trim();
  if(raw.endsWith('px')) return Number(raw.replace('px',''))||760;
  return document.getElementById('drawer')?.offsetWidth||760;
}
function setDrawerWidth(px){const clamped=Math.max(420, Math.min(window.innerWidth-40, Number(px)||760)); document.documentElement.style.setProperty('--drawer-width', `${clamped}px`); try{localStorage.setItem('towerDrawerWidthPx', String(clamped));}catch(_e){}}
function initDrawerUX(){
  try{
    const storedFont=localStorage.getItem('towerDrawerFontPx');
    if(storedFont) setDrawerFontSize(Number(storedFont)); else updateDrawerFontLabel();
    const storedWidth=localStorage.getItem('towerDrawerWidthPx');
    if(storedWidth) setDrawerWidth(Number(storedWidth));
  }catch(_e){updateDrawerFontLabel();}
  const handle=document.querySelector('.drawer-resizer');
  if(!handle) return;
  let startX=0, startW=0, dragging=false;
  handle.addEventListener('pointerdown', e=>{
    dragging=true; startX=e.clientX; startW=document.getElementById('drawer').offsetWidth; handle.setPointerCapture(e.pointerId); document.body.style.userSelect='none';
  });
  handle.addEventListener('pointermove', e=>{
    if(!dragging) return;
    const next=startW + (startX - e.clientX);
    setDrawerWidth(next);
    map&&map.invalidateSize(false);
  });
  const stop=()=>{dragging=false; document.body.style.userSelect='';};
  handle.addEventListener('pointerup', stop);
  handle.addEventListener('pointercancel', stop);
}
function tacLacKey(value){
  if(value===null||value===undefined) return null;
  const key=String(value).trim();
  return key===''?null:key;
}
function stringHash(value){
  let hash=2166136261;
  for(let i=0;i<value.length;i++){hash^=value.charCodeAt(i); hash=Math.imul(hash,16777619);}
  return hash>>>0;
}
function tacLacColor(value){
  const key=tacLacKey(value);
  if(key===null) return '#64748b';
  const numeric=Number(key);
  const seed=Number.isFinite(numeric)?Math.trunc(numeric):stringHash(key);
  const hue=((seed*137.508)%360+360)%360;
  return `hsl(${hue.toFixed(1)} 72% 42%)`;
}
function setAreaLegendVisible(show,persist=true){
  const visible=Boolean(show);
  const legend=document.querySelector('.area-legend');
  const checkbox=document.getElementById('showAreaLegend');
  if(legend) legend.style.display=visible?'':'none';
  if(checkbox) checkbox.checked=visible;
  if(persist){try{localStorage.setItem('towerShowAreaLegend',String(visible));}catch(_e){}}
}
function toggleAreaLegend(){
  setAreaLegendVisible(document.getElementById('showAreaLegend').checked);
}
function updateAreaLegend(groups){
  const el=document.getElementById('areaLegendItems');
  if(!el) return;
  const entries=[...groups.entries()].sort((a,b)=>{
    if(a[0]===null) return 1;
    if(b[0]===null) return -1;
    return String(a[0]).localeCompare(String(b[0]),undefined,{numeric:true});
  });
  el.innerHTML=entries.length?entries.map(([key,count])=>{
    const label=key===null?'Unknown':key;
    return `<div class="area-legend-row"><span class="area-legend-swatch" style="background:${tacLacColor(key)}"></span><span>${esc(label)}</span><span class="area-legend-count">${count}</span></div>`;
  }).join(''):'<span class="small">No towers shown</span>';
}
function minScore(){return Math.max(0,Math.min(1,(Number(document.getElementById('scoreMin').value)||0)/100))}
function syncScoreFilter(source){
  const slider=document.getElementById('scoreSlider'), num=document.getElementById('scoreMin');
  if(source==='slider') num.value=slider.value; else slider.value=num.value;
  renderMapTowers(false);
}
async function loadTowers(){
  const q=document.getElementById('mapSearch').value.trim();
  const lastSeenFrom=document.getElementById('lastSeenFrom').value;
  const lastSeenTo=document.getElementById('lastSeenTo').value;
  const params=new URLSearchParams({limit:5000,q,include_ignored:1});
  if(lastSeenFrom) params.set('last_seen_from',lastSeenFrom);
  if(lastSeenTo) params.set('last_seen_to',lastSeenTo);
  const data=await api('/api/towers?'+params); allTowers=data.items; renderMapTowers(true);
}
function clearLastSeenFilter(){
  document.getElementById('lastSeenFrom').value='';
  document.getElementById('lastSeenTo').value='';
  loadTowers();
}
function changeLastSeenFilter(source){
  const from=document.getElementById('lastSeenFrom'), to=document.getElementById('lastSeenTo');
  if(from.value&&to.value&&from.value>to.value){
    if(source==='from') to.value=from.value; else from.value=to.value;
  }
  loadTowers();
}
function towerCategory(t){
  if(t.ignored) return 'ignored';
  if(t.known) return 'known';
  if((Number(t.bayes_post_p)||0)>=ANOMALY_CATEGORY_CUTOFF || (Number(t.rule_score)||0)>0) return 'anom';
  return 'normal';
}
function categoryVisible(cat){
  if(cat==='ignored') return document.getElementById('showIgnored').checked;
  if(cat==='known') return document.getElementById('showKnown').checked;
  if(cat==='anom') return document.getElementById('showAnom').checked;
  return document.getElementById('showNormal').checked;
}
function renderMapTowers(fit){
  towerLayer.clearLayers(); estimateLayer.clearLayers();
  const threshold=minScore();
  let bounds=[]; let shown=0; let counts={normal:0,anom:0,known:0,ignored:0}; let areaGroups=new Map();
  for(const t of allTowers){
    const cat=towerCategory(t); counts[cat]++;
    if(!categoryVisible(cat)) continue;
    if((Number(t.bayes_post_p)||0)<threshold) continue;
    if(t.center_lat==null||t.center_lon==null) continue;
    shown++;
    const areaKey=tacLacKey(t.tac_lac);
    const color=tacLacColor(areaKey);
    areaGroups.set(areaKey,(areaGroups.get(areaKey)||0)+1);
    const spread=(t.features&&typeof t.features.gps_spread_m==='number')?t.features.gps_spread_m:null;
    if(spread!==null){const radius=Math.max(5,Math.min(500,spread)); L.circle([t.center_lat,t.center_lon],{radius,color:'#94a3b8',weight:1,fillColor:'#94a3b8',fillOpacity:0.06,interactive:false,bubblingMouseEvents:false}).addTo(estimateLayer);}
    const m=L.circleMarker([t.center_lat,t.center_lon],{radius:7+Math.min(12,(t.count||1)**0.35),color,fillColor:color,fillOpacity:.82,weight:2,interactive:true}).addTo(towerLayer);
    m.bindTooltip(`${esc(t.label)}<br>TAC/LAC ${esc(areaKey===null?'unknown':areaKey)}<br>Bayes ${pct(t.bayes_post_p)} / seen ${t.count}${spread!==null?`<br>GPS spread ${Math.round(spread)} m`:''}`);
    m.on('click',()=>openTower(t.id)); bounds.push([t.center_lat,t.center_lon]);
  }
  updateAreaLegend(areaGroups);
  const from=document.getElementById('lastSeenFrom').value, to=document.getElementById('lastSeenTo').value;
  const dateStatus=(from||to)?` · last seen ${from||'any date'} to ${to||'any date'} UTC`:'';
  document.getElementById('mapStatus').textContent=`${shown}/${allTowers.length} shown · normal ${counts.normal} · anomalous ${counts.anom} · known ${counts.known} · ignored ${counts.ignored} · min Bayes ${pct(threshold)}${dateStatus}`;
  if(fit&&bounds.length) map.fitBounds(bounds,{padding:[30,30],maxZoom:17});
}
    // Put these on `window` so inline onclick handlers can see them reliably.
    // Used only when the user explicitly clicks "Load table".
    window.AUTO_OBS_TABLE_LIMIT = 2000; // keep drawer snappy; user can "Load all" if needed
    async function openTower(id, opts={}){
      const t=await api('/api/towers/'+id); currentTowerData=t; drawerShowAllMethods=false; renderDrawer(t);
      if(opts.recenter && t.center_lat!=null) map.setView([t.center_lat,t.center_lon], Math.max(map.getZoom(),17));
    }
	function pickFeatures(f){const keys=['count','days_seen','stationary_count','gps_spread_m','clusters','cluster_top2_sep_m','stationary_clusters','stationary_cluster_top2_sep_m','signal_dist_model','stationary_signal_mad','stationary_signal_mad_z','stationary_jump_rate_8db','stationary_jump_rate_z','stationary_param_obs','stationary_pci_change_rate_z','stationary_earfcn_change_rate_z','local_stationary_window_min','local_stationary_window_frac','change_places_frac_stationary','place_rat_surprise','new_place_id','new_place_count','new_place_first_seen_local','new_place_prior_range','new_place_prior_count','new_place_prior_days','new_place_prior_stationary_count','new_place_prior_stationary_days','new_area_code_prior_same_rat_count','new_area_code_prior_same_rat_days','new_area_code_prior_same_code_count','new_area_code_prior_distinct_codes','new_area_code_prior_dominant_code','new_area_code_prior_dominant_frac','new_area_code_prior_range','new_place_post_count','new_place_post_days','new_place_post_stationary_count','new_place_post_stationary_days','stability_bonus','bad_gps_skipped','altitude_samples','altitude_rel_median_m','altitude_rel_p90_m','high_altitude_obs_frac','geo_altitude_confidence','stationary_altitude_samples','stationary_altitude_rel_median_m','stationary_altitude_rel_p90_m','stationary_high_altitude_obs_frac','stationary_geo_altitude_confidence']; let o={}; keys.forEach(k=>{if(f&&f[k]!==undefined)o[k]=f[k]}); return o}
	function bucketExplainerHtml(){
	  return `<details class="small" style="margin:8px 0 0">
	    <summary><b>What is a place bucket?</b></summary>
	    <div style="margin-top:6px;line-height:1.35">
	      A <b>place bucket</b> is a small local area bucketed from GPS using a Web‑Mercator map tile at <code>zoom 17</code> (shown like <code>z17/x/y</code>).
	      We use it to group nearby samples without needing addresses or external geocoding. Buckets are only an analysis convenience: they are approximate and can shift near tile edges.
	    </div>
	  </details>`;
	}
	function renderDrawer(t){
	  document.getElementById('drawer').classList.add('open');
	  document.getElementById('drawerTitle').textContent=t.label;
	  document.getElementById('drawerSub').textContent=`Bayes ${pct(t.bayes_post_p)} · rules ${Number(t.rule_score||0).toFixed(2)} · seen ${t.count}`;
  const allMethods=(t.methods||[]).slice().sort((a,b)=>Math.abs(b.delta_logodds||0)-Math.abs(a.delta_logodds||0));
  const shownMethods=drawerShowAllMethods ? allMethods : allMethods.filter(m=>m.triggered);
  const hiddenCount=Math.max(0, allMethods.length - shownMethods.length);
  const toggleLabel=drawerShowAllMethods ? 'Hide inactive methods' : `Show all methods${hiddenCount?` (${hiddenCount} hidden)`:''}`;
	  document.getElementById('drawerBody').innerHTML=`
	    <div class="pillbar"><button class="ghost" onclick="showPoints(${t.id},'all')" title="Overlay all good-GPS observation points for this tower (blue).">Obs points</button><button class="ghost" onclick="showPoints(${t.id},'raw')" title="Overlay all good-GPS observation points for this tower as small green dots.">Raw obs</button><button class="ghost" onclick="showPoints(${t.id},'stationary')" title="Overlay only stationary observations for this tower (green).">Stationary</button><button class="ghost" onclick="showPoints(${t.id},'bad')" title="Overlay excluded bad-GPS observations (orange).">Bad GPS</button><button class="ghost" onclick="showPoints(${t.id},'clusters')" title="Show cluster centers/radii used by multi-location methods.">Clusters</button><button class="ghost" onclick="showPoints(${t.id},'places')" title="Show place buckets (z17 tiles) where this tower was seen.">Place buckets</button><button class="ghost" onclick="clearOverlays()" title="Clear overlay layers.">Clear overlays</button></div>
	    ${bucketExplainerHtml()}
	    <div class="pillbar"><a class="badge" href="/api/towers/${t.id}/export.md">Export MD</a><a class="badge" href="/api/towers/${t.id}/export.docx">Export DOCX</a><button class="ghost" onclick="recomputeOneTower(${t.id})">Recompute this tower</button><button id="wigleEnrichButton" class="ghost" onclick="enrichTowerWithWigle(${t.id},${Boolean(t.wigle_enrichment)})">${t.wigle_enrichment?'Refresh WiGLE':'Check WiGLE'}</button><span id="towerRecomputeStatus" class="small"></span></div>
      <div id="wigleEnrichmentBox"></div>
	    <div class="meta-editor">
	      <h3 style="margin-top:0">Tower review metadata</h3>
	      <div class="meta-grid">
        <label><input id="towerKnown" type="checkbox" ${t.known?'checked':''}> Known</label>
        <label><input id="towerIgnored" type="checkbox" ${t.ignored?'checked':''}> Ignored</label>
        <label style="display:block"><span class="small">Analysis tag</span><select id="towerAnalysisStatus" style="width:100%;margin-top:6px">${analysisStatusOptionsHtml(t.analysis_status)}</select></label>
      </div>
      <div style="margin-top:10px">
        <label for="towerNotes"><b>Notes</b></label>
        <textarea id="towerNotes" placeholder="Add manual review notes here...">${esc(t.notes||'')}</textarea>
      </div>
      <div class="inline-actions">
        <button class="primary" onclick="saveTowerMetadata(${t.id})">Save tower metadata</button>
        <span id="towerMetaStatus" class="small">${t.has_note?'Stored note present.':'No note stored.'}</span>
      </div>
    </div>
    <h3>Identity</h3><div class="grid2">${['operator','rat','tac_lac','cell_id','pci','earfcn'].map(k=>`<div><b>${k}</b><br><code>${esc(t[k])}</code></div>`).join('')}</div>
    <h3>Important feature values</h3>${renderFeatureTable(t.features)}
    ${renderAltitudeView(t.altitude_view)}
      <h3>Observations</h3>
      <div class="pillbar" style="justify-content:space-between;align-items:center">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="ghost" onclick="loadObsList(${t.id}, window.AUTO_OBS_TABLE_LIMIT)">Load table</button>
          <button class="ghost" onclick="loadObsList(${t.id}, 50000)">Load all</button>
          <button class="ghost" onclick="showPoints(${t.id},'raw')">Overlay raw obs</button>
        </div>
        <span id="obsListStatus" class="small">${t.count<=3 ? 'Tip: use the table to open/ignore the exact point even if it overlaps the tower marker.' : 'Click “Load table” to fetch points (fast), or “Load all”.'}</span>
      </div>
      <div id="obsListBox"><p class="small">Press “Load table” to list this tower’s observation points here.</p></div>
      <div class="pillbar" style="justify-content:space-between;align-items:center"><h3 style="margin:0">XAI score breakdown</h3><button class="ghost" onclick="toggleDrawerMethods()">${esc(toggleLabel)}</button></div>
      ${shownMethods.map(renderMethod).join('') || '<p class="small">No methods to show.</p>'}`;
      renderWigleEnrichment(t.wigle_enrichment);
    }

function setTowerRecomputeStatus(kind,text){
  const el=document.getElementById('towerRecomputeStatus'); if(!el) return;
  el.textContent=text||'';
  el.style.color = kind==='error' ? '#b91c1c' : kind==='success' ? '#15803d' : kind==='working' ? '#1d4ed8' : '#64748b';
}
function renderWigleEnrichment(data){
  const box=document.getElementById('wigleEnrichmentBox'); if(!box) return;
  if(!data){box.innerHTML=''; return;}
  if(data.loading){box.innerHTML='<div class="card"><h3>WiGLE enrichment</h3><p class="small">Checking WiGLE…</p></div>'; return;}
  if(data.error){box.innerHTML=`<div class="card"><h3>WiGLE enrichment</h3><p class="small" style="color:#b91c1c">${esc(data.error)}</p></div>`; return;}
  const q=data.query||{};
  const rows=(data.results||[]).map(r=>`<tr><td><code>${esc(r.id||'')}</code></td><td>${esc(r.ssid||'')}</td><td>${esc(r.gentype||'')}</td><td>${esc(r.channel??'')}</td><td>${esc(r.qos??'')}</td><td>${esc(r.firsttime||'')}</td><td>${esc(r.lasttime||'')}</td></tr>`).join('');
  const summary=data.exists?`Confirmed: ${data.match_count} exact WiGLE match${data.match_count===1?'':'es'}.`:`No exact WiGLE match found.`;
  box.innerHTML=`<div class="card"><h3>WiGLE enrichment</h3><p><b>${esc(summary)}</b></p><p class="small">Queried PLMN/operator <code>${esc(q.cell_op??'not inferred')}</code>, TAC/LAC <code>${esc(q.cell_net??'')}</code>, Cell ID <code>${esc(q.cell_id??'')}</code>. WiGLE returned ${esc(data.wigle_total_results??0)} candidate result(s). Checked <code>${esc(data.checked_at||'')}</code>${data.cached?' (stored result)':''}.</p>${rows?`<div class="term-table-wrap"><table><tr><th>WiGLE ID</th><th>Network</th><th>Type</th><th>Channel</th><th>QoS</th><th>First seen</th><th>Last seen</th></tr>${rows}</table></div>`:''}</div>`;
}
async function enrichTowerWithWigle(towerId,refresh=false){
  renderWigleEnrichment({loading:true});
  try{
    const result=await api(`/api/towers/${towerId}/wigle-enrich?refresh=${refresh?1:0}`,{method:'POST'});
    renderWigleEnrichment(result);
    if(currentTowerData&&Number(currentTowerData.id)===Number(towerId)) currentTowerData.wigle_enrichment=result;
    const button=document.getElementById('wigleEnrichButton');
    if(button){button.textContent='Refresh WiGLE'; button.onclick=()=>enrichTowerWithWigle(towerId,true);}
    await openTower(towerId);
  }catch(e){
    renderWigleEnrichment({error:`WiGLE lookup failed: ${e&&e.message?e.message:String(e)}`});
  }
}
async function recomputeOneTower(towerId){
  try{
    setTowerRecomputeStatus('working','Recomputing…');
    const r=await api(`/api/towers/${towerId}/recompute`,{method:'POST'});
    setTowerRecomputeStatus('success',`Done.`);
    await loadTowers(); await loadTowerTable(); await loadAnomalyTable(); await loadAdmin(); await loadStats();
    // Refresh drawer with recomputed values.
    await openTower(towerId);
  }catch(e){
    const raw=(e&&e.message)?String(e.message):String(e);
    const msg = raw.includes('db_busy') ? 'DB busy; try again shortly.' : raw;
    setTowerRecomputeStatus('error',`Failed: ${msg}`);
  }
}

function obsRowClass(o){
  if(o.bad_gps) return 'obs-bad';
  if(o.ignored) return 'obs-ignored';
  return '';
}
	function renderObsTable(items){
	  if(!Array.isArray(items) || !items.length) return '<p class="small">No observations returned.</p>';
	  const rows = items.map(o=>{
	    const ts = o.ts_iso || o.ts || '';
	    const lat = (o.lat==null)?'':Number(o.lat).toFixed(6);
	    const lon = (o.lon==null)?'':Number(o.lon).toFixed(6);
	    const sig = (o.signal==null)?'—':String(o.signal);
	    const flags = `${o.stationary?'S':''}${o.bad_gps?'B':''}${o.ignored?'I':''}`;
	    const toggleLabel = o.ignored ? 'Use' : 'Ignore';
	    return `<tr class="${obsRowClass(o)}" data-obs="${esc(String(o.obs_uid||''))}">`+
	      `<td><button class="ghost" onclick="focusObs(${currentTowerId()},'${esc(String(o.obs_uid||''))}',${Number(o.lat)||0},${Number(o.lon)||0})">Show</button></td>`+
	      `<td class="mono">${esc(ts)}</td>`+
	      `<td class="mono">${esc(lat)}, ${esc(lon)}</td>`+
	      `<td class="mono">${esc(sig)}</td>`+
	      `<td class="mono">${esc(flags)}</td>`+
	      `<td><button class="ghost" onclick="toggleObsIgnoredFromList('${esc(String(o.obs_uid||''))}', ${o.ignored?0:1});">${toggleLabel}</button></td>`+
	    `</tr>`;
	  }).join('');
	  return `<div class="term-table-wrap"><table class="obs-table">`+
	    `<tr><th>Map</th><th>Time</th><th>Lat/Lon</th><th>Signal</th><th>Flags</th><th>Ignore</th></tr>`+
	    rows+
	  `</table></div>`+
	  `<p class="small">Flags: S=stationary, B=bad_gps, I=ignored. Ignored points stay visible but are excluded from recompute.</p>`;
	}

function updateObsListLocal(obs_uid, ignored){
  if(!currentObsList || !Array.isArray(currentObsList)) return;
  const id = String(obs_uid||'');
  for(const o of currentObsList){
    if(String(o.obs_uid||'')===id){ o.ignored = Boolean(ignored); break; }
  }
  const box=document.getElementById('obsListBox');
  if(box) box.innerHTML = renderObsTable(currentObsList);
}

    async function loadObsList(towerId, limit){
      try{
        const lim = Math.max(50, Math.min(Number(limit||window.AUTO_OBS_TABLE_LIMIT||2000), 100000));
        const box=document.getElementById('obsListBox');
        if(box) box.innerHTML = '<p class="small">Loading observations…</p>';
        const p = await api(`/api/towers/${towerId}/points?limit=${encodeURIComponent(String(lim))}&raw=0`);
        currentObsList = (p.all||[]).slice().sort((a,b)=>(Number(a.ts||0)-Number(b.ts||0)));
        if(box) box.innerHTML = renderObsTable(currentObsList);
        const st=document.getElementById('obsListStatus');
        const total = currentTowerData ? Number(currentTowerData.count||0) : 0;
        if(st){
          const shown = Array.isArray(currentObsList) ? currentObsList.length : 0;
          st.textContent = total>shown ? `Showing ${shown} of ~${total}. Use “Load all” if you need everything.` : `Showing ${shown} observations.`;
        }
      }catch(e){
        const msg=(e&&e.message)?String(e.message):String(e);
        const box=document.getElementById('obsListBox');
        if(box) box.innerHTML = `<p class="small" style="color:#b91c1c">Failed to load observations: ${esc(msg)}</p>`;
      }
    }

async function focusObs(towerId, obs_uid, lat, lon){
  try{
    if(Number.isFinite(lat) && Number.isFinite(lon) && lat && lon){
      map.setView([lat,lon], Math.max(map.getZoom(), 18));
    }
    // Ensure raw obs overlay is drawn so we can open the popup reliably.
    if(!obsMarkers.has(String(obs_uid||'')) || currentPointsMode!=='raw'){
      await showPoints(towerId,'raw');
    }
    const rec = obsMarkers.get(String(obs_uid||''));
    if(rec && rec.layer){
      try{ rec.layer.openPopup(); }catch(_e){}
    }
  }catch(_e){
    // no-op; overlay might not have the point due to filtering/limits
  }
}
function toggleDrawerMethods(){drawerShowAllMethods=!drawerShowAllMethods; if(currentTowerData) renderDrawer(currentTowerData);}
	function renderMethod(m){
	  const rows=(m.xai_rows||[]).map(i=>`<tr><td>${esc(i.role||'')}</td><td><code>${esc(i.name)}</code></td><td>${formatValue(i.value)}</td><td>${esc(i.definition||'')}</td></tr>`).join('');
	  const needsBucketHelp = (String(m.help||'').toLowerCase().includes('place bucket')) || (m.xai_rows||[]).some(r=>String(r.name||'').includes('place'));
	  return `<div class="term ${m.direction}"><h3>${esc(m.label)} <span class="badge">${m.direction==='down'?'lowers':'raises'}</span> <code>${Number(m.delta_logodds||0).toFixed(3)}</code></h3><p>${esc(m.help)}</p>${needsBucketHelp?bucketExplainerHtml():''}<p><b>Result for this tower:</b> ${esc(m.why)} Triggered: <code>${m.triggered}</code></p>${m.trigger_summary?`<p><b>Applies when:</b> ${esc(m.trigger_summary)}</p>`:''}<p><b>Equation:</b> <code>${esc(m.equation)}</code></p>${m.equation_note?`<p class="small"><b>Equation note:</b> ${esc(m.equation_note)}</p>`:''}<p><b>Effect summary:</b> norm01=<code>${Number(m.norm01||0).toFixed(3)}</code>, odds×=<code>${Number(m.odds_multiplier||1).toFixed(3)}</code>, P ${pct(m.p_before)} → ${pct(m.p_after)}</p><div class="term-table-wrap"><table><colgroup><col style="width:12%"><col style="width:20%"><col style="width:20%"><col style="width:48%"></colgroup><tr><th>Role</th><th>Variable</th><th>Value</th><th>Meaning</th></tr>${rows}</table></div>${(m.map_layers||[]).length?`<p><button class="ghost" onclick="showPoints(currentTowerId(),'${m.map_layers[0].includes('stationary')?'stationary':'all'}')">Show evidence points on map</button></p>`:''}</div>`
	}
function currentTowerId(){return currentTowerData ? Number(currentTowerData.id||0) : 0}
function closeDrawer(){document.getElementById('drawer').classList.remove('open'); currentTowerData=null;}
function clearOverlays(){pointLayer.clearLayers();clusterLayer.clearLayers();badLayer.clearLayers();placeLayer.clearLayers();centerLayer.clearLayers(); resetObsMarkers(); currentPointsMode='';}
function resetObsMarkers(){obsMarkers=new Map();}
function pointStyleFor(mode, x){
  const ignored = Boolean(x && x.ignored);
  if(ignored){
    return {radius:(mode==='raw'?3:4),color:'#111827',fillColor:'#94a3b8',fillOpacity:.35,weight:1,dashArray:'3 3'};
  }
  if(mode==='raw') return {radius:3,color:'#16a34a',fillColor:'#16a34a',fillOpacity:.55,weight:1};
  if(mode==='stationary') return {radius:4,color:'#16a34a',fillColor:'#16a34a',fillOpacity:.70,weight:1};
  if(mode==='bad') return {radius:5,color:'#111827',fillColor:'#f59e0b',fillOpacity:.80,weight:1};
  return {radius:4,color:'#2563eb',fillColor:'#2563eb',fillOpacity:.65,weight:1};
}
async function showPoints(id,mode){clearOverlays(); resetObsMarkers(); currentPointsMode=String(mode||''); const p=await api(`/api/towers/${id}/points?kind=${mode}`);
  if(mode==='bad'){(p.bad_gps||[]).forEach(x=>{const layer=L.circleMarker([x.lat,x.lon], pointStyleFor('bad',x)).addTo(badLayer); if(x&&x.obs_uid) obsMarkers.set(String(x.obs_uid), {layer, point:x}); bindPointTooltip(layer,x,'bad');})}
  else if(mode==='clusters'){(p.clusters||[]).forEach(c=>L.circle([c.lat,c.lon],{radius:Math.max(25,Math.sqrt(c.n)*18),color:'#7c3aed',fillOpacity:.08}).addTo(clusterLayer).bindTooltip(`cluster n=${c.n}`));(p.stationary_clusters||[]).forEach(c=>L.circle([c.lat,c.lon],{radius:Math.max(25,Math.sqrt(c.n)*18),color:'#16a34a',fillOpacity:.12}).addTo(clusterLayer).bindTooltip(`stationary cluster n=${c.n}`))}
	  else if(mode==='places'){(p.place_buckets||[]).forEach(b=>{if(!b.bounds)return; L.rectangle([[b.bounds.south,b.bounds.west],[b.bounds.north,b.bounds.east]],{color:'#2563eb',weight:1,fillOpacity:.05}).addTo(placeLayer).bindTooltip(`place bucket ${b.place_id} · n=${b.count}`)})}
  else {
    const arr = (mode==='stationary') ? (p.stationary||[]) : (p.points||[]);
    arr.forEach(x=>{
      const layer=L.circleMarker([x.lat,x.lon], pointStyleFor(mode,x)).addTo(pointLayer);
      if(x && x.obs_uid) obsMarkers.set(String(x.obs_uid), {layer, point:x});
      bindPointTooltip(layer,x,mode);
    });
  }
  if(p.center&&p.center.lat!=null)L.marker([p.center.lat,p.center.lon]).addTo(centerLayer).bindTooltip('robust center');
}

	async function toggleObsIgnored(obs_uid, ignored){
	  try{
	    const r = await api('/api/admin/observations/'+encodeURIComponent(String(obs_uid)), {
	      method:'PUT',
	      headers:{'content-type':'application/json'},
	      body: JSON.stringify({ignored: Boolean(ignored)}),
	    });
    const id = String(r.obs_uid||obs_uid);
    const rec = obsMarkers.get(id);
    if(rec && rec.layer){
      const isIgnored = Boolean(r.ignored);
      // Preserve the current overlay's styling while applying ignored marker style.
      rec.point = {...(rec.point||{}), ignored:isIgnored};
      rec.layer.setStyle(pointStyleFor(currentPointsMode||'all', rec.point));
	      try{ rec.layer.setPopupContent(pointTooltipHtml(rec.point, currentPointsMode||'')); }catch(_e){}
	    }
	    return r;
	  }catch(e){
	    const msg = (e && e.message) ? String(e.message) : String(e);
	    if(msg.includes('db_busy') || msg.toLowerCase().includes('busy') || msg.toLowerCase().includes('locked')){
	      alert('DB is busy importing/recomputing. Try again in a moment.');
	    } else {
	      alert('Failed to update observation: '+msg);
	    }
	    return null;
	  }
	}

	async function toggleObsIgnoredFromList(obs_uid, ignored){
	  const r = await toggleObsIgnored(obs_uid, ignored);
	  if(r && (r.obs_uid || obs_uid)){
	    updateObsListLocal(String(r.obs_uid||obs_uid), r.ignored ? 1 : 0);
	  }
	}
async function loadTowerTable(){const q=document.getElementById('towerSearch').value.trim(); const data=await api('/api/towers?limit=5000&q='+encodeURIComponent(q)+'&include_ignored=1'); towerTableItems=data.items; renderTowerTable('towerTable',towerTableItems,false)}
async function loadAnomalyTable(){
  const q=document.getElementById('anomalySearch').value.trim();
  const method=document.getElementById('anomalyMethod').value;
  const includeIgnored=document.getElementById('anomalyIgnored').checked?1:0;
  const data=await api('/api/anomaly-towers?q='+encodeURIComponent(q)+'&method_id='+encodeURIComponent(method)+'&include_ignored='+includeIgnored);
  anomalyTableItems=data.items;
  const select=document.getElementById('anomalyMethod'), selected=select.value;
  select.innerHTML='<option value="">All triggered anomalies</option>'+(data.available_methods||[]).map(m=>`<option value="${esc(m.id)}">${esc(m.label)} (${m.count})</option>`).join('');
  select.value=selected;
  document.getElementById('anomalyStatus').textContent=`${data.items.length} tower${data.items.length===1?'':'s'} with triggered anomalies`;
  renderAnomalyTable();
}
async function loadAdmin(){const q=document.getElementById('adminSearch').value.trim(); const data=await api('/api/towers?limit=5000&q='+encodeURIComponent(q)+'&include_ignored=1'); adminTableItems=data.items; renderTowerTable('adminTable',adminTableItems,true)}
function sortValue(t,key){
  if(key==='bayes_post_p'||key==='rule_score'||key==='count'||key==='tac_lac'||key==='cell_id'||key==='pci'||key==='earfcn') return Number(t[key]??-Infinity);
  if(key==='has_note') return t[key]?1:0;
  if(key==='known'||key==='ignored') return t[key]?1:0;
  return String(t[key]??'').toLowerCase();
}
function sortTowerItems(items,tableId){
  const s=tableSort[tableId]||{key:'bayes_post_p',dir:-1};
  return [...items].sort((a,b)=>{
    const av=sortValue(a,s.key), bv=sortValue(b,s.key);
    if(typeof av==='number'&&typeof bv==='number') return (av-bv)*s.dir;
    return String(av).localeCompare(String(bv))*s.dir;
  });
}
function sortHeader(tableId,key,label){
  const s=tableSort[tableId]||{key:'bayes_post_p',dir:-1};
  const arrow=s.key===key?(s.dir>0?' ▲':' ▼'):'';
  return `<th class="sortable" onclick="setTowerSort('${tableId}','${key}')">${label}${arrow}</th>`;
}
function setTowerSort(tableId,key){
  const s=tableSort[tableId]||{key,dir:1};
  tableSort[tableId]={key,dir:s.key===key?-s.dir:((key==='bayes_post_p'||key==='rule_score'||key==='count')?-1:1)};
  if(tableId==='anomalyTable') renderAnomalyTable();
  else renderTowerTable(tableId,tableId==='adminTable'?adminTableItems:towerTableItems,tableId==='adminTable');
}
async function showTowerOnMap(id,event){
  if(event) event.stopPropagation();
  document.querySelector('[data-view="mapView"]').click();
  document.getElementById('showNormal').checked=true;
  document.getElementById('showAnom').checked=true;
  document.getElementById('showKnown').checked=true;
  document.getElementById('showIgnored').checked=true;
  document.getElementById('mapSearch').value='';
  document.getElementById('scoreMin').value=0;
  document.getElementById('scoreSlider').value=0;
  await loadTowers();
  await openTower(id,{recenter:true});
}
function renderTowerTable(id,items,admin){
  const sorted=sortTowerItems(items,id);
  const headers=[
    '<th>Map</th>',
    sortHeader(id,'bayes_post_p','Bayes'),
    sortHeader(id,'rule_score','Rules'),
    sortHeader(id,'count','Seen'),
    sortHeader(id,'operator','Operator'),
    sortHeader(id,'rat','RAT'),
    sortHeader(id,'tac_lac','TAC/LAC'),
    sortHeader(id,'cell_id','Cell ID'),
    sortHeader(id,'pci','PCI'),
    sortHeader(id,'earfcn','EARFCN'),
    sortHeader(id,'analysis_status','Tag'),
    sortHeader(id,'has_note','Note'),
    sortHeader(id,'known','Known'),
    sortHeader(id,'ignored','Ignored'),
    admin?'<th>Delete</th>':''
  ].join('');
  document.getElementById(id).innerHTML=`<tr>${headers}</tr>`+sorted.map(t=>`<tr><td><button class="ghost" onclick="showTowerOnMap(${t.id},event)">Show</button></td><td class="score">${pct(t.bayes_post_p)}</td><td class="score">${Number(t.rule_score||0).toFixed(2)}</td><td>${t.count}</td><td>${esc(t.operator)}</td><td>${esc(t.rat)}</td><td><code>${esc(t.tac_lac)}</code></td><td><code>${esc(t.cell_id)}</code></td><td><code>${esc(t.pci)}</code></td><td><code>${esc(t.earfcn)}</code></td><td>${analysisTagHtml(t.analysis_status)}</td><td>${noteIndicatorHtml(t.notes)}</td><td onclick="event.stopPropagation()"><input type="checkbox" ${t.known?'checked':''} onchange="patchTower(${t.id},{known:this.checked})" title="Known tower"></td><td onclick="event.stopPropagation()"><input type="checkbox" ${t.ignored?'checked':''} onchange="patchTower(${t.id},{ignored:this.checked})" title="Ignored tower"></td>${admin?`<td onclick="event.stopPropagation()"><button class="ghost" onclick="deleteTower(${t.id})">Delete</button></td>`:''}</tr>`).join('');
}
function renderAnomalyTable(){
  const id='anomalyTable', sorted=sortTowerItems(anomalyTableItems,id);
  const headers=[
    '<th>Map</th>',
    sortHeader(id,'bayes_post_p','Bayes'),
    sortHeader(id,'rule_score','Rules'),
    sortHeader(id,'count','Seen'),
    sortHeader(id,'operator','Operator'),
    sortHeader(id,'rat','RAT'),
    sortHeader(id,'tac_lac','TAC/LAC'),
    sortHeader(id,'cell_id','Cell ID'),
    '<th>Triggered anomalies</th>'
  ].join('');
  document.getElementById(id).innerHTML=`<tr>${headers}</tr>`+sorted.map(t=>`<tr><td><button class="ghost" onclick="showTowerOnMap(${t.id},event)">Show</button></td><td class="score">${pct(t.bayes_post_p)}</td><td class="score">${Number(t.rule_score||0).toFixed(2)}</td><td>${t.count}</td><td>${esc(t.operator)}</td><td>${esc(t.rat)}</td><td><code>${esc(t.tac_lac)}</code></td><td><code>${esc(t.cell_id)}</code></td><td><div class="pillbar">${(t.triggered_anomalies||[]).map(m=>`<span class="tag-badge" title="${esc(m.why||'')}">${esc(m.label)} <code>+${Number(m.delta_logodds||0).toFixed(2)}</code></span>`).join('')}</div></td></tr>`).join('');
}
function setTowerMetaStatus(kind,text){
  const el=document.getElementById('towerMetaStatus'); if(!el) return;
  el.textContent=text||'';
  el.style.color = kind==='error' ? '#b91c1c' : kind==='success' ? '#15803d' : kind==='working' ? '#1d4ed8' : '#64748b';
}
async function patchTower(id,obj,opts={}){
  await api('/api/admin/towers/'+id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(obj)});
  await loadTowers(); await loadTowerTable(); await loadAnomalyTable(); await loadAdmin();
  if(opts.reloadDrawer) await openTower(id);
}
async function saveTowerMetadata(id){
  try{
    setTowerMetaStatus('working','Saving tower metadata...');
    await patchTower(id,{
      known:Boolean(document.getElementById('towerKnown')?.checked),
      ignored:Boolean(document.getElementById('towerIgnored')?.checked),
      analysis_status:document.getElementById('towerAnalysisStatus')?.value||'',
      notes:document.getElementById('towerNotes')?.value||'',
    },{reloadDrawer:true});
    setTowerMetaStatus('success','Tower metadata saved.');
  }catch(e){
    setTowerMetaStatus('error',`Save failed: ${e&&e.message?e.message:String(e)}`);
  }
}
async function deleteTower(id){if(confirm('Delete tower and observations?')){await api('/api/admin/towers/'+id,{method:'DELETE'}); await loadAdmin(); await loadTowerTable(); await loadAnomalyTable(); await loadTowers();}}
async function loadMethods(){const d=await api('/api/methods'); window.__helpGlossary=d.glossary||{}; appConfig={...(d.app_config||{})}; appConfigHelp={...(d.app_config_help||{})}; renderAppConfigPanel(appConfig, appConfigHelp); document.getElementById('methodsList').innerHTML=d.methods.map(m=>`<div class="card method-row"><h3>${esc(m.label)}</h3><p>${esc(m.help)}</p><label><input type="checkbox" data-mid="${m.id}" data-field="enabled" ${m.enabled?'checked':''}> enabled</label><br><label>Weight <input data-mid="${m.id}" data-field="weight" type="number" step="0.1" value="${m.weight}"></label><p><b>Equation:</b> <code>${esc(m.equation)}</code></p><p><b>Variables:</b> ${(m.variables||[]).map(v=>`<code title="${esc(d.glossary[v]||'')}">${esc(v)}</code>`).join(' ')}</p><textarea data-mid="${m.id}" data-field="thresholds">${esc(JSON.stringify(m.thresholds,null,2))}</textarea></div>`).join('')}
let importStatusPollTimer=null;
function stopImportStatusPolling(){
  if(importStatusPollTimer){ clearInterval(importStatusPollTimer); importStatusPollTimer=null; }
}
function renderImportProgressMeta(state){
  const el=document.getElementById('importsProgressMeta');
  if(!el) return;
  const msg=(state&&state.message)?String(state.message):'';
  el.textContent=msg;
}
async function refreshImportStatus(){
  try{
    const state=await api('/api/import-status');
    renderImportProgressMeta(state);
    if(state&&state.active){
      setStatusLine('importsStatus','working',state.message||'Import in progress…');
    }else if(state&&state.phase==='error'){
      setStatusLine('importsStatus','error',state.message||'Import failed.');
    }
    return state;
  }catch(_e){
    return null;
  }
}
function startImportStatusPolling(){
  stopImportStatusPolling();
  refreshImportStatus();
  importStatusPollTimer=setInterval(refreshImportStatus, 800);
}
async function saveAppConfig(){
  try{
    setMethodsStatus('working','Saving altitude discount configuration…');
    const updates={};
    document.querySelectorAll('#appConfigBox [data-config-key]').forEach(el=>{updates[el.dataset.configKey]=Number(el.value)});
    const r=await api('/api/config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({config:updates})});
    appConfig={...(r.config||{})};
    renderAppConfigPanel(appConfig, appConfigHelp);
    setMethodsStatus('success','Altitude configuration saved. Run recompute to apply it to tower scores.');
  }catch(e){
    setMethodsStatus('error',`Config save failed: ${e&&e.message?e.message:String(e)}`);
  }
}
async function saveMethods(){
  try{
    setMethodsStatus('working','Saving method settings…');
    let updates=[];
    for(const card of document.querySelectorAll('.method-row')){
      const mid=card.querySelector('[data-mid]').dataset.mid;
      updates.push({id:mid,enabled:card.querySelector('[data-field=enabled]').checked,weight:Number(card.querySelector('[data-field=weight]').value),thresholds:JSON.parse(card.querySelector('[data-field=thresholds]').value)});
    }
    await api('/api/methods',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({methods:updates})});
    setMethodsStatus('success','Method settings saved. Run recompute to apply them.');
  }catch(e){
    setMethodsStatus('error',`Save failed: ${e&&e.message?e.message:String(e)}`);
  }
}
async function recompute(origin='general'){
  try{
    if(origin==='imports') setStatusLine('importsStatus','working','Recomputing tower features and scores…');
    else setMethodsStatus('working','Recomputing tower features and scores…');
    const r=await api('/api/recompute',{method:'POST'});
    await loadTowers(); await loadTowerTable(); await loadAnomalyTable(); await loadAdmin(); await loadStats();
    const msg=`Recomputed ${formatInt(r.updated_towers||0)} towers.`;
    if(origin==='imports') setStatusLine('importsStatus','success',msg);
    else setMethodsStatus('success',msg);
  }catch(e){
    const raw = (e&&e.message)?String(e.message):String(e);
    const msg = raw.includes('db_busy')
      ? 'Recompute blocked: DB is busy importing/recomputing. Try again in a moment.'
      : `Recompute failed: ${raw}`;
    if(origin==='imports') setStatusLine('importsStatus','error',msg);
    else setMethodsStatus('error',msg);
  }
}
async function doImport(){
  const paths=document.getElementById('importPaths').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  if(!paths.length){
    setStatusLine('importsStatus','warn','Enter at least one JSONL path to import.');
    renderImportResult({error:'No paths provided.'});
    return;
  }
  try{
    setStatusLine('importsStatus','working',`Importing ${paths.length} path${paths.length===1?'':'s'}…`);
    startImportStatusPolling();
    const r=await api('/api/import',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({paths})});
    renderImportResult(r);
    const msg=r.error
      ? `Import failed: ${r.error}`
      : `Import complete: ${formatInt(r.files_imported||0)} file(s) imported, ${formatInt(r.files_skipped||0)} skipped, ${formatInt(r.new_towers||0)} new towers added.`;
    setStatusLine('importsStatus', r.error ? 'error' : ((r.files_imported||0) ? 'success' : 'warn'), msg);
    renderImportProgressMeta({message:msg});
    await loadStats(); await loadImports(); await loadTowers(); await loadTowerTable(); await loadAnomalyTable(); await loadAdmin();
  }catch(e){
    const msg=`Import failed: ${e&&e.message?e.message:String(e)}`;
    setStatusLine('importsStatus','error',msg);
    renderImportResult({error:msg});
    renderImportProgressMeta({message:msg});
  }finally{
    stopImportStatusPolling();
  }
}
async function uploadImport(){
  const files=document.getElementById('uploadFiles').files;
  if(!files.length){
    setStatusLine('importsStatus','warn','Choose at least one JSONL file first.');
    renderImportResult({error:'No uploaded files selected.'});
    return;
  }
  try{
    const fd=new FormData();
    for(const f of files) fd.append('files',f);
    setStatusLine('importsStatus','working',`Uploading and importing ${files.length} file${files.length===1?'':'s'}…`);
    startImportStatusPolling();
    const r=await api('/api/import',{method:'POST',body:fd});
    renderImportResult(r);
    const msg=r.error
      ? `Upload import failed: ${r.error}`
      : `Upload import complete: ${formatInt(r.files_imported||0)} file(s) imported, ${formatInt(r.files_skipped||0)} skipped, ${formatInt(r.new_towers||0)} new towers added.`;
    setStatusLine('importsStatus', r.error ? 'error' : ((r.files_imported||0) ? 'success' : 'warn'), msg);
    renderImportProgressMeta({message:msg});
    document.getElementById('uploadFiles').value='';
    document.getElementById('uploadSelection').textContent='No files selected.';
    await loadStats(); await loadImports(); await loadTowers(); await loadTowerTable(); await loadAnomalyTable(); await loadAdmin();
  }catch(e){
    const msg=`Upload import failed: ${e&&e.message?e.message:String(e)}`;
    setStatusLine('importsStatus','error',msg);
    renderImportResult({error:msg});
    renderImportProgressMeta({message:msg});
  }finally{
    stopImportStatusPolling();
  }
}
async function loadStats(){renderStatsBox(await api('/api/stats'))}
async function loadImports(){const d=await api('/api/imports?limit=500'); renderImportsHistory(d.items||[])}
async function loadHelp(){const h=await api('/api/help'); window.__helpGlossary=h.glossary||window.__helpGlossary||{}; const cfgRows=Object.entries(h.app_config||{}).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${typeof v==='number'?Number(v).toFixed(3):esc(v)}</td><td>${esc((h.app_config_help||{})[k]||'')}</td></tr>`).join(''); document.getElementById('helpBox').innerHTML=`<h1>Help</h1><p>${esc(h.summary)}</p><h2>Bayes score</h2><p><code>${esc(h.bayes_equation)}</code></p><h2>Altitude discount model</h2><p>Sea-level altitude is not used directly. The dashboard estimates a local ground/floor altitude per place bucket using a robust minimum, then discounts geo-heavy evidence based on height above that local baseline. With the default settings, about 10 m above local ground gives roughly half evidence.</p><table><tr><th>Config</th><th>Value</th><th>Meaning</th></tr>${cfgRows}</table><h2>Glossary</h2><table><tr><th>Term</th><th>Meaning</th></tr>${Object.entries(h.glossary).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`).join('')}</table><h2>Methods</h2>${h.methods.map(m=>`<div class="card"><h3>${esc(m.label)}</h3><p>${esc(m.help)}</p><p><code>${esc(m.equation)}</code></p><p>Variables: ${m.variables.map(v=>`<code>${esc(v)}</code>`).join(' ')}</p></div>`).join('')}`}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.nav button').forEach(x=>x.classList.remove('active')); b.classList.add('active'); document.querySelectorAll('.view').forEach(v=>v.classList.remove('active')); document.getElementById(b.dataset.view).classList.add('active'); setTimeout(()=>map&&map.invalidateSize(),50);});
document.getElementById('uploadFiles').addEventListener('change',e=>{const files=[...(e.target.files||[])]; document.getElementById('uploadSelection').textContent=files.length?files.map(f=>`${f.name} (${formatBytes(f.size)})`).join(' · '):'No files selected.'});
renderImportResult(null);
document.getElementById('mapSearch').addEventListener('keydown',e=>{if(e.key==='Enter')loadTowers()});
document.getElementById('anomalySearch').addEventListener('keydown',e=>{if(e.key==='Enter')loadAnomalyTable()});
initMap(); initDrawerUX(); loadTowers(); loadMethods(); loadStats(); loadImports(); loadHelp(); loadTowerTable(); loadAnomalyTable(); loadAdmin(); refreshImportStatus();
</script>
</body></html>"""


def create_app(db_path: str):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
    except Exception as exc:  # pragma: no cover
        raise SystemExit("FastAPI server dependencies missing. Install with: pip install fastapi uvicorn python-multipart") from exc

    init_db(db_path)
    app = FastAPI(title="Tower Intelligence Dashboard")

    def db_busy_response(detail: str = "Database is busy (import/recompute in progress). Try again in a moment.") -> JSONResponse:
        return JSONResponse({"error": "db_busy", "detail": detail}, status_code=409)

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        return index_html()

    @app.get("/api/stats")
    def stats() -> Dict[str, Any]:
        return db_stats(db_path)

    @app.get("/api/imports")
    def api_imports(limit: int = 200, offset: int = 0) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 2000))
        with connect_db(db_path) as con:
            rows = con.execute(
                """
                SELECT id,path,size,mtime,sha256,imported_rows,new_samples,tower_fingerprints,new_towers,observation_rows,new_observations,errors,imported_at
                FROM import_files
                ORDER BY imported_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, int(offset)),
            ).fetchall()
        return {"items": [dict(r) for r in rows], "limit": limit, "offset": offset}

    @app.get("/api/import-status")
    def api_import_status() -> Dict[str, Any]:
        return import_status_snapshot()

    @app.post("/api/import")
    async def api_import(request: StarletteRequest) -> Dict[str, Any]:
        paths: List[str] = []
        ctype = request.headers.get("content-type", "")
        if "application/json" in ctype:
            payload = await request.json()
            if payload and isinstance(payload.get("paths"), list):
                paths.extend(str(p) for p in payload["paths"])
        elif "multipart/form-data" in ctype:
            upload_dir = Path("imports_uploaded")
            try:
                form = await request.form()
                upload_dir.mkdir(exist_ok=True)
                for f in form.getlist("files"):
                    filename = getattr(f, "filename", None) or "upload.jsonl"
                    target = upload_dir / Path(filename).name
                    if target.exists():
                        stem = target.stem
                        suffix = target.suffix
                        target = upload_dir / f"{stem}-{stable_uid(filename, utc_now())[:10]}{suffix}"
                    data = await f.read()
                    target.write_bytes(data)
                    paths.append(str(target))
                for p in form.getlist("paths"):
                    text = str(p).strip()
                    if text:
                        paths.append(text)
            except Exception:
                body = await request.body()
                paths.extend(parse_multipart_paths(ctype, body, upload_dir))
        if not paths:
            return {"error": "No paths or files provided"}
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        set_import_status(
            active=True,
            task="import",
            phase="queued",
            started_at=utc_now(),
            total_files=len(paths),
            file_index=0,
            current_path="",
            current_file_size=0,
            current_file_bytes=0,
            current_file_percent=0.0,
            current_rows=0,
            current_observations=0,
            current_errors=0,
            imported_rows=0,
            tower_observations=0,
            files_imported=0,
            files_skipped=0,
            errors=0,
            detail=None,
            result=None,
            message=f"Queued import of {len(paths)} file(s)…",
        )

        def _progress(state: Dict[str, Any]) -> None:
            set_import_status(**state)

        def _run() -> Dict[str, Any]:
            return ingest_files(db_path, paths, progress_callback=_progress)
        try:
            return await asyncio.to_thread(_run)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                set_import_status(active=False, phase="error", detail=str(exc), message=f"Import failed: {exc}", finished_at=utc_now())
                return db_busy_response()
            raise
        except Exception as exc:
            set_import_status(active=False, phase="error", detail=str(exc), message=f"Import failed: {exc}", finished_at=utc_now())
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.post("/api/recompute")
    def api_recompute() -> Dict[str, Any]:
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            return recompute(db_path)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.post("/api/towers/{tower_id}/recompute")
    def api_recompute_one(tower_id: int) -> Dict[str, Any]:
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            return recompute_one_tower(db_path, int(tower_id))
        except ValueError:
            return JSONResponse({"error": "not found"}, status_code=404)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.get("/api/towers")
    def api_towers(
        q: str = "",
        limit: int = 500,
        offset: int = 0,
        sort: str = "bayes",
        include_ignored: int = 0,
        hide_known: int = 0,
        anomaly_only: int = 0,
        last_seen_from: Optional[dt.date] = None,
        last_seen_to: Optional[dt.date] = None,
    ) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 5000))
        clauses = ["1=1"]
        params: List[Any] = []
        if last_seen_from and last_seen_to and last_seen_from > last_seen_to:
            raise HTTPException(status_code=400, detail="last_seen_from must be on or before last_seen_to")
        if not include_ignored:
            clauses.append("t.ignored=0")
        if hide_known:
            clauses.append("t.known=0")
        if anomaly_only:
            clauses.append("COALESCE(f.bayes_post_p,0) >= 0.001")
        if last_seen_from:
            from_ts = dt.datetime.combine(last_seen_from, dt.time.min, tzinfo=dt.timezone.utc).timestamp()
            clauses.append("f.last_seen_ts >= ?")
            params.append(from_ts)
        if last_seen_to:
            through_ts = dt.datetime.combine(
                last_seen_to + dt.timedelta(days=1),
                dt.time.min,
                tzinfo=dt.timezone.utc,
            ).timestamp()
            clauses.append("f.last_seen_ts < ?")
            params.append(through_ts)
        if q:
            like = f"%{q}%"
            clauses.append("(t.label LIKE ? OR t.operator LIKE ? OR t.rat LIKE ? OR CAST(t.tac_lac AS TEXT) LIKE ? OR CAST(t.cell_id AS TEXT) LIKE ? OR CAST(t.pci AS TEXT) LIKE ? OR CAST(t.earfcn AS TEXT) LIKE ? OR t.notes LIKE ? OR t.analysis_status LIKE ?)")
            params += [like] * 9
        order = "COALESCE(f.bayes_post_p,0) DESC, COALESCE(f.rule_score,0) DESC"
        if sort == "count":
            order = "COALESCE(f.count,0) DESC"
        sql = f"""
          SELECT t.*, f.* FROM towers t
          LEFT JOIN tower_features f ON f.tower_id=t.id
          WHERE {' AND '.join(clauses)}
          ORDER BY {order}
          LIMIT ? OFFSET ?
        """
        with connect_db(db_path) as con:
            rows = con.execute(sql, (*params, limit, int(offset))).fetchall()
        return {"items": [tower_payload(r) for r in rows], "limit": limit, "offset": offset}

    @app.get("/api/anomaly-towers")
    def api_anomaly_towers(
        q: str = "",
        method_id: str = "",
        include_ignored: int = 0,
    ) -> Dict[str, Any]:
        clauses = ["1=1"]
        if not include_ignored:
            clauses.append("t.ignored=0")
        sql = f"""
          SELECT t.*, f.* FROM towers t
          LEFT JOIN tower_features f ON f.tower_id=t.id
          WHERE {' AND '.join(clauses)}
          ORDER BY COALESCE(f.bayes_post_p,0) DESC, COALESCE(f.rule_score,0) DESC
        """
        method_counts: Counter = Counter()
        items: List[Dict[str, Any]] = []
        with connect_db(db_path) as con:
            rows = con.execute(sql).fetchall()
        query = q.strip().lower()
        for row in rows:
            payload = tower_payload(row)
            anomalies = [
                method for method in payload.get("methods", [])
                if method.get("triggered")
                and method.get("direction") == "up"
                and float(method.get("delta_logodds") or 0.0) > 0.0
            ]
            tower_search_values = [
                payload.get("label"),
                payload.get("operator"),
                payload.get("rat"),
                payload.get("tac_lac"),
                payload.get("cell_id"),
                payload.get("pci"),
                payload.get("earfcn"),
                payload.get("notes"),
                payload.get("analysis_status"),
            ]
            anomaly_search_values = [
                value
                for method in anomalies
                for value in (method.get("id"), method.get("label"))
            ]
            if query and not any(query in str(value or "").lower() for value in tower_search_values + anomaly_search_values):
                continue
            for method in anomalies:
                method_counts[str(method.get("id") or "")] += 1
            if method_id and not any(str(method.get("id") or "") == method_id for method in anomalies):
                continue
            if not anomalies:
                continue
            payload["triggered_anomalies"] = anomalies
            items.append(payload)
        available_methods = [
            {
                "id": str(method["id"]),
                "label": method["label"],
                "count": int(method_counts.get(str(method["id"]), 0)),
            }
            for method in METHOD_REGISTRY
            if method.get("direction") == "up"
        ]
        available_methods.sort(key=lambda method: (-int(method["count"]), str(method["label"])))
        return {"items": items, "available_methods": available_methods}

    @app.get("/api/towers/{tower_id}")
    def api_tower(tower_id: int) -> Dict[str, Any]:
        with connect_db(db_path) as con:
            app_config = get_app_config(con)
            row = con.execute("SELECT t.*, f.* FROM towers t LEFT JOIN tower_features f ON f.tower_id=t.id WHERE t.id=?", (tower_id,)).fetchone()
            if not row:
                return JSONResponse({"error": "not found"}, status_code=404)
            payload = tower_payload(row, enrich_methods=True)
            payload["app_config"] = app_config
            payload["altitude_view"] = altitude_view_payload(payload.get("methods", []), payload.get("features", {}), app_config)
            payload["wigle_enrichment"] = get_wigle_enrichment(con, tower_id)
            return payload

    @app.post("/api/towers/{tower_id}/wigle-enrich")
    def api_wigle_enrich(tower_id: int, refresh: int = 0) -> Dict[str, Any]:
        try:
            result = wigle_enrich_tower(db_path, int(tower_id), refresh=bool(int(refresh)))
            recompute_one_tower(db_path, int(tower_id))
            return result
        except KeyError:
            return JSONResponse({"error": "not found"}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": "invalid_tower", "detail": str(exc)}, status_code=400)
        except RuntimeError as exc:
            return JSONResponse({"error": "wigle_error", "detail": str(exc)}, status_code=502)

    @app.get("/api/towers/{tower_id}/points")
    def api_points(tower_id: int, kind: str = "all", limit: int = 20000, raw: int = 1) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 100000))
        include_raw = bool(int(raw))
        with connect_db(db_path) as con:
            raw_select = "r.raw_json" if include_raw else "NULL AS raw_json"
            rows = con.execute(
                f"""
                SELECT o.*, r.ts_iso, r.alt_m, {raw_select}, r.gps_source, r.gps_status, r.hdop FROM tower_observations o
                LEFT JOIN raw_samples r ON r.sample_uid=o.sample_uid
                WHERE o.tower_id=? AND o.lat IS NOT NULL AND o.lon IS NOT NULL
                ORDER BY o.ts LIMIT ?
                """,
                (tower_id, limit),
            ).fetchall()
            frow = con.execute("SELECT * FROM tower_features WHERE tower_id=?", (tower_id,)).fetchone()
        feats = json_loads(frow["features_json"], {}) if frow else {}
        def point(r: sqlite3.Row) -> Dict[str, Any]:
            return {
                "obs_uid": r["obs_uid"],
                "sample_uid": r["sample_uid"],
                "lat": r["lat"],
                "lon": r["lon"],
                "alt_m": r["alt_m"],
                "ts": r["ts"],
                "ts_iso": r["ts_iso"],
                "signal": r["signal"],
                "stationary": bool(r["stationary"]),
                "bad_gps": bool(r["bad_gps"]),
                "ignored": bool(r["ignored"]) if "ignored" in r.keys() else False,
                "place_id": r["place_id"],
                "gps_source": r["gps_source"],
                "gps_status": r["gps_status"],
                "hdop": r["hdop"],
                "raw_cell": json_loads(r["raw_cell_json"], {}) if r["raw_cell_json"] else {},
                "raw_sample": json_loads(r["raw_json"], {}) if (include_raw and r["raw_json"]) else {},
            }
        places = []
        place_counts = Counter(r["place_id"] for r in rows if r["place_id"])
        for pid, count in place_counts.items():
            places.append({"place_id": pid, "count": count, "bounds": _place_bounds(pid)})
        all_points = [point(r) for r in rows]
        return {
            "all": all_points,
            "points": [point(r) for r in rows if not r["bad_gps"]],
            "stationary": [point(r) for r in rows if r["stationary"] and not r["bad_gps"]],
            "bad_gps": [point(r) for r in rows if r["bad_gps"]],
            "clusters": feats.get("clusters_detail", []),
            "stationary_clusters": feats.get("stationary_clusters_detail", []),
            "place_buckets": places,
            "center": {"lat": frow["center_lat"] if frow else None, "lon": frow["center_lon"] if frow else None},
        }

    @app.put("/api/admin/observations/{obs_uid}")
    async def api_update_observation(obs_uid: str, request: StarletteRequest) -> Dict[str, Any]:
        payload = await request.json()
        ignored = payload.get("ignored")
        if not isinstance(ignored, (bool, int, float)):
            return JSONResponse({"error": "ignored must be boolean"}, status_code=400)
        ignored_i = 1 if bool(ignored) else 0
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            with connect_db(db_path) as con:
                migrate_db(con)
                cur = con.execute("UPDATE tower_observations SET ignored=? WHERE obs_uid=?", (ignored_i, str(obs_uid)))
                con.commit()
                if cur.rowcount < 1:
                    return JSONResponse({"error": "not found"}, status_code=404)
                row = con.execute("SELECT obs_uid, ignored FROM tower_observations WHERE obs_uid=?", (str(obs_uid),)).fetchone()
                return {"obs_uid": row["obs_uid"], "ignored": bool(row["ignored"])}
        except sqlite3.OperationalError as exc:
            # SQLite allows only one writer; imports/recompute may hold a write lock.
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.get("/api/towers/{tower_id}/export.md")
    def api_export_md(tower_id: int) -> PlainTextResponse:
        with connect_db(db_path) as con:
            text = export_markdown(con, tower_id)
        return PlainTextResponse(text, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="tower-{tower_id}.md"'})

    @app.get("/api/towers/{tower_id}/export.docx")
    def api_export_docx(tower_id: int) -> Response:
        with connect_db(db_path) as con:
            data = export_docx(con, tower_id)
        return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={"Content-Disposition": f'attachment; filename="tower-{tower_id}.docx"'})

    @app.get("/api/methods")
    def api_methods() -> Dict[str, Any]:
        with connect_db(db_path) as con:
            settings = get_method_settings(con)
            app_config = get_app_config(con)
        return {"methods": list(settings.values()), "glossary": VARIABLE_GLOSSARY, "app_config": app_config, "app_config_help": GLOBAL_CONFIG_HELP}

    @app.put("/api/methods")
    def api_put_methods(payload: Dict[str, Any]) -> Dict[str, Any]:
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            with connect_db(db_path) as con:
                for item in payload.get("methods", []):
                    mid = item.get("id")
                    if not mid:
                        continue
                    con.execute(
                        "UPDATE method_settings SET enabled=?, weight=?, thresholds_json=?, updated_at=? WHERE method_id=?",
                        (1 if item.get("enabled", True) else 0, float(item.get("weight", 0)), json_dumps(item.get("thresholds", {})), utc_now(), mid),
                    )
                con.commit()
            return {"ok": True}
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.get("/api/config")
    def api_config() -> Dict[str, Any]:
        with connect_db(db_path) as con:
            config = get_app_config(con)
        return {"config": config, "help": GLOBAL_CONFIG_HELP}

    @app.put("/api/config")
    def api_put_config(payload: Dict[str, Any]) -> Dict[str, Any]:
        updates = payload.get("config", {}) if isinstance(payload, dict) else {}
        normalized: Dict[str, Any] = {}
        for key, default in GLOBAL_CONFIG_DEFAULTS.items():
            if key not in updates:
                continue
            value = updates[key]
            if isinstance(default, (int, float)):
                try:
                    normalized[key] = float(value)
                except Exception:
                    continue
            else:
                normalized[key] = value
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            with connect_db(db_path) as con:
                config = update_app_config(con, normalized)
            return {"ok": True, "config": config}
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.put("/api/admin/towers/{tower_id}")
    def api_update_tower(tower_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"label": str, "notes": str, "analysis_status": str, "known": bool, "ignored": bool}
        sets = []
        params = []
        for k, caster in allowed.items():
            if k in payload:
                sets.append(f"{k}=?")
                if isinstance(payload[k], bool):
                    params.append(1 if payload[k] else 0)
                elif k == "analysis_status":
                    params.append(normalize_analysis_status(payload[k]))
                else:
                    params.append(str(payload[k]))
        if not sets:
            return {"ok": True}
        sets.append("updated_at=?")
        params.append(utc_now())
        params.append(tower_id)
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            with connect_db(db_path) as con:
                con.execute(f"UPDATE towers SET {', '.join(sets)} WHERE id=?", params)
                con.commit()
            return {"ok": True}
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.delete("/api/admin/towers/{tower_id}")
    def api_delete_tower(tower_id: int) -> Dict[str, Any]:
        if not WRITE_TASK_LOCK.acquire(blocking=False):
            return db_busy_response()
        try:
            with connect_db(db_path) as con:
                con.execute("DELETE FROM towers WHERE id=?", (tower_id,))
                con.commit()
            return {"ok": True}
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                return db_busy_response()
            raise
        finally:
            try:
                WRITE_TASK_LOCK.release()
            except RuntimeError:
                pass

    @app.get("/api/help")
    def api_help() -> Dict[str, Any]:
        with connect_db(db_path) as con:
            methods = list(get_method_settings(con).values())
            app_config = get_app_config(con)
        return {
            "summary": "This local dashboard ranks anomalous/inconsistent cell tower fingerprints for manual review. It does not attribute a tower to police or any actor.",
            "bayes_equation": "logit(P suspicious | evidence) = logit(prior) + Σ method Δ log-odds",
            "glossary": VARIABLE_GLOSSARY,
            "methods": methods,
            "app_config": app_config,
            "app_config_help": GLOBAL_CONFIG_HELP,
            "analysis_status_values": [v for v in ANALYSIS_STATUS_VALUES if v],
            "docs": ["TOWER_INTEL_APP.md", "TOWER_ANOMALY_METHODS.md"],
        }

    return app


def serve(db_path: str, host: str, port: int) -> None:
    try:
        import uvicorn
    except Exception as exc:
        raise SystemExit("Server dependency missing. Install with: pip install fastapi uvicorn python-multipart") from exc
    app = create_app(db_path)
    uvicorn.run(app, host=host, port=port)


def cli_import_progress_reporter() -> Callable[[Dict[str, Any]], None]:
    last_len = 0

    def _report(progress: Dict[str, Any]) -> None:
        nonlocal last_len
        msg = format_import_progress(progress)
        if not msg:
            return
        line = f"[import] {msg}"
        pad = " " * max(0, last_len - len(line))
        phase = str(progress.get("phase") or "")
        if phase in {"done", "error"}:
            sys.stderr.write("\r" + line + pad + "\n")
            sys.stderr.flush()
            last_len = 0
            return
        sys.stderr.write("\r" + line + pad)
        sys.stderr.flush()
        last_len = len(line)

    return _report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Persistent local tower intelligence dashboard.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite DB path (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help=f"Start local web server (default: http://{DEFAULT_HOST}:{DEFAULT_PORT})")
    p_serve.add_argument("--host", default=DEFAULT_HOST, help=f"Bind host (default: {DEFAULT_HOST})")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Bind port (default: {DEFAULT_PORT})")

    p_ingest = sub.add_parser("ingest", help="Import one or more JSONL files into the DB")
    p_ingest.add_argument("files", nargs="+", help="JSONL files to import")
    p_ingest.add_argument("--max-lines", type=int, default=None, help="Read at most this many lines per file (default: all)")

    p_recompute = sub.add_parser("recompute", help="Recompute tower features and scores")
    p_recompute.add_argument("--sample-size", type=int, default=2500, help="Per-tower reservoir sample size for derived features (default: 2500)")
    p_recompute.add_argument("--refresh-stationary", action="store_true", help="Rebuild stationary flags before recomputing (usually unnecessary right after ingest).")
    p_recompute.add_argument("--no-backfill-altitudes", action="store_true", help="Skip raw-sample altitude backfill during recompute.")

    sub.add_parser("stats", help="Show DB summary")
    sub.add_parser("vacuum", help="Run SQLite VACUUM")

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        serve(args.db, args.host, args.port)
    elif args.cmd == "ingest":
        progress = cli_import_progress_reporter()
        print(json.dumps(ingest_files(args.db, args.files, max_lines=args.max_lines, progress_callback=progress), indent=2))
    elif args.cmd == "recompute":
        print(json.dumps(
            recompute(
                args.db,
                sample_size=args.sample_size,
                refresh_stationary=bool(args.refresh_stationary),
                backfill_altitudes=not bool(args.no_backfill_altitudes),
            ),
            indent=2,
            default=str,
        ))
    elif args.cmd == "stats":
        print(json.dumps(db_stats(args.db), indent=2))
    elif args.cmd == "vacuum":
        init_db(args.db)
        with connect_db(args.db) as con:
            con.execute("VACUUM")
        print("vacuum complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
