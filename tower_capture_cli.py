#!/usr/bin/env python3
"""Realtime CLI for Hack-Wanderer GPS and tower captures.

Prefers the live status JSON written by `hack-wanderer.py` on every wardrive
loop, can read normalized history from `tower_intel.sqlite`, and falls back to
tailing the latest JSONL log when needed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tower_anomaly_dashboard import (
    extract_operator,
    iter_jsonl_tail,
    iter_observed_cells,
    observation_signal,
    parse_time,
    pick_location,
    to_epoch_seconds,
    tower_key_from_cell,
)
from tower_intel_server import DEFAULT_DB, connect_db


DEFAULT_STATUS_PATHS = ("status/status.json", "status.json")
DEFAULT_JSONL_CANDIDATES = ("logs/*.jsonl", "hack-wanderer.jsonl")


@dataclass
class SourceSpec:
    kind: str
    path: str


def existing_file(path: str) -> bool:
    try:
        p = Path(path).expanduser()
        return p.is_file() and p.stat().st_size >= 0
    except Exception:
        return False


def coerce_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def coerce_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        return None


def parse_ts_epoch(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        parsed = parse_time(value.strip())
        if parsed is not None:
            return to_epoch_seconds(parsed)
    return None


def format_signal(value: Any) -> str:
    num = coerce_float(value)
    if num is None:
        return "-"
    if abs(num - round(num)) < 1e-9:
        return str(int(round(num)))
    return f"{num:.1f}"


def format_coord(value: Any) -> str:
    num = coerce_float(value)
    if num is None:
        return "-"
    return f"{num:.6f}"


def format_age(epoch: Optional[float], now_epoch: Optional[float] = None) -> str:
    if epoch is None:
        return "-"
    if now_epoch is None:
        now_epoch = time.time()
    delta = max(0, int(now_epoch - epoch))
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"


def tower_identity_text(tower: Dict[str, Any]) -> str:
    parts = [
        str(tower.get("rat") or "?"),
        str(tower.get("tac_lac") if tower.get("tac_lac") is not None else "?"),
        str(tower.get("cell_id") if tower.get("cell_id") is not None else "?"),
        str(tower.get("pci") if tower.get("pci") is not None else "?"),
        str(tower.get("earfcn") if tower.get("earfcn") is not None else "?"),
    ]
    return "/".join(parts)


def normalize_tower_entry(tower: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(tower.get("id") or tower.get("tower_id") or tower.get("key") or tower_identity_text(tower)),
        "tower_id": coerce_int(tower.get("tower_id") if tower.get("tower_id") is not None else tower.get("id")),
        "operator": tower.get("operator") or "",
        "rat": tower.get("rat") or "",
        "tac_lac": coerce_int(tower.get("tac_lac")),
        "cell_id": coerce_int(tower.get("cell_id")),
        "pci": coerce_int(tower.get("pci")),
        "earfcn": coerce_int(tower.get("earfcn")),
        "signal": coerce_float(tower.get("signal")),
        "seen_count": max(1, coerce_int(tower.get("seen_count")) or 1),
        "last_seen": tower.get("last_seen") or tower.get("seen_time_utc") or tower.get("timestamp_utc"),
        "last_seen_epoch": parse_ts_epoch(
            tower.get("last_seen_epoch")
            if tower.get("last_seen_epoch") is not None
            else tower.get("seen_time_utc")
            if tower.get("seen_time_utc")
            else tower.get("last_seen")
        ),
        "first_seen": tower.get("first_seen"),
        "lat": coerce_float(tower.get("lat")),
        "lon": coerce_float(tower.get("lon")),
        "bad_gps": int(bool(tower.get("bad_gps"))),
        "source": tower.get("source") or "",
    }


def sort_towers(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        (normalize_tower_entry(item) for item in items),
        key=lambda item: (
            item.get("last_seen_epoch") is not None,
            item.get("last_seen_epoch") or -1,
            item.get("tower_id") if item.get("tower_id") is not None else -1,
            item.get("id") or "",
        ),
        reverse=True,
    )


def load_status_snapshot(path: str, *, limit: int) -> Dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    towers_raw = payload.get("towers_current_session") or payload.get("towers_all") or payload.get("towers") or []
    towers: List[Dict[str, Any]] = []
    for entry in towers_raw:
        if not isinstance(entry, dict):
            continue
        seen_loc = entry.get("seen_location") or {}
        towers.append({
            "id": entry.get("key") or tower_identity_text(entry),
            "operator": ((payload.get("network") or {}).get("cops_current") or {}).get("operator") or "",
            "rat": entry.get("rat"),
            "tac_lac": entry.get("tac_lac"),
            "cell_id": entry.get("cell_id"),
            "pci": entry.get("pci"),
            "earfcn": entry.get("earfcn"),
            "signal": entry.get("rsrp"),
            "seen_count": entry.get("seen_count"),
            "last_seen": entry.get("seen_time_utc") or payload.get("timestamp_utc"),
            "first_seen": entry.get("first_seen_time_utc"),
            "lat": seen_loc.get("lat"),
            "lon": seen_loc.get("lon"),
            "source": entry.get("source"),
        })
    towers = sort_towers(towers)[:limit]
    location = payload.get("location") or {}
    return {
        "source_kind": "status",
        "source_path": str(Path(path).expanduser()),
        "updated_at": payload.get("timestamp_utc") or payload.get("local_time"),
        "updated_at_epoch": parse_ts_epoch(payload.get("timestamp_utc") or payload.get("local_time")),
        "gps": {
            "lat": coerce_float(location.get("lat")),
            "lon": coerce_float(location.get("lon")),
            "alt_m": coerce_float(location.get("alt_m")),
            "timestamp_utc": location.get("timestamp_utc") or payload.get("gps_time_utc"),
            "source": location.get("source") or "",
            "status": ((payload.get("gps_device") or {}).get("status") or (payload.get("gps_lte_modem") or {}).get("fix_status") or ""),
            "bad_gps": 0,
        },
        "towers": towers,
        "raw": payload,
    }


def load_db_snapshot(path: str, *, limit: int) -> Dict[str, Any]:
    latest_sample: Optional[Dict[str, Any]] = None
    towers: List[Dict[str, Any]] = []
    with connect_db(path) as con:
        row = con.execute(
            """
            SELECT ts_iso, ts, lat, lon, alt_m, gps_source, gps_status, hdop, bad_gps
            FROM raw_samples
            WHERE ts IS NOT NULL
            ORDER BY ts DESC, id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            row = con.execute(
                """
                SELECT ts_iso, ts, lat, lon, alt_m, gps_source, gps_status, hdop, bad_gps
                FROM raw_samples
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        if row:
            latest_sample = dict(row)
        selected: Dict[int, Dict[str, Any]] = {}
        scan_limit = max(int(limit) * 50, 500)
        max_scan = max(scan_limit, 20000)
        while len(selected) < int(limit) and scan_limit <= max_scan:
            rows = con.execute(
                """
                SELECT
                  o.id AS obs_row_id,
                  t.id AS tower_id,
                  t.operator,
                  t.rat,
                  t.tac_lac,
                  t.cell_id,
                  t.pci,
                  t.earfcn,
                  o.signal,
                  o.lat,
                  o.lon,
                  o.bad_gps,
                  r.ts_iso AS last_seen,
                  COALESCE(o.ts, r.ts) AS last_seen_epoch
                FROM tower_observations o
                JOIN towers t ON t.id = o.tower_id
                LEFT JOIN raw_samples r ON r.sample_uid = o.sample_uid
                WHERE t.ignored = 0 AND o.ignored = 0
                ORDER BY o.id DESC
                LIMIT ?
                """,
                (scan_limit,),
            ).fetchall()
            for item in rows:
                tower_id = int(item["tower_id"])
                if tower_id not in selected:
                    selected[tower_id] = dict(item)
                    if len(selected) >= int(limit):
                        break
            if len(rows) < scan_limit or scan_limit >= max_scan:
                break
            scan_limit = min(scan_limit * 2, max_scan)
        if selected:
            tower_ids = sorted(selected)
            placeholders = ",".join("?" for _ in tower_ids)
            counts = con.execute(
                f"""
                SELECT tower_id, COUNT(*) AS seen_count
                FROM tower_observations
                WHERE ignored = 0 AND tower_id IN ({placeholders})
                GROUP BY tower_id
                """,
                tower_ids,
            ).fetchall()
            count_map = {int(item["tower_id"]): int(item["seen_count"]) for item in counts}
            for tower_id, item in selected.items():
                item["seen_count"] = count_map.get(int(tower_id), 1)
            towers = sort_towers(selected.values())[:limit]
    if latest_sample is None:
        raise ValueError(f"no samples found in {path}")
    return {
        "source_kind": "db",
        "source_path": str(Path(path).expanduser()),
        "updated_at": latest_sample.get("ts_iso"),
        "updated_at_epoch": coerce_float(latest_sample.get("ts")),
        "gps": {
            "lat": coerce_float(latest_sample.get("lat")),
            "lon": coerce_float(latest_sample.get("lon")),
            "alt_m": coerce_float(latest_sample.get("alt_m")),
            "timestamp_utc": latest_sample.get("ts_iso"),
            "source": latest_sample.get("gps_source") or "",
            "status": latest_sample.get("gps_status") or "",
            "bad_gps": int(bool(latest_sample.get("bad_gps"))),
        },
        "towers": towers,
        "raw": {"latest_sample": latest_sample},
    }


def find_latest_jsonl(path_hint: str = "") -> Optional[str]:
    candidates: List[Path] = []
    if path_hint:
        hint = Path(path_hint).expanduser()
        if hint.is_file():
            return str(hint.resolve())
        candidates.extend(sorted(hint.parent.glob(hint.name)))
    for pattern in DEFAULT_JSONL_CANDIDATES:
        candidates.extend(sorted(Path(".").glob(pattern)))
    unique: Dict[str, Path] = {}
    for item in candidates:
        try:
            if item.is_file():
                unique[str(item.resolve())] = item.resolve()
        except Exception:
            continue
    if not unique:
        return None
    return str(max(unique.values(), key=lambda p: p.stat().st_mtime))


def load_jsonl_snapshot(path: str, *, limit: int, tail_lines: int) -> Dict[str, Any]:
    rows = list(iter_jsonl_tail(path, max(tail_lines, limit)))
    if not rows:
        raise ValueError(f"no JSONL rows found in {path}")
    latest = rows[-1]
    tower_map: Dict[str, Dict[str, Any]] = {}
    seen_counts: Dict[str, int] = {}
    for index, row in enumerate(rows):
        ts_text = row.get("timestamp_utc") or row.get("timestamp_local")
        ts_epoch = parse_ts_epoch(ts_text)
        operator = extract_operator(row)
        loc = row.get("location") or {}
        for cell in iter_observed_cells(row):
            key = tower_key_from_cell(operator, cell)
            identity = tower_identity_text({
                "rat": key.rat,
                "tac_lac": key.tac_lac,
                "cell_id": key.cell_id,
                "pci": key.pci,
                "earfcn": key.earfcn,
            })
            seen_counts[identity] = seen_counts.get(identity, 0) + 1
            current = tower_map.get(identity)
            rank = (ts_epoch if ts_epoch is not None else float(index), index)
            current_rank = current.get("_rank") if current else None
            if current is not None and current_rank is not None and current_rank >= rank:
                continue
            tower_map[identity] = {
                "id": identity,
                "operator": operator,
                "rat": key.rat,
                "tac_lac": key.tac_lac,
                "cell_id": key.cell_id,
                "pci": key.pci,
                "earfcn": key.earfcn,
                "signal": observation_signal(row, cell),
                "last_seen": ts_text,
                "last_seen_epoch": ts_epoch,
                "lat": loc.get("lat"),
                "lon": loc.get("lon"),
                "source": cell.get("source"),
                "_rank": rank,
            }
    towers = []
    for identity, item in tower_map.items():
        item["seen_count"] = seen_counts.get(identity, 1)
        item.pop("_rank", None)
        towers.append(item)
    towers = sort_towers(towers)[:limit]
    latest_loc = latest.get("location") or {}
    return {
        "source_kind": "jsonl",
        "source_path": str(Path(path).expanduser()),
        "updated_at": latest.get("timestamp_utc") or latest.get("timestamp_local"),
        "updated_at_epoch": parse_ts_epoch(latest.get("timestamp_utc") or latest.get("timestamp_local")),
        "gps": {
            "lat": coerce_float(latest_loc.get("lat")),
            "lon": coerce_float(latest_loc.get("lon")),
            "alt_m": coerce_float(latest_loc.get("alt_m")),
            "timestamp_utc": latest_loc.get("timestamp_utc") or latest.get("gps_time_utc"),
            "source": latest_loc.get("source") or "",
            "status": ((latest.get("gps_device") or {}).get("status") or ""),
            "bad_gps": 0,
        },
        "towers": towers,
        "raw": latest,
    }


def resolve_status_path(path_hint: str = "") -> Optional[str]:
    paths = [path_hint] if path_hint else []
    paths.extend(DEFAULT_STATUS_PATHS)
    for path in paths:
        if path and existing_file(path):
            return str(Path(path).expanduser().resolve())
    return None


def resolve_source(args: argparse.Namespace) -> SourceSpec:
    source = args.source
    if source == "status":
        path = resolve_status_path(args.status_path)
        if not path:
            raise ValueError("status JSON not found")
        return SourceSpec("status", path)
    if source == "db":
        if not existing_file(args.db):
            raise ValueError(f"database not found: {args.db}")
        return SourceSpec("db", str(Path(args.db).expanduser().resolve()))
    if source == "jsonl":
        path = find_latest_jsonl(args.jsonl_path)
        if not path:
            raise ValueError("JSONL log not found")
        return SourceSpec("jsonl", path)

    status_path = resolve_status_path(args.status_path)
    if status_path:
        return SourceSpec("status", status_path)
    if existing_file(args.db):
        return SourceSpec("db", str(Path(args.db).expanduser().resolve()))
    jsonl_path = find_latest_jsonl(args.jsonl_path)
    if jsonl_path:
        return SourceSpec("jsonl", jsonl_path)
    raise ValueError("no live source found; checked status JSON, SQLite DB, and JSONL logs")


def load_snapshot(args: argparse.Namespace) -> Dict[str, Any]:
    source = resolve_source(args)
    if source.kind == "status":
        return load_status_snapshot(source.path, limit=args.limit)
    if source.kind == "db":
        return load_db_snapshot(source.path, limit=args.limit)
    return load_jsonl_snapshot(source.path, limit=args.limit, tail_lines=args.tail_lines)


def render_text(snapshot: Dict[str, Any], *, limit: int) -> str:
    lines = []
    now_epoch = time.time()
    updated = snapshot.get("updated_at") or "-"
    updated_age = format_age(snapshot.get("updated_at_epoch"), now_epoch)
    lines.append("Hack-Wanderer Live Capture View")
    lines.append(f"Source: {snapshot.get('source_kind')}  Path: {snapshot.get('source_path')}")
    lines.append(f"Updated: {updated}  Age: {updated_age}")
    gps = snapshot.get("gps") or {}
    gps_bits = [
        f"lat={format_coord(gps.get('lat'))}",
        f"lon={format_coord(gps.get('lon'))}",
        f"alt_m={format_signal(gps.get('alt_m'))}",
        f"src={gps.get('source') or '-'}",
        f"status={gps.get('status') or '-'}",
        f"bad_gps={int(bool(gps.get('bad_gps')))}",
    ]
    gps_ts = gps.get("timestamp_utc")
    if gps_ts:
        gps_bits.append(f"gps_ts={gps_ts}")
    lines.append("GPS: " + "  ".join(gps_bits))
    lines.append("")
    towers = snapshot.get("towers") or []
    if not towers:
        lines.append("No tower captures found.")
        return "\n".join(lines)

    headers = ["id", "last_seen", "age", "seen", "sig", "rat", "tac/lac", "cell", "pci", "earfcn", "operator"]
    rows: List[List[str]] = []
    for tower in towers[:limit]:
        rows.append([
            str(tower.get("id") or "-"),
            str(tower.get("last_seen") or "-"),
            format_age(tower.get("last_seen_epoch"), now_epoch),
            str(tower.get("seen_count") or 1),
            format_signal(tower.get("signal")),
            str(tower.get("rat") or "-"),
            str(tower.get("tac_lac") if tower.get("tac_lac") is not None else "-"),
            str(tower.get("cell_id") if tower.get("cell_id") is not None else "-"),
            str(tower.get("pci") if tower.get("pci") is not None else "-"),
            str(tower.get("earfcn") if tower.get("earfcn") is not None else "-"),
            str(tower.get("operator") or "-"),
        ])
    widths = []
    for idx, header in enumerate(headers):
        widths.append(max(len(header), *(len(row[idx]) for row in rows)))
    header_line = "  ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers))
    separator = "  ".join("-" * width for width in widths)
    lines.append(f"Latest towers ({min(limit, len(towers))} shown)")
    lines.append(header_line)
    lines.append(separator)
    for row in rows:
        lines.append("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))
    return "\n".join(lines)


def maybe_clear_screen(enabled: bool) -> None:
    if enabled and sys.stdout.isatty():
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show realtime GPS position and latest tower captures.")
    parser.add_argument("--source", choices=["auto", "status", "db", "jsonl"], default="auto", help="Data source to read. auto prefers live status JSON.")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path for --source db or auto fallback.")
    parser.add_argument("--status-path", default="", help="Status JSON path. auto also checks status/status.json and status.json.")
    parser.add_argument("--jsonl-path", default="", help="JSONL log path or glob. auto falls back to the latest matching log.")
    parser.add_argument("--limit", type=int, default=10, help="How many tower rows to show.")
    parser.add_argument("--tail-lines", type=int, default=250, help="How many JSONL lines to scan when using the jsonl source.")
    parser.add_argument("--watch", action="store_true", help="Refresh continuously.")
    parser.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds for --watch.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a text table.")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear the screen between watch refreshes.")
    return parser.parse_args(list(argv))


def run_once(args: argparse.Namespace) -> int:
    snapshot = load_snapshot(args)
    if args.json:
        print(json.dumps(snapshot, ensure_ascii=True, indent=2))
    else:
        print(render_text(snapshot, limit=args.limit))
    return 0


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    if args.limit <= 0:
        print("--limit must be greater than 0", file=sys.stderr)
        return 2
    if args.tail_lines <= 0:
        print("--tail-lines must be greater than 0", file=sys.stderr)
        return 2
    if args.interval <= 0:
        print("--interval must be greater than 0", file=sys.stderr)
        return 2
    try:
        if not args.watch:
            return run_once(args)
        while True:
            maybe_clear_screen(not args.no_clear)
            snapshot = load_snapshot(args)
            if args.json:
                print(json.dumps(snapshot, ensure_ascii=True, indent=2))
            else:
                print(render_text(snapshot, limit=args.limit))
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"tower_capture_cli error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
