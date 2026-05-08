#!/usr/bin/env python3
"""
tower_map.py

Read a JSONL log and render observed towers onto a Google Map.
Markers are placed at the device GPS location at the time of observation,
grouped per (cell_id, tac_lac, rat).

Example:
  python3 tower_map.py input.jsonl --out towers.html --api-key "$GMAPS_API_KEY"

Or:
  export GMAPS_API_KEY="..."
  python3 tower_map.py input.jsonl --out towers.html
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


def parse_utc(ts: str) -> Optional[dt.datetime]:
    if not ts or not isinstance(ts, str):
        return None
    # Accept "...Z" and ISO strings with offset
    try:
        if ts.endswith("Z"):
            return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def pick_location(obj: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """
    Prefer:
      obj["location"]["lat/lon"]
    then:
      obj["gps_device"]["location"]["lat/lon"]
    """
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


@dataclass
class TowerAgg:
    cell_id: int
    tac_lac: Optional[int]
    rat: Optional[str]
    stat: Optional[str]

    first_seen: dt.datetime
    last_seen: dt.datetime
    count: int

    sum_lat: float
    sum_lon: float

    def add(self, when: dt.datetime, lat: float, lon: float, stat: Optional[str]) -> None:
        if when < self.first_seen:
            self.first_seen = when
        if when > self.last_seen:
            self.last_seen = when
        self.count += 1
        self.sum_lat += lat
        self.sum_lon += lon
        # Keep the latest non-empty status (often useful)
        if stat:
            self.stat = stat

    @property
    def avg_lat(self) -> float:
        return self.sum_lat / max(self.count, 1)

    @property
    def avg_lon(self) -> float:
        return self.sum_lon / max(self.count, 1)


def iter_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                # Skip malformed lines (common in logs)
                continue


def aggregate_towers(path: str) -> Tuple[Dict[Tuple[int, Optional[int], Optional[str]], TowerAgg], Optional[Tuple[float, float]]]:
    aggs: Dict[Tuple[int, Optional[int], Optional[str]], TowerAgg] = {}
    # For map centering: average of all seen points
    center_sum_lat = 0.0
    center_sum_lon = 0.0
    center_n = 0

    for obj in iter_jsonl(path):
        ts = parse_utc(obj.get("timestamp_utc", ""))
        if ts is None:
            continue

        loc = pick_location(obj)
        if loc is None:
            continue
        lat, lon = loc

        towers = obj.get("towers")
        if not isinstance(towers, list) or not towers:
            continue

        # Center stats
        center_sum_lat += lat
        center_sum_lon += lon
        center_n += 1

        for t in towers:
            if not isinstance(t, dict):
                continue
            cell_id = t.get("cell_id")
            if not isinstance(cell_id, int):
                # Sometimes cell_id is string; attempt coercion
                try:
                    cell_id = int(cell_id)
                except Exception:
                    continue

            tac_lac = t.get("tac_lac")
            if tac_lac is not None and not isinstance(tac_lac, int):
                try:
                    tac_lac = int(tac_lac)
                except Exception:
                    tac_lac = None

            rat = t.get("rat")
            if rat is not None and not isinstance(rat, str):
                rat = str(rat)

            stat = t.get("stat")
            if stat is not None and not isinstance(stat, str):
                stat = str(stat)

            key = (cell_id, tac_lac, rat)
            if key not in aggs:
                aggs[key] = TowerAgg(
                    cell_id=cell_id,
                    tac_lac=tac_lac,
                    rat=rat,
                    stat=stat,
                    first_seen=ts,
                    last_seen=ts,
                    count=1,
                    sum_lat=lat,
                    sum_lon=lon,
                )
            else:
                aggs[key].add(ts, lat, lon, stat)

    center = None
    if center_n > 0:
        center = (center_sum_lat / center_n, center_sum_lon / center_n)
    return aggs, center


def iso_z(d: dt.datetime) -> str:
    # Render as "...Z" if UTC offset is zero; otherwise keep ISO with offset
    if d.tzinfo is not None and d.utcoffset() == dt.timedelta(0):
        return d.astimezone(dt.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"
    return d.isoformat(timespec="seconds")


def build_html(markers: List[Dict[str, Any]], center: Tuple[float, float], api_key: str, zoom: int) -> str:
    # We embed marker data as JSON and build info windows client-side.
    marker_json = json.dumps(markers, ensure_ascii=False)

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Tower Observations</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    html, body, #map {{
      height: 100%;
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
    }}
    .info {{
      min-width: 260px;
      line-height: 1.35;
    }}
    .info h3 {{
      margin: 0 0 8px 0;
      font-size: 16px;
    }}
    .kv {{
      margin: 2px 0;
    }}
    .muted {{
      color: #666;
      font-size: 12px;
      margin-top: 8px;
    }}
  </style>
</head>
<body>
  <div id="map"></div>

  <script>
    const MARKERS = {marker_json};

    function escapeHtml(s) {{
      return String(s)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }}

    function formatInfo(m) {{
      const title = `Cell ID: ${{m.cell_id}}`;
      const rat = m.rat ?? '(unknown)';
      const tac = (m.tac_lac === null || m.tac_lac === undefined) ? '(unknown)' : m.tac_lac;
      const stat = m.stat ?? '(unknown)';
      return `
        <div class="info">
          <h3>${{escapeHtml(title)}}</h3>
          <div class="kv"><b>RAT</b>: ${{escapeHtml(rat)}}</div>
          <div class="kv"><b>TAC/LAC</b>: ${{escapeHtml(tac)}}</div>
          <div class="kv"><b>Status</b>: ${{escapeHtml(stat)}}</div>
          <div class="kv"><b>First seen</b>: ${{escapeHtml(m.first_seen)}}</div>
          <div class="kv"><b>Last seen</b>: ${{escapeHtml(m.last_seen)}}</div>
          <div class="kv"><b>Count</b>: ${{escapeHtml(m.count)}}</div>
          <div class="muted">Marker location is the average device GPS position when this tower was observed.</div>
        </div>
      `;
    }}

    function initMap() {{
      const center = {{ lat: {center[0]}, lng: {center[1]} }};
      const map = new google.maps.Map(document.getElementById("map"), {{
        center,
        zoom: {zoom},
        mapTypeId: "roadmap",
      }});

      const infowindow = new google.maps.InfoWindow();

      for (const m of MARKERS) {{
        const marker = new google.maps.Marker({{
          position: {{ lat: m.lat, lng: m.lon }},
          map,
          title: `cell_id=${{m.cell_id}}`,
        }});

        marker.addListener("click", () => {{
          infowindow.setContent(formatInfo(m));
          infowindow.open({{ anchor: marker, map }});
        }});
      }}
    }}
  </script>

  <script async defer
    src="https://maps.googleapis.com/maps/api/js?key={html.escape(api_key)}&callback=initMap">
  </script>
</body>
</html>
"""


def main() -> int:
    p = argparse.ArgumentParser(description="Plot tower observations from JSONL onto Google Maps.")
    p.add_argument("jsonl", help="Input .jsonl file (one JSON object per line)")
    p.add_argument("--out", default="towers.html", help="Output HTML file (default: towers.html)")
    p.add_argument("--api-key", default=os.environ.get("GMAPS_API_KEY", ""), help="Google Maps JS API key (or env GMAPS_API_KEY)")
    p.add_argument("--zoom", type=int, default=14, help="Initial map zoom (default: 14)")
    args = p.parse_args()

    if not args.api_key:
        raise SystemExit("ERROR: missing Google Maps API key. Provide --api-key or set GMAPS_API_KEY.")

    aggs, center = aggregate_towers(args.jsonl)
    if not aggs:
        raise SystemExit("ERROR: no tower observations found (missing towers[] / timestamps / or GPS lat/lon).")
    if center is None:
        # Fallback to first tower avg location
        first = next(iter(aggs.values()))
        center = (first.avg_lat, first.avg_lon)

    # Turn aggregated towers into marker objects for the HTML
    markers: List[Dict[str, Any]] = []
    for (_, _, _), a in sorted(
        aggs.items(),
        key=lambda kv: (kv[1].cell_id, kv[1].tac_lac or -1, kv[1].rat or ""),
    ):
        markers.append(
            {
                "cell_id": a.cell_id,
                "tac_lac": a.tac_lac,
                "rat": a.rat,
                "stat": a.stat,
                "first_seen": iso_z(a.first_seen),
                "last_seen": iso_z(a.last_seen),
                "count": a.count,
                "lat": a.avg_lat,
                "lon": a.avg_lon,
            }
        )

    html_text = build_html(markers=markers, center=center, api_key=args.api_key, zoom=args.zoom)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_text)

    print(f"Wrote {args.out} with {len(markers)} tower markers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
