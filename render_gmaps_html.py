#!/usr/bin/env python3
"""
render_gmaps_html.py

Renders the legacy Google-Maps based `towers.html` template by injecting a Google Maps API key
from `.env` (or environment) into the placeholder string `YOUR_GOOGLE_MAPS_API_KEY`.

This prevents accidentally committing API keys into git history.

Usage:
  python3 render_gmaps_html.py --in towers.html --out towers.with-key.html

Env:
  GOOGLE_MAPS_API_KEY=...
"""

from __future__ import annotations

import argparse
import os
from typing import Dict


def load_dotenv(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                if k:
                    out[k] = v
    except FileNotFoundError:
        return {}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="towers.html", help="Input HTML template path")
    ap.add_argument("--out", dest="out_path", default="towers.with-key.html", help="Output HTML path")
    ap.add_argument("--env-file", default=".env", help="Path to .env file")
    args = ap.parse_args()

    env = dict(os.environ)
    env.update(load_dotenv(args.env_file))
    key = (env.get("GOOGLE_MAPS_API_KEY") or "").strip()
    if not key:
        raise SystemExit("Missing GOOGLE_MAPS_API_KEY (set it in .env or env var).")

    with open(args.in_path, "r", encoding="utf-8") as f:
        html = f.read()

    if "YOUR_GOOGLE_MAPS_API_KEY" not in html:
        raise SystemExit("Input template does not contain placeholder YOUR_GOOGLE_MAPS_API_KEY.")

    out = html.replace("YOUR_GOOGLE_MAPS_API_KEY", key)
    with open(args.out_path, "w", encoding="utf-8") as f:
        f.write(out)

    print(f"Wrote {args.out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

