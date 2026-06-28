#!/usr/bin/env python3
"""Automatically set the Linux timezone for a roaming hack-wanderer Pi.

Preferred source order:
1. GPS coordinates from the live status JSON, resolved offline with
   timezonefinder when available.
2. GPS coordinates resolved through a public timezone API when internet works.
3. IP-based timezone lookup, including tzupdate when available.

The script is deliberately patient: it can run at boot while the modem is still
bringing up 3G data and while hack-wanderer is still waiting for the first GPS
fix.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional, Tuple


def log(message: str) -> None:
    print(message, flush=True)


def run(cmd, *, timeout: int = 60, check: bool = False):
    log("+ " + " ".join(str(part) for part in cmd))
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)


def current_timezone() -> str:
    try:
        out = run(["timedatectl", "show", "-p", "Timezone", "--value"], timeout=10)
        value = out.stdout.strip()
        if value:
            return value
    except Exception:
        pass
    try:
        text = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if text:
            return text
    except Exception:
        pass
    return ""


def valid_timezone(name: str) -> bool:
    if not name or name.startswith("/") or ".." in name:
        return False
    return Path("/usr/share/zoneinfo", name).exists()


def set_timezone(name: str) -> bool:
    if not valid_timezone(name):
        log(f"Refusing invalid timezone: {name!r}")
        return False
    before = current_timezone()
    if before == name:
        log(f"Timezone already set to {name}")
        return False
    run(["timedatectl", "set-timezone", name], timeout=30, check=True)
    try:
        Path("/etc/timezone").write_text(name + "\n", encoding="utf-8")
    except Exception as exc:
        log(f"Could not update /etc/timezone: {exc}")
    after = current_timezone()
    log(f"Timezone changed: {before or '(unknown)'} -> {after}")
    return after == name


def maybe_restart(service: str) -> None:
    if service:
        run(["systemctl", "restart", service], timeout=60)


def read_status_payload(status_path: Path) -> Optional[dict]:
    try:
        return json.loads(status_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"GPS status not ready at {status_path}: {exc}")
        return None


def read_gps(status_path: Path) -> Optional[Tuple[float, float]]:
    payload = read_status_payload(status_path)
    if not payload:
        return None
    candidates = [
        payload.get("location") or {},
        ((payload.get("gps_device") or {}).get("location") or {}),
    ]
    for item in candidates:
        try:
            lat = float(item.get("lat"))
            lon = float(item.get("lon"))
        except Exception:
            continue
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            return lat, lon
    log("GPS status exists but has no usable lat/lon yet.")
    return None


def parse_utc_timestamp(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).timestamp()
    except Exception:
        return None


def gps_utc_timestamp_from_status(status_path: Path) -> Optional[float]:
    payload = read_status_payload(status_path)
    if not payload:
        return None
    candidates = [
        payload.get("gps_time_utc"),
        (payload.get("location") or {}).get("timestamp_utc"),
        ((payload.get("gps_device") or {}).get("location") or {}).get("timestamp_utc"),
        (payload.get("gps_device") or {}).get("timestamp_utc"),
    ]
    for candidate in candidates:
        ts = parse_utc_timestamp(candidate)
        if ts is not None:
            return ts
    log("GPS status exists but has no usable UTC timestamp yet.")
    return None


def sync_clock_from_gps(status_path: Path, *, min_skew_seconds: float) -> bool:
    gps_ts = gps_utc_timestamp_from_status(status_path)
    if gps_ts is None:
        return False
    now_ts = time.time()
    skew = gps_ts - now_ts
    gps_dt = dt.datetime.fromtimestamp(gps_ts, dt.timezone.utc)
    if abs(skew) < min_skew_seconds:
        log(f"System clock close to GPS UTC ({skew:+.1f}s skew).")
        return False
    stamp = gps_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    log(f"Setting system clock from GPS UTC {stamp} ({skew:+.1f}s skew).")
    run(["date", "-u", "-s", stamp], timeout=30, check=True)
    return True


def add_venv_site_packages(venv: Path) -> None:
    bin_dir = str(venv / "bin")
    path = os.environ.get("PATH", "")
    if bin_dir not in path.split(os.pathsep):
        os.environ["PATH"] = bin_dir + os.pathsep + path
    for path in glob.glob(str(venv / "lib" / "python*" / "site-packages")):
        if path not in sys.path:
            sys.path.insert(0, path)


def install_helper_tools(venv: Path) -> None:
    if not venv.exists():
        run([sys.executable, "-m", "venv", str(venv)], timeout=120)
    pip = venv / "bin" / "pip"
    env = os.environ.copy()
    env.setdefault("PIP_DEFAULT_TIMEOUT", "20")
    log("+ " + " ".join([str(pip), "install", "-q", "timezonefinder", "tzupdate"]))
    subprocess.run([str(pip), "install", "-q", "timezonefinder", "tzupdate"], env=env, timeout=180, check=False)
    add_venv_site_packages(venv)


def timezone_from_gps_offline(lat: float, lon: float, venv: Path, try_install: bool) -> Optional[str]:
    add_venv_site_packages(venv)
    try:
        from timezonefinder import TimezoneFinder  # type: ignore
    except Exception:
        if not try_install:
            return None
        install_helper_tools(venv)
        try:
            from timezonefinder import TimezoneFinder  # type: ignore
        except Exception as exc:
            log(f"timezonefinder unavailable: {exc}")
            return None
    try:
        tz = TimezoneFinder().timezone_at(lat=lat, lng=lon)
        if tz:
            log(f"GPS offline timezone lookup: {lat},{lon} -> {tz}")
            return tz
    except Exception as exc:
        log(f"GPS offline timezone lookup failed: {exc}")
    return None


def fetch_json(url: str, timeout: int = 12) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "hack-wanderer-auto-timezone/1"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        data = response.read(20000)
    return json.loads(data.decode("utf-8", "replace"))


def timezone_from_gps_online(lat: float, lon: float) -> Optional[str]:
    urls = [
        "https://timeapi.io/api/TimeZone/coordinate?"
        + urllib.parse.urlencode({"latitude": lat, "longitude": lon}),
        "https://api.geotimezone.com/public/timezone?"
        + urllib.parse.urlencode({"latitude": lat, "longitude": lon}),
    ]
    for url in urls:
        try:
            data = fetch_json(url)
            for key in ("timeZone", "timezone", "iana_timezone", "ianaTimeZone"):
                value = data.get(key) if isinstance(data, dict) else None
                if isinstance(value, str) and value:
                    log(f"GPS online timezone lookup: {lat},{lon} -> {value}")
                    return value
        except Exception as exc:
            log(f"GPS online timezone lookup failed via {url}: {exc}")
    return None


def timezone_from_ip_online() -> Optional[str]:
    urls = [
        "https://ipapi.co/timezone/",
        "http://ip-api.com/line/?fields=timezone",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hack-wanderer-auto-timezone/1"})
            with urllib.request.urlopen(req, timeout=12) as response:
                text = response.read(2000).decode("utf-8", "replace").strip()
            if text and "/" in text:
                log(f"IP timezone lookup -> {text}")
                return text
        except Exception as exc:
            log(f"IP timezone lookup failed via {url}: {exc}")
    return None


def run_tzupdate() -> bool:
    if not any(Path(p, "tzupdate").exists() for p in os.environ.get("PATH", "").split(os.pathsep)):
        return False
    before = current_timezone()
    result = run(["tzupdate"], timeout=90)
    if result.stdout:
        log(result.stdout.strip())
    if result.stderr:
        log(result.stderr.strip())
    after = current_timezone()
    return result.returncode == 0 and after and after != before


def choose_timezone(args) -> Optional[str]:
    gps = read_gps(Path(args.status_path))
    if gps:
        lat, lon = gps
        tz = timezone_from_gps_offline(lat, lon, Path(args.venv), try_install=False)
        if tz:
            return tz
        tz = timezone_from_gps_online(lat, lon)
        if tz:
            return tz
        tz = timezone_from_gps_offline(lat, lon, Path(args.venv), try_install=args.install)
        if tz:
            return tz
    if run_tzupdate():
        return current_timezone()
    return timezone_from_ip_online()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-path", default="/home/pi/code/hack-wanderer/status/status.json")
    parser.add_argument("--venv", default="/opt/hack-wanderer-tz/venv")
    parser.add_argument("--wait-seconds", type=int, default=7200)
    parser.add_argument("--interval-seconds", type=int, default=60)
    parser.add_argument("--restart-service", default="")
    parser.add_argument("--install", action="store_true", help="Try to install timezonefinder into the helper venv when internet is available.")
    parser.add_argument("--gps-clock-min-skew-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)

    deadline = time.monotonic() + max(0, args.wait_seconds)
    attempt = 0
    while True:
        attempt += 1
        log(f"Timezone update attempt {attempt}; current={current_timezone() or '(unknown)'}")
        try:
            if sync_clock_from_gps(Path(args.status_path), min_skew_seconds=args.gps_clock_min_skew_seconds):
                maybe_restart(args.restart_service)
        except Exception as exc:
            log(f"GPS clock sync failed: {exc}")
        tz = choose_timezone(args)
        if tz:
            changed = set_timezone(tz)
            if changed:
                maybe_restart(args.restart_service)
            return 0
        if time.monotonic() >= deadline:
            log("No timezone source available before timeout.")
            return 75
        time.sleep(max(5, args.interval_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
