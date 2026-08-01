#!/usr/bin/env python3
"""Print plain-English cellular, GPS, and time status from a Hack-Wanderer log."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Optional, Tuple


CPSI_RE = re.compile(r"\+CPSI:\s*(.+)", re.IGNORECASE)
GPS_DEVICE_RE = re.compile(r"GPS \(device ([^)]+)\) source=device:\s*(.+)", re.IGNORECASE)
GPS_MODEM_RE = re.compile(r"GPS \(LTE modem\) source=lte_modem:\s*(.+)", re.IGNORECASE)
SATS_USED_RE = re.compile(r"\bsats_used=(\d+)", re.IGNORECASE)
GPS_TIMESTAMP_RE = re.compile(r"\btimestamp=([^\s]+)", re.IGNORECASE)
MODEM_UTC_RE = re.compile(r"\butc=([^\s]+)", re.IGNORECASE)


def latest_log(log_dir: Path) -> Optional[Path]:
    candidates = [path for path in log_dir.glob("hack-wanderer_*.log") if path.is_file()]
    return max(candidates, key=lambda path: path.stat().st_mtime, default=None)


def latest_cpsi(lines: Iterable[str]) -> Optional[str]:
    return latest_statuses(lines)[0]


def latest_statuses(lines: Iterable[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    cpsi = None
    gps_device = None
    gps_modem = None
    for line in lines:
        match = CPSI_RE.search(line)
        if match:
            cpsi = match.group(1).strip()
        match = GPS_DEVICE_RE.search(line)
        if match:
            gps_device = f"{match.group(1).strip()}: {match.group(2).strip()}"
        match = GPS_MODEM_RE.search(line)
        if match:
            gps_modem = match.group(1).strip()
    return cpsi, gps_device, gps_modem


def interpret_cpsi(cpsi: str) -> Tuple[str, int]:
    status = cpsi.upper()
    if "NO SERVICE" in status:
        return "NO CELLULAR SERVICE", 1
    if any(rat in status for rat in ("NR5G", "LTE", "E-UTRAN")):
        return "LTE/5G CONNECTED", 0
    if "GSM" in status:
        return "CELLULAR CONNECTED, BUT GSM/2G ONLY", 1
    if any(rat in status for rat in ("WCDMA", "UMTS", "HSPA")):
        return "CELLULAR CONNECTED, BUT 3G ONLY", 1
    return "CELLULAR STATUS UNKNOWN", 2


def interpret_gps_device(gps_status: str) -> Tuple[str, int]:
    status = gps_status.upper()
    if "NO FIX" in status:
        return "GPS RECEIVER CONNECTED, BUT NO FIX", 1
    if "DISABLED" in status:
        return "GPS DISABLED", 1
    if "LAT=" in status and "LON=" in status:
        match = SATS_USED_RE.search(gps_status)
        if match:
            satellites = int(match.group(1))
            if satellites > 0:
                return f"GPS FIX AVAILABLE ({satellites} SATELLITES USED)", 0
            return "GPS POSITION REPORTED, BUT FIX IS INVALID (0 SATELLITES USED)", 1
        return "GPS POSITION AVAILABLE", 0
    return "GPS STATUS UNKNOWN", 2


def time_source(gps_device: Optional[str], gps_modem: Optional[str]) -> Tuple[str, Optional[str]]:
    if gps_device:
        match = GPS_TIMESTAMP_RE.search(gps_device)
        if match:
            return "EXTERNAL GPS", match.group(1)
    if gps_modem:
        match = MODEM_UTC_RE.search(gps_modem)
        if match:
            return "LTE MODEM GPS", match.group(1)
    return "RASPBERRY PI SYSTEM CLOCK ONLY", None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check cellular, GPS, and time status in the latest Hack-Wanderer log."
    )
    parser.add_argument("--log", type=Path, help="Check this specific log file.")
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "logs",
        help="Directory containing hack-wanderer_*.log files (default: ./logs).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log_path = args.log or latest_log(args.log_dir)
    if log_path is None:
        print(f"ERROR: no hack-wanderer_*.log files found in {args.log_dir}", file=sys.stderr)
        return 2
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            cpsi, gps_device, gps_modem = latest_statuses(handle)
    except OSError as exc:
        print(f"ERROR: cannot read {log_path}: {exc}", file=sys.stderr)
        return 2
    if cpsi is None:
        print(f"CELLULAR STATUS UNKNOWN\nLog: {log_path}\nNo +CPSI status found.")
        return 2

    verdict, lte_exit_code = interpret_cpsi(cpsi)
    print(f"Cellular: {verdict}")
    print(f"Log: {log_path}")
    print(f"Modem: +CPSI: {cpsi}")

    print()
    if gps_device is None:
        gps_verdict = "GPS STATUS UNKNOWN"
        print(f"GPS: {gps_verdict}")
        print("No external GPS status found in the log.")
    else:
        gps_verdict, _gps_exit_code = interpret_gps_device(gps_device)
        print(f"GPS: {gps_verdict}")
        print(f"Device: {gps_device}")
    if gps_modem:
        print(f"LTE modem GPS: {gps_modem}")

    source, gps_time = time_source(gps_device, gps_modem)
    print()
    print(f"Time source available in log: {source}")
    if gps_time:
        print(f"GPS time (UTC): {gps_time}")
    print("Log timestamp source: Raspberry Pi system clock")
    print("Cellular-network time: NOT RECORDED by Hack-Wanderer")
    # Preserve the checker's original contract: the process exit code describes
    # LTE status; GPS and time are additional human-readable diagnostics.
    return lte_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
