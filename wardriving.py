#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time

try:
    import serial
except ImportError:
    serial = None

try:
    import yaml
except ImportError:
    yaml = None


DEFAULT_CONFIG = {
    "mode": "test",
    "serial": {
        "port": "/dev/cu.SLAB_USBtoUART",
        "baudrate": 115200,
        "timeout_s": 1.0,
        "write_timeout_s": 1.0,
        "init_delay_s": 0.5,
        "inter_command_delay_s": 0.1,
        "init_retries": 3,
        "retry_delay_s": 0.5,
    },
    "timeouts": {
        "default_s": 4.0,
        "operator_scan_s": 120.0,
        "gps_s": 6.0,
        "sim_read_s": 4.0,
        "vendor_s": 5.0,
    },
    "features": {
        "operator_scan": True,
        "gps": True,
        "vendor_specific": True,
        "sim_read": True,
    },
    "sim_read": {
        "files": [
            {"name": "iccid", "file_id": "2FE2", "length": 10},
            {"name": "spn", "file_id": "6F46", "length": 17},
            {"name": "ad", "file_id": "6FAD", "length": 4},
        ]
    },
    "extra_commands": [],
    "output": {
        "raw": False
    },
}


ACT_RAT = {
    0: "GSM",
    1: "GSM Compact",
    2: "UTRAN",
    3: "GSM EGPRS",
    4: "UTRAN HSDPA",
    5: "UTRAN HSUPA",
    6: "UTRAN HSDPA/HSUPA",
    7: "LTE",
    8: "CDMA",
    9: "EVDO",
    10: "EVDO A",
    11: "1xRTT",
    12: "HSPA+",
    13: "LTE",
    14: "eHRPD",
    15: "NR5G",
    16: "E-UTRAN NB-S1",
    17: "LTE-M",
    18: "LTE Cat-M1",
    19: "LTE Cat-NB1",
}

REG_STATUS = {
    0: "not_registered",
    1: "registered_home",
    2: "searching",
    3: "registration_denied",
    4: "unknown",
    5: "registered_roaming",
}


def eprint(*args):
    print(*args, file=sys.stderr)


def deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_yaml_config(path):
    if not path:
        return {}
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if yaml is None:
        raise RuntimeError("PyYAML is required to load YAML config files.")
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Config file must contain a YAML mapping at the top level.")
    return data


def resolve_config(args):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config_path = args.config
    if not config_path and os.path.exists("config.yaml"):
        config_path = "config.yaml"
    if config_path:
        config = deep_merge(config, load_yaml_config(config_path))

    if args.mode:
        config["mode"] = args.mode
    if args.port:
        config["serial"]["port"] = args.port
    if args.baudrate is not None:
        config["serial"]["baudrate"] = args.baudrate
    if args.timeout_s is not None:
        config["serial"]["timeout_s"] = args.timeout_s
    if args.write_timeout_s is not None:
        config["serial"]["write_timeout_s"] = args.write_timeout_s
    if args.init_delay_s is not None:
        config["serial"]["init_delay_s"] = args.init_delay_s
    if args.inter_command_delay_s is not None:
        config["serial"]["inter_command_delay_s"] = args.inter_command_delay_s
    if args.operator_scan and args.no_operator_scan:
        raise ValueError("Choose only one of --operator-scan or --no-operator-scan.")
    if args.operator_scan:
        config["features"]["operator_scan"] = True
    if args.no_operator_scan:
        config["features"]["operator_scan"] = False
    if args.gps and args.no_gps:
        raise ValueError("Choose only one of --gps or --no-gps.")
    if args.gps:
        config["features"]["gps"] = True
    if args.no_gps:
        config["features"]["gps"] = False
    if args.vendor_specific and args.no_vendor_specific:
        raise ValueError("Choose only one of --vendor-specific or --no-vendor-specific.")
    if args.vendor_specific:
        config["features"]["vendor_specific"] = True
    if args.no_vendor_specific:
        config["features"]["vendor_specific"] = False
    if args.sim_read and args.no_sim_read:
        raise ValueError("Choose only one of --sim-read or --no-sim-read.")
    if args.sim_read:
        config["features"]["sim_read"] = True
    if args.no_sim_read:
        config["features"]["sim_read"] = False
    if args.operator_scan_timeout_s is not None:
        config["timeouts"]["operator_scan_s"] = args.operator_scan_timeout_s
    if args.output_raw:
        config["output"]["raw"] = True
    if args.extra_command:
        config["extra_commands"] = config.get("extra_commands", []) + args.extra_command

    return config


class ATClient:
    def __init__(self, serial_port, config):
        self.ser = serial_port
        self.config = config
        self.command_log = []

    def initialize(self):
        time.sleep(self.config["serial"]["init_delay_s"])
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        retries = self.config["serial"]["init_retries"]
        ok = False
        for _ in range(retries):
            result = self.send("AT", timeout_s=self.config["timeouts"]["default_s"], retries=0)
            if result["ok"]:
                ok = True
                break
            time.sleep(self.config["serial"]["retry_delay_s"])
        if ok:
            self.send("ATE0")
            self.send("AT+CMEE=2")
        return ok

    def send(self, cmd, timeout_s=None, retries=0):
        attempt = 0
        last_result = None
        while attempt <= retries:
            attempt += 1
            last_result = self._send_once(cmd, timeout_s)
            self.command_log.append(last_result)
            if last_result["ok"]:
                return last_result
            time.sleep(self.config["serial"]["retry_delay_s"])
        return last_result

    def _send_once(self, cmd, timeout_s=None):
        if timeout_s is None:
            timeout_s = self.config["timeouts"]["default_s"]
        start = time.monotonic()
        self.ser.write((cmd + "\r").encode("ascii", errors="ignore"))
        self.ser.flush()
        lines = []
        error = None
        ok = False
        end_time = time.monotonic() + timeout_s
        while time.monotonic() < end_time:
            raw = self.ser.readline()
            if not raw:
                continue
            text = raw.decode(errors="ignore").strip()
            if not text:
                continue
            if text == cmd:
                continue
            lines.append(text)
            upper = text.upper()
            if upper == "OK":
                ok = True
                break
            if upper.startswith("+CME ERROR") or upper.startswith("+CMS ERROR") or upper == "ERROR":
                error = text
                break
            if upper in ("NO CARRIER", "NO DIALTONE", "NO ANSWER", "BUSY"):
                error = text
                break
        if not ok and error is None and time.monotonic() >= end_time:
            error = "timeout"
        elapsed = round(time.monotonic() - start, 3)
        time.sleep(self.config["serial"]["inter_command_delay_s"])
        return {
            "command": cmd,
            "lines": lines,
            "ok": ok,
            "error": error,
            "elapsed_s": elapsed,
        }


def extract_prefixed_value(lines, prefix):
    for line in lines:
        if line.startswith(prefix):
            value = line.split(":", 1)[1].strip()
            return value.strip('"')
    return None


def extract_first_numeric(lines):
    for line in lines:
        stripped = line.strip()
        if stripped.isdigit():
            return stripped
    return None


def parse_csq(lines):
    for line in lines:
        if line.startswith("+CSQ:"):
            payload = line.split(":", 1)[1].strip()
            parts = [p.strip() for p in payload.split(",")]
            if len(parts) >= 2:
                rssi = safe_int(parts[0])
                ber = safe_int(parts[1])
                rssi_dbm = None
                if rssi is not None and 0 <= rssi <= 31:
                    rssi_dbm = -113 + 2 * rssi
                return {
                    "rssi": rssi,
                    "rssi_dbm": rssi_dbm,
                    "ber": ber,
                }
    return {}


def parse_cpin(lines):
    value = extract_prefixed_value(lines, "+CPIN")
    if value:
        return value
    return None


def parse_ccid(lines):
    value = extract_prefixed_value(lines, "+CCID")
    if value:
        return value
    numeric = extract_first_numeric(lines)
    if numeric:
        return numeric
    return None


def parse_cops_current(lines):
    for line in lines:
        if line.startswith("+COPS:"):
            payload = line.split(":", 1)[1].strip()
            parts = split_fields(payload)
            if len(parts) >= 4:
                return {
                    "mode": safe_int(parts[0]),
                    "format": safe_int(parts[1]),
                    "operator": strip_quotes(parts[2]),
                    "act": safe_int(parts[3]),
                }
    return {}


def parse_cops_scan(lines):
    for line in lines:
        if line.startswith("+COPS:"):
            payload = line.split(":", 1)[1].strip()
            return parse_operator_list(payload)
    return []


def parse_reg(lines, prefix):
    for line in lines:
        if line.startswith("+" + prefix + ":"):
            payload = line.split(":", 1)[1].strip()
            parts = split_fields(payload)
            if not parts:
                return {}
            if len(parts) == 1:
                stat = safe_int(parts[0])
                return build_reg_entry(stat, None, None, None)
            stat = safe_int(parts[1]) if len(parts) >= 2 else safe_int(parts[0])
            lac = parse_hex_or_int(parts[2]) if len(parts) >= 3 else None
            ci = parse_hex_or_int(parts[3]) if len(parts) >= 4 else None
            act = safe_int(parts[4]) if len(parts) >= 5 else None
            return build_reg_entry(stat, lac, ci, act)
    return {}


def parse_ceer(lines):
    value = extract_prefixed_value(lines, "+CEER")
    if value:
        return value
    return None


def parse_qnwinfo(lines):
    value = extract_prefixed_value(lines, "+QNWINFO")
    if not value:
        return {}
    parts = split_fields(value)
    if len(parts) >= 3:
        return {
            "rat": strip_quotes(parts[0]),
            "operator": strip_quotes(parts[1]),
            "band": strip_quotes(parts[2]),
            "channel": safe_int(parts[3]) if len(parts) >= 4 else None,
        }
    return {"raw": value}


def parse_cgnsinf(lines):
    value = extract_prefixed_value(lines, "+CGNSINF")
    if not value:
        return {}
    parts = split_fields(value)
    if len(parts) >= 6:
        return {
            "run_status": safe_int(parts[0]),
            "fix_status": safe_int(parts[1]),
            "utc": parts[2],
            "lat": safe_float(parts[3]),
            "lon": safe_float(parts[4]),
            "alt_m": safe_float(parts[5]),
            "raw": value,
        }
    return {"raw": value}


def parse_crsm(lines):
    value = extract_prefixed_value(lines, "+CRSM")
    if not value:
        return {}
    parts = split_fields(value)
    if len(parts) >= 2:
        return {
            "sw1": safe_int(parts[0]),
            "sw2": safe_int(parts[1]),
            "response": strip_quotes(parts[2]) if len(parts) >= 3 else None,
        }
    return {"raw": value}


def build_reg_entry(stat, lac, ci, act):
    entry = {
        "stat_code": stat,
        "stat_text": REG_STATUS.get(stat, "unknown") if stat is not None else None,
        "lac_tac": lac,
        "cell_id": ci,
        "act": act,
        "rat": ACT_RAT.get(act) if act is not None else None,
    }
    return entry


def safe_int(value):
    try:
        return int(str(value).strip().strip('"'))
    except (TypeError, ValueError):
        return None


def safe_float(value):
    try:
        return float(str(value).strip().strip('"'))
    except (TypeError, ValueError):
        return None


def parse_hex_or_int(value):
    text = str(value).strip().strip('"')
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    has_hex = any(c in "abcdefABCDEF" for c in text)
    if has_hex:
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text)
    except ValueError:
        return None


def strip_quotes(value):
    if value is None:
        return None
    return str(value).strip().strip('"')


def split_fields(payload):
    fields = []
    buf = ""
    in_quotes = False
    for ch in payload:
        if ch == '"':
            in_quotes = not in_quotes
            buf += ch
            continue
        if ch == "," and not in_quotes:
            fields.append(buf.strip())
            buf = ""
            continue
        buf += ch
    if buf or payload.endswith(","):
        fields.append(buf.strip())
    return fields


def parse_operator_list(payload):
    groups = []
    buf = ""
    in_quotes = False
    depth = 0
    for ch in payload:
        if ch == '"':
            in_quotes = not in_quotes
        if ch == "(" and not in_quotes:
            depth += 1
            if depth == 1:
                buf = ""
                continue
        if ch == ")" and not in_quotes:
            depth -= 1
            if depth == 0:
                groups.append(buf)
                buf = ""
                continue
        if depth >= 1:
            buf += ch
    operators = []
    for group in groups:
        parts = split_fields(group)
        if len(parts) >= 4:
            operators.append({
                "status": safe_int(parts[0]),
                "long": strip_quotes(parts[1]),
                "short": strip_quotes(parts[2]),
                "numeric": strip_quotes(parts[3]),
                "act": safe_int(parts[4]) if len(parts) >= 5 else None,
                "rat": ACT_RAT.get(safe_int(parts[4])) if len(parts) >= 5 else None,
            })
    return operators


def collect_info(at):
    info = {}
    info["ati"] = at.send("ATI")["lines"]
    info["manufacturer"] = extract_first_line(at.send("AT+CGMI")["lines"])
    info["model"] = extract_first_line(at.send("AT+CGMM")["lines"])
    info["revision"] = extract_first_line(at.send("AT+CGMR")["lines"])
    imei = extract_first_numeric(at.send("AT+CGSN")["lines"])
    if not imei:
        imei = extract_first_numeric(at.send("AT+GSN")["lines"])
    info["imei"] = imei
    return info


def extract_first_line(lines):
    for line in lines:
        if not line:
            continue
        upper = line.upper()
        if upper == "OK":
            continue
        if upper == "ERROR" or upper.startswith("+CME ERROR") or upper.startswith("+CMS ERROR"):
            continue
        return line.strip()
    return None


def collect_sim(at, config):
    sim = {}
    sim["status"] = parse_cpin(at.send("AT+CPIN?")["lines"])
    sim["iccid"] = parse_ccid(at.send("AT+CCID")["lines"])
    sim["imsi"] = extract_first_numeric(at.send("AT+CIMI")["lines"])
    sim["valid"] = sim["status"] == "READY" if sim["status"] else False
    sim["pin_required"] = sim["status"] == "SIM PIN"
    sim["blocked"] = sim["status"] == "SIM PUK"
    sim["files"] = []
    if config["features"].get("sim_read"):
        sim["files"] = read_sim_files(at, config)
    return sim


def read_sim_files(at, config):
    results = []
    for entry in config.get("sim_read", {}).get("files", []):
        name = entry.get("name")
        file_id = entry.get("file_id")
        length = entry.get("length")
        if not file_id or not length:
            continue
        file_id_int = parse_hex_or_int(file_id)
        if file_id_int is None:
            continue
        cmd = "AT+CRSM=176,{},{},{},{}".format(file_id_int, 0, 0, length)
        res = at.send(cmd, timeout_s=config["timeouts"]["sim_read_s"])
        parsed = parse_crsm(res["lines"]) if res["lines"] else {}
        parsed["name"] = name
        parsed["file_id"] = file_id
        parsed["length"] = length
        parsed["ok"] = res["ok"]
        parsed["error"] = res["error"]
        results.append(parsed)
    return results


def collect_network(at, config):
    network = {}
    at.send("AT+CREG=2")
    at.send("AT+CGREG=2")
    at.send("AT+CEREG=2")

    network["csq"] = parse_csq(at.send("AT+CSQ")["lines"])
    network["creg"] = parse_reg(at.send("AT+CREG?")["lines"], "CREG")
    network["cgreg"] = parse_reg(at.send("AT+CGREG?")["lines"], "CGREG")
    network["cereg"] = parse_reg(at.send("AT+CEREG?")["lines"], "CEREG")
    network["cops_current"] = parse_cops_current(at.send("AT+COPS?")["lines"])

    if config["features"].get("operator_scan"):
        scan = at.send("AT+COPS=?", timeout_s=config["timeouts"]["operator_scan_s"])
        network["operators_available"] = parse_cops_scan(scan["lines"])
        network["operators_raw"] = scan["lines"]
    else:
        network["operators_available"] = []
        network["operators_raw"] = []
    return network


def collect_vendor_info(at, config):
    if not config["features"].get("vendor_specific"):
        return {}
    vendor = {}
    qnw = at.send("AT+QNWINFO", timeout_s=config["timeouts"]["vendor_s"])
    vendor["qnwinfo"] = parse_qnwinfo(qnw["lines"])
    vendor["qnwinfo_raw"] = qnw["lines"]
    vendor["qeng_servingcell"] = at.send('AT+QENG="servingcell"', timeout_s=config["timeouts"]["vendor_s"])["lines"]
    vendor["qeng_neighborcell"] = at.send('AT+QENG="neighbourcell"', timeout_s=config["timeouts"]["vendor_s"])["lines"]
    vendor["qcsq"] = at.send("AT+QCSQ", timeout_s=config["timeouts"]["vendor_s"])["lines"]
    return vendor


def collect_gps(at, config):
    if not config["features"].get("gps"):
        return {}
    gps = {}
    gps["cgnspwr"] = at.send("AT+CGNSPWR?", timeout_s=config["timeouts"]["gps_s"])["lines"]
    gps_info = at.send("AT+CGNSINF", timeout_s=config["timeouts"]["gps_s"])
    gps["cgnsinf"] = parse_cgnsinf(gps_info["lines"])
    gps["cgps"] = at.send("AT+CGPS?", timeout_s=config["timeouts"]["gps_s"])["lines"]
    gps["cgpsinfo"] = at.send("AT+CGPSINFO", timeout_s=config["timeouts"]["gps_s"])["lines"]
    gps["qgps"] = at.send("AT+QGPS?", timeout_s=config["timeouts"]["gps_s"])["lines"]
    gps["qgpsloc"] = at.send("AT+QGPSLOC?", timeout_s=config["timeouts"]["gps_s"])["lines"]
    gps["gpsinfo"] = at.send("AT+GPSINFO", timeout_s=config["timeouts"]["gps_s"])["lines"]
    return gps


def collect_errors(at):
    errors = {}
    errors["ceer"] = parse_ceer(at.send("AT+CEER")["lines"])
    return errors


def run_extra_commands(at, config):
    extra_results = []
    for cmd in config.get("extra_commands", []):
        extra_results.append(at.send(cmd))
    return extra_results


def best_registration(network):
    for key in ("cereg", "cgreg", "creg"):
        entry = network.get(key) or {}
        if entry.get("stat_code") is not None:
            return entry
    return {}


def diagnose(results):
    issues = []
    if not results["meta"]["at_ok"]:
        issues.append("No AT response. Check port, baudrate, power, or cabling.")
    sim_status = results.get("sim", {}).get("status")
    if sim_status and sim_status != "READY":
        issues.append("SIM status: {}".format(sim_status))
    reg = best_registration(results.get("network", {}))
    if reg:
        if reg.get("stat_code") == 3:
            issues.append("Registration denied. SIM could be barred or restricted.")
        elif reg.get("stat_code") in (0, 2, 4):
            issues.append("Not registered or still searching.")
    else:
        issues.append("Registration status unavailable.")
    csq = results.get("network", {}).get("csq", {})
    if not csq or csq.get("rssi") in (None, 99):
        issues.append("Signal strength unknown.")
    ceer = results.get("errors", {}).get("ceer")
    if ceer and "no error" not in ceer.lower():
        issues.append("CEER: {}".format(ceer))
    return issues


def print_summary(results, config):
    info = results.get("info", {})
    sim = results.get("sim", {})
    network = results.get("network", {})
    vendor = results.get("vendor", {})
    gps = results.get("gps", {})
    reg = best_registration(network)
    cops = network.get("cops_current", {})
    csq = network.get("csq", {})

    print("Wardriving test mode")
    print("Port: {} baud {}".format(
        config["serial"]["port"],
        config["serial"]["baudrate"])
    )
    print("")
    print("Modem info")
    print("  Manufacturer: {}".format(info.get("manufacturer") or "unknown"))
    print("  Model: {}".format(info.get("model") or "unknown"))
    print("  Revision: {}".format(info.get("revision") or "unknown"))
    print("  IMEI: {}".format(info.get("imei") or "unknown"))
    if info.get("ati"):
        print("  ATI: {}".format(" | ".join(info["ati"])))
    print("")
    print("SIM")
    print("  Status: {}".format(sim.get("status") or "unknown"))
    print("  ICCID: {}".format(sim.get("iccid") or "unknown"))
    print("  IMSI: {}".format(sim.get("imsi") or "unknown"))
    print("  Valid: {}".format("yes" if sim.get("valid") else "no"))
    if sim.get("pin_required"):
        print("  PIN required: yes")
    if sim.get("blocked"):
        print("  SIM blocked (PUK): yes")
    if sim.get("files"):
        print("  SIM files:")
        for item in sim["files"]:
            status = "ok" if item.get("ok") else "error"
            file_id = item.get("file_id")
            print("    {} ({}): {}".format(item.get("name") or "file", file_id, status))
    print("")
    print("Network")
    if csq:
        print("  Signal: rssi={} dBm={} ber={}".format(
            csq.get("rssi"),
            csq.get("rssi_dbm"),
            csq.get("ber"),
        ))
    if reg:
        print("  Registration: {} ({})".format(
            reg.get("stat_text"),
            reg.get("stat_code"),
        ))
        if reg.get("rat"):
            print("  RAT: {}".format(reg.get("rat")))
        if reg.get("lac_tac") is not None:
            print("  LAC/TAC: {}".format(reg.get("lac_tac")))
        if reg.get("cell_id") is not None:
            print("  Cell ID: {}".format(reg.get("cell_id")))
    if cops:
        print("  Operator: {} (act {})".format(
            cops.get("operator") or "unknown",
            cops.get("act") if cops.get("act") is not None else "unknown",
        ))
    if network.get("operators_available"):
        print("  Operators found: {}".format(len(network["operators_available"])))
    if vendor.get("qnwinfo"):
        qnw = vendor["qnwinfo"]
        if qnw.get("band"):
            print("  Band: {}".format(qnw.get("band")))
    print("")
    print("GPS")
    if gps.get("cgnsinf"):
        cgns = gps["cgnsinf"]
        if cgns.get("fix_status") is not None:
            print("  CGNS fix status: {}".format(cgns.get("fix_status")))
        if cgns.get("lat") is not None and cgns.get("lon") is not None:
            print("  Location: {}, {}".format(cgns.get("lat"), cgns.get("lon")))
    else:
        print("  No GPS info detected.")
    print("")
    if results.get("diagnostics"):
        print("Diagnostics")
        for issue in results["diagnostics"]:
            print("  - {}".format(issue))

    if config["output"].get("raw"):
        print("")
        print("Raw command log")
        for entry in results["command_log"]:
            print("  {} -> {} ({})".format(
                entry["command"],
                "OK" if entry["ok"] else "ERR",
                entry["error"] or "ok"
            ))
            for line in entry["lines"]:
                print("    {}".format(line))


def require_dependency(module, name):
    if module is None:
        eprint("Missing dependency: {}. Install with pip.".format(name))
        sys.exit(1)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Cellular wardriving test and diagnostics tool.")
    parser.add_argument("--config", help="Path to YAML config file.")
    parser.add_argument("--mode", choices=["test"], help="Mode to run. Only 'test' is implemented.")
    parser.add_argument("--port", help="Serial port (e.g. /dev/cu.SLAB_USBtoUART).")
    parser.add_argument("--baudrate", type=int, help="Serial baudrate.")
    parser.add_argument("--timeout-s", type=float, help="Serial read timeout in seconds.")
    parser.add_argument("--write-timeout-s", type=float, help="Serial write timeout in seconds.")
    parser.add_argument("--init-delay-s", type=float, help="Delay after opening the port.")
    parser.add_argument("--inter-command-delay-s", type=float, help="Delay between AT commands.")
    parser.add_argument("--operator-scan", action="store_true", help="Enable operator scan.")
    parser.add_argument("--no-operator-scan", action="store_true", help="Disable operator scan.")
    parser.add_argument("--operator-scan-timeout-s", type=float, help="Timeout for AT+COPS=?")
    parser.add_argument("--gps", action="store_true", help="Enable GPS queries.")
    parser.add_argument("--no-gps", action="store_true", help="Disable GPS queries.")
    parser.add_argument("--vendor-specific", action="store_true", help="Enable vendor-specific commands.")
    parser.add_argument("--no-vendor-specific", action="store_true", help="Disable vendor-specific commands.")
    parser.add_argument("--sim-read", action="store_true", help="Enable SIM file reads via AT+CRSM.")
    parser.add_argument("--no-sim-read", action="store_true", help="Disable SIM file reads.")
    parser.add_argument("--extra-command", action="append", help="Extra AT command to run.")
    parser.add_argument("--output-json", help="Write full results to JSON file.")
    parser.add_argument("--output-raw", action="store_true", help="Print raw command log.")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        config = resolve_config(args)
    except Exception as exc:
        eprint("Config error: {}".format(exc))
        return 2

    require_dependency(serial, "pyserial")
    if args.config or os.path.exists("config.yaml"):
        require_dependency(yaml, "pyyaml")

    try:
        ser = serial.Serial(
            port=config["serial"]["port"],
            baudrate=config["serial"]["baudrate"],
            timeout=config["serial"]["timeout_s"],
            write_timeout=config["serial"]["write_timeout_s"],
        )
    except Exception as exc:
        eprint("Failed to open serial port: {}".format(exc))
        return 2

    results = {
        "meta": {
            "mode": config["mode"],
            "port": config["serial"]["port"],
            "baudrate": config["serial"]["baudrate"],
        },
        "info": {},
        "sim": {},
        "network": {},
        "vendor": {},
        "gps": {},
        "errors": {},
        "diagnostics": [],
        "command_log": [],
    }

    with ser:
        at = ATClient(ser, config)
        results["meta"]["at_ok"] = at.initialize()
        results["info"] = collect_info(at)
        results["sim"] = collect_sim(at, config)
        results["network"] = collect_network(at, config)
        results["vendor"] = collect_vendor_info(at, config)
        results["gps"] = collect_gps(at, config)
        results["errors"] = collect_errors(at)
        results["extra"] = run_extra_commands(at, config)
        results["command_log"] = at.command_log

    results["diagnostics"] = diagnose(results)
    print_summary(results, config)

    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as handle:
                json.dump(results, handle, indent=2)
        except Exception as exc:
            eprint("Failed to write JSON output: {}".format(exc))
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
