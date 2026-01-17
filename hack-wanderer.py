#!/usr/bin/env python3
import argparse
import datetime
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
        "vendor_s": 10.0,
    },
    "features": {
        "operator_scan": False,
        "gps": True,
        "vendor_specific": True,
        "sim_read": True,
        "auto_register": True,
    },
    "tower_scan": {
        "enabled": True,
        "passes": 2,
        "detach_before_scan": False,
        "dwell_s": 1.0,
        "qeng_timeout_s": 10.0,
        "qeng_retries": 1,
        "operator_scan_each_loop": False,
    },
    "external_gps": {
        "enabled": True,
        "port": "/dev/ttyACM0",
        "baudrate": 9600,
        "timeout_s": 0.5,
        "read_duration_s": 2.0,
        "max_lines": 200,
    },
    "wardrive": {
        "interval_s": 5.0,
        "duration_s": 60.0,
        "jsonl_path": "hack-wanderer.jsonl",
        "wigle_csv_path": "",
    },
    "sim": {
        "pin": "",
        "pin_env_key": "SIM_PIN",
        "env_file": ".env",
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
        "raw": False,
        "json_path": ""
    },
    "status_page": {
        "json_path": "status/status.json",
    },
    "logging": {
        "enabled": True,
        "dir": "logs",
        "file": "",
        "file_level": "debug",
        "console_level": "info",
    },
    "ui": {
        "color": True,
        "emoji": True,
        "interactive": False,
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

LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
}

LEVEL_NAMES = {
    10: "DEBUG",
    20: "INFO",
    30: "WARNING",
    40: "ERROR",
}

EMOJI = {
    "debug": "\U0001F50D",
    "info": "\u2139",
    "warning": "\u26A0",
    "error": "\u274C",
    "success": "\u2705",
    "step": "\U0001F9ED",
    "modem": "\U0001F4F1",
    "sim": "\U0001F4B3",
    "network": "\U0001F4F6",
    "gps": "\U0001F4CD",
    "test": "\U0001F9EA",
    "diag": "\U0001F6E0",
}

ANSI_COLORS = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
    "bold": "\033[1m",
}

LEVEL_COLORS = {
    "debug": "gray",
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
}


def command_key(cmd):
    text = cmd.strip()
    if text.startswith("AT+QENG="):
        return 'AT+QENG="..."'
    if text.startswith("AT+CPIN="):
        return "AT+CPIN="
    if text.startswith("AT+CRSM="):
        return "AT+CRSM=176"
    if "=" in text and text.endswith("?"):
        return text
    if text.endswith("?"):
        return text
    if "=" in text:
        return text.split("=", 1)[0] + "="
    return text


def describe_command(cmd):
    key = command_key(cmd.upper())
    descriptions = {
        "AT": ("Modem ping", "Check if the modem responds to AT."),
        "ATE0": ("Disable echo", "Turn off command echo for cleaner responses."),
        "AT+CMEE=2": ("Verbose errors", "Enable detailed error codes."),
        "AT+CGMI": ("Manufacturer", "Read the modem manufacturer string."),
        "AT+CGMM": ("Model", "Read the modem model string."),
        "AT+CGMR": ("Revision", "Read the modem firmware revision."),
        "AT+CGSN": ("IMEI", "Read IMEI (serial number)."),
        "AT+GSN": ("IMEI", "Read IMEI (alternate command)."),
        "AT+CPIN?": ("SIM PIN status", "Check whether SIM needs a PIN or is ready."),
        "AT+CPIN=": ("SIM PIN entry", "Submit SIM PIN to unlock the SIM."),
        "AT+CCID": ("SIM ICCID", "Read SIM card ICCID identifier."),
        "AT+CIMI": ("SIM IMSI", "Read subscriber IMSI."),
        "AT+CSQ": ("Signal quality", "Read RSSI and BER."),
        "AT+CREG=2": ("Enable CREG detail", "Enable extended GSM registration info."),
        "AT+CGREG=2": ("Enable CGREG detail", "Enable extended GPRS registration info."),
        "AT+CEREG=2": ("Enable CEREG detail", "Enable extended EPS/LTE registration info."),
        "AT+CREG?": ("GSM registration", "Read 2G/3G registration status."),
        "AT+CGREG?": ("GPRS registration", "Read GPRS registration status."),
        "AT+CEREG?": ("EPS registration", "Read LTE/NR registration status."),
        "AT+COPS?": ("Current operator", "Read current operator and RAT."),
        "AT+COPS=0": ("Auto registration", "Register automatically to available operator."),
        "AT+COPS=?": ("Operator scan", "Scan for nearby operators."),
        "AT+CEER": ("Last error", "Read last extended error report."),
        "AT+QNWINFO": ("QNWINFO", "Read RAT, band, and operator (Quectel)."),
        'AT+QENG="..."': ("QENG", "Serving/neighbor cell info (Quectel)."),
        "AT+QCSQ": ("QCSQ", "Extended signal quality (Quectel)."),
        "AT+CGNSPWR?": ("GNSS power", "Read GNSS power state."),
        "AT+CGNSINF": ("GNSS info", "Read GNSS fix and location."),
        "AT+CGPS?": ("GPS state", "Read GPS state (varies by vendor)."),
        "AT+CGPSINFO": ("GPS info", "Read GPS info (varies by vendor)."),
        "AT+QGPS?": ("QGPS state", "Read Quectel GPS state."),
        "AT+QGPSLOC?": ("QGPS location", "Read Quectel GPS location."),
        "AT+GPSINFO": ("GPS info", "Read GPS info (varies by vendor)."),
        "AT+CRSM=176": ("SIM file read", "Read SIM EF file by ID."),
        "ATI": ("Modem ID", "Read modem identification info."),
    }
    title, purpose = descriptions.get(key, ("AT command", "Execute AT command."))
    return {"title": title, "purpose": purpose, "key": key}


def eprint(*args):
    print(*args, file=sys.stderr)


def now_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def normalize_level(value, default):
    if not value:
        return LEVELS[default]
    key = str(value).strip().lower()
    return LEVELS.get(key, LEVELS[default])


class RunLogger:
    def __init__(self, config):
        self.config = config
        ui_cfg = config.get("ui", {})
        log_cfg = config.get("logging", {})
        self.use_color = bool(ui_cfg.get("color"))
        if self.use_color and (not sys.stdout.isatty() or os.getenv("NO_COLOR")):
            self.use_color = False
        self.use_emoji = bool(ui_cfg.get("emoji"))
        self.interactive = bool(ui_cfg.get("interactive")) and sys.stdin.isatty()
        self.console_level = normalize_level(log_cfg.get("console_level"), "info")
        self.file_level = normalize_level(log_cfg.get("file_level"), "debug")
        self.enabled = bool(log_cfg.get("enabled", True))
        self.file_path = self._resolve_log_path(log_cfg)
        self._file_handle = None
        if self.enabled and self.file_path:
            try:
                dirpath = os.path.dirname(self.file_path)
                if dirpath:
                    os.makedirs(dirpath, exist_ok=True)
                self._file_handle = open(self.file_path, "a", encoding="utf-8")
            except OSError as exc:
                eprint("Failed to open log file {}: {}".format(self.file_path, exc))
                self._file_handle = None
                self.enabled = False

    def _resolve_log_path(self, log_cfg):
        custom = log_cfg.get("file")
        if custom:
            return custom
        directory = log_cfg.get("dir") or "."
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        filename = "hack-wanderer_{}.log".format(stamp)
        return os.path.join(directory, filename)

    def close(self):
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def _emoji(self, key):
        if not self.use_emoji:
            return ""
        return EMOJI.get(key, "")

    def with_emoji(self, key, text):
        emoji = self._emoji(key)
        if emoji:
            return "{} {}".format(emoji, text)
        return text

    def _style(self, text, color=None, bold=False):
        if not self.use_color:
            return text
        codes = []
        if bold:
            codes.append(ANSI_COLORS["bold"])
        if color and color in ANSI_COLORS:
            codes.append(ANSI_COLORS[color])
        if not codes:
            return text
        return "{}{}{}".format("".join(codes), text, ANSI_COLORS["reset"])

    def _write_file(self, level, message):
        if not self.enabled or not self._file_handle:
            return
        if level < self.file_level:
            return
        label = LEVEL_NAMES.get(level, "INFO")
        self._file_handle.write("{} {} {}\n".format(now_timestamp(), label, message))
        self._file_handle.flush()

    def _write_console(self, level, message, color=None, prefix=True, bold=False):
        if level < self.console_level:
            return
        out = message
        if prefix:
            name = LEVEL_NAMES.get(level, "INFO")
            emoji = self._emoji(name.lower())
            prefix_text = "[{}]".format(name)
            if emoji:
                prefix_text = "{} {}".format(emoji, prefix_text)
            prefix_text = self._style(prefix_text, LEVEL_COLORS.get(name.lower()), bold=True)
            out = "{} {}".format(prefix_text, message)
        if color:
            out = self._style(out, color, bold=bold)
        print(out)

    def log(self, level_name, message, color=None, prefix=True, bold=False):
        level = normalize_level(level_name, "info")
        self._write_file(level, message)
        self._write_console(level, message, color=color, prefix=prefix, bold=bold)

    def debug(self, message):
        self.log("debug", message)

    def info(self, message):
        self.log("info", message)

    def warning(self, message):
        self.log("warning", message)

    def error(self, message):
        self.log("error", message)

    def print_line(self, message, level_name="info", color=None, bold=False):
        level = normalize_level(level_name, "info")
        if message:
            self._write_file(level, message)
        self._write_console(level, message, color=color, prefix=False, bold=bold)

    def section(self, title, emoji_key=None):
        label = title
        emoji = self._emoji(emoji_key) if emoji_key else ""
        if emoji:
            label = "{} {}".format(emoji, title)
        self.print_line(label, level_name="info", color="magenta", bold=True)

    def step(self, message):
        if self.interactive:
            prompt = "{} Press Enter to {}...".format(self._emoji("step"), message)
            prompt = self._style(prompt.strip(), "blue", bold=True)
            try:
                input(prompt + " ")
            except EOFError:
                pass
        self.info(message)

    def command_block(self, title, purpose, cmd, result, summary, raw_lines):
        self.print_line("")
        header = "{} {}".format(self._emoji("step"), title) if self.use_emoji else title
        self.print_line(header, color="blue", bold=True)
        self.print_line("  Purpose: {}".format(purpose), color="gray")
        self.print_line("  Command: {}".format(cmd), color="cyan")
        status = "OK" if result.get("ok") else "ERROR"
        status_color = "green" if result.get("ok") else "red"
        self.print_line(
            "  Status: {} ({}) elapsed={}s".format(status, result.get("error") or "ok", result.get("elapsed_s")),
            color=status_color
        )
        if summary:
            self.print_line("  TL;DR: {}".format(summary), color="yellow")
        if raw_lines:
            self.print_line("  Output:")
            for line in raw_lines:
                self.print_line("    {}".format(line), color="gray")

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


def load_env_file(path):
    if not path or not os.path.exists(path):
        return {}
    data = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            data[key] = value
    return data


def redact_config(config):
    cleaned = json.loads(json.dumps(config))
    sim_cfg = cleaned.get("sim", {})
    if "pin" in sim_cfg and sim_cfg.get("pin"):
        sim_cfg["pin"] = "****"
        cleaned["sim"] = sim_cfg
    return cleaned


def mask_command(cmd):
    upper = cmd.strip().upper()
    if upper.startswith("AT+CPIN="):
        return "AT+CPIN=****"
    return cmd


def iso_timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_sim_read_file(value):
    if not value:
        raise ValueError("SIM file definition is empty.")
    if "," in value:
        parts = [part.strip() for part in value.split(",")]
    else:
        parts = [part.strip() for part in value.split(":")]
    if len(parts) != 3:
        raise ValueError("SIM file definition must be name,file_id,length.")
    name, file_id, length_text = parts
    length = safe_int(length_text)
    if length is None:
        raise ValueError("SIM file length must be an integer.")
    return {"name": name, "file_id": file_id, "length": length}


def resolve_config(args):
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config_path = args.config
    if not config_path and os.path.exists("config.yaml"):
        config_path = "config.yaml"
    if config_path:
        config = deep_merge(config, load_yaml_config(config_path))

    env_file = config.get("sim", {}).get("env_file")
    env_values = load_env_file(env_file) if env_file else {}
    env_key = config.get("sim", {}).get("pin_env_key", "SIM_PIN")
    if env_key in env_values and env_values.get(env_key):
        config["sim"]["pin"] = env_values[env_key]

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
    if args.init_retries is not None:
        config["serial"]["init_retries"] = args.init_retries
    if args.retry_delay_s is not None:
        config["serial"]["retry_delay_s"] = args.retry_delay_s
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
    if args.gps_device and args.no_gps_device:
        raise ValueError("Choose only one of --gps-device or --no-gps-device.")
    if args.gps_device:
        config["external_gps"]["enabled"] = True
    if args.no_gps_device:
        config["external_gps"]["enabled"] = False
    if args.vendor_specific and args.no_vendor_specific:
        raise ValueError("Choose only one of --vendor-specific or --no-vendor-specific.")
    if args.vendor_specific:
        config["features"]["vendor_specific"] = True
    if args.no_vendor_specific:
        config["features"]["vendor_specific"] = False
    if args.auto_register and args.no_auto_register:
        raise ValueError("Choose only one of --auto-register or --no-auto-register.")
    if args.auto_register:
        config["features"]["auto_register"] = True
    if args.no_auto_register:
        config["features"]["auto_register"] = False
    if args.sim_read and args.no_sim_read:
        raise ValueError("Choose only one of --sim-read or --no-sim-read.")
    if args.sim_read:
        config["features"]["sim_read"] = True
    if args.no_sim_read:
        config["features"]["sim_read"] = False
    if args.operator_scan_timeout_s is not None:
        config["timeouts"]["operator_scan_s"] = args.operator_scan_timeout_s
    if args.sim_pin:
        config["sim"]["pin"] = args.sim_pin
    if args.default_timeout_s is not None:
        config["timeouts"]["default_s"] = args.default_timeout_s
    if args.gps_timeout_s is not None:
        config["timeouts"]["gps_s"] = args.gps_timeout_s
    if args.sim_read_timeout_s is not None:
        config["timeouts"]["sim_read_s"] = args.sim_read_timeout_s
    if args.vendor_timeout_s is not None:
        config["timeouts"]["vendor_s"] = args.vendor_timeout_s
    if args.gps_device_timeout_s is not None:
        config["external_gps"]["timeout_s"] = args.gps_device_timeout_s
    if args.gps_device_read_duration_s is not None:
        config["external_gps"]["read_duration_s"] = args.gps_device_read_duration_s
    if args.gps_device_port:
        config["external_gps"]["port"] = args.gps_device_port
    if args.gps_device_baudrate is not None:
        config["external_gps"]["baudrate"] = args.gps_device_baudrate
    if args.output_raw:
        config["output"]["raw"] = True
    if args.output_json:
        config["output"]["json_path"] = args.output_json
    if args.log_dir:
        config["logging"]["dir"] = args.log_dir
    if args.log_file:
        config["logging"]["file"] = args.log_file
    if args.no_log:
        config["logging"]["enabled"] = False
    if args.log_level:
        config["logging"]["file_level"] = args.log_level
    if args.console_level:
        config["logging"]["console_level"] = args.console_level
    if args.color and args.no_color:
        raise ValueError("Choose only one of --color or --no-color.")
    if args.color:
        config["ui"]["color"] = True
    if args.no_color:
        config["ui"]["color"] = False
    if args.emoji and args.no_emoji:
        raise ValueError("Choose only one of --emoji or --no-emoji.")
    if args.emoji:
        config["ui"]["emoji"] = True
    if args.no_emoji:
        config["ui"]["emoji"] = False
    if args.interactive and args.no_interactive:
        raise ValueError("Choose only one of --interactive or --no-interactive.")
    if args.interactive:
        config["ui"]["interactive"] = True
    if args.no_interactive:
        config["ui"]["interactive"] = False
    if args.extra_command:
        config["extra_commands"] = config.get("extra_commands", []) + args.extra_command
    if args.clear_sim_read_files:
        config["sim_read"]["files"] = []
    if args.sim_read_file:
        entries = []
        for value in args.sim_read_file:
            entries.append(parse_sim_read_file(value))
        config["sim_read"]["files"] = config.get("sim_read", {}).get("files", []) + entries
    if args.duration_s is not None:
        config["wardrive"]["duration_s"] = args.duration_s
    if args.interval_s is not None:
        config["wardrive"]["interval_s"] = args.interval_s
    if args.jsonl_path:
        config["wardrive"]["jsonl_path"] = args.jsonl_path
    if args.wigle_csv:
        config["wardrive"]["wigle_csv_path"] = args.wigle_csv

    return config


class ATClient:
    def __init__(self, serial_port, config, logger):
        self.ser = serial_port
        self.config = config
        self.logger = logger
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
            self.logger.debug("Disabling echo and enabling verbose errors.")
            self.send("ATE0")
            self.send("AT+CMEE=2")
        return ok

    def send(self, cmd, timeout_s=None, retries=0):
        attempt = 0
        last_result = None
        masked = mask_command(cmd)
        desc = describe_command(cmd)
        while attempt <= retries:
            attempt += 1
            self.logger.info("AT command [{} / {}]: {} - {}".format(
                attempt, retries + 1, masked, desc["title"]
            ))
            last_result = self._send_once(cmd, timeout_s)
            last_result["command"] = masked
            self.command_log.append(last_result)
            summary = summarize_response(cmd, last_result["lines"])
            title = "{} (attempt {}/{})".format(desc["title"], attempt, retries + 1)
            self.logger.command_block(
                title,
                desc["purpose"],
                masked,
                last_result,
                summary,
                last_result["lines"],
            )
            for line in last_result["lines"]:
                self.logger.debug("AT response: {}".format(line))
            if last_result["ok"]:
                self.logger.info("AT OK: {} ({}s)".format(masked, last_result["elapsed_s"]))
                return last_result
            self.logger.warning("AT error: {} ({})".format(masked, last_result["error"] or "error"))
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


def parse_qeng_servingcell(lines):
    towers = []
    for line in lines:
        if not line.startswith('+QENG: "servingcell"'):
            continue
        payload = line.split(":", 1)[1].strip()
        parts = split_fields(payload)
        if len(parts) < 6:
            continue
        # Expected patterns vary; parse best-effort for LTE/NR and GSM/UMTS.
        mode = strip_quotes(parts[1]) if len(parts) > 1 else None
        rat = strip_quotes(parts[2]) if len(parts) > 2 else None
        entry = {
            "source": "qeng_servingcell",
            "mode": mode,
            "rat": rat,
            "raw": line,
        }
        # Common LTE format: mode, rat, fdd/tdd, mcc, mnc, cellid, pci, earfcn, band, bw, rsrp, rsrq, rssi, sinr
        if rat in ("LTE", "CAT-M1", "CAT-NB1", "NB-IOT", "NR5G"):
            entry.update({
                "duplex": strip_quotes(parts[3]) if len(parts) > 3 else None,
                "mcc": safe_int(parts[4]) if len(parts) > 4 else None,
                "mnc": safe_int(parts[5]) if len(parts) > 5 else None,
                "cell_id": parse_hex_or_int(parts[6]) if len(parts) > 6 else None,
                "pci": safe_int(parts[7]) if len(parts) > 7 else None,
                "earfcn": safe_int(parts[8]) if len(parts) > 8 else None,
                "band": strip_quotes(parts[9]) if len(parts) > 9 else None,
                "bandwidth": strip_quotes(parts[10]) if len(parts) > 10 else None,
                "rsrp": safe_int(parts[11]) if len(parts) > 11 else None,
                "rsrq": safe_int(parts[12]) if len(parts) > 12 else None,
                "rssi": safe_int(parts[13]) if len(parts) > 13 else None,
                "sinr": safe_int(parts[14]) if len(parts) > 14 else None,
            })
        else:
            # Fallback: just capture mcc/mnc/cell if present.
            entry.update({
                "mcc": safe_int(parts[3]) if len(parts) > 3 else None,
                "mnc": safe_int(parts[4]) if len(parts) > 4 else None,
                "cell_id": parse_hex_or_int(parts[5]) if len(parts) > 5 else None,
            })
        towers.append(entry)
    return towers


def parse_qeng_neighborcell(lines):
    towers = []
    for line in lines:
        if not line.startswith('+QENG: "neighbourcell'):
            continue
        payload = line.split(":", 1)[1].strip()
        parts = split_fields(payload)
        if len(parts) < 3:
            continue
        category = strip_quotes(parts[0]) if parts else None
        rat = strip_quotes(parts[1]) if len(parts) > 1 else None
        entry = {
            "source": "qeng_neighborcell",
            "category": category,
            "rat": rat,
            "raw": line,
        }
        # LTE neighbor: rat, mcc, mnc, earfcn, pci, rsrq, rsrp, rssi, sinr
        entry.update({
            "mcc": safe_int(parts[2]) if len(parts) > 2 else None,
            "mnc": safe_int(parts[3]) if len(parts) > 3 else None,
            "earfcn": safe_int(parts[4]) if len(parts) > 4 else None,
            "pci": safe_int(parts[5]) if len(parts) > 5 else None,
            "rsrq": safe_int(parts[6]) if len(parts) > 6 else None,
            "rsrp": safe_int(parts[7]) if len(parts) > 7 else None,
            "rssi": safe_int(parts[8]) if len(parts) > 8 else None,
            "sinr": safe_int(parts[9]) if len(parts) > 9 else None,
        })
        towers.append(entry)
    return towers


def build_towers_snapshot(network, vendor):
    towers = []
    reg = best_registration(network)
    if reg:
        towers.append({
            "source": "registration",
            "rat": reg.get("rat"),
            "cell_id": reg.get("cell_id"),
            "tac_lac": reg.get("lac_tac"),
            "stat": reg.get("stat_text"),
        })
    qeng_serving = parse_qeng_servingcell(vendor.get("qeng_servingcell", []))
    qeng_neighbor = parse_qeng_neighborcell(vendor.get("qeng_neighborcell", []))
    towers.extend(qeng_serving)
    towers.extend(qeng_neighbor)
    return towers


def summarize_response(cmd, lines):
    key = command_key(cmd.upper())
    if key in ("AT+CGMI", "AT+CGMM", "AT+CGMR"):
        value = extract_first_line(lines)
        return "Value: {}".format(value or "unknown")
    if key in ("AT+CGSN", "AT+GSN"):
        value = extract_first_numeric(lines)
        return "IMEI: {}".format(value or "unknown")
    if key == "ATI":
        if lines:
            return "Lines: {}".format(" | ".join(lines))
        return "No identification lines."
    if key == "AT+CPIN?":
        status = parse_cpin(lines)
        return "SIM status: {}".format(status or "unknown")
    if key == "AT+CCID":
        value = parse_ccid(lines)
        return "ICCID: {}".format(value or "unknown")
    if key == "AT+CIMI":
        value = extract_first_numeric(lines)
        return "IMSI: {}".format(value or "unknown")
    if key == "AT+CSQ":
        csq = parse_csq(lines)
        if csq:
            return "RSSI: {} dBm: {} BER: {}".format(
                csq.get("rssi"), csq.get("rssi_dbm"), csq.get("ber")
            )
        return "Signal quality not reported."
    if key in ("AT+CREG?", "AT+CGREG?", "AT+CEREG?"):
        prefix = key.split("+", 1)[1].split("?", 1)[0]
        reg = parse_reg(lines, prefix)
        if reg:
            return "Status: {} ({}) RAT: {} LAC/TAC: {} Cell ID: {}".format(
                reg.get("stat_text"),
                reg.get("stat_code"),
                reg.get("rat") or "unknown",
                reg.get("lac_tac"),
                reg.get("cell_id"),
            )
        return "Registration status unavailable."
    if key == "AT+COPS?":
        cops = parse_cops_current(lines)
        if cops:
            return "Operator: {} RAT: {}".format(
                cops.get("operator") or "unknown",
                ACT_RAT.get(cops.get("act")) or "unknown",
            )
        return "Operator not reported."
    if key == "AT+COPS=?":
        operators = parse_cops_scan(lines)
        return "Operators found: {}".format(len(operators))
    if key == "AT+CEER":
        ceer = parse_ceer(lines)
        return "Last error: {}".format(ceer or "unknown")
    if key == "AT+QNWINFO":
        qnw = parse_qnwinfo(lines)
        if qnw:
            return "RAT: {} Band: {} Operator: {}".format(
                qnw.get("rat") or "unknown",
                qnw.get("band") or "unknown",
                qnw.get("operator") or "unknown",
            )
        return "QNWINFO not reported."
    if key == "AT+CGNSINF":
        info = parse_cgnsinf(lines)
        if info:
            return "Fix: {} Lat: {} Lon: {}".format(
                info.get("fix_status"),
                info.get("lat"),
                info.get("lon"),
            )
        return "GNSS info not reported."
    if key == "AT+CRSM=176":
        crsm = parse_crsm(lines)
        if crsm:
            return "SW1/SW2: {}/{} Response: {}".format(
                crsm.get("sw1"),
                crsm.get("sw2"),
                crsm.get("response") or "none",
            )
        return "SIM read response not reported."
    if lines:
        return "Response lines: {}".format(len(lines))
    return "No response lines."


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


def nmea_checksum_ok(sentence):
    if "*" not in sentence:
        return True
    data, checksum_text = sentence.split("*", 1)
    checksum_text = checksum_text.strip()
    data = data.lstrip("$")
    calc = 0
    for ch in data:
        calc ^= ord(ch)
    try:
        expected = int(checksum_text[:2], 16)
    except ValueError:
        return False
    return calc == expected


def parse_nmea_latlon(value, hemisphere):
    if not value:
        return None
    try:
        head = value.split(".")[0]
        if len(head) < 4:
            return None
        deg_len = 2 if len(head) <= 4 else 3
        degrees = float(value[:deg_len])
        minutes = float(value[deg_len:])
        coord = degrees + minutes / 60.0
        hemi = (hemisphere or "").upper()
        if hemi in ("S", "W"):
            coord *= -1
        return round(coord, 7)
    except (ValueError, TypeError):
        return None


def nmea_timestamp_utc(date_text, time_text):
    if not time_text or len(time_text) < 6:
        return None
    try:
        hours = int(time_text[0:2])
        minutes = int(time_text[2:4])
        seconds_float = float(time_text[4:])
    except (ValueError, TypeError):
        return None
    seconds_int = int(seconds_float)
    micros = int(round((seconds_float - seconds_int) * 1_000_000))
    if date_text and len(date_text) >= 6:
        try:
            day = int(date_text[0:2])
            month = int(date_text[2:4])
            year = 2000 + int(date_text[4:6])
            dt = datetime.datetime(year, month, day, hours, minutes, seconds_int, micros, tzinfo=datetime.timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except (ValueError, TypeError):
            pass
    now = datetime.datetime.utcnow()
    dt = datetime.datetime(now.year, now.month, now.day, hours, minutes, seconds_int, micros, tzinfo=datetime.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def parse_nmea_gga(line):
    parts = line.split(",")
    if len(parts) < 10:
        return {}
    lat = parse_nmea_latlon(parts[2], parts[3])
    lon = parse_nmea_latlon(parts[4], parts[5])
    return {
        "time_utc": parts[1] or None,
        "timestamp_utc": nmea_timestamp_utc("", parts[1]) if parts[1] else None,
        "lat": lat,
        "lon": lon,
        "fix_quality": safe_int(parts[6]),
        "satellites": safe_int(parts[7]),
        "hdop": safe_float(parts[8]),
        "alt_m": safe_float(parts[9]),
        "geoid_sep_m": safe_float(parts[11]) if len(parts) > 11 else None,
        "dgps_age_s": safe_float(parts[13]) if len(parts) > 13 else None,
    }


def parse_nmea_rmc(line):
    parts = line.split(",")
    if len(parts) < 10:
        return {}
    lat = parse_nmea_latlon(parts[3], parts[4])
    lon = parse_nmea_latlon(parts[5], parts[6])
    timestamp = nmea_timestamp_utc(parts[9], parts[1])
    return {
        "time_utc": parts[1] or None,
        "date": parts[9] or None,
        "timestamp_utc": timestamp,
        "status": parts[2] or None,
        "lat": lat,
        "lon": lon,
        "speed_knots": safe_float(parts[7]),
        "course_deg": safe_float(parts[8]),
        "mag_var": safe_float(parts[10]) if len(parts) > 10 else None,
    }


def parse_nmea_gsa(line):
    parts = line.split(",")
    if len(parts) < 17:
        return {}
    sats = [p for p in parts[3:15] if p]
    return {
        "mode": parts[1] or None,
        "fix_type": safe_int(parts[2]),
        "satellites": sats,
        "pdop": safe_float(parts[15]),
        "hdop": safe_float(parts[16]) if len(parts) > 16 else None,
        "vdop": safe_float(parts[17]) if len(parts) > 17 else None,
    }


def parse_nmea_gsv(line):
    parts = line.split(",")
    if len(parts) < 4:
        return {}
    entry = {
        "message_index": safe_int(parts[2]),
        "message_count": safe_int(parts[1]),
        "in_view": safe_int(parts[3]),
        "satellites": [],
    }
    for idx in range(4, len(parts) - 3, 4):
        prn = parts[idx]
        elev = safe_int(parts[idx + 1]) if len(parts) > idx + 1 else None
        az = safe_int(parts[idx + 2]) if len(parts) > idx + 2 else None
        snr = safe_int(parts[idx + 3]) if len(parts) > idx + 3 else None
        if prn:
            entry["satellites"].append({
                "prn": prn,
                "elevation_deg": elev,
                "azimuth_deg": az,
                "snr_db": snr,
            })
    return entry


def parse_nmea_gll(line):
    parts = line.split(",")
    if len(parts) < 7:
        return {}
    lat = parse_nmea_latlon(parts[1], parts[2])
    lon = parse_nmea_latlon(parts[3], parts[4])
    timestamp = nmea_timestamp_utc("", parts[5])
    return {
        "lat": lat,
        "lon": lon,
        "time_utc": parts[5] or None,
        "timestamp_utc": timestamp,
        "status": parts[6] or None,
    }


def aggregate_nmea(parsed, raw_lines):
    gga = parsed.get("gga") or {}
    rmc = parsed.get("rmc") or {}
    gsa = parsed.get("gsa") or {}
    gsv = parsed.get("gsv") or []
    gll = parsed.get("gll") or {}
    location = {}
    location_source = None
    for key, data in (("rmc", rmc), ("gga", gga), ("gll", gll)):
        if data and data.get("lat") is not None and data.get("lon") is not None:
            location = {
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "alt_m": data.get("alt_m"),
                "speed_knots": data.get("speed_knots"),
                "course_deg": data.get("course_deg"),
            }
            if data.get("timestamp_utc"):
                location["timestamp_utc"] = data["timestamp_utc"]
            location_source = key
            break
    sats_in_use = gga.get("satellites") if gga else None
    if sats_in_use is None and gsa:
        sats_in_use = len(gsa.get("satellites", [])) if gsa.get("satellites") else None
    sats_in_view = None
    for entry in gsv:
        if entry.get("in_view") is not None:
            sats_in_view = max(sats_in_view or 0, entry["in_view"])
    hdop = gga.get("hdop") or gsa.get("hdop")
    timestamp = None
    for candidate in (rmc.get("timestamp_utc"), gga.get("timestamp_utc"), gll.get("timestamp_utc")):
        if candidate:
            timestamp = candidate
            break
    return {
        "location": location,
        "location_source": location_source,
        "has_fix": bool(location),
        "timestamp_utc": timestamp,
        "status": rmc.get("status") or gll.get("status"),
        "fix_quality": gga.get("fix_quality"),
        "fix_type": gsa.get("fix_type"),
        "hdop": hdop,
        "satellites": {
            "in_use": sats_in_use,
            "in_view": sats_in_view,
            "used_prns": gsa.get("satellites") or [],
        },
        "gga": gga,
        "rmc": rmc,
        "gsa": gsa,
        "gsv": gsv,
        "gll": gll,
        "raw_sample": raw_lines[:20],
    }


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


def ensure_sim_ready(at, config, logger):
    pin = (config.get("sim", {}) or {}).get("pin")
    status_before = parse_cpin(at.send("AT+CPIN?")["lines"])
    info = {
        "status_before": status_before,
        "status_after": status_before,
        "pin_configured": bool(pin),
        "pin_attempted": False,
        "pin_ok": None,
        "pin_error": None,
    }
    if status_before in ("SIM PIN", "SIM PIN2"):
        if pin:
            logger.warning("SIM PIN required. Attempting unlock with configured PIN.")
            res = at.send('AT+CPIN="{}"'.format(pin))
            info["pin_attempted"] = True
            info["pin_ok"] = res["ok"]
            if not res["ok"]:
                info["pin_error"] = res["error"]
                logger.error("SIM PIN unlock failed: {}".format(res["error"] or "error"))
            time.sleep(1)
            status_after = parse_cpin(at.send("AT+CPIN?")["lines"])
            info["status_after"] = status_after
            if status_after == "READY":
                logger.info("SIM PIN accepted.")
            else:
                logger.warning("SIM status after PIN: {}".format(status_after or "unknown"))
        else:
            logger.warning("SIM PIN required but no PIN configured.")
    elif status_before == "SIM PUK":
        logger.error("SIM PUK required; SIM is blocked.")
    elif status_before == "READY":
        logger.info("SIM is ready (no PIN needed).")
    else:
        logger.warning("SIM status: {}".format(status_before or "unknown"))
    return info


def collect_sim(at, config, sim_status=None, pin_info=None):
    sim = {}
    sim["status"] = sim_status or parse_cpin(at.send("AT+CPIN?")["lines"])
    sim["iccid"] = parse_ccid(at.send("AT+CCID")["lines"])
    sim["imsi"] = extract_first_numeric(at.send("AT+CIMI")["lines"])
    sim["valid"] = sim["status"] == "READY" if sim["status"] else False
    sim["pin_required"] = sim["status"] in ("SIM PIN", "SIM PIN2")
    sim["blocked"] = sim["status"] == "SIM PUK"
    sim["pin_configured"] = bool((config.get("sim", {}) or {}).get("pin"))
    if pin_info:
        sim["pin_check"] = pin_info
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

    if config["features"].get("auto_register"):
        at.send("AT+COPS=0", timeout_s=config["timeouts"]["operator_scan_s"])

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


def collect_vendor_info(at, config, logger):
    if not config["features"].get("vendor_specific"):
        return {}
    vendor = {}
    vendor_timeout = config["timeouts"]["vendor_s"]
    qeng_timeout = max(vendor_timeout, 10.0)
    qeng_retries = 1
    tower_cfg = config.get("tower_scan", {}) or {}
    passes = max(1, safe_int(tower_cfg.get("passes")) or 1)
    detach_before_scan = bool(tower_cfg.get("detach_before_scan"))
    dwell_s = tower_cfg.get("dwell_s", 1.0)
    qeng_timeout = max(qeng_timeout, tower_cfg.get("qeng_timeout_s", qeng_timeout))
    qeng_retries = max(qeng_retries, safe_int(tower_cfg.get("qeng_retries")) or 1)
    do_operator_scan = bool(tower_cfg.get("operator_scan_each_loop"))
    scan_actions = []

    qnw = at.send("AT+QNWINFO", timeout_s=vendor_timeout)
    vendor["qnwinfo"] = parse_qnwinfo(qnw["lines"])
    vendor["qnwinfo_raw"] = qnw["lines"]
    vendor["qcsq"] = at.send("AT+QCSQ", timeout_s=vendor_timeout)["lines"]

    serving_all = []
    neighbor_all = []

    if detach_before_scan:
        scan_actions.append("detach/reattach")
        logger.info("Tower scan: detaching (AT+COPS=2) before neighbor/serving queries.")
        at.send("AT+COPS=2", timeout_s=config["timeouts"]["operator_scan_s"])
        time.sleep(dwell_s)
        at.send("AT+COPS=0", timeout_s=config["timeouts"]["operator_scan_s"])
        time.sleep(dwell_s)

    if do_operator_scan:
        scan_actions.append("operator_scan")
        logger.info("Tower scan: running operator scan to refresh PLMN list.")
        at.send("AT+COPS=?", timeout_s=config["timeouts"]["operator_scan_s"])

    for idx in range(passes):
        logger.info("Tower scan pass {}/{} (qeng)".format(idx + 1, passes))
        res_serv = at.send('AT+QENG="servingcell"', timeout_s=qeng_timeout, retries=qeng_retries)
        res_nei = at.send('AT+QENG="neighbourcell"', timeout_s=qeng_timeout, retries=qeng_retries)
        if res_serv["lines"]:
            serving_all.extend(res_serv["lines"])
        if res_nei["lines"]:
            neighbor_all.extend(res_nei["lines"])
        if dwell_s:
            time.sleep(dwell_s)

    vendor["qeng_servingcell"] = serving_all
    vendor["qeng_neighborcell"] = neighbor_all
    vendor["scan_activity"] = "passes={} detach={} op_scan={} qeng_timeout={} retries={}".format(
        passes,
        detach_before_scan,
        do_operator_scan,
        qeng_timeout,
        qeng_retries,
    )
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


def collect_external_gps(config, logger):
    cfg = config.get("external_gps", {}) or {}
    enabled = bool(cfg.get("enabled", True))
    port = cfg.get("port") or "/dev/ttyACM0"
    baudrate = cfg.get("baudrate") or 9600
    timeout_s = cfg.get("timeout_s", 0.5)
    read_duration_s = cfg.get("read_duration_s", 2.0)
    max_lines = cfg.get("max_lines", 200) or 200
    result = {
        "source": "serial_nmea",
        "port": port,
        "baudrate": baudrate,
        "enabled": enabled,
    }
    if not enabled:
        result["available"] = False
        logger.info("External GPS disabled in config.")
        return result
    if serial is None:
        result["available"] = False
        result["error"] = "pyserial missing"
        logger.warning("External GPS skipped: pyserial not installed.")
        return result
    try:
        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=timeout_s,
            write_timeout=timeout_s,
        )
    except Exception as exc:
        result["available"] = False
        result["error"] = str(exc)
        logger.warning("External GPS not available on {}: {}".format(port, exc))
        return result

    raw_lines = []
    parsed = {"gga": None, "rmc": None, "gsa": None, "gsv": [], "gll": None}
    start = time.monotonic()
    try:
        while (time.monotonic() - start) < read_duration_s and len(raw_lines) < max_lines:
            raw = ser.readline()
            if not raw:
                continue
            try:
                line = raw.decode(errors="ignore").strip()
            except Exception:
                continue
            if not line:
                continue
            if not nmea_checksum_ok(line):
                continue
            raw_lines.append(line)
            upper = line.upper()
            if upper.startswith("$GPGGA") or upper.startswith("$GNGGA") or upper.startswith("$GAGGA"):
                entry = parse_nmea_gga(line)
                entry["raw"] = line
                parsed["gga"] = entry
            elif upper.startswith("$GPRMC") or upper.startswith("$GNRMC") or upper.startswith("$GARMC"):
                entry = parse_nmea_rmc(line)
                entry["raw"] = line
                parsed["rmc"] = entry
            elif upper.startswith("$GPGSA") or upper.startswith("$GNGSA") or upper.startswith("$GAGSA"):
                entry = parse_nmea_gsa(line)
                entry["raw"] = line
                parsed["gsa"] = entry
            elif upper.startswith("$GPGSV") or upper.startswith("$GNGSV") or upper.startswith("$GAGSV"):
                entry = parse_nmea_gsv(line)
                entry["raw"] = line
                parsed["gsv"].append(entry)
            elif upper.startswith("$GPGLL") or upper.startswith("$GNGLL") or upper.startswith("$GAGLL"):
                entry = parse_nmea_gll(line)
                entry["raw"] = line
                parsed["gll"] = entry
    finally:
        ser.close()

    report = aggregate_nmea(parsed, raw_lines)
    report.update(result)
    report["available"] = bool(raw_lines)
    if report.get("has_fix"):
        loc = report.get("location") or {}
        sats = report.get("satellites") or {}
        logger.info("GPS (device {}) source=device: lat={} lon={} alt={} sats_used={} sats_view={} timestamp={}".format(
            port,
            loc.get("lat"),
            loc.get("lon"),
            loc.get("alt_m"),
            sats.get("in_use"),
            sats.get("in_view"),
            loc.get("timestamp_utc"),
        ))
    else:
        logger.info("GPS (device {}) source=device: no fix yet ({} sentences)".format(
            port,
            len(raw_lines),
        ))
    return report


def log_modem_gps(logger, gps_data):
    if not gps_data:
        logger.info("GPS (LTE modem) source=lte_modem: disabled or skipped.")
        return
    cgns = gps_data.get("cgnsinf") or {}
    if cgns.get("lat") is not None and cgns.get("lon") is not None:
        logger.info("GPS (LTE modem) source=lte_modem: lat={} lon={} alt={} fix_status={} utc={}".format(
            cgns.get("lat"),
            cgns.get("lon"),
            cgns.get("alt_m"),
            cgns.get("fix_status"),
            cgns.get("utc"),
        ))
    else:
        logger.info("GPS (LTE modem) source=lte_modem: no fix reported.")


def best_location_from_sources(gps_modem, gps_device):
    device_loc = (gps_device or {}).get("location") or {}
    if device_loc.get("lat") is not None and device_loc.get("lon") is not None:
        chosen = dict(device_loc)
        chosen["source"] = "gps_device"
        return chosen
    cgns = (gps_modem or {}).get("cgnsinf") or {}
    if cgns.get("lat") is not None and cgns.get("lon") is not None:
        return {
            "lat": cgns.get("lat"),
            "lon": cgns.get("lon"),
            "alt_m": cgns.get("alt_m"),
            "timestamp_utc": cgns.get("utc"),
            "source": "lte_modem",
        }
    return {}


def collect_errors(at):
    errors = {}
    errors["ceer"] = parse_ceer(at.send("AT+CEER")["lines"])
    return errors


def run_extra_commands(at, config):
    extra_results = []
    for cmd in config.get("extra_commands", []):
        extra_results.append(at.send(cmd))
    return extra_results


def build_snapshot(at, config, logger):
    network = collect_network(at, config)
    vendor = collect_vendor_info(at, config, logger)
    gps_modem = collect_gps(at, config)
    gps_device = collect_external_gps(config, logger)
    log_modem_gps(logger, gps_modem)
    snapshot = {
        "timestamp_utc": iso_timestamp(),
        "network": network,
        "vendor": vendor,
        "gps": gps_modem,
        "gps_device": gps_device,
        "scan_activity": vendor.get("scan_activity"),
        "location": best_location_from_sources(gps_modem, gps_device),
        "towers": build_towers_snapshot(network, vendor),
    }
    return snapshot


def write_jsonl(handle, obj):
    handle.write(json.dumps(obj, ensure_ascii=True) + "\n")
    handle.flush()


def write_status_snapshot(path, snapshot, logger):
    if not path:
        return
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {
            "timestamp_utc": snapshot.get("timestamp_utc"),
            "location": snapshot.get("location"),
            "network": snapshot.get("network"),
            "towers": snapshot.get("towers"),
            "gps_lte_modem": snapshot.get("gps"),
            "gps_device": snapshot.get("gps_device"),
            "sim_status": snapshot.get("sim_status"),
            "scan_status": snapshot.get("scan_activity"),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, indent=2)
    except Exception as exc:
        logger.warning("Failed to write status snapshot to {}: {}".format(path, exc))


def write_wigle_header(handle):
    handle.write("WigleWifi-1.6,appRelease=hack-wanderer,model=cellular,release=1,device=modem,display=cellular,board=unknown,brand=unknown\n")
    handle.write("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n")
    handle.flush()


def snapshot_to_wigle_rows(snapshot):
    rows = []
    location = snapshot.get("location") or best_location_from_sources(
        snapshot.get("gps"),
        snapshot.get("gps_device"),
    )
    lat = location.get("lat")
    lon = location.get("lon")
    alt = location.get("alt_m")
    if lat is None or lon is None:
        return rows
    network = snapshot.get("network", {})
    csq = network.get("csq", {})
    reg = best_registration(network)
    operator = (network.get("cops_current") or {}).get("operator") or "unknown"
    cell_id = reg.get("cell_id") if reg else None
    mac = "CELL-{}".format(cell_id) if cell_id is not None else "CELL-UNKNOWN"
    ssid = "CELL-{}".format(operator)
    rssi = csq.get("rssi_dbm") if csq else None
    row = {
        "MAC": mac,
        "SSID": ssid,
        "AuthMode": "CELL",
        "FirstSeen": snapshot.get("timestamp_utc"),
        "Channel": "",
        "RSSI": rssi if rssi is not None else "",
        "CurrentLatitude": lat,
        "CurrentLongitude": lon,
        "AltitudeMeters": alt if alt is not None else "",
        "AccuracyMeters": "",
        "Type": "CELL",
    }
    rows.append(row)
    return rows


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


def print_summary(results, config, logger):
    info = results.get("info", {})
    sim = results.get("sim", {})
    network = results.get("network", {})
    vendor = results.get("vendor", {})
    gps = results.get("gps", {})
    reg = best_registration(network)
    cops = network.get("cops_current", {})
    csq = network.get("csq", {})

    logger.section("Hack-Wanderer test mode", "test")
    logger.print_line("Port: {} baud {}".format(
        config["serial"]["port"],
        config["serial"]["baudrate"]),
        color="cyan"
    )
    if results.get("meta", {}).get("log_file"):
        logger.print_line("Log file: {}".format(results["meta"]["log_file"]), color="gray")
    logger.print_line("")
    logger.section("Modem info", "modem")
    logger.print_line("  Manufacturer: {}".format(info.get("manufacturer") or "unknown"))
    logger.print_line("  Model: {}".format(info.get("model") or "unknown"))
    logger.print_line("  Revision: {}".format(info.get("revision") or "unknown"))
    logger.print_line("  IMEI: {}".format(info.get("imei") or "unknown"))
    if info.get("ati"):
        logger.print_line("  ATI: {}".format(" | ".join(info["ati"])))
    logger.print_line("")
    logger.section("SIM", "sim")
    logger.print_line("  Status: {}".format(sim.get("status") or "unknown"))
    logger.print_line("  ICCID: {}".format(sim.get("iccid") or "unknown"))
    logger.print_line("  IMSI: {}".format(sim.get("imsi") or "unknown"))
    valid = sim.get("valid")
    if valid is True:
        logger.print_line("  {}".format(logger.with_emoji("success", "Valid: yes")), color="green")
    elif valid is False:
        logger.print_line("  {}".format(logger.with_emoji("error", "Valid: no")), color="red")
    else:
        logger.print_line("  {}".format(logger.with_emoji("warning", "Valid: unknown")), color="yellow")
    pin_configured = sim.get("pin_configured")
    if pin_configured is True:
        logger.print_line("  PIN configured: yes")
    elif pin_configured is False:
        logger.print_line("  PIN configured: no")
    if sim.get("pin_required"):
        logger.print_line("  {}".format(logger.with_emoji("warning", "PIN required: yes")), color="yellow")
    if sim.get("blocked"):
        logger.print_line("  {}".format(logger.with_emoji("error", "SIM blocked (PUK): yes")), color="red")
    pin_check = sim.get("pin_check") or {}
    if pin_check.get("pin_attempted"):
        if pin_check.get("pin_ok") and pin_check.get("status_after") == "READY":
            logger.print_line("  {}".format(logger.with_emoji("success", "PIN unlock: success")), color="green")
        else:
            status_after = pin_check.get("status_after") or "unknown"
            logger.print_line("  {}".format(logger.with_emoji("error", "PIN unlock: failed ({})".format(status_after))), color="red")
    elif pin_check.get("status_before") in ("SIM PIN", "SIM PIN2") and not pin_check.get("pin_configured"):
        logger.print_line("  {}".format(logger.with_emoji("warning", "PIN not provided")), color="yellow")
    if sim.get("files"):
        logger.print_line("  SIM files:")
        for item in sim["files"]:
            status = "ok" if item.get("ok") else "error"
            file_id = item.get("file_id")
            color = "green" if item.get("ok") else "red"
            logger.print_line("    {} ({}): {}".format(item.get("name") or "file", file_id, status), color=color)
    logger.print_line("")
    logger.section("Network", "network")
    if csq:
        logger.print_line("  Signal: rssi={} dBm={} ber={}".format(
            csq.get("rssi"),
            csq.get("rssi_dbm"),
            csq.get("ber"),
        ))
    if reg:
        logger.print_line("  Registration: {} ({})".format(
            reg.get("stat_text"),
            reg.get("stat_code"),
        ))
        if reg.get("rat"):
            logger.print_line("  RAT: {}".format(reg.get("rat")))
        if reg.get("lac_tac") is not None:
            logger.print_line("  LAC/TAC: {}".format(reg.get("lac_tac")))
        if reg.get("cell_id") is not None:
            logger.print_line("  Cell ID: {}".format(reg.get("cell_id")))
    if cops:
        logger.print_line("  Operator: {} (act {})".format(
            cops.get("operator") or "unknown",
            cops.get("act") if cops.get("act") is not None else "unknown",
        ))
    if network.get("operators_available"):
        logger.print_line("  Operators found: {}".format(len(network["operators_available"])))
    if vendor.get("qnwinfo"):
        qnw = vendor["qnwinfo"]
        if qnw.get("band"):
            logger.print_line("  Band: {}".format(qnw.get("band")))
    logger.print_line("")
    logger.section("GPS", "gps")
    gps_modem = gps or {}
    gps_device = results.get("gps_device") or {}
    device_loc = gps_device.get("location") or {}
    device_sats = gps_device.get("satellites") or {}
    if gps_device.get("enabled") is False:
        logger.print_line("  External GPS: disabled by config.")
    elif device_loc.get("lat") is not None and device_loc.get("lon") is not None:
        logger.print_line("  Device GPS ({}): lat={} lon={} alt={} sats_used={} in_view={} hdop={} source=device".format(
            gps_device.get("port") or "external",
            device_loc.get("lat"),
            device_loc.get("lon"),
            device_loc.get("alt_m"),
            device_sats.get("in_use"),
            device_sats.get("in_view"),
            gps_device.get("hdop"),
        ))
    else:
        logger.print_line("  Device GPS ({}): no fix (in_use={} in_view={}) source=device".format(
            gps_device.get("port") or "external",
            device_sats.get("in_use"),
            device_sats.get("in_view"),
        ))
    if gps_modem.get("cgnsinf"):
        cgns = gps_modem["cgnsinf"]
        if cgns.get("fix_status") is not None:
            logger.print_line("  LTE GPS fix status: {} source=lte_modem".format(cgns.get("fix_status")))
        if cgns.get("lat") is not None and cgns.get("lon") is not None:
            logger.print_line("  LTE GPS location: {}, {} alt={} utc={} source=lte_modem".format(
                cgns.get("lat"),
                cgns.get("lon"),
                cgns.get("alt_m"),
                cgns.get("utc"),
            ))
    else:
        logger.print_line("  LTE GPS: no info detected.")
    logger.print_line("")
    if results.get("diagnostics"):
        logger.section("Diagnostics", "diag")
        for issue in results["diagnostics"]:
            logger.print_line("  - {}".format(issue), color="yellow")

    if config["output"].get("raw"):
        logger.print_line("")
        logger.section("Raw command log", "debug")
        for entry in results["command_log"]:
            status = "OK" if entry["ok"] else "ERR"
            color = "green" if entry["ok"] else "red"
            logger.print_line("  {} -> {} ({})".format(
                entry["command"],
                status,
                entry["error"] or "ok"
            ), color=color)
            for line in entry["lines"]:
                logger.print_line("    {}".format(line), color="gray")


def require_dependency(module, name, logger=None):
    if module is None:
        message = "Missing dependency: {}. Install with pip.".format(name)
        if logger:
            logger.error(message)
        else:
            eprint(message)
        raise RuntimeError(message)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Hack-Wanderer cellular diagnostics and wardriving tool.")
    parser.add_argument("--config", help="Path to YAML config file.")
    parser.add_argument("--mode", choices=["test", "wardrive"], help="Mode to run.")
    parser.add_argument("--port", help="Serial port (e.g. /dev/cu.SLAB_USBtoUART).")
    parser.add_argument("--baudrate", type=int, help="Serial baudrate.")
    parser.add_argument("--timeout-s", type=float, help="Serial read timeout in seconds.")
    parser.add_argument("--write-timeout-s", type=float, help="Serial write timeout in seconds.")
    parser.add_argument("--init-delay-s", type=float, help="Delay after opening the port.")
    parser.add_argument("--inter-command-delay-s", type=float, help="Delay between AT commands.")
    parser.add_argument("--init-retries", type=int, help="Retries for AT init ping.")
    parser.add_argument("--retry-delay-s", type=float, help="Delay between retries.")
    parser.add_argument("--operator-scan", action="store_true", help="Enable operator scan.")
    parser.add_argument("--no-operator-scan", action="store_true", help="Disable operator scan.")
    parser.add_argument("--operator-scan-timeout-s", type=float, help="Timeout for AT+COPS=?")
    parser.add_argument("--default-timeout-s", type=float, help="Default timeout for AT commands.")
    parser.add_argument("--gps-timeout-s", type=float, help="Timeout for GPS AT commands.")
    parser.add_argument("--sim-read-timeout-s", type=float, help="Timeout for SIM file reads.")
    parser.add_argument("--vendor-timeout-s", type=float, help="Timeout for vendor-specific commands.")
    parser.add_argument("--gps", action="store_true", help="Enable GPS queries.")
    parser.add_argument("--no-gps", action="store_true", help="Disable GPS queries.")
    parser.add_argument("--gps-device", action="store_true", help="Enable external NMEA GPS (/dev/ttyACM0).")
    parser.add_argument("--no-gps-device", action="store_true", help="Disable external NMEA GPS.")
    parser.add_argument("--gps-device-port", help="Serial port for external NMEA GPS (e.g. /dev/ttyACM0).")
    parser.add_argument("--gps-device-baudrate", type=int, help="Baudrate for external NMEA GPS.")
    parser.add_argument("--gps-device-timeout-s", type=float, help="Serial timeout when reading external GPS.")
    parser.add_argument("--gps-device-read-duration-s", type=float, help="Seconds to sample NMEA sentences from external GPS.")
    parser.add_argument("--vendor-specific", action="store_true", help="Enable vendor-specific commands.")
    parser.add_argument("--no-vendor-specific", action="store_true", help="Disable vendor-specific commands.")
    parser.add_argument("--auto-register", action="store_true", help="Enable automatic network registration.")
    parser.add_argument("--no-auto-register", action="store_true", help="Disable automatic network registration.")
    parser.add_argument("--sim-read", action="store_true", help="Enable SIM file reads via AT+CRSM.")
    parser.add_argument("--no-sim-read", action="store_true", help="Disable SIM file reads.")
    parser.add_argument("--sim-pin", help="SIM PIN (if required).")
    parser.add_argument("--sim-read-file", action="append", help="SIM file to read: name,file_id,length")
    parser.add_argument("--clear-sim-read-files", action="store_true", help="Clear SIM read file list.")
    parser.add_argument("--extra-command", action="append", help="Extra AT command to run.")
    parser.add_argument("--output-json", help="Write full results to JSON file.")
    parser.add_argument("--output-raw", action="store_true", help="Print raw command log.")
    parser.add_argument("--duration-s", type=float, help="Wardrive duration in seconds (0 = forever).")
    parser.add_argument("--interval-s", type=float, help="Wardrive sampling interval in seconds.")
    parser.add_argument("--jsonl-path", help="Wardrive JSONL output path.")
    parser.add_argument("--wigle-csv", help="Wigle CSV output path (draft).")
    parser.add_argument("--log-dir", help="Directory for log files.")
    parser.add_argument("--log-file", help="Explicit log file path.")
    parser.add_argument("--log-level", choices=LEVELS.keys(), help="Log level for file output.")
    parser.add_argument("--console-level", choices=LEVELS.keys(), help="Log level for console output.")
    parser.add_argument("--no-log", action="store_true", help="Disable log file creation.")
    parser.add_argument("--color", action="store_true", help="Force colored output.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--emoji", action="store_true", help="Force emoji output.")
    parser.add_argument("--no-emoji", action="store_true", help="Disable emoji output.")
    parser.add_argument("--interactive", action="store_true", help="Prompt before each step.")
    parser.add_argument("--no-interactive", action="store_true", help="Disable step prompts.")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        config = resolve_config(args)
    except Exception as exc:
        eprint("Config error: {}".format(exc))
        return 2
    logger = RunLogger(config)
    exit_code = 0
    try:
        logger.info("Starting hack-wanderer {}".format(config["mode"]))
        config_path = args.config or ("config.yaml" if os.path.exists("config.yaml") else "")
        env_file = config.get("sim", {}).get("env_file")
        if config_path:
            logger.info("Config file: {}".format(config_path))
        if env_file:
            logger.info("Env file: {}".format(env_file))
        logger.debug("Effective config: {}".format(json.dumps(redact_config(config), indent=2)))
        if logger.file_path and logger.enabled:
            logger.info("Log file: {}".format(logger.file_path))
        try:
            require_dependency(serial, "pyserial", logger)
            if args.config or os.path.exists("config.yaml"):
                require_dependency(yaml, "pyyaml", logger)
        except RuntimeError:
            return 2

        results = {
            "meta": {
                "mode": config["mode"],
                "port": config["serial"]["port"],
                "baudrate": config["serial"]["baudrate"],
                "log_file": logger.file_path if logger.enabled else "",
            },
            "info": {},
            "sim": {},
            "network": {},
            "vendor": {},
            "gps": {},
            "gps_device": {},
            "errors": {},
            "diagnostics": [],
            "command_log": [],
        }

        ser = None
        at = None

        def open_modem():
            nonlocal ser, at
            logger.step("Open serial port {}".format(config["serial"]["port"]))
            ser = serial.Serial(
                port=config["serial"]["port"],
                baudrate=config["serial"]["baudrate"],
                timeout=config["serial"]["timeout_s"],
                write_timeout=config["serial"]["write_timeout_s"],
            )
            at = ATClient(ser, config, logger)
            logger.step("Initialize modem")
            results["meta"]["at_ok"] = at.initialize()
            if not results["meta"]["at_ok"]:
                logger.warning("No AT response during initialization.")
            return at

        try:
            open_modem()
        except Exception as exc:
            logger.error("Failed to open serial port: {}".format(exc))
            return 2

        try:
            logger.step("Collect modem info")
            results["info"] = collect_info(at)
            logger.step("Check SIM PIN state")
            pin_info = ensure_sim_ready(at, config, logger)
            if config["mode"] == "test":
                logger.step("Collect SIM info")
                results["sim"] = collect_sim(at, config, sim_status=pin_info.get("status_after"), pin_info=pin_info)
                logger.step("Collect network info")
                results["network"] = collect_network(at, config)
                if config.get("features", {}).get("vendor_specific"):
                    logger.step("Collect vendor-specific info")
                results["vendor"] = collect_vendor_info(at, config, logger)
                if config.get("features", {}).get("gps"):
                    logger.step("Collect GPS info")
                results["gps"] = collect_gps(at, config)
                log_modem_gps(logger, results["gps"])
                logger.step("Collect external GPS info")
                results["gps_device"] = collect_external_gps(config, logger)
                results["location"] = best_location_from_sources(results["gps"], results["gps_device"])
                logger.step("Collect error status")
                results["errors"] = collect_errors(at)
                if config.get("extra_commands"):
                    logger.step("Run extra commands")
                results["extra"] = run_extra_commands(at, config)
                results["command_log"] = at.command_log
            else:
                duration_s = config.get("wardrive", {}).get("duration_s", 0)
                interval_s = config.get("wardrive", {}).get("interval_s", 5.0)
                jsonl_path = config.get("wardrive", {}).get("jsonl_path") or "wardrive.jsonl"
                wigle_path = config.get("wardrive", {}).get("wigle_csv_path") or ""
                if duration_s and duration_s < 0:
                    logger.warning("Negative duration ignored; running forever.")
                    duration_s = 0
                end_time = time.monotonic() + duration_s if duration_s else None
                logger.step("Start wardriving loop")
                logger.info("Wardrive JSONL: {}".format(jsonl_path))
                wigle_handle = None
                if wigle_path:
                    logger.info("Wigle CSV (draft): {}".format(wigle_path))
                with open(jsonl_path, "a", encoding="utf-8") as jsonl_handle:
                    if wigle_path:
                        wigle_handle = open(wigle_path, "a", encoding="utf-8")
                        if wigle_handle.tell() == 0:
                            write_wigle_header(wigle_handle)
                    try:
                        while True:
                            if end_time and time.monotonic() >= end_time:
                                logger.info("Wardrive duration reached; stopping.")
                                break
                            try:
                                snapshot = build_snapshot(at, config, logger)
                            except (serial.SerialException, OSError, AttributeError) as exc:
                                logger.error("Serial connection lost: {}. Attempting reopen...".format(exc))
                                try:
                                    if ser:
                                        ser.close()
                                except Exception:
                                    pass
                                time.sleep(2)
                                try:
                                    open_modem()
                                    continue
                                except Exception as reopen_exc:
                                    logger.error("Reopen failed: {}. Retrying in 5s.".format(reopen_exc))
                                    time.sleep(5)
                                    continue

                            snapshot["sim_status"] = pin_info.get("status_after")
                            write_jsonl(jsonl_handle, snapshot)
                            status_path = (config.get("status_page") or {}).get("json_path") or ""
                            write_status_snapshot(status_path, snapshot, logger)
                            if wigle_handle:
                                for row in snapshot_to_wigle_rows(snapshot):
                                    wigle_handle.write(",".join([
                                        str(row.get("MAC", "")),
                                        str(row.get("SSID", "")),
                                        str(row.get("AuthMode", "")),
                                        str(row.get("FirstSeen", "")),
                                        str(row.get("Channel", "")),
                                        str(row.get("RSSI", "")),
                                        str(row.get("CurrentLatitude", "")),
                                        str(row.get("CurrentLongitude", "")),
                                        str(row.get("AltitudeMeters", "")),
                                        str(row.get("AccuracyMeters", "")),
                                        str(row.get("Type", "")),
                                    ]) + "\n")
                                    wigle_handle.flush()
                            logger.info("Snapshot saved at {}".format(snapshot["timestamp_utc"]))
                            time.sleep(interval_s)
                    finally:
                        if wigle_handle:
                            wigle_handle.close()
        finally:
            try:
                if ser:
                    ser.close()
            except Exception:
                pass

        if config["mode"] == "test":
            results["diagnostics"] = diagnose(results)
            print_summary(results, config, logger)

        json_path = config.get("output", {}).get("json_path")
        if json_path:
            try:
                with open(json_path, "w", encoding="utf-8") as handle:
                    json.dump(results, handle, indent=2)
                logger.info("Wrote JSON output to {}".format(json_path))
            except Exception as exc:
                logger.error("Failed to write JSON output: {}".format(exc))
                return 2
    finally:
        logger.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
