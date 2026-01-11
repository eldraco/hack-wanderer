# Hack-Wanderer (Cellular Wardriving)

This repo contains a Python script that connects to a cellular modem over a serial port and runs AT commands to verify modem, SIM, and network status. It supports a test/diagnostics mode and a wardriving mode that logs periodic snapshots.

## Requirements

- Python 3.8+
- `pyserial`
- `pyyaml` (only required when loading a YAML config file)

Install dependencies:

```bash
pip install pyserial pyyaml
```

## Quick start

```bash
python hack-wanderer.py --port /dev/cu.SLAB_USBtoUART --mode test
```

With a config file:

```bash
python hack-wanderer.py --config config.example.yaml
```

Write full results to JSON:

```bash
python hack-wanderer.py --config config.example.yaml --output-json results.json
```

By default, a log file is created under `logs/` for each run.

Wardriving mode (JSONL):

```bash
python hack-wanderer.py --config config.example.yaml --mode wardrive
```

## Configuration

All settings can be provided via CLI flags or a YAML file. CLI flags override the YAML values.
Set `output.json_path` in YAML to always write JSON results without a CLI flag.

Example config (`config.example.yaml`):

```yaml
mode: test
serial:
  port: /dev/cu.SLAB_USBtoUART
  baudrate: 115200
  timeout_s: 1.0
  write_timeout_s: 1.0
  init_delay_s: 0.5
  inter_command_delay_s: 0.1
  init_retries: 3
  retry_delay_s: 0.5

timeouts:
  default_s: 4.0
  operator_scan_s: 120.0
  gps_s: 6.0
  sim_read_s: 4.0
  vendor_s: 5.0

features:
  operator_scan: false
  gps: true
  vendor_specific: true
  sim_read: true
  auto_register: true

external_gps:
  enabled: true
  port: /dev/ttyACM0
  baudrate: 9600
  timeout_s: 0.5
  read_duration_s: 2.0
  max_lines: 200

sim:
  pin: ""
  pin_env_key: SIM_PIN
  env_file: .env

wardrive:
  interval_s: 5.0
  duration_s: 60.0
  jsonl_path: hack-wanderer.jsonl
  wigle_csv_path: ""

sim_read:
  files:
    - name: iccid
      file_id: "2FE2"
      length: 10
    - name: spn
      file_id: "6F46"
      length: 17
    - name: ad
      file_id: "6FAD"
      length: 4

extra_commands: []
output:
  raw: false
  json_path: ""

status_page:
  json_path: status/status.json

logging:
  enabled: true
  dir: logs
  file: ""
  file_level: debug
  console_level: info

ui:
  color: true
  emoji: true
  interactive: false
```

An external NMEA GPS receiver (defaults to `/dev/ttyACM0`) is sampled alongside the modem's LTE/GNSS. Configure it under `external_gps` or via `--gps-device-*` flags, or disable with `--no-gps-device`.

## What the script checks

- Modem info: manufacturer, model, firmware revision, IMEI
- SIM info: SIM status, ICCID, IMSI, basic SIM file reads via `AT+CRSM`
- SIM PIN state and optional unlock using a configured PIN
- Network status: signal quality, registration status (2G/3G/4G), current operator
- Operator scan: available nearby operators (`AT+COPS=?`)
- Optional vendor-specific data (if supported): band, serving cell, neighbor cell
- Optional GPS info (if supported)
- Error diagnostics (`AT+CEER`)

## Notes

- `AT+COPS=?` can take a long time. It is disabled by default; enable with `--operator-scan`.
- SIM file reads are limited to a small list of common EF files. Full SIM exploration requires APDU workflows (e.g., `AT+CSIM`), which are not implemented yet.
- GPS commands are queried only (no power-on commands are issued).
- If you see `SIM PIN` or `SIM PUK`, the SIM is locked or blocked. The tool only reports it.
- Raspberry Pi + SIM7600: to expose the USB Ethernet interface and AT command ports, set the USB composition once with `AT+CUSBPIDSWITCH=9011,1,1` (run via UART or an existing AT port, then reboot the modem). This switches the modem into a composite mode that presents ECM/NCM networking plus AT serial devices.

## Logging and verbosity

- Every run writes a log file (defaults to `logs/hack-wanderer_YYYYmmdd_HHMMSS.log`).
- Console output is verbose and colored by default; disable with `--no-color` or `--no-emoji`.
- Use step-by-step mode to prompt before each phase:

```bash
python hack-wanderer.py --config config.example.yaml --interactive
```

- For full command/response detail on the console:

```bash
python hack-wanderer.py --config config.example.yaml --console-level debug
```

- SIM PIN values are redacted in logs and console output.
- SIM PIN can be loaded from `.env` via `SIM_PIN` (recommended to avoid committing secrets).
- Wardriving mode writes JSONL snapshots with timestamps and a `towers` array built from registration + vendor cell info; set `duration_s` to `0` to run forever.
- Wigle CSV export is a draft format for now and may need adjustments for cell tower uploads.

## CLI options

Run `python hack-wanderer.py --help` for the full list. Key flags:

- `--port`, `--baudrate`
- `--operator-scan` / `--no-operator-scan`
- `--gps` / `--no-gps`
- `--gps-device` / `--no-gps-device`, `--gps-device-port`, `--gps-device-baudrate`, `--gps-device-timeout-s`, `--gps-device-read-duration-s`
- `--vendor-specific` / `--no-vendor-specific`
- `--auto-register` / `--no-auto-register`
- `--sim-read` / `--no-sim-read`
- `--sim-pin` to provide a SIM PIN if required
- `--sim-read-file` to add SIM EF reads (format: `name,file_id,length`)
- `--clear-sim-read-files` to reset the SIM file list
- `--extra-command` to add extra AT commands
- `--output-json` to save full results
- `--output-raw` to print raw command logs
- `--duration-s`, `--interval-s` for wardriving mode
- `--jsonl-path` to override the wardriving JSONL file
- `--wigle-csv` to write a draft Wigle CSV
- `--log-dir`, `--log-file`, `--log-level`, `--console-level`
- `--no-log` to disable log files
- `--color` / `--no-color`, `--emoji` / `--no-emoji`
- `--interactive` / `--no-interactive`

## Local status page (small display)

- The wardrive loop writes a live snapshot to `status/status.json` and a matching display at `status/index.html` (auto-refresh every 3s).
- Serve it locally or open directly with a browser: `chromium-browser file:///home/pi/code/hack-wanderer/status/index.html`.
- To auto-open on boot (kiosk on :0, adjust if your user/desktop differ):
  ```bash
  sudo cp /home/pi/code/hack-wanderer/hack-wanderer-status-http.service /etc/systemd/system/hack-wanderer-status-http.service
  sudo cp /home/pi/code/hack-wanderer/hack-wanderer-display.service /etc/systemd/system/hack-wanderer-display.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now hack-wanderer-status-http.service
  sudo systemctl enable --now hack-wanderer-display.service
  ```
  This starts a tiny local web server on `http://127.0.0.1:8800/` and opens it in kiosk mode. It assumes `chromium-browser` is installed, `DISPLAY=:0`, and `.Xauthority` is in `/home/pi`.

## Autostart on boot (systemd)

1. Adjust `config.yaml` (or CLI flags in the service file) so `mode` is `wardrive` and `duration_s` is `0` (run forever).
2. Copy the unit file into place and enable it:
   ```bash
   sudo cp /home/pi/code/hack-wanderer/hack-wanderer.service /etc/systemd/system/hack-wanderer.service
   sudo systemctl daemon-reload
   sudo systemctl enable hack-wanderer.service
   sudo systemctl start hack-wanderer.service
   ```
3. Logs go to `logs/service.log` and `logs/service.err` (plus the normal run logs). Check status with `sudo systemctl status hack-wanderer.service`.
