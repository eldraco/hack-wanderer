# Cellular Wardriving (Test Mode)

This repo contains a Python script that connects to a cellular modem over a serial port and runs AT commands to verify modem, SIM, and network status. It is a test and diagnostics tool for now; wardriving collection can be built on top later.

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
python wardriving.py --port /dev/cu.SLAB_USBtoUART --mode test
```

With a config file:

```bash
python wardriving.py --config config.example.yaml
```

Write full results to JSON:

```bash
python wardriving.py --config config.example.yaml --output-json results.json
```

## Configuration

All settings can be provided via CLI flags or a YAML file. CLI flags override the YAML values.

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
  operator_scan: true
  gps: true
  vendor_specific: true
  sim_read: true

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
```

## What the script checks

- Modem info: manufacturer, model, firmware revision, IMEI
- SIM info: SIM status, ICCID, IMSI, basic SIM file reads via `AT+CRSM`
- Network status: signal quality, registration status (2G/3G/4G), current operator
- Operator scan: available nearby operators (`AT+COPS=?`)
- Optional vendor-specific data (if supported): band, serving cell, neighbor cell
- Optional GPS info (if supported)
- Error diagnostics (`AT+CEER`)

## Notes

- `AT+COPS=?` can take a long time. Disable it with `--no-operator-scan` if needed.
- SIM file reads are limited to a small list of common EF files. Full SIM exploration requires APDU workflows (e.g., `AT+CSIM`), which are not implemented yet.
- GPS commands are queried only (no power-on commands are issued).
- If you see `SIM PIN` or `SIM PUK`, the SIM is locked or blocked. The tool only reports it.

## CLI options

Run `python wardriving.py --help` for the full list. Key flags:

- `--port`, `--baudrate`
- `--operator-scan` / `--no-operator-scan`
- `--gps` / `--no-gps`
- `--vendor-specific` / `--no-vendor-specific`
- `--sim-read` / `--no-sim-read`
- `--extra-command` to add extra AT commands
- `--output-json` to save full results
- `--output-raw` to print raw command logs
