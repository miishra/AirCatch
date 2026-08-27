# BlePhasyr_Decoder — BLE 1M advertising sniffer for raw IQ (`ble_sniffer.py`)

A pure-Python BLE 1M (LE 1M PHY) legacy-advertising sniffer that decodes raw I/Q
recordings and emits **per-packet Carrier Frequency Offset (CFO) features** as a
CSV. This is the primary front-end that produces the CSVs consumed by
`Aircatch.py`.

Pipeline role: `IQ capture (SPI .bin or .cf32) → ble_sniffer.py → cfo_samples*.csv → Aircatch.py`.

## What it does

- Resamples the whole capture once, computes the FM discriminator once, then
  scans continuously for Access-Address correlations (energy-based burst
  detection is **not** used; `--thr` is ignored).
- Dewhitens and CRC-checks in the same byte domain as BLESDR.
- Estimates several CFOs per packet over a configurable window
  (preamble → AA → header → payload; CRC bits are excluded):
  an overall CFO plus transition-specific CFOs (`00/11/10/01`).
- Detects tag ecosystems (Apple Find My, Google, Samsung, Tile) and can filter
  to them.
- Optionally attaches a GPS track (`mobile_timestamp/lat/lon`) to each packet
  for later speed analysis in `Aircatch.py`.
- Optionally emits a per-AdvA CFO boxplot PDF.

## Requirements

- Python 3.10+ (developed on 3.12).
- `numpy` (and `matplotlib` for `--plot-cfo`). Install via the repo-root
  `requirements.txt`.

## Input formats

- **`.cf32` / `.cfile`** — interleaved complex float32.
- **Raw SPI `.bin`** — int16 IQ framed in 2048-byte chunks with a 4-byte
  per-chunk header (the format streamed by the EFR32MG24 firmware via the ESP32
  bridge). The header bytes are zeroed (not deleted) so timing is preserved.

## Usage

```bash
# Decode a CF32 capture on channel 37, write per-packet CFO CSV
python3 ble_sniffer.py capture.cf32 \
    --fs-in 4e6 \
    --channel 37 \
    --plot-cfo \
    --cfo-csv cfo_samples.csv

# Decode a raw SPI int16 capture from the EFR32/ESP32 chain
python3 ble_sniffer.py rail_data.bin \
    --fs-in 1344106.9 \
    --channel 37 \
    --timestamps-csv rail_data_timestamps.csv \
    --cfo-csv cfo_samples_rail.csv
```

### Key options

| Flag | Default | Description |
|---|---|---|
| `filename` | *(required)* | Input IQ file (`.cf32`/`.cfile` or raw SPI `.bin`). |
| `--fs-in <Hz>` | `1344106.9` | Input IQ sample rate. **Must match the capture.** |
| `--channel <37\|38\|39>` | `37` | BLE advertising channel. |
| `--try-adv-channels` | off | Try channels 37/38/39 per window. |
| `--cfo-mode {aa,header,payload}` | payload | CFO estimation window extent. |
| `--plot-cfo` / `--cfo-pdf <path>` | off / `cfo_boxplot_by_adva.pdf` | Save per-AdvA CFO boxplot. |
| `--cfo-csv <path>` | `cfo_samples_rail.csv` | **Per-packet CFO output CSV.** |
| `--timestamps-csv <path>` | none | SPI chunk-timestamp CSV to align packet times. |
| `--aa-min <0..32>` / `--pre-min <0..8>` | 28 / 7 | AA / preamble correlation gates. |
| `--no-crc` | off | Keep packets even if CRC fails. |
| `--auto-fs-scan` | off | Scan `--fs-in` ± span to maximize CRC-OK (use when the rate is uncertain). |
| `--fs-scan-span` / `--fs-scan-steps` | 0.05 / 21 | Range/resolution of the fs scan. |
| `--slip-sweep` / `--slip-max` | off / 8 | Sweep bit-slip around the AA boundary. |
| `--crc-diag` / `--crc-diag-max` | off / 20 | CRC failure diagnostics + histograms. |
| `--workers <N>` / `--mp-chunksize <N>` | 0 / 8 | Multiprocessing across decode windows (0 = auto). |
| `--stats-only` | off | Print stats only; don't print decoded packets. |
| `--out-airtag <path>` | `airtag_packets.txt` | Dump matched AirTag/Find My packets. |

Run `python3 ble_sniffer.py --help` for the complete list.

## Output: CFO CSV

One row per decoded advertisement. Columns include:

`timestamp, mobile_timestamp, mobile_lat, mobile_lon, mobile_accuracy_m, AdvA,
CFO_Hz, CFO_00_Hz, CFO_11_Hz, CFO_10_Hz, CFO_01_Hz, CFO_from_transitions_Hz,
nprod_00, nprod_11, nprod_10, nprod_01, nprod_total, crc_ok, is_tag_ecosystem,
pdu_type, pdu_type_name, length, channel, phase, polarity, slip, window_start,
window_end, aa_pos, aa_corr, pre_corr, tag_type, ground_truth_apple, cfo_window`

These map directly onto the columns `Aircatch.py` expects
(`timestamp, AdvA, payload, crc_ok, CFO_Hz, CFO_00_Hz, CFO_11_Hz, CFO_10_Hz,
CFO_01_Hz`); note that `payload` must be supplied for ecosystem/ground-truth
tagging in the detector.

## Notes / limitations

- LE 1M legacy advertising only.
- An incorrect `--fs-in` is the most common cause of zero CRC-OK; use
  `--auto-fs-scan` if unsure.
- Captures include bystander BLE traffic — treat output as privacy-sensitive.
