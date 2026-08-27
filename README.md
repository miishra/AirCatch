# AirCatch: Effectively Tracing Advanced Tag-Based Trackers

AirCatch is an end-to-end system for detecting and tracing Bluetooth Low Energy
(BLE) tag-based trackers (Apple Find My / AirTag, Google Find My Device, Samsung
SmartTag, Tile) that rotate their MAC address and rolling public key to evade
detection. A transmitter's **Carrier Frequency Offset (CFO)** is a hardware
fingerprint that persists across those rotations; AirCatch estimates CFO features
per BLE advertisement, clusters them, and flags a cluster as an adversarial
tracker when it shows high MAC churn, sufficient temporal persistence, and a
dense CFO core — while staying ecosystem-aware so legitimate tags are not
mistaken for an attacker.

> Artifact reviewers: see [`ARTIFACT-APPENDIX.md`](ARTIFACT-APPENDIX.md) for
> badges, environment setup, experiments, and the security/ethics notes.

## Project overview

The end-to-end pipeline is:

```
BLE capture (Ubertooth / SDR / EFR32MG24+ESP32)
   → per-packet CFO feature CSV (ble_sniffer.py / iq2pcap)
   → detection & evaluation (Aircatch.py, block_benchmark.py)
   → metrics + plots
```

An ESP32 running evasive Find My firmware (`Modified_Openhaystack_ESP32/`) acts
as the adversary that generates positive test scenarios, and an Android app
provides an on-device companion detector.

## Components

Each component has its own README with build and usage details.

| Component | Path | Description |
|---|---|---|
| **Detection engine** | [`Aircatch.py`](Aircatch.py) | CFO-based adversary detection: per-device segmentation, PCA + agglomerative clustering, core-density decision, per-scenario metrics and paper plots. |
| **Block-size benchmark** | [`block_benchmark.py`](block_benchmark.py) | Sweeps the periodic block size and reports a full confusion matrix (calibration). |
| **SDR/RAIL sniffer (Python)** | [`BlePhasyr_Decoder/`](BlePhasyr_Decoder/README.md) | Decodes raw IQ (SPI int16 or CF32) → per-packet CFO CSV. Primary CSV producer. |
| **SDR decoder (C++)** | [`BLESDR/`](BLESDR/README.md) | `iq2pcap`: complex-float IQ → PCAP + features CSV + aligned IQ chunks. |
| **EFR32MG24 firmware** | [`EFR32MG24/`](EFR32MG24/README.md) | RAIL sniffer firmware (XIAO EFR32MG24) streaming IQ over SPI. |
| **ESP32 SPI→USB bridge** | [`ESP_I2C_Slave/`](ESP_I2C_Slave/README.md) | Forwards EFR32 IQ frames to the host over USB-CDC (SPI slave; folder name is legacy). |
| **Modified Ubertooth** | [`Modified_Ubertooth/`](Modified_Ubertooth/README.md) | Ubertooth firmware/host patches exposing per-packet CFO (FREQEST). |
| **Attacker firmware** | [`Modified_Openhaystack_ESP32/`](Modified_Openhaystack_ESP32/README.md) | ESP32 evasive Find My beacon (rotating MAC/key) — the adversary node. |
| **Android companion** | [`Android App/`](Android%20App/README.md) | On-device tracker detector fed by a USB serial sniffer. |

## Key features

- **CFO-based detection** — five CFO estimates per advertisement (overall +
  `00/11/10/01` transition CFOs) as a hardware fingerprint.
- **Adversary detection engine** — density-based clustering on a robust CFO
  "core", MAC-churn analysis, duration coverage, and ecosystem awareness.
- **Classical ML pipeline** — `StandardScaler` → PCA → agglomerative clustering
  with silhouette-based `k` selection (no pretrained model required).
- **Hardware support** — Ubertooth One, generic SDR (complex-float IQ), and an
  EFR32MG24 + ESP32 capture chain.

## Installation

### Prerequisites (host analysis)

- Python 3.10+ (developed on 3.12).
- Python packages: `numpy`, `pandas`, `scikit-learn`, `matplotlib`, `scipy`
  (plus `pyserial` for `ESP_I2C_Slave/usb_capture.py` and `cryptography` for the
  attacker key generator).

```bash
git clone https://github.com/miishra/AirCatch.git
cd AirCatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt      # numpy pandas scikit-learn matplotlib scipy pyserial cryptography
python3 Aircatch.py --help
```

Capture-chain toolchains (CMake+OpenSSL for BLESDR, ESP-IDF, Simplicity Studio,
Ubertooth tools, Android Studio) are documented in each component's README and
are only needed to regenerate CSVs from the radio.

## Usage

`Aircatch.py` operates on a CSV (or a folder of CSVs) of decoded advertisements.

```bash
# Run over a single CSV or a folder (recursively loads *.csv)
python3 Aircatch.py --input path/to/captures/

# Override the strict core-density threshold
python3 Aircatch.py --input path/to/captures/ --density-min 1.2

# Sweep the density threshold and report the confusion matrix
python3 Aircatch.py --sweep-density

# Grid-search periodic block size × density
python3 Aircatch.py --sweep-block-density --sweep-block-grid 300,600,900,1200

# Run over all configured scenario subfolders and aggregate metrics
python3 Aircatch.py --run-multiscenario
```

If `--input` is omitted, it batches the default controlled subfolder configured
at the top of `Aircatch.py`.

### Outputs

For a run labelled `<label>` it writes (to the working directory): a meta CSV, a
candidate-checks CSV, an evaluation report `.txt` (TP/FP/FN/TN, precision,
recall, F1, FP/hour, FN/hour, time-to-detect median/p90/p95, silhouette,
purity), and PDF plots (PR bars, FP/FN per hour, TTD CDF, silhouette histogram,
core-density CDFs). `--run-multiscenario` writes aggregate plots under
`multiscenario_results/`.

### Configuration options

Key tunable parameters (module constants at the top of `Aircatch.py`):

- **`WINDOW_S`** — time-bucket size in seconds (default 120).
- **`K_RANGE`** — range of cluster counts tested (default 3–19).
- **`MIN_DURATION_S`** / `DUR_MIN` — strict-decision minimum support (default 1700 s).
- **`DENSITY_MIN`** — core-density threshold for the strict decision (default 1.15).
- **`PERIODIC_BLOCK_S` / `PERIODIC_STEP_S`** — periodic block/step (default 2400 s).
- **`KEY_SIM_THR`** — ecosystem key-similarity merge threshold (default 0.99).
- **`TYPE_SEP_WEIGHT`** — weight for ecosystem type separation (default 1.0).
- **`CORE_RADIUS_MODE`** — core radius estimator: `pctl` / `mad` / `std` (default `std`).

## Data format

Input CSV — one row per decoded BLE advertisement — must contain:

| Column | Meaning |
|---|---|
| `timestamp` | Packet capture time (seconds, float). |
| `AdvA` | BLE advertising address (MAC). |
| `payload` | Advertisement payload (hex; used for ecosystem + ground-truth tagging). |
| `crc_ok` | 1 if CRC passed (non-1 rows are dropped unless `b210=True`). |
| `CFO_Hz`, `CFO_00_Hz`, `CFO_11_Hz`, `CFO_10_Hz`, `CFO_01_Hz` | The five CFO estimates (Hz). |
| `mobile_timestamp`, `mobile_lat`, `mobile_lon` | *(optional)* GPS track for speed plots. |

`BlePhasyr_Decoder/ble_sniffer.py` emits these columns directly (see its README).
Ground truth is read from the scenario file/folder names: `__adv0__` (and
`apple0/google0/samsung0/tile0`) is benign; `__adv1__`…`__adv4__` (or any
`apple/google/samsung/tile ≥ 1`) is attacker-present; payload prefixes
`4c001219fc/fd/fe/ff` mark the adversary MACs.

## Performance metrics

Precision/recall/F1 for malicious-tracker identification, FP-per-hour and
FN-per-hour operational rates, time-to-detect (median/p90/p95), and clustering
quality (silhouette, purity). See the generated `*_eval_report__*.txt`.

## Security, privacy, and ethics

This repository includes **evasive tracker firmware** and **passive BLE capture**
tooling. Read the *Security/Privacy Issues and Ethical Concerns* section of
[`ARTIFACT-APPENDIX.md`](ARTIFACT-APPENDIX.md) before running anything: flashing
scripts erase devices, the OpenHaystack firmware creates an unsanctioned locatable
tag, and passive captures record bystanders' BLE identifiers. Operate only on
hardware you own, with authorization, in a controlled setting.

## Research output

AirCatch supports research in privacy-preserving tracker detection, forensic
analysis of location-tracking attacks, cross-ecosystem BLE security, and radio
fingerprinting / device identification.
