# Artifact Appendix

Paper title: **AirCatch: Effectively Tracing Advanced Tag-Based Trackers**
<!-- TODO(authors): confirm the exact accepted title, and add author list + year/BibTeX. -->

Requested Badge(s):
  - [x] **Available**
  - [x] **Functional**
  - [x] **Reproduced**

## Description

This artifact accompanies *AirCatch: Effectively Tracing Advanced Tag-Based
Trackers*.
<!-- TODO(authors): fill in the citation, e.g.:
> A. Author, B. Author, and C. Author. "AirCatch: Effectively Tracing Advanced
> Tag-Based Trackers." Proceedings on Privacy Enhancing Technologies (PoPETs),
> 2026.
-->

AirCatch is an end-to-end system for detecting and tracing Bluetooth Low Energy
(BLE) tag-based trackers (Apple Find My / AirTag, Google Find My Device,
Samsung SmartTag, Tile) that rotate their MAC address and rolling public key to
evade detection. The core idea is that a physical transmitter's **Carrier
Frequency Offset (CFO)** is a hardware fingerprint that persists across MAC/key
rotations. AirCatch estimates several CFO features per BLE advertisement,
segments packets per device identity, clusters segments in CFO feature space,
and flags a cluster as an adversarial tracker when it shows (a) high MAC churn,
(b) sufficient temporal persistence, and (c) a dense CFO "core" — while
remaining ecosystem-aware so legitimate tags are not confused with an attacker.

The artifact contains the full pipeline that supports the paper:

| Component | Path | Role in the paper |
|---|---|---|
| Detection engine | `Aircatch.py` | CFO-based adversary detection, clustering, per-scenario metrics, and paper plots. |
| Block-size benchmark | `block_benchmark.py` | Sweeps the periodic block size and reports the confusion matrix used for calibration. |
| SDR/RAIL sniffer | `BlePhasyr_Decoder/ble_sniffer.py` | Decodes raw IQ (SPI int16 or CF32) to BLE packets and emits per-packet CFO features as CSV. |
| SDR decoder (C++) | `BLESDR/` | `iq2pcap`: complex-float IQ → PCAP + features + aligned IQ chunks. |
| EFR32MG24 firmware | `EFR32MG24/` | RAIL sniffer firmware that captures advertisements and streams IQ over SPI. |
| ESP32 bridge | `ESP_I2C_Slave/` | Receives IQ frames from the EFR32 over I2C and forwards them to the host over USB-CDC. |
| Modified Ubertooth | `Modified_Ubertooth/` | Firmware patches (`le_phy.c`, `ubertooth_callback.c`) enabling CFO measurement on Ubertooth One. |
| Attacker firmware | `Modified_Openhaystack_ESP32/` | ESP32 Find My spoofing firmware with continuous MAC/key rotation — the *adversary* used to generate positive scenarios. |
| Android companion | `Android App/` | On-device tracker-detection companion app (Kotlin). |

### Security/Privacy Issues and Ethical Concerns

Reviewers and future users should be aware of the following before running this
artifact.

1. **Offensive tracker firmware (`Modified_Openhaystack_ESP32/`).** This is a
   fully functional Apple Find My ("OpenHaystack"-compatible) beacon that
   generates NIST P-224 key pairs and **continuously rotates its MAC address and
   advertised key (50,000+ keys/day) to evade tracking detection**. Flashing it
   turns an ESP32 into an unsanctioned Find My tag. It transmits on the BLE
   advertising channels and can be located through Apple's crowd-sourced
   network. Only flash and operate it on hardware you own, in an RF-isolated or
   controlled setting, and never attach it to another person or their property.
   It exists in the artifact solely to *generate the adversarial signal that
   AirCatch is designed to catch.*

2. **Firmware flashing overwrites devices.** `Modified_Openhaystack_ESP32/flash_esp32.sh`,
   `EFR32MG24/Flashing/flash.sh`, and the ESP-IDF flash flow **erase the
   target microcontroller**. Use dedicated development boards, not production
   devices.

3. **Passive BLE capture is a privacy-sensitive activity.** The Ubertooth, SDR,
   and EFR32 receivers passively record *all* BLE advertisements in range,
   which will include advertisements from bystanders' phones, tags, and
   wearables. Captured data therefore contains third-party MAC addresses and RF
   fingerprints. Operate the receivers only where you have authorization, and
   treat captures as personal data.

4. **Why the raw dataset is not released.** For exactly the reason above, the
   `controlled/` capture dataset used in the paper is **not** distributed with
   this artifact: it was collected in real environments (home-to-work commutes,
   an airport, car trips) and contains bystander BLE identifiers and RF
   fingerprints that cannot be safely anonymized without destroying the CFO
   signal the paper studies. See [Limitations](#limitations) for what this means
   for reproduction, and [Testing the Environment](#testing-the-environment) for
   the synthetic sample used in its place.

5. **No IRB / human-subjects data.** The artifact contains no survey responses,
   interview transcripts, or other human-subjects material.

The host-side analysis code (`Aircatch.py`, `block_benchmark.py`,
`ble_sniffer.py`) does **not** disable any host security mechanism (no ASLR/
firewall changes, no privileged operations); it only reads local CSV/IQ files
and writes CSV/PDF/PNG outputs.

## Basic Requirements

### Hardware Requirements

**Host analysis (Functional badge, and re-running the pipeline over captures):**
Can run on a laptop. No special hardware is required to run `Aircatch.py` /
`block_benchmark.py` over CSV inputs. More cores help: both tools parallelize
across input CSVs and grid points (up to `min(32, cpu_count())` / `--workers`
processes). 8 GB RAM is comfortable for the sample and per-scenario runs.

**Signal capture (required to regenerate the CSVs from the radio, and to
reproduce the paper's end-to-end results — see below):** the paper's results
were produced from live captures, so full reproduction requires the capture
chain. The following hardware was used in the paper:

- **Ubertooth One** (with the firmware in `Modified_Ubertooth/`), *or*
- A **software-defined radio** producing complex-float IQ (used with `BLESDR/iq2pcap`
  and `BlePhasyr_Decoder/ble_sniffer.py`), *or*
- A **Seeed XIAO EFR32MG24** board — part `EFR32MG24A020F1536GM48` — running the
  RAIL firmware in `EFR32MG24/`, bridged to the host by an **ESP32** (USB-CDC)
  running `ESP_I2C_Slave/`.
- **Adversary node:** an **ESP32** running `Modified_Openhaystack_ESP32/` to emit
  the rotating-identity tracker signal for positive scenarios.
- Optionally, an **Android phone** (min API 21 / Android 5.0; Android 12+ for the
  USB-host sniffer flow) for the companion app.

<!-- TODO(authors, Reproduced badge): list the exact machine used for the paper's
     experiments, e.g. "CPU model, #cores, RAM, OS", and the exact SDR model /
     sample rate if an SDR was used. This matters because TTD and throughput
     numbers depend on it. -->

### Software Requirements

- **OS:** Ubuntu 22.04 LTS (Linux). The host code is OS-agnostic Python and
  should run on any Linux/macOS with the packages below; it was developed and
  run on Linux.
- **Python:** 3.12 (the shipped bytecode is `cpython-312`; 3.10+ is expected to
  work — the code uses `list[Path]` / `X | Y` syntax, so **3.10 is the minimum**).
- **Python packages** (host analysis): `numpy`, `pandas`, `scikit-learn`,
  `matplotlib`, `scipy`. The IQ sniffer additionally uses `numpy` (and
  `pyserial` for the `ESP_I2C_Slave/usb_capture.py` host capture script). The
  attacker key generator uses `cryptography`. A `requirements.txt` is provided
  at the repository root.
  <!-- TODO(authors, Reproduced badge): pin exact versions you validated with,
       e.g. numpy==2.0.x, pandas==2.2.x, scikit-learn==1.5.x, matplotlib==3.9.x,
       scipy==1.14.x. -->
- **Container runtime (recommended for review):** Docker 24+ (a `Dockerfile` is
  provided at the repository root so reviewers get a pinned environment).
  <!-- TODO(authors): add the Dockerfile referenced here, or delete this bullet
       if you prefer a bare pip install. -->
- **Capture-chain toolchains** (only needed to build firmware / regenerate CSVs
  from radio):
  - `BLESDR/iq2pcap`: CMake ≥ 3.10, a C++17 compiler, and **OpenSSL** (libcrypto).
  - EFR32MG24 firmware: **Simplicity Studio v6** with the EFR32xG24 SDK
    (RAIL "SoC Empty" project), and **OpenOCD 0.12** for flashing.
  - ESP32 firmware (bridge and attacker): **ESP-IDF** (with TinyUSB enabled for
    the bridge), or `esptool`.
  - Ubertooth: the standard Ubertooth host tools + `libusb`, rebuilt with the
    patches in `Modified_Ubertooth/`.
  - Android app: **Android Gradle Plugin 8.13.2**, **Kotlin 2.0.21**, JDK 17,
    `compileSdk 34` (Android SDK 34).

- **ML models:** none. AirCatch uses classical, unsupervised methods
  (StandardScaler, PCA, agglomerative clustering, silhouette selection) fit at
  run time; there is no pretrained model to download.
- **Datasets:** the paper's `controlled/` capture dataset is **not** released
  (see [Security/Privacy](#securityprivacy-issues-and-ethical-concerns)). A
  synthetic sample CSV showcasing the expected input format is used for the
  functional test (see [Testing the Environment](#testing-the-environment)).

### Estimated Time and Storage Consumption

- **Environment setup:** ~10 human-minutes + ~5 compute-minutes (`pip install`
  or `docker build`).
- **Functional test (synthetic sample):** < 1 human-minute + < 1 compute-minute.
- **A single-scenario pipeline run** over one folder of captures: a few
  human-minutes to launch + minutes-to-tens-of-minutes of compute, depending on
  capture length and core count.
- **Full multi-scenario evaluation** (`--run-multiscenario` over HtoW, WtoH,
  Airport, Car_Trip): dominated by capture length and core count.
  <!-- TODO(authors, Reproduced badge): give a concrete wall-clock figure from
       your machine, e.g. "40 human-minutes + 3 compute-hours on 16 cores". -->
- **Disk:** the code and synthetic sample are < 100 MB. Full captures and
  generated IQ chunks can be large (many GB).
  <!-- TODO(authors, Reproduced badge): state the on-disk size of the full
       controlled/ dataset if a reviewer were to regenerate it. -->

## Environment

### Accessibility

The artifact is hosted on GitHub:

- Repository: <https://github.com/miishra/AirCatch>
- Latest revision on the default branch (do **not** cite a specific commit at
  submission time; the artifact chairs will collect a stable commit/tag after
  evaluation): <https://github.com/miishra/AirCatch/tree/main>

<!-- TODO(authors, Available badge): PoPETs requires a persistent archive. Before
     the badge is finalized, deposit a snapshot on Zenodo/Figshare and add the
     DOI here. Personal web pages / Google Drive / Dropbox are not accepted. -->

### Set Up the Environment

Clone the repository and install the host dependencies. Two supported paths:

**Option A — local virtualenv:**

```bash
git clone https://github.com/miishra/AirCatch.git
cd AirCatch
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Option B — Docker (pinned environment):**

```bash
git clone https://github.com/miishra/AirCatch.git
cd AirCatch
docker build -t aircatch:main .
```

<!-- TODO(authors): requirements.txt now exists at the repo root, so Option A
     works verbatim. Option B still needs a Dockerfile added at the repo root —
     add it, or delete the Docker option here and in Software Requirements. -->

Building the capture-chain components is only needed to regenerate CSVs from a
radio (not for the Functional test). For the SDR decoder:

```bash
cd BLESDR
cmake -S . -B build
cmake --build build          # produces the iq2pcap binary
```

Firmware (EFR32MG24, ESP32, Ubertooth) and the Android app follow the standard
flows for their toolchains; see each subdirectory's `README.md`.

### Testing the Environment

Because the raw dataset is not released, the functional smoke test runs the
detection pipeline over a **synthetic sample CSV** that reproduces the expected
input schema. The input schema `Aircatch.py` expects (one row per decoded BLE
advertisement) is:

| Column | Meaning |
|---|---|
| `timestamp` | Packet capture time (seconds, float). |
| `AdvA` | BLE advertising address (MAC). |
| `payload` | Advertisement payload (hex string; used for ecosystem + ground-truth tagging). |
| `crc_ok` | 1 if CRC passed (rows with `crc_ok != 1` are dropped unless `b210=True`). |
| `CFO_Hz`, `CFO_00_Hz`, `CFO_11_Hz`, `CFO_10_Hz`, `CFO_01_Hz` | The five CFO feature estimates (Hz). |
| `mobile_timestamp`, `mobile_lat`, `mobile_lon` | *(optional)* GPS track for speed plots. |

Run the pipeline over a single CSV:

```bash
# inside the venv or the Docker container, from the repo root
python3 Aircatch.py --input sample/sample_capture.csv
```

Expected behaviour: the run prints per-file progress and an `=== Outputs ===`
block, and writes (in the working directory) files named like
`aircatch_single_sample_capture_*`:
`..._meta__dens1.15.csv`, `..._candidate_checks__dens1.15.csv`,
`..._eval_report__dens1.15.txt`, and the evaluation PDFs
(`..._eval__dens1.15__prf_bar.pdf`, `..._fp_fn_per_hour.pdf`, `..._ttd_cdf.pdf`,
`..._silhouette_hist.pdf`). If those files are produced without a traceback, the
environment is correctly set up.

<!-- TODO(authors): add sample/sample_capture.csv to the repo — a small synthetic
     capture (e.g. one benign scenario plus one with a rotating-identity tracker,
     using payload prefixes 4c001219fc/fd/fe/ff to mark the adversary and the
     __adv1__ filename token) so the command above runs as written. This is
     required by the badge process when the real dataset is withheld. -->

## Artifact Evaluation

### Main Results and Claims

<!-- TODO(authors): map each claim to the exact figure/table numbers in the
     final paper, and fill in the concrete target numbers (the code computes
     precision, recall, F1, FP/hour, FN/hour, TTD median/p90/p95, silhouette,
     and purity — see aircatch_*_eval_report__*.txt). -->

#### Main Result 1: AirCatch detects rotating-identity trackers with high precision and recall

Across the controlled scenarios, AirCatch flags scenarios that contain an
adversarial (MAC/key-rotating) tracker as positive and benign scenarios as
negative. The independent variable is the scenario/adversary setting
(adv0…adv4, i.e. number of concurrent attacker tags); the dependent variables
are precision, recall, F1, and per-hour false-positive/false-negative rates.
This is produced by [Experiment 1](#experiment-1-per-scenario-detection-metrics)
and [Experiment 3](#experiment-3-multi-scenario-aggregate). It corresponds to
the detection-performance figure/table in the paper.
<!-- TODO(authors): "Figure X / Table Y". -->

#### Main Result 2: The CFO core-density signal separates adversarial from benign clusters

Adversarial clusters exhibit a denser CFO "core" than benign traffic, which is
what makes the strict decision rule work. The core-density CDFs (flagged vs.
not, and adv-present vs. not) are produced as PDFs by
[Experiment 1](#experiment-1-per-scenario-detection-metrics). This supports the
core-density claim in the paper.
<!-- TODO(authors): "Figure X". -->

#### Main Result 3: Detection is timely, and calibration is robust to block size

AirCatch confirms an attacker within a bounded time-to-detect (TTD), and the
detection quality is stable across a range of periodic block sizes. The
independent variable is the block size (`PERIODIC_BLOCK_S`); the dependent
variables are the confusion matrix (TP/FP/FN/TN) and derived rates. This is
produced by [Experiment 2](#experiment-2-block-size-calibration) and by the TTD
CDF from [Experiment 1](#experiment-1-per-scenario-detection-metrics).
<!-- TODO(authors): "Figure X / Table Y". -->

### Experiments

> **Prerequisite for all experiments below (Reproduced badge):** a `controlled/`
> capture dataset laid out as `controlled/<SCENARIO>/<run-folder>/*.csv`, where
> `<SCENARIO> ∈ {HtoW, WtoH, Airport, Car_Trip, Benign}` and each run folder
> follows the naming convention the code parses, e.g.
> `scenarios_car__adv1_apple1_google0_samsung0_tile0__<date>/…` and optional
> `..._tx-10s_rot-5min.csv`. Ground truth is read from these names: `__adv0__`
> (and `apple0/google0/samsung0/tile0`) is benign; `__adv1__`…`__adv4__` (or any
> `apple/google/samsung/tile ≥ 1`) is a positive (attacker-present) scenario;
> and packets whose payload contains `4c001219fc/fd/fe/ff` mark the adversary
> MACs. Because this dataset is withheld (see
> [Security/Privacy](#securityprivacy-issues-and-ethical-concerns)), reviewers
> reproducing the numbers must regenerate it with the capture chain (see
> [Hardware Requirements](#hardware-requirements) and
> [Limitations](#limitations)).

#### Experiment 1: Per-scenario detection metrics

- Time: a few human-minutes to launch + minutes–tens of minutes compute per
  scenario folder (scales with capture length and cores).
- Storage: outputs are small (CSV/TXT/PDF); < 10 GB.

Run the detector over one scenario folder (or any folder/file of CSVs):

```bash
# batch over the default controlled subfolder, or point --input anywhere
python3 Aircatch.py --input controlled/HtoW
```

This writes the per-scenario evaluation report and plots described in
[Testing the Environment](#testing-the-environment):
`aircatch_*_eval_report__dens1.15.txt` (TP/FP/FN/TN, precision, recall, F1,
FP/hour, FN/hour, TTD median/p90/p95, silhouette, purity), the PR-bar, FP/FN-per-
hour, TTD-CDF, and silhouette-histogram PDFs, and the core-density CDF PDFs.
Compare the reported precision/recall/F1 and the core-density CDFs against the
paper. Supports [Main Result 1](#main-result-1-aircatch-detects-rotating-identity-trackers-with-high-precision-and-recall)
and [Main Result 2](#main-result-2-the-cfo-core-density-signal-separates-adversarial-from-benign-clusters).

You can override the strict density threshold, or sweep it:

```bash
python3 Aircatch.py --input controlled/HtoW --density-min 1.2
python3 Aircatch.py --sweep-density        # sweeps DENSITY_MIN, reports confusion matrix
```

#### Experiment 2: Block-size calibration

- Time: a few human-minutes to launch + compute scales with (#blocks × #CSVs) /
  `--workers`.
- Storage: two CSVs; < 10 GB.

Sweep the periodic block size while holding the shipped calibration ratio fixed
(`DUR_RATIO = 1700/2400`), producing a full confusion matrix per block size:

```bash
python3 block_benchmark.py --outdir block_benchmark_out
# or, from within Aircatch.py's own sweep:
python3 Aircatch.py --sweep-block-density
```

Outputs `block_benchmark_out/block_benchmark_per_file.csv` (per-gate diagnostics
per CSV) and `block_benchmark_out/block_benchmark_summary.csv` (TP/FP/FN/TN and
derived rates per block size). This shows detection quality is stable across
block sizes and identifies the operating point used in the paper. Supports
[Main Result 3](#main-result-3-detection-is-timely-and-calibration-is-robust-to-block-size).

#### Experiment 3: Multi-scenario aggregate

- Time: a few human-minutes to launch + compute scales with total capture length
  and cores.
- Storage: plots + CSVs under `multiscenario_results/`; < 10 GB (excluding input
  captures).

Run the full evaluation across all scenario subfolders and aggregate:

```bash
python3 Aircatch.py --run-multiscenario
```

This iterates over `CONTROLLED_SUBFOLDERS = [HtoW, WtoH, Airport, Car_Trip]`,
aggregates metrics by adversary setting, and writes the aggregate metric plots
into `multiscenario_results/`. Supports
[Main Result 1](#main-result-1-aircatch-detects-rotating-identity-trackers-with-high-precision-and-recall).

<!-- TODO(authors): if the paper reports a headline table/number, add the exact
     expected values here and the acceptable tolerance (e.g. "within 5%"). -->

## Limitations

- **The raw capture dataset is intentionally withheld.** The `controlled/`
  captures contain third-party BLE identifiers and RF fingerprints collected in
  public settings and cannot be anonymized without destroying the CFO signal.
  Consequently, the paper's **numeric results cannot be reproduced from released
  data alone**. Reviewers can (a) confirm the full pipeline runs end-to-end on
  the synthetic sample ([Testing the Environment](#testing-the-environment)),
  and (b) reproduce the numbers only by regenerating equivalent captures with
  the capture chain described in [Hardware Requirements](#hardware-requirements).
  We argue the artifact still merits Functional evaluation because every stage of
  the pipeline is provided and runnable, and the Reproduced path is fully
  documented and gated only by hardware and data-collection effort, not by
  missing code.
- **Capture reproduction requires specialized, non-commodity hardware** (an
  Ubertooth One, an SDR, or an EFR32MG24 + ESP32 bridge, plus an ESP32 attacker
  node). Exact CFO values and time-to-detect depend on the specific receiver and
  its sampling rate, so absolute numbers may differ across hardware even when the
  qualitative trends reproduce.
- **The attacker firmware is dual-use.** `Modified_Openhaystack_ESP32/` is a
  working evasive tracker; it is included only to generate the adversarial signal
  and must be operated ethically (see
  [Security/Privacy](#securityprivacy-issues-and-ethical-concerns)).
- **The Android companion app** requires an Android device (and, for the USB
  sniffer flow, USB-host support and a compatible serial receiver); it is a
  companion to the analysis and is not required to reproduce the paper's core
  detection results.

## Notes on Reusability

AirCatch is designed to be reused beyond this paper:

- **Bring your own capture front-end.** The detector only needs a CSV with a
  `timestamp`, `AdvA`, `payload`, `crc_ok`, and the five `CFO_*_Hz` columns
  (see [Testing the Environment](#testing-the-environment)). Any receiver that
  can emit CFO estimates per advertisement can feed the pipeline, independent of
  the Ubertooth/SDR/EFR32 front-ends shipped here.
- **Tunable detection.** Key knobs are exposed as module constants in
  `Aircatch.py` — `WINDOW_S`, `K_RANGE`, `MIN_DURATION_S`, `DENSITY_MIN`,
  `PERIODIC_BLOCK_S`/`PERIODIC_STEP_S`, `KEY_SIM_THR`, `TYPE_SEP_WEIGHT`, and the
  core-radius mode (`CORE_RADIUS_MODE ∈ {pctl, mad, std}`) — and several are also
  overridable/sweepable from the CLI (`--density-min`, `--sweep-density`,
  `--sweep-block-density`, `--sweep-density-grid`, `--sweep-block-grid`). This
  makes it straightforward to recalibrate for a new deployment, receiver, or
  set of tracker ecosystems.
- **Ecosystem extensibility.** Ecosystem classification and key/PRIVID
  extraction are isolated in dedicated functions
  (`classify_tag_ecosystem_from_payload`, `extract_pubkey_from_payload`,
  `get_samsung_privid_from_payload`), so support for additional tracker
  ecosystems can be added without touching the clustering/decision logic.
- **Modular capture chain.** The SDR decoder, EFR32/ESP32 firmware, and Ubertooth
  patches are independent and can be reused as standalone BLE CFO-capture tools.
