# Artifact Appendix

Paper title: **AirCatch: Effectively Tracing Advanced Tag-Based Trackers**

Requested Badge(s):
  - [x] **Available**
  - [x] **Functional**
  - [x] **Reproduced**

## Description


This artifact accompanies *AirCatch: Effectively Tracing Advanced Tag-Based
Trackers* by A Mishra, Swadeep, G Noubir and M Cunche.

AirCatch is an end-to-end system for detecting and tracing Bluetooth Low Energy
(BLE) tag-based trackers (Apple Find My / AirTag, Google Find My Device, Samsung
SmartTag, Tile) that rotate their MAC address and rolling public key to evade
detection. The core idea is that a physical transmitter's **Carrier Frequency
Offset (CFO)** is a hardware fingerprint that persists across those rotations.
AirCatch estimates several CFO features per BLE advertisement, segments packets
per device identity, clusters segments in CFO feature space, and flags a cluster
as an adversarial tracker when it shows (a) high MAC churn, (b) sufficient
temporal persistence, and (c) a dense CFO "core", while remaining
ecosystem-aware so legitimate tags are not mistaken for an attacker.

The artifact contains the full pipeline that supports the paper:

```
BLE capture (Ubertooth / SDR / EFR32MG24+ESP32)
   → per-packet CFO feature CSV (ble_sniffer.py / iq2pcap)
   → detection & evaluation (Aircatch.py, block_benchmark.py)
   → metrics + plots
```

An ESP32 running evasive Find My firmware acts as the *adversary* that generates
the positive test scenarios, and an Android app provides an on-device companion
detector. Each component has its own README with build and usage details.

The capture dataset used in the paper ships with the artifact under
[`dataset/`](dataset/). BLE advertising addresses in them
are pseudonymized (see [Security/Privacy Issues and Ethical Concerns](#securityprivacy-issues-and-ethical-concerns)).

| Component | Path | What it does |
|---|---|---|
| **Detection engine** | [`Aircatch.py`](Aircatch.py) | CFO-based adversary detection: per-device segmentation, PCA + agglomerative clustering, core-density decision, per-scenario metrics and plots. |
| **Block-size benchmark** | [`block_benchmark.py`](block_benchmark.py) | Sweeps the periodic block size and reports the full confusion matrix used for calibration. |
| **Paper reproduction** | [`reproduce_paper.py`](reproduce_paper.py) | One command: runs every stage and curates all paper figures/tables into `Paper_Results/`. |
| **CFO figure plotter** | [`plot_cfo_figures.py`](plot_cfo_figures.py) | Regenerates Figures 2a/2b/3a/3b/5 (per-device CFO, CFO over time, adversary CFO, transition CFOs) from `dataset/`. |
| **Fingerprint classifier** | [`fingerprint_classifier.py`](fingerprint_classifier.py) | Random-forest per-device fingerprinting; drives the §7.2 transition-feature ablation. |
| **SDR/RAIL sniffer (Python)** | [`BlePhasyr_Decoder/`](BlePhasyr_Decoder/README.md) | Decodes raw IQ (SPI int16 or CF32) → per-packet CFO CSV. Primary CSV producer. |
| **SDR decoder (C++)** | [`BLESDR/`](BLESDR/README.md) | `iq2pcap`: complex-float IQ → PCAP + features CSV + aligned IQ chunks. |
| **EFR32MG24 firmware** | [`EFR32MG24/`](EFR32MG24/README.md) | RAIL sniffer firmware (XIAO EFR32MG24) that captures advertisements and streams IQ over SPI. |
| **ESP32 SPI→USB bridge** | [`ESP_I2C_Slave/`](ESP_I2C_Slave/README.md) | Receives IQ frames from the EFR32 over SPI and forwards them to the host over USB-CDC (folder name is legacy). |
| **Modified Ubertooth** | [`Modified_Ubertooth/`](Modified_Ubertooth/README.md) | Firmware/host patches (`le_phy.c`, `ubertooth_callback.c`) exposing per-packet CFO (FREQEST) on Ubertooth One. |
| **Attacker firmware** | [`Modified_Openhaystack_ESP32/`](Modified_Openhaystack_ESP32/README.md) | ESP32 evasive Find My beacon with continuous MAC/key rotation — the adversary used to generate positive scenarios. |
| **Android companion** | [`Android App/`](Android%20App/README.md) | On-device tracker detector (Kotlin) fed by a USB serial sniffer. |

The detector's key properties are: five CFO estimates per advertisement (overall
plus the `00/11/10/01` transition CFOs) used as a hardware fingerprint;
density-based clustering on a robust CFO "core" combined with MAC-churn analysis
and duration coverage; and a classical, unsupervised ML pipeline
(`StandardScaler` → PCA → agglomerative clustering with silhouette-based `k`
selection) that requires no pretrained model.

**Input data format.** `Aircatch.py` consumes a CSV (or a folder of CSVs) with
one row per decoded BLE advertisement:

| Column | Meaning |
|---|---|
| `timestamp` | Packet capture time (seconds, float). |
| `AdvA` | BLE advertising address (Keyed MAC to avoid collecting sensitive data) |
| `payload` | Advertisement payload (hex; used for ecosystem + ground-truth tagging). |
| `crc_ok` | 1 if CRC passed (rows with `crc_ok != 1` are dropped unless `b210=True`). |
| `CFO_Hz`, `CFO_00_Hz`, `CFO_11_Hz`, `CFO_10_Hz`, `CFO_01_Hz` | The five CFO estimates (Hz). |
| `mobile_timestamp`, `mobile_lat`, `mobile_lon` | *(optional)* GPS track for speed plots. |

`BlePhasyr_Decoder/ble_sniffer.py` emits these columns directly. Ground truth is
read from the scenario file/folder names: `__adv0__` (and
`apple0/google0/samsung0/tile0`) is benign; `__adv1__`…`__adv4__` (or any
`apple/google/samsung/tile ≥ 1`) is attacker-present; payload prefixes
`4c001219fc/fd/fe/ff` mark the adversary MACs that had been setup using  [`Modified_Openhaystack_ESP32/`](Modified_Openhaystack_ESP32/README.md)

### Security/Privacy Issues and Ethical Concerns

This repository includes **evasive tracker firmware** and **passive BLE capture**
tooling.

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

2. **Passive BLE capture is a privacy-sensitive activity.** The Ubertooth, SDR,
   and EFR32 receivers passively record *all* BLE advertisements in range, which
   will include advertisements from bystanders' phones, tags, and wearables.
   Captured data therefore contains third-party MAC addresses and RF
   fingerprints. Operate the receivers only where you have authorization, and
   treat captures as personal data.

3. **The released dataset is pseudonymized.** Every BLE advertising address in
   `dataset/` is replaced at decode time by
   `HMAC-SHA256(k, addr)` truncated to six bytes and re-formatted as a MAC
   (`hide_mac_with_hmac()` in `BlePhasyr_Decoder/ble_sniffer.py`). The key `k` is
   32 random bytes generated per capture session and never written to disk, so
   the mapping is **irreversible** and addresses cannot be linked back to real
   devices or across sessions. Within a session the mapping is stable, which is
   what lets the detector track a transmitter across its rotations. The CFO
   columns are physical-layer measurements and are published unmodified — they
   are the object of study.

4. **No IRB / human-subjects data.** The artifact contains no survey responses,
   interview transcripts, or other human-subjects material, so no ethical review
   process applies.

The host-side analysis code (`Aircatch.py`, `block_benchmark.py`,
`ble_sniffer.py`) does **not** disable any host security mechanism (no ASLR or
firewall changes, no privileged operations); it only reads local CSV/IQ files
and writes CSV/PDF/PNG outputs. It runs no exploit or malware sample.

## Basic Requirements

### Hardware Requirements

**Host analysis** Can run on a laptop; no
special hardware is required to run `Aircatch.py` / `block_benchmark.py` over
CSV inputs. More cores help, as both tools parallelize across input CSVs and
grid points (up to `min(32, cpu_count())` / `--workers` processes), but neither
requires more than 8 GB RAM for the smoke test or a per-scenario run.

**Signal capture** Generating the CSVs from the radio requires
the capture chain. The following hardware was used in the paper:

- A **software-defined radio** producing complex-float IQ (used with
  `BLESDR/iq2pcap` and `BlePhasyr_Decoder/ble_sniffer.py`), *or*
- A **Seeed XIAO EFR32MG24** board — part `EFR32MG24A020F1536GM48` — running the
  RAIL firmware in `EFR32MG24/`, bridged to the host by an **ESP32** (USB-CDC)
  running `ESP_I2C_Slave/`.
- **Adversary node:** an **ESP32** running `Modified_Openhaystack_ESP32/` to emit
  the rotating-identity tracker signal for the positive scenarios.
- Optionally, an **Android phone** (Android 12+ for the
  USB-host sniffer flow) for the companion app.

This hardware is commodity and purchasable, but not present on a typical
reviewer machine; the Functional path above is designed to need none of it.

**Machine used for the paper's experiments.** All captures were decoded and all
reported results were produced on a single workstation:

| | |
|---|---|
| CPU | Intel Core i9-10900X @ 3.70 GHz — 10 cores / 20 threads, boost 4.7 GHz |
| RAM | 256 GB |
| OS | Ubuntu 24.04.3 LTS |
| Python | 3.12.3 |
| SDR | Ettus Research **USRP B210** |


### Software Requirements

- **OS:** developed and run on **Ubuntu 24.04.3 LTS**. The host code is
  OS-agnostic Python and should run on any Linux or macOS with the packages
  below; no OS-specific mechanism is used.
- **OS packages:** none beyond a working Python 3 and, if you build the SDR
  decoder, `build-essential`, `cmake`, and `libssl-dev`.
- **Artifact packaging:** a [`Dockerfile`](Dockerfile) at the repository root
  builds a pinned environment (`python:3.12-slim-bookworm` + the exact package
  versions below). Verified with **Docker 29.0.2**; any Docker 24+ should work.
  It has two targets: the default **`analysis`** image (978 MB) for the
  host-side pipeline, and an opt-in **`hardware`** image (1.57 GB) that adds the
  firmware flashing and capture toolchain — see
  [Flashing firmware from the container](#flashing-firmware-from-the-container).
- **Interpreter:** **Python 3.12.3** (the version used for the paper's results).
- **Python packages:** `numpy`, `pandas`, `scikit-learn`, `matplotlib`, `scipy`
  for the host analysis; `pyserial` for the `ESP_I2C_Slave/usb_capture.py`
  capture script; `cryptography` for the attacker key generator. All are pinned
  in [`requirements.txt`](requirements.txt) at the repository root to the
  versions the paper's results were produced with: `numpy==2.2.6`,
  `pandas==2.3.3`, `scikit-learn==1.8.0`, `matplotlib==3.10.8`, `scipy==1.16.3`,
  `pyserial==3.5`, `cryptography==46.0.3`.

- **Machine learning models:** none. AirCatch uses classical, unsupervised
  methods (StandardScaler, PCA, agglomerative clustering, silhouette selection)
  fit at run time; there is no pretrained model to download.
- **Datasets:** every capture behind the paper's results ships with the artifact
  under `dataset/` (72 MB). No external download is required.

  | File(s) | Used for |
  |---|---|
  | `Home_to_work.csv`, `Work_to_home.csv`, `car_trip_final.csv`, `airport_total_trip.csv` | the four mobility traces — Table 1, Table 2, Figures 6/7, and the adversary CFOs in Figure 3b |
  | `sdr_b210_static_devices.csv` | USRP B210 static-device capture — Figures 2a/2b/5 and the §7.2 ablation |
  | `blephasyr_static_devices.csv` | EFR32MG24 (BlePhasyr) static-device capture — Figure 3a and the §7.2 ablation |

  The mobility traces were recorded with the Ubertooth/RAIL capture chain; see
  [Generating the evaluation scenarios](#generating-the-evaluation-scenarios)
  for how the per-scenario inputs are derived from them.

- **Capture-chain toolchains** (only needed to build firmware or regenerate CSVs
  from radio, i.e. for the Reproduced badge):
  - `BLESDR/iq2pcap`: CMake ≥ 3.10, a C++17 compiler, and **OpenSSL** (libcrypto).
  - EFR32MG24 firmware: **Simplicity Studio v6** with the EFR32xG24 SDK
    (RAIL "SoC Empty" project), and **OpenOCD 0.12** for flashing.
  - ESP32 firmware (bridge and attacker): **ESP-IDF** (with TinyUSB enabled for
    the bridge), or `esptool`.
  - Ubertooth: the standard Ubertooth host tools + `libusb`, rebuilt with the
    patches in `Modified_Ubertooth/`.
  - Android app: **Android Gradle Plugin 8.13.2**, **Kotlin 2.0.21**, JDK 17,
    `compileSdk 34` (Android SDK 34).

### Estimated Time and Storage Consumption

| Step | Human time | Compute time | Disk |
|---|---|---|---|
| Clone (includes the 21 MB base captures) | ~1 min | download-bound | ~50 MB |
| Environment setup | ~10 min | ~5 min | < 100 MB |
| Functional test (one scenario CSV) | < 1 min | < 1 min | negligible |
| Experiment 1 (one scenario folder) | a few min | minutes to tens of minutes | < 100 MB of outputs |
| Experiment 2 (block-size sweep) | a few min | scales with (#blocks × #CSVs) / `--workers` | two CSVs |
| Experiment 3 (multi-scenario aggregate) | a few min | scales with total capture length and cores | < 100 MB of outputs |

The artifact is **~50 MB on disk**: 21 MB of base captures plus the code.
Generating the full scenario tree from them (see
[Generating the evaluation scenarios](#generating-the-evaluation-scenarios))
expands this to roughly 700 MB. Every experiment runs off those CSVs, so no experiment adds more than a
few hundred MB of outputs (CSV/TXT/PDF). Compute times for Experiments 1–3 are
dominated by capture length and core count; the figures above assume the
20-thread machine listed under [Hardware Requirements](#hardware-requirements).

## Environment

### Accessibility

The artifact is hosted on GitHub:

- Repository: <https://github.com/miishra/AirCatch>
- Latest revision on the default branch:
  <https://github.com/miishra/AirCatch/tree/main>


### Set Up the Environment

Two supported paths. **Docker is recommended for review**, since it pins the
interpreter and every package version.

**Option A — Docker (pinned environment):**

```bash
git clone https://github.com/miishra/AirCatch.git
cd AirCatch
docker build -t aircatch:main .
```

The build takes a couple of minutes and ends with
`naming to docker.io/library/aircatch:main`. Running the image with no arguments
executes [`test.sh`](test.sh) (the functional check). To reproduce every paper
figure and table instead, and copy them back to the host:

```bash
docker run --rm -v "$PWD/Paper_Results:/out" aircatch:main \
    sh -c 'python3 reproduce_paper.py --quick && cp -r Paper_Results/* /out/'
```

To get an interactive shell in the container instead:

```bash
docker run --rm -it --entrypoint bash aircatch:main
```

**Option B — local virtualenv:**

```bash
git clone https://github.com/miishra/AirCatch.git
cd AirCatch
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Either way, confirm the detector loads:

```bash
python3 Aircatch.py --help
```

This prints the argument list (`--input`, `--density-min`, `--sweep-density`,
`--sweep-block-density`, `--run-multiscenario`, …) and exits.

Building the capture chain is only needed to regenerate CSVs from a radio, not
for the functional test. For the SDR decoder:

```bash
cd BLESDR
cmake -S . -B build
cmake --build build          # produces the iq2pcap binary
```

Firmware (EFR32MG24, ESP32, Ubertooth) and the Android app follow the standard
flows for their toolchains; see each subdirectory's `README.md`.

### Generating the evaluation scenarios

The experiments below run on per-scenario inputs derived from the base captures
in `dataset/` by [`scenario_gen.py`](scenario_gen.py). For each
capture it strips all rows carrying the adversary payload tags, then re-injects
the selected tags with a controlled transmit interval and MAC-rotation period —
so each generated CSV is a real background capture with a synthetic adversary
placed in it. One invocation writes a run folder holding five CSVs, one per
`(tx, rot)` setting in `{2s, 10s, 15s, 30s, 1min}`:

```bash
# one adversary tag, into controlled/HtoW/
python3 scenario_gen.py --input dataset/Home_to_work.csv \
    --outdir controlled/HtoW --seed 1337 --select-adv-tags 4c001219ff
```

Vary `--select-adv-tags` to set the adversary count: one tag for `adv1`, and
comma-separated tags drawn from `4c001219fc,4c001219fd,4c001219fe,4c001219ff`
for `adv2`–`adv4`. Repeat per source capture, writing into `controlled/HtoW`,
`controlled/WtoH`, `controlled/Car_Trip`, and `controlled/Airport`. Run folders are auto-named
`scenarios_<source-stem>__adv<N>_apple<N>_google<N>_samsung<N>_tile<N>[__advtag-…]__<timestamp>/`,
which is the layout `Aircatch.py`'s ground-truth parser expects — so no renaming
is needed. Omitting every `--select-*` flag drops into an interactive prompt and,
if nothing is selected, emits a single background-only CSV (the `adv0` baseline).

> The RNG is seeded (`--seed 1337`), so a given invocation is repeatable. It does
> **not** reproduce the paper's CSVs byte-for-byte: the exact per-run selections
> — in particular which legitimate Apple/Google/Samsung/Tile device was
> re-introduced in the `adv0` runs — were not recorded. Expect the same
> qualitative behaviour and small numeric differences.

### Flashing firmware from the container

Reviewers running only the host-side evaluation can skip this section — the
default image covers everything the Functional badge needs.

If you do have the hardware, the `hardware` target adds the full flashing and
capture toolchain, so no host toolchain install is required:

```bash
docker build --target hardware -t aircatch:hw .
```

| Tool | Version | Used for |
|---|---|---|
| `openocd` (bundled) | 0.12.0+dev-01514 | Flash the EFR32MG24 over SWD (`EFR32MG24/Flashing/flash.sh`) |
| `esptool` | 5.1.0 | Flash the ESP32 bridge and the OpenHaystack adversary |
| `dfu-util` | 0.11 | DFU-mode recovery |
| `ubertooth` | 2018.12.R1 | Ubertooth One host tools (`ubertooth-btle`) |
| `arm-none-eabi-gcc` | 12.2.1 | Rebuild the patched Ubertooth firmware |
| `libbtbb`, `libusb-1.0`, `usbutils` | — | USB/Bluetooth baseband support |

The container needs access to the USB device. Pass the specific node:

```bash
# ESP32 on /dev/ttyUSB0 (adjust to your port; check with ls /dev/tty{USB,ACM}*)
docker run --rm -it --device=/dev/ttyUSB0 aircatch:hw bash
```

or, for tools that enumerate the bus themselves (OpenOCD via CMSIS-DAP,
`ubertooth-btle`, `esptool` in ROM-bootloader mode), expose the USB bus:

```bash
docker run --rm -it --privileged -v /dev/bus/usb:/dev/bus/usb aircatch:hw bash
```

Then, inside the container:

```bash
# ESP32 adversary firmware (prebuilt bins ship under firmware/esp32-openhaystack)
./Modified_Openhaystack_ESP32/flash_esp32.sh -p /dev/ttyUSB0 \
    -b firmware/esp32-openhaystack -k keys.txt
# ...or generate keys and flash in one step, from the repo root:
./keys_and_flash.sh -p /dev/ttyUSB0 -b firmware/esp32-openhaystack

# EFR32MG24 sniffer firmware (prebuilt .hex ships under firmware/efr32mg24)
./EFR32MG24/Flashing/flash.sh firmware/efr32mg24/ble_packet_monitor.hex

# ESP32 SPI->USB bridge firmware (prebuilt bins ship under firmware/esp32-slave)
./ESP_I2C_Slave/flash_esp32.sh -p /dev/ttyACM0 -b firmware/esp32-slave
```

**OpenOCD is bundled, not installed from a package.** The EFR32MG24 is an
EFM32 **Series 2** part and needs OpenOCD's `efm32s2` flash driver, which is
absent from the OpenOCD 0.12.0 *release* — so Debian's `openocd`, Homebrew's,
and similar cannot program this board; they ship only the older `efm32x`
driver. [`tools/openocd-silabs/`](tools/openocd-silabs/README.md) therefore
carries the Silicon Labs build (0.12.0+dev-01514, GPL-2.0, provenance and
source pointers in that README), which has both the driver and the vendor
`efm32s2_g23.cfg` target config.

`flash.sh` uses the bundled build by default, falling back to a Silicon Labs
install on the host. It verifies the driver is present and **refuses to start**
otherwise, since an unequipped OpenOCD erases the device and then fails to
program it. `OPENOCD`, `OPENOCD_SCRIPTS`, `TARGET_CFG`, and `FIRMWARE` all
override the defaults — needed on macOS, Windows, or ARM hosts, as the bundled
binary is static x86-64 Linux.

> **Two things the container deliberately does not include.** Building the
> EFR32MG24 firmware needs **Simplicity Studio v6**, a proprietary GUI IDE that
> cannot be containerized; and building the ESP32 firmware from source needs the
> multi-GB **ESP-IDF**. Both produce a binary you then flash with the tools
> above, so the container covers flashing but not those two builds. Prebuilt
> binaries ship under [`firmware/`](firmware/) for all three — the EFR32MG24
> sniffer (`efr32mg24/`), the OpenHaystack adversary (`esp32-openhaystack/`), and
> the SPI→USB bridge (`esp32-slave/`) — so they flash out of the box; rebuilding
> any of them from source needs the respective toolchain above. See
> [`EFR32MG24/README.md`](EFR32MG24/README.md),
> [`Modified_Openhaystack_ESP32/README.md`](Modified_Openhaystack_ESP32/README.md),
> and [`ESP_I2C_Slave/README.md`](ESP_I2C_Slave/README.md).


### Testing the Environment

[`test.sh`](test.sh) runs the whole host-side path end to end and is the single
command a reviewer needs. It takes about two minutes:

```bash
docker run --rm aircatch:main     # Option A, runs test.sh by default
./test.sh                         # Option B, from the repo root
```

It checks five stages — dependency versions, both CLIs load, the detector runs
on a shipped base capture, `scenario_gen.py` builds a scenario from
`dataset/car_trip_final.csv`, and the detector then runs on that generated
adversary scenario. All output goes to a scratch directory, so the repository is
left untouched. Expected final block:

```
==============================================
 passed: 10    failed: 0
 RESULT: OK - environment is set up correctly
==============================================
```

Stage 5 prints the evaluation report from the generated adversary scenario. On a
correct setup it reports a detection, which confirms the pipeline is not merely
running but working:

```
TP=4 FP=0 FN=1 TN=0
Precision=1.0000 Recall=0.8000 F1=0.8889
```

The exit status is 0 only if all ten checks pass. To run just the detector on a
single capture instead:

```bash
python3 Aircatch.py --input dataset/airport_total_trip.csv
```

Expected output: the run prints per-file progress, then an `=== Outputs ===`
block, and exits with status 0. It writes 11 files prefixed
`aircatch_single_airport_total_trip.csv_` into the working directory:

- `..._meta__dens1.15.csv` — per-cluster metadata,
- `..._candidate_checks__dens1.15.csv` — per-candidate gate diagnostics,
- `..._eval_report__dens1.15.txt` — TP/FP/FN/TN, precision, recall, F1, FP/hour,
  FN/hour, TTD median/p90/p95, silhouette, purity,
- `..._advmax_per_scenario__densgrid.csv` — density-grid sweep summary,
- `..._eval__dens1.15__prf_bar.pdf`, `..._eval__dens1.15__fp_fn_per_hour.pdf`,
  `..._eval__dens1.15__ttd_cdf.pdf`, `..._adv_mac_pct_cdf__dens1.15.pdf`,
  the two `..._core_density_cdf_*.pdf`, and
  `..._advmax_core_density_vs_tx_rot__dens1.15.png` — evaluation plots.

If those files are produced and the process exits 0, the environment is set up
correctly.

> Note: the `=== Outputs ===` block announces two further plots
> (`..._core_density_dist__dens1.15.png` and
> `..._eval__dens1.15__silhouette_hist.pdf`) that are not written for this
> input, because the relevant series is empty on a single capture. The
> announcements are unconditional in the code. This is expected and not an
> error.


## Artifact Evaluation

### Main Results and Claims

The paper's headline results, and the concrete values to expect from the
artifact, are:

- **Zero false positives** on every benign trace (the three commutes plus the
  airport stress test) with correct detection of every adversary-present
  configuration across transmission periods `T_tx ∈ {2, 10, 15, 30, 60}s`
  (`T_rot = T_tx`) — Table 2.
- **Fingerprint separability:** within-ecosystem device identification reaches
  **85% accuracy / 83% F1** on *both* the USRP B210 and the BlePhasyr pipelines
  (§7.2). The per-transition CFO features are what buy this: dropping them and
  keeping only the single carrier CFO costs a little on the SDR capture but
  collapses the commodity-receiver capture entirely — see
  `Paper_Results/Section_7.2_Fingerprint_Transition_Ablation.txt`
  (`python3 reproduce_paper.py --stages fingerprint`).
- **Operating point:** `δ = 1.15` (core-density threshold), `T_min = 40 min`
  (persistence), `B = 2400 s` (block), `λ = 1.5`, `r_min = 0.15`.
- **Core-density separation:** median core density rises from **≤ 0.92** (benign)
  to **1.81–2.49** (tracking), with the 95th percentile at **6.27–6.67** vs.
  **0.58–0.76** (Figure 6). At `δ = 1.15`, **70–86 %** of adversary-present
  cluster cores exceed the threshold, versus only **1.2–1.6 %** on two benign
  routes (and 59 % ≤ δ on the densest route, Home→Work).

The eval report additionally emits precision, recall, F1, FP/hour, FN/hour, TTD
median/p90/p95, silhouette, and purity (`aircatch_*_eval_report__*.txt`); these
are computed by the artifact and are not separately tabulated in the paper.

#### Main Result 1: AirCatch detects rotating-identity trackers with high precision and recall

Across the controlled scenarios, AirCatch flags scenarios containing an
adversarial (MAC/key-rotating) tracker as positive and benign scenarios as
negative. The independent variable is the adversary setting (adv0…adv4, the
number of concurrent attacker tags); the dependent variables are precision,
recall, F1, and the per-hour false-positive and false-negative rates. As the
number of concurrent attacker tags increases, detection remains stable rather
than degrading. This claim is supported by
[Experiment 1](#experiment-1-per-scenario-detection-metrics) and
[Experiment 3](#experiment-3-multi-scenario-aggregate), and corresponds to
**Table 2** (per-scenario detection outcomes) in the paper — no false alarms on
benign traces and a correct flag whenever an adversary is present.

#### Main Result 2: The CFO core-density signal separates adversarial from benign clusters

Adversarial clusters exhibit a denser CFO "core" than benign traffic, which is
what makes the strict decision rule work. The independent variable is whether
the scenario contains an adversary; the dependent variable is the per-cluster
core density (`core_mac_density_scaled`), reported as CDFs (flagged vs. not, and
adv-present vs. not). This claim is supported by
[Experiment 1](#experiment-1-per-scenario-detection-metrics) and corresponds to
**Figure 6** (core-density CDFs, adversary-present vs. absent per route) and
**Figure 7** (core density over time) in the paper.

#### Main Result 3: Detection is timely, and calibration is robust to block size

AirCatch confirms an attacker within a bounded time-to-detect (TTD), and
detection quality is stable across a range of periodic block sizes. The
independent variable is the block size (`PERIODIC_BLOCK_S`); the dependent
variables are the confusion matrix (TP/FP/FN/TN) and the rates derived from it.
Varying block size over the sweep grid changes the confusion matrix only
marginally, identifying the operating point used in the paper. This claim is
supported by [Experiment 2](#experiment-2-block-size-calibration) and by the TTD
CDF from [Experiment 1](#experiment-1-per-scenario-detection-metrics). In the
paper this appears as the operating-point selection (block `B = 2400 s`, §5.4;
`T_min = 40 min`, §7.4) together with the persistence-duration evidence in
**Figure 7** / §7.5 — median adversarial cluster persistence **1570–2120 s**
versus **760–1180 s** for benign clusters. The block-size confusion-matrix sweep
is an artifact-side calibration and is not separately tabulated in the paper.

### Experiments

> **Prerequisite:** the experiments below read the per-scenario inputs, which
> you generate once from `dataset/` — see
> [Generating the evaluation scenarios](#generating-the-evaluation-scenarios).
> That writes `controlled/<SCENARIO>/<run-folder>/*.csv` with
> `<SCENARIO> ∈ {HtoW, WtoH, Car_Trip, Airport}`, matching
> `Aircatch.py`'s `CONTROLLED_ROOT` / `CONTROLLED_SUBFOLDERS`. Run folders
> follow the naming convention the code parses, e.g.
> `scenarios_car_trip_final__adv1_apple0_google0_samsung0_tile0__advtag-4c001219ff__<date>/`,
> with per-run files such as `scenario_tx-10s_rot-5min.csv`. Ground truth is read
> from these names as described under [Description](#description).

#### One-command reproduction (`reproduce_paper.py`)

[`reproduce_paper.py`](reproduce_paper.py) runs the whole data-driven pipeline end
to end — scenario generation, detection, the fingerprint ablation and the
block-size sweep — and curates the outputs into `Paper_Results/`, named exactly
as the paper labels them:

```bash
python3 reproduce_paper.py            # everything (tens of minutes of compute)
python3 reproduce_paper.py --quick    # smaller block grid, faster
python3 reproduce_paper.py --stages table1,scenarios,detection
python3 reproduce_paper.py --stages fingerprint      # just the §7.2 ablation
```

Or in the container, copying the results back out to the host:

```bash
docker build -t aircatch:main .
docker run --rm -v "$PWD/Paper_Results:/out" aircatch:main \
    sh -c 'python3 reproduce_paper.py --quick && cp -r Paper_Results/* /out/'
```

The artifact is self-contained: every input `reproduce_paper.py` reads lives
under `dataset/`, so the container needs no bind-mounted data and no network.

Stages: `table1`, `scenarios`, `detection`, `figure7`, `figures`, `figure4`,
`fingerprint`, `blocks`. Everything at the top of `Paper_Results/` is **generated
from `dataset/`** — nothing is copied from the paper:

```
Paper_Results/
  Table_1.csv / Table_1.txt          dataset summary
  Table_2.csv / Table_2.txt          detection outcomes
  Figure_2a_SDR_B210_PerDevice_CFO.pdf     per-device CFO (USRP B210)
  Figure_2b_SDR_B210_CFO_Over_Time.pdf     CFO over four 15-min windows
  Figure_3a_BlePhasyr_PerDevice_CFO.pdf    per-device CFO (EFR32MG24)
  Figure_3b_BlePhasyr_Adversary_CFO.pdf    the four ESP32 adversaries
  Figure_5_PerDevice_Transition_CFO.pdf    transition CFOs (00/01/10/11)
  Figure_6.pdf                       core-density CDF (adversary present vs absent)
  Figure_7a..f_*.pdf                 core density over time (6 panels)
  Section_7.2_Fingerprint_Transition_Ablation.csv / .txt
                                     transition-CFO features: carrier CFO only vs. all
  Section_7.2_Fingerprint_Runs/      per-run reports + confusion matrices
  REPRODUCED.md                      manifest + provenance notes
  EXTRA/                             every other plot the pipeline emits
```

Only the paper's figures/tables sit at the top level; all auxiliary plots (PR
bars, TTD CDFs, silhouette histograms, grouped detection bars, per-scenario CDFs,
the block-size sweep, …) go to
`Paper_Results/EXTRA/`.

Which script produces what:

| Figures | Produced by | From |
|---|---|---|
| 2a, 2b, 3a, 3b, 5 | [`plot_cfo_figures.py`](plot_cfo_figures.py) | the static-device captures + `car_trip_final.csv` |
| 6, 7a–f, Tables 1–2 | `Aircatch.py` / `scenario_gen.py` | the mobility traces |
| §7.2 ablation | [`fingerprint_classifier.py`](fingerprint_classifier.py) | both static-device captures |

Two notes on how those are built:

- **Figures 2, 3 and 5** are drawn by `plot_cfo_figures.py`. The per-device violin
  helper `save_violin_cfo_for_all_devices()` is *called but never defined* in the
  shipped `scenario_gen.py` (the call is swallowed by a `try/except`), so that
  plotting is reimplemented. Devices are numbered in ascending MAC order. Figure 2b
  delegates to `scenario_gen.save_cfo_drift_plot_for_all_devices()`, which does
  exist.
- **Figure 7** plots scenarios straight out of `controlled/` — the adv0 background
  and the adv1 tx-1min stealth run for each route, both produced from `dataset/` by
  the `scenarios` stage — with the δ = 1.15 threshold line. Note that
  `scenario_gen.py` re-injects adversary pseudonyms drawn from the background MAC
  pool, so a rebuild with a different `--seed` yields a different realisation.

Outside the artifact: **Figures 9, 10** (Ubertooth FREQEST captures are not
shipped) and **Figures 1, 8** (hardware photo and protocol diagrams — not
data-generated). The stages below document the same commands individually.

#### Experiment 1: Per-scenario detection metrics

- Time: a few human-minutes to launch + minutes to tens of minutes of compute
  per scenario folder (scales with capture length and core count).
- Storage: outputs are small (CSV/TXT/PDF).

Run the detector over one scenario folder (or any folder or file of CSVs):

```bash
python3 Aircatch.py --input controlled/HtoW
```

This writes `aircatch_*_eval_report__dens1.15.txt` — containing TP/FP/FN/TN,
precision, recall, F1, FP/hour, FN/hour, TTD median/p90/p95, silhouette, and
purity — together with the PR-bar, FP/FN-per-hour, TTD-CDF, and
silhouette-histogram PDFs, and the core-density CDF PDFs. Compare the reported
detection outcomes against the paper's **Table 2**, and the core-density CDFs
against **Figure 6** (with the per-cluster core-density-over-time view in
**Figure 7**).

You can override the strict density threshold, or sweep it:

```bash
python3 Aircatch.py --input controlled/HtoW --density-min 1.2
python3 Aircatch.py --sweep-density        # sweeps DENSITY_MIN, reports confusion matrix
```

Supports [Main Result 1](#main-result-1-aircatch-detects-rotating-identity-trackers-with-high-precision-and-recall)
and [Main Result 2](#main-result-2-the-cfo-core-density-signal-separates-adversarial-from-benign-clusters).

#### Experiment 2: Block-size calibration

- Time: a few human-minutes to launch + compute scaling with
  (#blocks × #CSVs) / `--workers`.
- Storage: two CSVs.

Sweep the periodic block size while holding the shipped calibration ratio fixed
(`DUR_RATIO = 1700/2400`), producing a full confusion matrix per block size:

```bash
python3 block_benchmark.py --outdir block_benchmark_out
# or, from within Aircatch.py's own sweep:
python3 Aircatch.py --sweep-block-density
```

This writes `block_benchmark_out/block_benchmark_per_file.csv` (per-gate
diagnostics per CSV) and `block_benchmark_out/block_benchmark_summary.csv`
(TP/FP/FN/TN and derived rates per block size). The summary should show
detection quality holding roughly constant across block sizes, identifying the
operating point used in the paper.

Supports [Main Result 3](#main-result-3-detection-is-timely-and-calibration-is-robust-to-block-size).

#### Experiment 3: Multi-scenario aggregate

- Time: a few human-minutes to launch + compute scaling with total capture
  length and core count.
- Storage: plots + CSVs under `multiscenario_results/`.

Run the full evaluation across all scenario subfolders and aggregate:

```bash
python3 Aircatch.py --run-multiscenario
```

This iterates over `CONTROLLED_SUBFOLDERS = [HtoW, WtoH, Airport, Car_Trip]`,
aggregates metrics by adversary setting, and writes
`aircatch_multiscenario_agg_by_adv_setting.csv` plus one grouped bar plot per
adversary setting (`aircatch_grouped__adv<N>.pdf`) into
`multiscenario_results/`. These aggregate plots are the cross-scenario view of
the paper's detection-performance results.

Supports [Main Result 1](#main-result-1-aircatch-detects-rotating-identity-trackers-with-high-precision-and-recall).

**Expected values and tolerance.** The paper's headline is **zero false
positives** with a correct flag for every adversary-present configuration
(Table 2). Because the analysis is deterministic given the shipped CSVs, the
per-scenario ✓/✗ detection outcomes should reproduce **exactly** at `δ = 1.15`.
Core-density magnitudes (Figures 6–7) may drift slightly across BLAS /
scikit-learn builds but preserve the separation (benign median ≤ 0.92 vs.
tracking 1.81–2.49); treat any run that keeps benign cores below `δ` and
adversary cores above it as a pass.

## Limitations

- **Capture regeneration is not byte-reproducible.** The shipped CSVs are the
  exact inputs behind the paper's numbers, so the analysis reproduces
  deterministically from them. Re-recording equivalent captures with the
  capture chain will not reproduce them byte-for-byte: CFO is receiver- and
  environment-specific, and the scenarios were recorded in live public settings
  (commutes, an airport, car trips) that cannot be replayed.
- **Capture reproduction requires specialized, non-commodity hardware** (an
  Ubertooth One, an SDR, or an EFR32MG24 + ESP32 bridge, plus an ESP32 attacker
  node). Exact CFO values and time-to-detect depend on the specific receiver and
  its sampling rate, so absolute numbers may differ across hardware even when the
  qualitative trends reproduce.
- **The attacker firmware is dual-use.** `Modified_Openhaystack_ESP32/` is a
  working evasive tracker, included only to generate the adversarial signal, and
  must be operated ethically (see
  [Security/Privacy Issues and Ethical Concerns](#securityprivacy-issues-and-ethical-concerns)).
- **The Android companion app** requires an Android device and, for the USB
  sniffer flow, USB-host support plus a compatible serial receiver. It is a
  companion to the offline analysis and is not required to reproduce the paper's
  core detection results.

## Notes on Reusability

AirCatch is designed to be reused beyond this paper:

- **Bring your own capture front-end.** The detector only needs a CSV with the
  `timestamp`, `AdvA`, `payload`, `crc_ok`, and five `CFO_*_Hz` columns described
  under [Description](#description). Any receiver that can emit per-advertisement
  CFO estimates can feed the pipeline, independent of the Ubertooth, SDR, and
  EFR32 front-ends shipped here.
- **Tunable detection.** The decision logic is driven by module constants at the
  top of `Aircatch.py`, so recalibrating for a new deployment, receiver, or set
  of tracker ecosystems needs no code changes:

  | Constant | Meaning | Default |
  |---|---|---|
  | `WINDOW_S` | Time-bucket size (seconds) | 120 |
  | `K_RANGE` | Range of cluster counts tested | 3–19 |
  | `MIN_DURATION_S` / `DUR_MIN` | Strict-decision minimum support (seconds) | 1700 |
  | `DENSITY_MIN` | Core-density threshold for the strict decision | 1.15 |
  | `PERIODIC_BLOCK_S` / `PERIODIC_STEP_S` | Periodic block / step (seconds) | 2400 |
  | `KEY_SIM_THR` | Ecosystem key-similarity merge threshold | 0.99 |
  | `TYPE_SEP_WEIGHT` | Weight for ecosystem type separation | 1.0 |
  | `CORE_RADIUS_MODE` | Core radius estimator (`pctl` / `mad` / `std`) | `std` |

  Several are also overridable or sweepable from the CLI (`--density-min`,
  `--sweep-density`, `--sweep-block-density`, `--sweep-density-grid`,
  `--sweep-block-grid`).
- **Ecosystem extensibility.** Ecosystem classification and key/PRIVID
  extraction are isolated in dedicated functions
  (`classify_tag_ecosystem_from_payload`, `extract_pubkey_from_payload`,
  `get_samsung_privid_from_payload`), so support for additional tracker
  ecosystems can be added without touching the clustering or decision logic.
- **A low-cost SDR substitute for BLE IQ capture.** The
  [`EFR32MG24/`](EFR32MG24/README.md) firmware plus the
  [`ESP_I2C_Slave/`](ESP_I2C_Slave/README.md) bridge turn a Seeed XIAO
  EFR32MG24 and an ESP32 — two commodity dev boards costing orders of magnitude
  less than a USRP — into a receiver that streams **raw int16 IQ samples** off
  the air. The EFR32's RAIL stack captures BLE advertisements, frames the IQ in
  2048-byte chunks (`CHUNK_BYTES`, `TARGET_MBPS = 5` sustained), and ships them
  over SPI to the ESP32, which forwards them to the host over USB-CDC at roughly
  1.344 MS/s (`FS_IN_DEFAULT` in `ble_sniffer.py`).

  Nothing about that chain is CFO-specific. Anyone needing physical-layer BLE
  samples — modulation and RF-fingerprinting work, PHY debugging, teaching, or
  any receiver-side measurement that a packet-level sniffer such as an Ubertooth
  cannot expose — can reuse it as a standalone IQ front-end and ignore the rest
  of AirCatch. The practical limits are that it targets **LE 1M legacy
  advertising** and that sustained throughput is bounded by the SPI clock, so it
  complements rather than replaces a wideband SDR.

Beyond the paper, the artifact supports research in privacy-preserving tracker
detection, forensic analysis of location-tracking attacks, cross-ecosystem BLE
security, and radio fingerprinting / device identification.
