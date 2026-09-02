# BLESDR — IQ-to-PCAP BLE decoder (`iq2pcap`)

A standalone C++ tool that reads a raw complex-float I/Q recording, decodes BLE
legacy advertising packets from it, and writes:

- a **PCAP** file (link type `BLE_LL_WITH_PHDR`, 256) that opens in Wireshark,
- a **features CSV** with per-packet RF fingerprints (including the CFO features
  consumed by `Aircatch.py`), and
- optionally, **aligned raw-IQ chunks** (one binary file per packet) for
  downstream signal analysis.

It is built on a modified copy of the [BLESDR](https://github.com/JiaoXianjun/BTLE)
encoder/decoder (`modified_lib/`) and is used in AirCatch as the SDR front-end:
`SDR capture (.cf32) → iq2pcap → features.csv → Aircatch.py`.

## Requirements

- CMake ≥ 3.10 and a C++17 compiler (GCC/Clang).
- **OpenSSL** (libcrypto) — linked for the HMAC used in tag-key handling.
- A math library (`libm`, linked automatically when present).

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential cmake libssl-dev
```

## Build

```bash
cd BLESDR
cmake -S . -B build
cmake --build build          # produces ./build/iq2pcap
```

## Input format

A raw **interleaved complex float32** file (`I, Q, I, Q, …`, i.e. GNU Radio /
`.cf32` / `.cfile` format). The tool assumes the samples are already at (or near)
the BLE band; specify the true sample rate with `--fs`.

## Usage

```bash
./build/iq2pcap --file capture.cf32 \
                --out out.pcap \
                --features-out features.csv \
                --channel 37 \
                --fs 4e6
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--file <path>` | *(required)* | Input complex-float32 IQ file. |
| `--out <path>` | `out.pcap` | Output PCAP path. |
| `--features-out <path>` | `features.csv` | Output per-packet features CSV. |
| `--channel <37\|38\|39>` | `37` | BLE advertising channel of the capture. |
| `--fs <Hz>` | `4e6` | Input IQ sample rate in Hz. |
| `--decim <N>` | `1` | Integer decimation applied before decoding. |
| `--chunk <N>` | `1000000` | Samples processed per streaming chunk. |
| `--dump-iq-dir <dir>` | *(off)* | If set, write one aligned raw-IQ chunk per decoded packet into this directory. |
| `--prepad-us <us>` | `200` | Microseconds of pre-roll kept in dumped IQ chunks. |
| `--gate <none\|energy\|struct\|mid>` | `none` | Windowing/gating mode used when extracting the feature window. |
| `--gate-k <float>` | `4.0` | Threshold multiplier for `energy`/`struct` gating. |
| `--gate-pad-us <us>` | `8` | Padding around the gated window. |
| `--gate-mid-a-us <us>` | `12` | Start of the `mid` gate window (µs from packet start). |
| `--gate-mid-b-us <us>` | `80` | End of the `mid` gate window (µs from packet start). |

## Output: features CSV

One row per successfully decoded packet. Columns include AdvA, PDU/type, CRC
status, RF fingerprints (`iq_gain_alpha`, `iq_phase_deg`, `rise_time_us`,
`psd_centroid_hz`, `psd_pnr_db`, `bw_3db_hz`, `gated_len_us`) and the
transition-specific CFO estimates. Map these to the column names
`Aircatch.py` expects (`timestamp`, `AdvA`, `payload`, `crc_ok`, `CFO_Hz`,
`CFO_00_Hz`, `CFO_11_Hz`, `CFO_10_Hz`, `CFO_01_Hz`) before feeding the detector.

## Notes / limitations

- Only **legacy advertising** PDUs on channels 37/38/39 are decoded.
- `--fs` must match the capture; a wrong rate collapses CRC recovery. If you are
  unsure of the exact rate, cross-check with `BlePhasyr_Decoder/ble_sniffer.py`,
  which has an `--auto-fs-scan` mode.
- Passively captured IQ contains bystander BLE traffic; treat outputs as
  privacy-sensitive (see the root [`README.md`](../README.md)).
