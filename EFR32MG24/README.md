# EFR32MG24 — RAIL BLE capture front-end

The **Seeed XIAO EFR32MG24** (part `EFR32MG24A020F1536GM48`) acts as one of the
three interchangeable capture front-ends in AirCatch. RAIL-based firmware sniffs
BLE legacy advertisements, extracts the raw IQ samples needed for CFO
estimation, and streams them over **SPI** to the ESP32 USB bridge, which forwards
them to the host.

Pipeline role:

```
EFR32MG24 (this firmware) → SPI → ESP32 bridge (../ESP_I2C_Slave/)
   → USB-CDC → host capture (usb_capture.py) → *.bin
   → ../BlePhasyr_Decoder/ble_sniffer.py → per-packet CFO CSV → ../Aircatch.py
```

This front-end is only needed to **regenerate CSVs from the radio**. Running the
detector over existing CSVs requires none of it.

## Contents

| Path | Description |
|---|---|
| [`Code/`](Code/README.md) | The firmware sources and full build/flash/pinout documentation. **Start here.** |
| `Flashing/flash.sh` | Command-line OpenOCD flashing helper (see below). |

## Quick start

1. Build the firmware — see [`Code/README.md`](Code/README.md) for the
   Simplicity Studio v6 project setup (RAIL "SoC Empty", EUSART + IO Stream
   drivers) and the EFR32↔ESP32 pin map.
2. Flash it, either from Simplicity Studio's flash/debug launcher or with
   `Flashing/flash.sh`.
3. Wire the SPI pins to the ESP32 bridge and capture on the host — see
   [`../ESP_I2C_Slave/README.md`](../ESP_I2C_Slave/README.md).

## Flashing from the command line

`Flashing/flash.sh` programs a prebuilt `.hex` over SWD using a CMSIS-DAP
probe and OpenOCD 0.12. **Edit the three variables at the top of the script
before first use** — they point at a local toolchain install and build output:

| Variable | Meaning |
|---|---|
| `OPENOCD` | Path to the OpenOCD 0.12 binary (defaults to the Arduino-bundled Silicon Labs build). |
| `OPENOCD_SCRIPTS` | Path to that OpenOCD install's `scripts/` directory. |
| `FIRMWARE` | Path to your built `.hex` file. |

```bash
Flashing/flash.sh
```

The script confirms interactively before programming, then runs
`transport select swd` against target `efm32s2_g23.cfg` and
`program <hex> verify reset exit`.

> ⚠️ Flashing **erases the target device**. Use a dedicated development board.

## Requirements

- Seeed XIAO EFR32MG24 board (`EFR32MG24A020F1536GM48`).
- **Simplicity Studio v6** with the EFR32xG24 SDK (Gecko SDK / RAIL) to build.
- **OpenOCD 0.12** and a CMSIS-DAP debug probe for command-line flashing.
- An ESP32 running [`../ESP_I2C_Slave/`](../ESP_I2C_Slave/README.md) to bridge
  the captured IQ to the host.

## Notes / limitations

- Captured IQ is int16, framed in 2048-byte chunks with a small per-chunk header
  — the format `ble_sniffer.py` reads in raw-SPI mode. Decode with the matching
  `--fs-in`.
- Only LE 1M legacy advertising is captured.
- The receiver records **all** BLE advertisements in range, including
  bystanders'. Treat captures as privacy-sensitive and operate only where you
  have authorization — see [`../ARTIFACT-APPENDIX.md`](../ARTIFACT-APPENDIX.md)
  → *Security/Privacy Issues and Ethical Concerns*.
