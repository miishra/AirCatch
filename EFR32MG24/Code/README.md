# EFR32MG24 BLE Packet Monitor Firmware

RAIL-based BLE packet-sniffer firmware for the **Seeed XIAO EFR32MG24** board
(part `EFR32MG24A020F1536GM48`). It captures BLE advertisements, extracts raw IQ
samples for CFO analysis, and streams them out over **SPI** (as SPI master) to
the ESP32 USB bridge (`../../ESP_I2C_Slave/`), which forwards them to the host.

Pipeline role: `EFR32MG24 (this firmware) → SPI → ESP32 bridge → USB-CDC → host → ble_sniffer.py`.

## Requirements

- **Simplicity Studio v6** with the **EFR32xG24 SDK** (Gecko SDK / RAIL).
- Base project: **RAIL — SoC Empty** for part `EFR32MG24A020F1536GM48`.
- Drivers: **EUSART** and **IO Stream: Retarget STDIO**.
- **OpenOCD 0.12** for command-line flashing (a CMSIS-DAP debug probe), or flash
  from within Simplicity Studio.

## Build (Simplicity Studio)

1. Install Simplicity Studio and the SDK for EFR32xG24.
2. Create a new **RAIL (SoC Empty)** project; choose part
   **EFR32MG24A020F1536GM48**.
3. Install the **EUSART** driver and **IO Stream: Retarget STDIO**.
4. Add/replace the sources in `Code/` (`main.c`, `app_init.*`, `app_process.*`,
   `ble_packet_monitor.*`).
5. Configure EUSART1 for STDIO: **RX = PA09**, **TX = PA08**.
6. Build.

## Pin configuration (SPI to the ESP32 bridge)

From `ble_packet_monitor.c` (EUSART0 / SPI0, XIAO MG24 pin names):

| Signal | EFR32 pin | XIAO pad |
|---|---|---|
| SPI CLK  | PA03 | D8  |
| SPI MISO | PA04 | D9  |
| SPI MOSI | PA05 | D10 |
| SPI CS   | PC07 | D7  |

Wire these to the ESP32 SPI-slave pins (MOSI/MISO/SCLK/CS) documented in
`../../ESP_I2C_Slave/README.md`.

Key firmware constants: `CHUNK_BYTES = 2048`, ring buffer `RING_N = 120`
(~240 KB), RX FIFO `4096` bytes with a `2020`-byte threshold, and a target
sustained TX rate `TARGET_MBPS = 5`. Energy-gate thresholds are auto-tuned
between `ENERGY_THRESH_MIN` and `ENERGY_THRESH_MAX`.

## Flash

**From Simplicity Studio:** use the built-in flash/debug launcher.

**Command line (OpenOCD):** `../Flashing/flash.sh` flashes a prebuilt
`.hex` over SWD using CMSIS-DAP:

```bash
../Flashing/flash.sh
```

Before running it, edit the paths at the top of the script:

- `OPENOCD` / `OPENOCD_SCRIPTS` — your OpenOCD 0.12 install (the script defaults
  to the Arduino-bundled Silicon Labs OpenOCD).
- `FIRMWARE` — path to your built `.hex`.

The script prompts before flashing (**it erases the device**) and runs:
`transport select swd`, target `efm32s2_g23.cfg`, then
`program <hex> verify reset exit`.

## Key files

| File | Role |
|---|---|
| `main.c` | Entry point. |
| `app_init.c/.h` | Peripheral/RAIL/SPI setup. |
| `app_process.c/.h` | Main loop; drains RX FIFO and queues IQ frames for SPI TX. |
| `ble_packet_monitor.c/.h` | BLE packet capture, IQ framing, SPI DMA transmit. |

## Notes / limitations

- The captured IQ is int16, framed in 2048-byte chunks with a small per-chunk
  header — the format `ble_sniffer.py` reads in raw-SPI mode. Use the sample
  rate that matches this front-end when decoding (`--fs-in`).
- Capture includes bystander BLE traffic; treat output as privacy-sensitive.
