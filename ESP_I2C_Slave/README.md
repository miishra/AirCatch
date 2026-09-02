# ESP32 SPI-to-USB Bridge

Firmware that turns an ESP32 into a **high-speed bridge** between the EFR32MG24
BLE sniffer and a host computer. The EFR32 streams captured IQ frames to the
ESP32 over **SPI** (the ESP32 is the SPI *slave*), and the ESP32 forwards them to
the host over **USB CDC** (serial). `usb_capture.py` is the host-side capture script.

> Note: despite the historical folder name (`ESP_I2C_Slave`), the transport is
> **SPI**, not I2C. The naming is kept for continuity with earlier revisions.

Pipeline role: `EFR32MG24 (SPI master) → ESP32 (this firmware, SPI slave) → USB-CDC → usb_capture.py → *.bin → ble_sniffer.py`.

## Hardware / wiring

The ESP32 acts as an **SPI slave** on the following pins (see `main/main.c`):

| Signal | ESP32 pin |
|---|---|
| MOSI | GPIO 13 |
| MISO | GPIO 12 |
| SCLK | GPIO 11 |
| CS   | GPIO 10 |

Connect these to the EFR32MG24's SPI master pins (see the EFR32MG24 README).
The USB port of the ESP32 enumerates as a USB-CDC serial device on the host.

Firmware parameters: SPI chunk size `MAX_SPI_BYTES = 2048`, TX buffer
`TX_BUF_SIZE = 4096`, queue depth `QUEUE_SIZE = 50`, and an expected frame seed
of `0xDEEB` for basic frame validation.

## Requirements

- **ESP-IDF** (v5.x) with **TinyUSB** enabled. If TinyUSB is not already active,
  enable the USB-CDC device via `idf.py menuconfig`
  (Component config → TinyUSB).
- Host: **Python 3** with **pyserial** (`pip install pyserial`).

## Build & flash (ESP-IDF)

```bash
cd ESP_I2C_Slave
idf.py set-target esp32s3      # use the target that matches your board
idf.py menuconfig              # ensure TinyUSB / USB-CDC is enabled
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## Flash prebuilt binaries (`flash_esp32.sh`)

If you only want to flash (no full ESP-IDF install), `flash_esp32.sh` writes the
built artifacts with `esptool` — mirroring the OpenHaystack flasher but for this
standard app (no key partition). It reads `flasher_args.json` from the build dir
when present (so chip/offsets are always correct) and otherwise falls back to the
standard layout for `--chip` (default `esp32s3`).

```bash
# flash the prebuilt bins shipped in the artifact
./flash_esp32.sh -p /dev/ttyACM0 -b ../firmware/esp32-slave

# or flash your own ESP-IDF build
./flash_esp32.sh -p /dev/ttyACM0 -b build
```

Options: `-p/--port`, `-b/--builddir`, `-c/--chip`, `-v/--venvdir`,
`-s/--slow` (115200 baud), `-h/--help`.

## Capture on the host

Edit the serial port at the top of `usb_capture.py` (default `/dev/ttyACM1`,
115200 baud) and the output filename, then run:

```bash
python3 usb_capture.py
```

This writes:

- `<name>.bin` — the raw IQ byte stream (feed this to
  `../BlePhasyr_Decoder/ble_sniffer.py` with the matching `--fs-in`), and
- `<name>_timestamps.csv` — per-chunk timing
  (`chunk_index, byte_offset, chunk_size, elapsed_seconds, epoch_seconds,
  iso_timestamp`) used to align packet times (`--timestamps-csv`).

Press `Ctrl+C` to stop the capture.

## Notes / limitations

- The USB-CDC device may enumerate as `/dev/ttyACM0` or `/dev/ttyACM1`; adjust
  `usb_capture.py` accordingly (`ls /dev/ttyACM*`).
- Sustained throughput depends on the SPI clock configured on the EFR32 side
  (the EFR32 firmware targets ~5 Mbps).
