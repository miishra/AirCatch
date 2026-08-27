# Modified Ubertooth — CFO-instrumented BLE firmware & host tools

Patches to [Project Ubertooth](https://github.com/greatscottgadgets/ubertooth)
that expose the CC2400 radio's per-packet **frequency-offset (FREQEST)**
measurements so an Ubertooth One can be used as a low-cost CFO capture front-end
for AirCatch.

## What was changed

- **`bluetooth_rxtx/le_phy.c`** (device firmware): the LE RX buffer
  (`_le_rx_t`) is extended with a `freqest_per_byte[]` array so the firmware
  records the CC2400 FREQEST value per received byte in addition to RSSI. A
  rounding/clipping helper (`mean_i8_round_clip`) aggregates these int8 FREQEST
  readings. Transition-specific CFO aggregates are carried back to the host in
  otherwise-unused legacy fields.
- **`ubertoothtool/host/libubertooth/src/ubertooth_callback.c`** (host library):
  on each received LE advertising packet it prints the CFO breakdown, converting
  the int8 FREQEST LSB units to Hz using the CC2400 scale (`k = 5200.0` Hz/LSB,
  i.e. ~5.2 kHz/LSB):

  ```
  systime=<t> cfoTot=<Hz> w0=<Hz> w8=<Hz> w4=<Hz> w2=<Hz>
  ```

  The transition CFOs are carried in the legacy `rssi_avg/rssi_min/rssi_max/
  offset_min/offset_avg` fields and re-interpreted here as
  `cfoTot / w0 / w8 / w4 / w2`.

## Requirements

- Ubertooth One hardware.
- The upstream Ubertooth source tree (host tools + firmware) and its toolchain:
  - Firmware: the `gcc-arm-none-eabi` toolchain used by upstream Ubertooth.
  - Host: `libusb-1.0`, `libbtbb`, CMake, a C compiler.

## How to apply

These files are drop-in replacements for the corresponding files in an upstream
Ubertooth checkout. They are **not** a standalone buildable tree.

1. Clone upstream Ubertooth at a compatible release.
2. Overwrite the two files with the copies here:
   - `host/bluetooth_rxtx/le_phy.c`  ← `bluetooth_rxtx/le_phy.c`
   - `host/libubertooth/src/ubertooth_callback.c` ← `ubertoothtool/host/libubertooth/src/ubertooth_callback.c`
3. Rebuild and flash the firmware, and rebuild the host tools, following the
   upstream Ubertooth build instructions.
4. Run the LE sniffing command (e.g. `ubertooth-btle -f`) and capture the
   per-packet `cfoTot/w0/w8/w4/w2` lines for downstream analysis.

## Notes / limitations

- CFO is derived from the CC2400 FREQEST register; the 5.2 kHz/LSB scale is an
  approximation and absolute values are receiver-specific.
- Only LE 1M legacy advertising is targeted.
- Licensing follows upstream Ubertooth (GPL); see the file headers.
