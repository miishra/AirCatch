# Modified OpenHaystack ESP32 — evasive tracker firmware (adversary node)

Custom Apple **Find My ("OpenHaystack"-compatible)** beacon firmware for the
ESP32. It generates and broadcasts long sequences of Find My keys, **continuously
rotating its MAC address and advertised key to evade tracking-detection tools**.

In AirCatch this is the **adversary**: it produces the rotating-identity tracker
signal that the detector is designed to catch, so it is used to generate the
positive ("attacker present") capture scenarios.

> ⚠️ **Ethics / safety.** This turns an ESP32 into an unsanctioned, evasive Find
> My tag that is locatable through Apple's crowd-sourced network. Only flash and
> operate it on hardware you own, in a controlled/RF-isolated setting, and never
> attach it to another person or their property. Flashing **erases** the target
> device. See the root [`README.md`](../README.md) → *Security, privacy, and
> ethical concerns*.

## Requirements

- ESP32 development board.
- **Python 3** with the **cryptography** library (for key generation):
  `pip install cryptography`.
- **esptool** (installed automatically into a virtualenv by `flash_esp32.sh`).
- To rebuild the firmware from source: **ESP-IDF** (or the legacy `make` flow via
  the provided `Makefile`/`component.mk`).

## Quick start

1. **Generate keys** (NIST P-224 / SECP224R1 key pairs, OpenHaystack-compatible):

   ```bash
   python3 keygen.py -n 50000 -o keys.txt -p private_keys.pem
   ```

   Options: `-n/--num-keys` (default 10), `-o/--output` (public keys, default
   `keys.txt`), `-p/--private` (PEM, default `private_keys.pem`),
   `--no-private` to skip writing private keys.

2. **Flash** the firmware with the generated keys:

   ```bash
   ./flash_esp32.sh -p /dev/ttyACM0 -k keys.txt
   ```

   `flash_esp32.sh` options:
   - `-p, --port <port>` — serial port of the ESP32.
   - `-k, --keys <file>` — file with one base64 public key per line
     (or pass keys directly as positional args).
   - `-s, --slow` — flash at 115200 baud instead of 921600 (for long/bad cables).
   - `-v, --venvdir <dir>` — virtualenv to use/create for `esptool`.
   - `-b, --builddir <dir>` — directory with the built firmware artifacts
     (defaults to `build/` next to the script; use `../firmware/esp32-openhaystack`
     to flash the prebuilt bins shipped in the artifact).
   - `-h, --help` — full usage.

   The script builds a temporary keyfile, creates a venv with `esptool`, flashes,
   and cleans up.

   To generate keys and flash in one step, use the wrapper in the repo root:

   ```bash
   ./keys_and_flash.sh -n 100 -p /dev/ttyACM0 -b firmware/esp32-openhaystack
   ```

   It calls `keygen.py` then `flash_esp32.sh`; `--skip-keygen` reuses an existing
   keys file. Run `./keys_and_flash.sh --help` for all options.

## Utilities

- **`get_payloads_from_keys.py`** — derive the broadcast MAC + Apple Offline
  Finding payload for each key, and write them to CSV (useful for building ground
  truth / correlating captures to keys):

  ```bash
  python3 get_payloads_from_keys.py keys_fc.txt out.csv --state fd --hint fd
  ```

  Accepts either a binary key-partition dump (LE `uint32` count + 28-byte
  entries) or a text list of base64 28-byte keys. The MAC is `key[0] | 0xC0`
  followed by `key[1..5]`; the payload embeds `key[6..27]` and `key[0]>>6`,
  mirroring `main/openhaystack_main.c`.

## Key files

| File | Role |
|---|---|
| `keygen.py` | Generate P-224 key pairs (public list + private PEM). |
| `flash_esp32.sh` | Build keyfile, set up esptool venv, flash firmware. |
| `get_payloads_from_keys.py` | Derive MAC + Find My payload from keys → CSV. |
| `main/openhaystack_main.c` | ESP32 firmware: rotate MAC/key and advertise. |
| `partitions.csv` | Flash partition table (key storage). |

## Capabilities

- Continuous MAC-address + key rotation (50,000+ keys/day) to defeat naïve
  detectors.
- Broadcasts OpenHaystack-compatible Apple Offline Finding advertisements.
- Payload marker prefixes (`4c001219fc/fd/fe/ff`) let the AirCatch pipeline label
  adversary packets as ground truth.

## Notes / limitations

- P-224 key generation for very large `-n` can take a while; generate keys once
  and reuse the file.
- The advertised marker prefixes are intentional so AirCatch can score
  detections; a real-world attacker would omit them.
