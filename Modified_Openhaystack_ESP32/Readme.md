# Modified OpenHaystack ESP32

Custom AirTag firmware for ESP32 with dynamic MAC address spoofing. Generates and broadcasts sequences of OpenHaystack keys to evade detection.

## Quick Start

1. Generate keys:
```bash
python ./keygen_maybe.py -n 50000
```

2. Flash to ESP32:
```bash
./flash_esp32.sh -p /dev/ttyACM0 -k keys.txt
```

## Key Files

- `keygen_maybe.py` - Generate key sequences
- `flash_esp32.sh` - Flash firmware to device
- `get_payloads_from_keys.py` - Extract payloads from keys
- `main/` - ESP32 firmware source

## Capabilities

- Continuous MAC address changes (50,000+ keys per day)
- Broadcasts OpenHaystack compatible advertisements
- Evades standard tracking detection methods

