#!/bin/bash
#
# keys_and_flash.sh - Generate OpenHaystack keys and flash them to an ESP32 in one step.
#
# Thin wrapper around Modified_Openhaystack_ESP32/keygen.py and flash_esp32.sh.
#
set -e

# Directory of this script, and the ESP32 firmware subdirectory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ESP_DIR="$SCRIPT_DIR/Modified_Openhaystack_ESP32"

# Defaults
NUM_KEYS=100
PORT=/dev/ttyACM0
KEYS_FILE="$ESP_DIR/keys.txt"
BUILD_DIR=""            # empty -> flash_esp32.sh default (ESP_DIR/build)
SLOW=""
SKIP_KEYGEN=""

usage() {
    cat <<EOF
keys_and_flash.sh - Generate keys and flash them to an ESP32 in one step

Usage: keys_and_flash.sh [options]

Options:
  -n, --num-keys <N>    Number of keys to generate (default: $NUM_KEYS)
  -p, --port <port>     Serial port of the ESP32 (default: $PORT)
  -o, --output <file>   Where to write/read the public keys
                        (default: Modified_Openhaystack_ESP32/keys.txt)
  -b, --builddir <dir>  Firmware build directory (default: the firmware's build/)
  -s, --slow            Flash at 115200 baud (for long/bad USB cables)
      --skip-keygen     Reuse an existing keys file instead of regenerating
  -h, --help            Show this message and exit
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--num-keys) NUM_KEYS="$2"; shift 2 ;;
        -p|--port)     PORT="$2";     shift 2 ;;
        -o|--output)   KEYS_FILE="$2"; shift 2 ;;
        -b|--builddir) BUILD_DIR="$2"; shift 2 ;;
        -s|--slow)     SLOW="-s";     shift ;;
        --skip-keygen) SKIP_KEYGEN=1; shift ;;
        -h|--help)     usage ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

# Sanity: firmware directory must exist
if [[ ! -d "$ESP_DIR" ]]; then
    echo "Firmware directory not found: $ESP_DIR"
    exit 1
fi

# 1) Generate keys (unless reusing an existing file)
if [[ -n "$SKIP_KEYGEN" ]]; then
    if [[ ! -f "$KEYS_FILE" ]]; then
        echo "--skip-keygen was given but keys file does not exist: $KEYS_FILE"
        exit 1
    fi
    echo "==> Reusing existing keys file: $KEYS_FILE"
else
    echo "==> Generating $NUM_KEYS keys -> $KEYS_FILE"
    python3 "$ESP_DIR/keygen.py" -n "$NUM_KEYS" -o "$KEYS_FILE"
fi

# 2) Flash
echo "==> Flashing to $PORT"
FLASH_ARGS=(-p "$PORT" -k "$KEYS_FILE")
[[ -n "$SLOW" ]] && FLASH_ARGS+=("$SLOW")
[[ -n "$BUILD_DIR" ]] && FLASH_ARGS+=(-b "$BUILD_DIR")

"$ESP_DIR/flash_esp32.sh" "${FLASH_ARGS[@]}"
