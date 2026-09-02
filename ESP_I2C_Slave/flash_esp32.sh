#!/bin/bash
#
# flash_esp32.sh - Flash the ESP32 SPI-to-USB bridge ("I2C-slave") firmware.
#
# Analogous to Modified_Openhaystack_ESP32/flash_esp32.sh, but for a standard
# ESP-IDF application (no key partition). It flashes the three prebuilt
# artifacts (bootloader, partition table, app) with esptool.
#
# Flash layout is taken from the build's flasher_args.json when present (the
# authoritative source for chip + offsets + flash settings), so it works across
# targets. If that file is absent (e.g. flashing a stripped distribution dir),
# it falls back to the standard offsets for the selected --chip.

cleanup() {
    rm -f "$SCRIPT_DIR/tmp_read_flasher_args.py"
}

# Directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Defaults
VENV_DIR="$SCRIPT_DIR/venv"          # esptool virtualenv (created if needed)
BUILD_DIR="$SCRIPT_DIR/build"        # firmware artifacts
PORT=/dev/ttyACM0                    # ESP32-S3 usually enumerates as ttyACM*
BAUDRATE=921600
CHIP=esp32s3                         # matches CMakeLists SUPPORTED_TARGETS

# Parameter parsing
while [[ $# -gt 0 ]]; do
    KEY="$1"
    case "$KEY" in
        -p|--port)     PORT="$2";     shift 2 ;;
        -s|--slow)     BAUDRATE=115200; shift ;;
        -v|--venvdir)  VENV_DIR="$2"; shift 2 ;;
        -b|--builddir) BUILD_DIR="$2"; shift 2 ;;
        -c|--chip)     CHIP="$2";     shift 2 ;;
        -h|--help)
            echo "flash_esp32.sh - Flash the ESP32 SPI-to-USB bridge firmware"
            echo ""
            echo "Call: flash_esp32.sh [-p <port>] [-b <dir>] [-c <chip>] [-v <dir>] [-s]"
            echo ""
            echo "Optional Arguments:"
            echo "  -h, --help            Show this message and exit."
            echo "  -p, --port <port>     Serial interface of the ESP32 (default: $PORT)."
            echo "  -s, --slow            Flash at 115200 instead of 921600 baud."
            echo "  -v, --venvdir <dir>   Python virtualenv with esptool (created if missing)."
            echo "  -b, --builddir <dir>  Directory with the built firmware artifacts"
            echo "                        (bootloader/, partition_table/, <app>.bin, and"
            echo "                        ideally flasher_args.json). Default: build/ next to"
            echo "                        this script."
            echo "  -c, --chip <chip>     Target chip for the fallback layout when"
            echo "                        flasher_args.json is absent (default: $CHIP)."
            exit 1
        ;;
        *) echo "Unknown argument: $1"; echo "Try --help"; exit 1 ;;
    esac
done

# Sanity check: Port
if [[ ! -e "$PORT" ]]; then
    echo "$PORT does not exist, please specify a valid serial interface with the -p argument"
    exit 1
fi

# Sanity check: Build directory
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Build directory $BUILD_DIR does not exist."
    echo "Build the firmware first (idf.py build) or point -b at the artifacts."
    exit 1
fi

# Setup esptool (reuse if on PATH, else use/create a venv). Mirrors the
# OpenHaystack flasher so a container that preinstalls esptool needs no network.
ESPTOOL=""
if command -v esptool.py > /dev/null 2>&1; then
    ESPTOOL="esptool.py"
    echo "Using esptool already on PATH: $(command -v esptool.py)"
elif command -v esptool > /dev/null 2>&1; then
    ESPTOOL="esptool"
    echo "Using esptool already on PATH: $(command -v esptool)"
elif [[ ! -d "$VENV_DIR" ]]; then
    PYTHON="$(which python3 || which python)"
    if [[ -z "$PYTHON" ]] || ! ($PYTHON -V 2>&1 | grep "Python 3" > /dev/null); then
        echo "Could not find a Python 3 installation."
        exit 1
    fi
    if ! ($PYTHON -c "import venv" &> /dev/null); then
        echo "Python 3 module \"venv\" was not found."
        exit 1
    fi
    $PYTHON -m venv "$VENV_DIR" || { echo "Creating venv in $VENV_DIR failed."; exit 1; }
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install esptool || { echo "Could not install esptool in $VENV_DIR"; exit 1; }
    ESPTOOL="esptool.py"
else
    source "$VENV_DIR/bin/activate"
    ESPTOOL="esptool.py"
fi

trap cleanup EXIT

# Build the flash plan: chip + (offset file) pairs, plus flash mode/freq/size.
WRITE_ARGS=()
FLASHER_JSON="$BUILD_DIR/flasher_args.json"

if [[ -f "$FLASHER_JSON" ]]; then
    echo "Using flash layout from $FLASHER_JSON"
    cat > "$SCRIPT_DIR/tmp_read_flasher_args.py" << 'EOF'
import json, os, sys

json_path = sys.argv[1]
build_dir = sys.argv[2]

with open(json_path) as f:
    data = json.load(f)

# Chip
chip = data.get("extra_esptool_args", {}).get("chip", "")
print(chip)

# Flash mode/freq/size (write_flash_args), passed through verbatim
for tok in data.get("write_flash_args", []):
    print(tok)

# offset -> file, files made absolute against the build dir
for offset, rel in sorted(data.get("flash_files", {}).items(), key=lambda kv: int(kv[0], 16)):
    print(offset)
    print(os.path.join(build_dir, rel))
EOF
    mapfile -t PLAN < <(python3 "$SCRIPT_DIR/tmp_read_flasher_args.py" "$FLASHER_JSON" "$BUILD_DIR")
    if [[ ${#PLAN[@]} -lt 3 ]]; then
        echo "Failed to parse $FLASHER_JSON"
        exit 1
    fi
    [[ -n "${PLAN[0]}" ]] && CHIP="${PLAN[0]}"
    WRITE_ARGS=("${PLAN[@]:1}")
else
    # Fallback: standard single-app layout with per-chip bootloader offset.
    echo "flasher_args.json not found; using standard $CHIP layout"
    case "$CHIP" in
        esp32) BOOTLOADER_OFFSET=0x1000 ;;
        *)     BOOTLOADER_OFFSET=0x0 ;;   # esp32s3/s2/c3/c6/... boot from 0x0
    esac

    BOOTLOADER_BIN="$BUILD_DIR/bootloader/bootloader.bin"
    PARTITION_BIN="$BUILD_DIR/partition_table/partition-table.bin"
    # App bin: the single top-level .bin (excludes bootloader/partition subdirs)
    mapfile -t APP_BINS < <(find "$BUILD_DIR" -maxdepth 1 -name "*.bin" 2>/dev/null)
    if [[ ${#APP_BINS[@]} -ne 1 ]]; then
        echo "Expected exactly one application .bin in $BUILD_DIR, found ${#APP_BINS[@]}."
        echo "Provide a flasher_args.json or a clean build directory."
        exit 1
    fi
    APP_BIN="${APP_BINS[0]}"

    for bin in "$BOOTLOADER_BIN" "$PARTITION_BIN" "$APP_BIN"; do
        if [[ ! -f "$bin" ]]; then
            echo "Missing build artifact: $bin"
            exit 1
        fi
    done

    WRITE_ARGS=(
        "$BOOTLOADER_OFFSET" "$BOOTLOADER_BIN"
        0x8000               "$PARTITION_BIN"
        0x10000              "$APP_BIN"
    )
fi

echo "Chip     : $CHIP"
echo "Port     : $PORT"
echo "Baud     : $BAUDRATE"
echo "Flashing the ESP32 will overwrite the current firmware."

set -e
$ESPTOOL --chip "$CHIP" --before default_reset --after hard_reset \
    --baud "$BAUDRATE" --port "$PORT" \
    write_flash "${WRITE_ARGS[@]}"

echo "Successfully flashed the SPI-to-USB bridge firmware to $PORT"
