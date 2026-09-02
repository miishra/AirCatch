#!/bin/bash

cleanup() {
    echo "cleanup ..."
    rm -f "$KEYFILE"
}

# Directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Defaults: Directory for the virtual environment
VENV_DIR="$SCRIPT_DIR/venv"

# Defaults: Directory containing the built firmware artifacts
BUILD_DIR="$SCRIPT_DIR/build"

# Defaults: Serial port to access the ESP32
PORT=/dev/ttyS0

# Defaults: Fast baud rate
BAUDRATE=921600

# Array to hold multiple public keys
PUBKEYS=()

# Parameter parsing
while [[ $# -gt 0 ]]; do
    KEY="$1"
    case "$KEY" in
        -p|--port)
            PORT="$2"
            shift
            shift
        ;;
        -s|--slow)
            BAUDRATE=115200
            shift
        ;;
        -v|--venvdir)
            VENV_DIR="$2"
            shift
            shift
        ;;
        -b|--builddir)
            BUILD_DIR="$2"
            shift
            shift
        ;;
        -k|--keys)
            KEYS_FILE="$2"
            shift
            shift
        ;;
        -h|--help)
            echo "flash_esp32.sh - Flash the OpenHaystack firmware with multiple keys onto an ESP32 module"
            echo ""
            echo "  This script will create a virtual environment for the required tools."
            echo ""
            echo "Call: flash_esp32.sh [-p <port>] [-v <dir>] [-b <dir>] [-s] -k <keysfile>"
            echo "  OR: flash_esp32.sh [-p <port>] [-v <dir>] [-b <dir>] [-s] PUBKEY1 [PUBKEY2 ...]"
            echo ""
            echo "Required Arguments:"
            echo "  Either provide keys via -k/--keys pointing to a file with one base64 key per line,"
            echo "  OR provide one or more base64-encoded public keys as arguments"
            echo ""
            echo "Optional Arguments:"
            echo "  -h, --help"
            echo "      Show this message and exit."
            echo "  -p, --port <port>"
            echo "      Specify the serial interface to which the device is connected."
            echo "  -s, --slow"
            echo "      Use 115200 instead of 921600 baud when flashing."
            echo "      Might be required for long/bad USB cables or slow USB-to-Serial converters."
            echo "  -v, --venvdir <dir>"
            echo "      Select Python virtual environment with esptool installed."
            echo "      If the directory does not exist, it will be created."
            echo "  -b, --builddir <dir>"
            echo "      Directory containing the built firmware artifacts"
            echo "      (bootloader.bin, partition-table.bin, openhaystack.bin)."
            echo "      Defaults to the 'build' directory next to this script."
            echo "  -k, --keys <file>"
            echo "      Path to a file containing base64-encoded public keys, one per line."
            exit 1
        ;;
        *)
            # Treat as a public key
            PUBKEYS+=("$1")
            shift
        ;;
    esac
done

# If keys file is provided, read keys from it
if [[ -n "$KEYS_FILE" ]]; then
    if [[ ! -f "$KEYS_FILE" ]]; then
        echo "Keys file $KEYS_FILE does not exist"
        exit 1
    fi
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^# ]]; then
            PUBKEYS+=("$line")
        fi
    done < "$KEYS_FILE"
fi

# Sanity check: At least one pubkey exists
if [[ ${#PUBKEYS[@]} -eq 0 ]]; then
    echo "Missing public keys, call with --help for usage"
    exit 1
fi

# Check maximum number of keys
if [[ ${#PUBKEYS[@]} -gt 50000 ]]; then
    echo "Too many keys provided (${#PUBKEYS[@]}), maximum is 50000"
    exit 1
fi

echo "Found ${#PUBKEYS[@]} public key(s) to flash"

# Sanity check: Port
if [[ ! -e "$PORT" ]]; then
    echo "$PORT does not exist, please specify a valid serial interface with the -p argument"
    exit 1
fi

# Sanity check: Build artifacts
BOOTLOADER_BIN="$BUILD_DIR/bootloader/bootloader.bin"
PARTITION_BIN="$BUILD_DIR/partition_table/partition-table.bin"
FIRMWARE_BIN="$BUILD_DIR/openhaystack.bin"
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Build directory $BUILD_DIR does not exist, specify it with the -b argument or build the firmware first"
    exit 1
fi
for bin in "$BOOTLOADER_BIN" "$PARTITION_BIN" "$FIRMWARE_BIN"; do
    if [[ ! -f "$bin" ]]; then
        echo "Missing build artifact: $bin"
        echo "Build the firmware first, or point -b at the correct build directory"
        exit 1
    fi
done

# Setup the virtual environment
# If esptool is already on PATH (e.g. inside the project's `hardware` container,
# which preinstalls it), use it directly rather than building a venv -- that
# path needs network access, which a container may not have.
if command -v esptool.py > /dev/null 2>&1; then
    echo "Using esptool already on PATH: $(command -v esptool.py)"
elif [[ ! -d "$VENV_DIR" ]]; then
    # Create the virtual environment
    PYTHON="$(which python3)"
    if [[ -z "$PYTHON" ]]; then
        PYTHON="$(which python)"
    fi
    if [[ -z "$PYTHON" ]]; then
        echo "Could not find a Python installation, please install Python 3."
        exit 1
    fi
    if ! ($PYTHON -V 2>&1 | grep "Python 3" > /dev/null); then
        echo "Executing \"$PYTHON\" does not run Python 3, please make sure that python3 or python on your PATH points to Python 3"
        exit 1
    fi
    if ! ($PYTHON -c "import venv" &> /dev/null); then
        echo "Python 3 module \"venv\" was not found."
        exit 1
    fi
    $PYTHON -m venv "$VENV_DIR"
    if [[ $? != 0 ]]; then
        echo "Creating the virtual environment in $VENV_DIR failed."
        exit 1
    fi
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install esptool
    if [[ $? != 0 ]]; then
        echo "Could not install Python 3 module esptool in $VENV_DIR";
        exit 1
    fi
else
    source "$VENV_DIR/bin/activate"
fi

# Prepare the key file with all keys
KEYFILE="$SCRIPT_DIR/tmp.key"
KEYS_INPUT="$SCRIPT_DIR/tmp.keys.input"
if [[ -f "$KEYFILE" || -f "$KEYS_INPUT" ]]; then
    echo "$KEYFILE or $KEYS_INPUT already exists, stopping here not to override files..."
    exit 1
fi

# Write collected keys into a temporary file to avoid huge argv
for k in "${PUBKEYS[@]}"; do
    echo "$k" >> "$KEYS_INPUT"
done

# Create a Python script to build the key file
cat > "$SCRIPT_DIR/tmp_build_keys.py" << 'EOF'
import sys
import base64
import struct
from pathlib import Path

def load_keys(path):
    keys = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            keys.append(line)
    return keys

def main():
    keys_file = sys.argv[1]
    output_file = sys.argv[2]
    keys_input_path = sys.argv[3]

    keys_b64 = load_keys(keys_input_path)

    keys_binary = []
    for i, key_b64 in enumerate(keys_b64):
        try:
            key_bytes = base64.b64decode(key_b64)
            if len(key_bytes) != 28:
                print(f"Error: Key {i+1} has invalid length {len(key_bytes)}, expected 28 bytes")
                sys.exit(1)
            keys_binary.append(key_bytes)
        except Exception as e:
            print(f"Error decoding key {i+1}: {e}")
            sys.exit(1)
    
    # Write to file: 4 bytes for count, then all keys
    with open(output_file, 'wb') as f:
        f.write(struct.pack('<I', len(keys_binary)))  # Little-endian 32-bit unsigned int
        for key in keys_binary:
            f.write(key)
    
    print(f"Successfully created key file with {len(keys_binary)} keys")

if __name__ == '__main__':
    main()
EOF

# Build the key file
python3 "$SCRIPT_DIR/tmp_build_keys.py" "$KEYFILE" "$KEYFILE" "$KEYS_INPUT"
if [[ $? != 0 ]]; then
    echo "Could not build the key file"
    rm -f "$SCRIPT_DIR/tmp_build_keys.py" "$KEYS_INPUT"
    exit 1
fi
rm -f "$SCRIPT_DIR/tmp_build_keys.py" "$KEYS_INPUT"

# Call esptool.py. Errors from here on are critical
set -e
trap cleanup INT TERM EXIT

# Clear NVM
esptool.py --after no_reset --port "$PORT" \
    erase_region 0x9000 0x5000
esptool.py --before no_reset --baud $BAUDRATE --port "$PORT" \
    write_flash 0x1000  "$BOOTLOADER_BIN" \
                0x8000  "$PARTITION_BIN" \
                0x120000 "$KEYFILE" \
                0x20000 "$FIRMWARE_BIN"

echo "Successfully flashed ${#PUBKEYS[@]} keys to ESP32"