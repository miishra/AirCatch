#!/bin/bash
#
# Flash the EFR32MG24 RAIL sniffer firmware over SWD using OpenOCD + CMSIS-DAP.
#
#   ./flash.sh <firmware.hex>
#   FIRMWARE=path/to/fw.hex ./flash.sh
#
# Uses the OpenOCD bundled at tools/openocd-silabs/, which has the `efm32s2`
# flash driver this part requires. Everything is overridable by environment
# variable:
#
#   OPENOCD          openocd binary        (default: tools/openocd-silabs/)
#   OPENOCD_SCRIPTS  scripts directory     (default: the binary's own)
#   TARGET_CFG       target config         (default: target/efm32s2_g23.cfg)
#   FIRMWARE         .hex to program       (default: $1)
#
# WARNING: programming ERASES the target device. Use a dedicated dev board.

set -uo pipefail

# ---- OpenOCD binary -------------------------------------------------------
# The EFR32MG24 is EFM32 Series 2, which needs the `efm32s2` flash driver.
# Upstream OpenOCD 0.12.0 (e.g. Debian's) does NOT have that driver -- it only
# ships the older `efm32x`, which cannot program this part. So we require an
# OpenOCD that does: the copy bundled at tools/openocd-silabs/ (default), or a
# Silicon Labs / Arduino install on the host.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLED="$REPO_ROOT/tools/openocd-silabs"
SILABS_OPENOCD="$HOME/.arduino15/packages/SiliconLabs/tools/openocd/0.12.0-arduino1-static"

if [ -n "${OPENOCD:-}" ]; then
    :
elif [ -x "$BUNDLED/bin/openocd" ]; then
    OPENOCD="$BUNDLED/bin/openocd"
    : "${OPENOCD_SCRIPTS:=$BUNDLED/share/openocd/scripts}"
elif [ -x "$SILABS_OPENOCD/bin/openocd" ]; then
    OPENOCD="$SILABS_OPENOCD/bin/openocd"
    : "${OPENOCD_SCRIPTS:=$SILABS_OPENOCD/share/openocd/scripts}"
elif command -v openocd >/dev/null 2>&1; then
    OPENOCD="$(command -v openocd)"
else
    echo "Error: no usable openocd found." >&2
    echo "  Expected the bundled build at $BUNDLED/bin/openocd" >&2
    echo "  (see tools/openocd-silabs/README.md), or set \$OPENOCD." >&2
    exit 1
fi

# Refuse to continue on an OpenOCD without the efm32s2 driver: it would erase
# the device and then fail to program it.
# NB: use grep -c, not grep -q. With `set -o pipefail`, grep -q exits on the
# first match, strings takes SIGPIPE, and the pipeline reports failure even
# though the driver was found. grep -c consumes all input.
_have_driver=1
if command -v strings >/dev/null 2>&1; then
    _have_driver=$(strings "$OPENOCD" 2>/dev/null | grep -cx "efm32s2" || true)
fi
if [ "${_have_driver:-1}" -eq 0 ]; then
    echo "Error: $OPENOCD lacks the 'efm32s2' flash driver required by the" >&2
    echo "  EFR32MG24 (EFM32 Series 2). Upstream OpenOCD 0.12.0 ships only the" >&2
    echo "  older 'efm32x' driver, which cannot program this part." >&2
    echo "  Use the bundled build: OPENOCD=$BUNDLED/bin/openocd $0 <fw.hex>" >&2
    exit 1
fi

# ---- scripts dir ----------------------------------------------------------
if [ -z "${OPENOCD_SCRIPTS:-}" ]; then
    for d in "$(dirname "$OPENOCD")/../share/openocd/scripts" \
             /usr/share/openocd/scripts \
             /usr/local/share/openocd/scripts; do
        [ -d "$d" ] && { OPENOCD_SCRIPTS="$(cd "$d" && pwd)"; break; }
    done
fi
if [ -z "${OPENOCD_SCRIPTS:-}" ] || [ ! -d "$OPENOCD_SCRIPTS" ]; then
    echo "Error: could not locate the OpenOCD scripts directory." >&2
    echo "  Set \$OPENOCD_SCRIPTS explicitly." >&2
    exit 1
fi

# ---- target config --------------------------------------------------------
# efm32s2_g23.cfg sets FLASHBASE 0x08000000 (family group 23) and sources
# efm32s2.cfg, which declares the efm32s2 flash bank.
: "${TARGET_CFG:=target/efm32s2_g23.cfg}"
if [ ! -f "$OPENOCD_SCRIPTS/$TARGET_CFG" ]; then
    echo "Error: $TARGET_CFG not found under $OPENOCD_SCRIPTS/." >&2
    echo "  This config ships with the Silicon Labs OpenOCD, not upstream." >&2
    exit 1
fi

# ---- firmware -------------------------------------------------------------
FIRMWARE="${FIRMWARE:-${1:-}}"
if [ -z "$FIRMWARE" ]; then
    echo "Usage: $0 <firmware.hex>   (or set \$FIRMWARE)" >&2
    echo "  Build it in Simplicity Studio v6; see ../Code/README.md." >&2
    exit 1
fi
if [ ! -f "$FIRMWARE" ]; then
    echo "Error: firmware file not found: $FIRMWARE" >&2
    exit 1
fi

ask() {
    echo
    echo "Flash Device - ALL DATA WILL BE ERASED!"
    read -r -p "Press Y or Enter to continue or N to exit: " choice
    choice=$(echo "$choice" | tr '[:lower:]' '[:upper:]')
    if [ "$choice" = "N" ]; then
        return 1
    elif [ "$choice" = "Y" ] || [ -z "$choice" ]; then
        return 0
    else
        ask
    fi
}

echo "OpenOCD  : $OPENOCD"
echo "Scripts  : $OPENOCD_SCRIPTS"
echo "Target   : $TARGET_CFG"
echo "Firmware : $FIRMWARE"

if ! ask; then
    exit 0
fi

echo "Flashing device..."

"$OPENOCD" -s "$OPENOCD_SCRIPTS" \
        -f interface/cmsis-dap.cfg \
        -c "transport select swd" \
        -f "$TARGET_CFG" \
        -c "init" \
        -c "reset halt" \
        -c "program $FIRMWARE verify reset exit"

if [ $? -eq 0 ]; then
    echo "✓ Flashing completed successfully!"
    echo "Your device should now be running the new firmware!"
else
    echo "✗ Flashing failed!"
    exit 1
fi
