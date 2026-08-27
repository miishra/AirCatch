#!/bin/bash

OPENOCD="$HOME/.arduino15/packages/SiliconLabs/tools/openocd/0.12.0-arduino1-static/bin/openocd"
OPENOCD_SCRIPTS="$HOME/.arduino15/packages/SiliconLabs/tools/openocd/0.12.0-arduino1-static/share/openocd/scripts"
FIRMWARE="$HOME/SimplicityStudio/v6_workspace/Final_Try/cmake_gcc/build/base/Final_Try.hex"

ask() {
    echo
    echo "Flash Device - ALL DATA WILL BE ERASED!"
    read -p "Press Y or Enter to continue or N to exit: " choice
    choice=$(echo "$choice" | tr '[:lower:]' '[:upper:]')
    if [ "$choice" = "N" ]; then
        return 1
    elif [ "$choice" = "Y" ] || [ -z "$choice" ]; then
        return 0
    else
        ask
    fi
}

if [ ! -f "$FIRMWARE" ]; then
    echo "Error: Firmware file not found: $FIRMWARE"
    exit 1
fi

echo "Firmware file: $FIRMWARE"
echo "Using Arduino's OpenOCD with efm32s2 driver support"

if ! ask; then
    exit 0
fi

echo "Flashing device..."


$OPENOCD -f interface/cmsis-dap.cfg \
        -c "transport select swd" \
        -f target/efm32s2_g23.cfg \
        -c "init" \
        -c "reset halt" \
        -c "program $FIRMWARE verify reset exit"

if [ $? -eq 0 ]; then
    echo "✓ Flashing completed successfully!"
    echo "Your device should now be running the new firmware!"
else
    echo "✗ Flashing failed!"
fi