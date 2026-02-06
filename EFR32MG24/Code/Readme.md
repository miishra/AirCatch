# EFR32MG24 BLE Packet Monitor Firmware

BLE packet sniffer firmware for the XIAO EFR32MG24 board that captures advertisement packets and streams IQ samples for CFO analysis.

## Build Instructions

1. Download Simplicity Studio
2. Install SDK for EFR32XG24
3. Create new project (RAIL - SOC Empty)
4. Choose part: **EFR32MG24A020F1536GM48**
5. Install EUSART driver and IO Stream: Retarget STDIO
6. Configure EUSART1:
   - RX: PA09
   - TX: PA08
7. Build and flash using OpenOCD

## Key Files

- `main.c` - Entry point
- `ble_packet_monitor.c/h` - Packet capture
- `app_process.c/h` - Main loop
- `app_init.c/h` - Setup



