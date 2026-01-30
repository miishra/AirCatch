#ifndef BLE_PACKET_MONITOR_H
#define BLE_PACKET_MONITOR_H

#include "rail.h"
#include <stdint.h>
#include <stdbool.h>

// Init BLE channel-37 monitor + SPI streaming
void ble_packet_monitor_init(RAIL_Handle_t rail_handle);

// ISR context: just latch events
void ble_packet_monitor_on_event(RAIL_Handle_t rail_handle, RAIL_Events_t events);

// Main loop: drain RX FIFO and enqueue IQ frames for SPI
void ble_packet_monitor_process(RAIL_Handle_t rail_handle);

// Optional stats print (kept because your app_process.c calls it) :contentReference[oaicite:0]{index=0}
void ble_packet_monitor_stats(void);

#endif // BLE_PACKET_MONITOR_H