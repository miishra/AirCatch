#include <stdio.h>
#include "sl_component_catalog.h"
#include "sl_rail.h"
#include "sl_rail_util_init.h"
#include "sl_code_classification.h"
#include "ble_packet_monitor.h"

#if defined(SL_CATALOG_KERNEL_PRESENT)
#include "app_task_init.h"
#endif

void app_process_action(void)
{
  RAIL_Handle_t rail_handle = sl_rail_util_get_handle(SL_RAIL_UTIL_HANDLE_INST0);
  // Drain IQ FIFO + enqueue SPI frames (non-ISR context)
  RAIL_StartRx(rail_handle, 0, NULL);
  ble_packet_monitor_process(rail_handle);
}

SL_CODE_RAM void sl_rail_util_on_event(sl_rail_handle_t rail_handle, sl_rail_events_t events)
{
  ble_packet_monitor_on_event((RAIL_Handle_t)rail_handle, (RAIL_Events_t)events);

#if defined(SL_CATALOG_KERNEL_PRESENT)
  app_task_notify();
#endif
}