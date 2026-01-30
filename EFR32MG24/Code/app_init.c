#include <stdio.h>
#include "sl_component_catalog.h"
#include "sl_rail_util_init.h"
#include "ble_packet_monitor.h"

#if defined(SL_CATALOG_KERNEL_PRESENT)
#include "app_task_init.h"
#endif

void rail_app_init(void)
{
  RAIL_Handle_t rail_handle = sl_rail_util_get_handle(SL_RAIL_UTIL_HANDLE_INST0);
  printf("RAIL handle is Starting!\r\n");
  if (rail_handle == NULL) {
    // UART may be broken, but keep it
    printf("ERROR: RAIL handle is NULL!\r\n");
    while (1) { }
  }

  ble_packet_monitor_init(rail_handle);
}

void app_init(void)
{
#if !defined(SL_CATALOG_KERNEL_PRESENT)
  rail_app_init();
  // For this SPI test, just run the blocking CLI
  // spi_test_cli();
#else
  app_task_init();
#endif
}