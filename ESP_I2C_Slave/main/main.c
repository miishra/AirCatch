#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/spi_slave.h"
#include "driver/spi_common.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"

/* esp_tinyusb 2.x public API */
#include "tinyusb.h"
#include "tinyusb_default_config.h"

/* TinyUSB core */
#include "tusb.h"
#include "class/cdc/cdc_device.h"

#define TX_BUF_SIZE 4096
#define MAX_SPI_BYTES 2048
#define QUEUE_SIZE 50

static const char *TAG = "SPI_USB";

#define PIN_MOSI 13
#define PIN_MISO 12
#define PIN_SCLK 11
#define PIN_CS   10

#define EXPECTED_SEED 0xDEEB  // Expected seed value

typedef struct {
    uint8_t data[MAX_SPI_BYTES];
    uint16_t len;
} packet_t;

static QueueHandle_t tx_queue;

static volatile uint64_t spi_rx_bytes = 0;
static volatile uint64_t usb_tx_bytes = 0;
static volatile uint64_t valid_packets = 0;
static volatile uint64_t checksum_errors = 0;
static volatile uint64_t bad_seed_count = 0;
static volatile uint64_t queue_drops = 0;

// --- USB CDC task ---
static void usb_tx_task(void *arg)
{
    packet_t pkt;

    ESP_LOGI(TAG, "USB CDC TX task running on core %d", xPortGetCoreID());

    while (1) {
        // Wait for a packet from SPI queue
        if (xQueueReceive(tx_queue, &pkt, portMAX_DELAY) == pdTRUE) {
            // Wait until USB is connected
            while (!tud_cdc_connected()) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }

            size_t sent = 0;
            while (sent < pkt.len) {
                size_t avail = tud_cdc_write_available();
                if (avail > 0) {
                    size_t chunk = (pkt.len - sent) < avail ? (pkt.len - sent) : avail;
                    tud_cdc_write(pkt.data + sent, chunk);
                    tud_cdc_write_flush();
                    sent += chunk;
                    usb_tx_bytes += chunk;
                } else {
                    taskYIELD();
                }
            }
        }
    }

    vTaskDelete(NULL);
}

// --- SPI Receiver Task ---
static void spi_receiver_task(void *arg)
{
    ESP_LOGI(TAG, "SPI RX task on CORE %d (highest priority)", xPortGetCoreID());
    
    packet_t *pkt = heap_caps_malloc(sizeof(packet_t), MALLOC_CAP_8BIT);
    if (!pkt) {
        ESP_LOGE(TAG, "Buffer allocation failed!");
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        memset(pkt->data, 0, MAX_SPI_BYTES);

        spi_slave_transaction_t t;
        memset(&t, 0, sizeof(t));
        t.length = 8 * MAX_SPI_BYTES;
        t.rx_buffer = pkt->data;

        if (spi_slave_transmit(SPI3_HOST, &t, portMAX_DELAY) == ESP_OK) {
            int bytes = t.trans_len / 8;
            if (bytes >= 4) {
                spi_rx_bytes += bytes;

                uint16_t seed = (pkt->data[0] << 8) | pkt->data[1];
                uint8_t checksum_hdr_1 = pkt->data[2];
                uint8_t checksum_hdr_2 = pkt->data[3];

                if (seed == EXPECTED_SEED) {
                    uint8_t checksum_calc_1 = 0;
                    uint8_t checksum_calc_2 = 0;

                    if (bytes > 10) {
                        for (int i = 4; i < 10 && i < bytes; i++) {
                            checksum_calc_1 ^= pkt->data[i];
                        }
                        for (int i = bytes - 10; i < bytes - 1 && i >= 0; i++) {
                            checksum_calc_2 ^= pkt->data[i];
                        }
                    }

                    if (checksum_hdr_1 == checksum_calc_1 &&
                        checksum_hdr_2 == checksum_calc_2) {
                        valid_packets++;
                        pkt->len = bytes;
                        if (xQueueSend(tx_queue, pkt, 0) != pdTRUE) {
                            queue_drops++;
                        }
                    } else {
                        checksum_errors++;
                    }
                } else {
                    bad_seed_count++;
                }
            }
        }
    }

    heap_caps_free(pkt);
    vTaskDelete(NULL);
}

// --- Stats Task ---
static void stats_task(void *arg)
{
    int64_t last_time = esp_timer_get_time();
    uint64_t last_rx = 0;
    uint64_t last_tx = 0;

    vTaskDelay(pdMS_TO_TICKS(1000));

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));

        int64_t now = esp_timer_get_time();
        uint64_t rx = spi_rx_bytes;
        uint64_t tx = usb_tx_bytes;

        float interval = (now - last_time) / 1000000.0;

        uint64_t rx_bytes = rx - last_rx;
        uint64_t tx_bytes = tx - last_tx;

        float rx_mbps = (rx_bytes * 8.0 / 1024.0) / 1024.0 / interval;
        float tx_mbps = (tx_bytes * 8.0 / 1024.0) / 1024.0 / interval;

        int queue_depth = uxQueueMessagesWaiting(tx_queue);

        ESP_LOGI(TAG, "SPI RX: %llu KB/s | USB TX: %llu KB/s | Q:%3d/%d | Mbps RX: %.2f TX: %.2f",
                 rx_bytes / 1024, tx_bytes / 1024, queue_depth, QUEUE_SIZE, rx_mbps, tx_mbps);
        ESP_LOGI(TAG, "Valid: %llu | BadSeed: %llu | ChkErr: %llu | QDrops: %llu",
                 valid_packets, bad_seed_count, checksum_errors, queue_drops);

        last_time = now;
        last_rx = rx;
        last_tx = tx;
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "=== SPI to USB CDC Bridge ===");

    // Initialize TinyUSB
    const tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    // Create SPI->USB queue
    tx_queue = xQueueCreate(QUEUE_SIZE, sizeof(packet_t));
    if (!tx_queue) {
        ESP_LOGE(TAG, "Queue creation failed!");
        return;
    }

    // Initialize SPI slave
    spi_bus_config_t buscfg = {
        .mosi_io_num = PIN_MOSI,
        .miso_io_num = PIN_MISO,
        .sclk_io_num = PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = MAX_SPI_BYTES,
    };

    spi_slave_interface_config_t slvcfg = {
        .mode = 0,
        .spics_io_num = PIN_CS,
        .queue_size = 5,
        .flags = 0,
        .post_setup_cb = NULL,
        .post_trans_cb = NULL,
    };

    ESP_ERROR_CHECK(spi_slave_initialize(SPI3_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO));

    // Create tasks
    xTaskCreatePinnedToCore(spi_receiver_task, "spi_rx", 4096, NULL, 20, NULL, 1);
    xTaskCreatePinnedToCore(usb_tx_task, "usb_tx", 4096, NULL, 15, NULL, 0);
    xTaskCreatePinnedToCore(stats_task, "stats", 3072, NULL, 5, NULL, 0);

    ESP_LOGI(TAG, "Started SPI->USB bridge. Core0: USB TX + Stats, Core1: SPI RX");

    while (1) vTaskDelay(pdMS_TO_TICKS(60000));
}
