#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "nvs_flash.h"
#include "esp_partition.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include "esp_bt_defs.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"

static const char *LOG_TAG = "open_haystack";

/* ---------------- Config ---------------- */

#define KEY_SIZE                28
#define MAX_KEYS                50000
#define ROTATION_INTERVAL_MS    2000   // 1 minute

/* ---------------- BLE ADV ---------------- */

static esp_bd_addr_t rnd_addr = {0};

static uint8_t adv_data[31] = {
    0x1e,
    0xff,
    0x4c, 0x00,       // Apple
    0x12, 0x19,       // Offline Finding
    0xfd,             // state
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,             // first 2 bits
    0xfd              // hint
};

static esp_ble_adv_params_t ble_adv_params = {
    .adv_int_min       = 0x0640, // 1s (valid, but irrelevant since we stop fast)
    .adv_int_max       = 0x0640,
    .adv_type          = ADV_TYPE_NONCONN_IND,
    .own_addr_type     = BLE_ADDR_TYPE_RANDOM,
    .channel_map       = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

/* ---------------- Keys ---------------- */

static const esp_partition_t *key_partition = NULL;
static uint8_t key_buf[KEY_SIZE];
static uint32_t num_keys = 0;
static uint32_t current_key = 0;

/* ---------------- Timers ---------------- */

static TimerHandle_t rotation_timer;

/* ---------------- Helpers ---------------- */

void set_addr_from_key(esp_bd_addr_t addr, uint8_t *key)
{
    addr[0] = key[0] | 0xC0;
    memcpy(&addr[1], &key[1], 5);
}

void set_payload_from_key(uint8_t *payload, uint8_t *key)
{
    memcpy(&payload[7], &key[6], 22);
    payload[29] = key[0] >> 6;
}

static void set_max_tx_power(void)
{
    const esp_power_level_t max_power = ESP_PWR_LVL_P9; // Max TX power (9 dBm on ESP32)

    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, max_power));
    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, max_power));
    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, max_power));
}

static esp_err_t read_key(uint32_t index, uint8_t *out)
{
    if (!key_partition || index >= num_keys) {
        return ESP_FAIL;
    }

    size_t offset = 4 + index * KEY_SIZE;
    return esp_partition_read(key_partition, offset, out, KEY_SIZE);
}

/* ---------------- Partition ---------------- */

int load_keys(void)
{
    key_partition = esp_partition_find_first(0x40, 0x00, "key");

    if (!key_partition) {
        ESP_LOGE(LOG_TAG, "Key partition not found");
        return ESP_FAIL;
    }

    ESP_ERROR_CHECK(
        esp_partition_read(key_partition, 0, &num_keys, sizeof(uint32_t))
    );

    if (num_keys == 0 || num_keys > MAX_KEYS) {
        ESP_LOGE(LOG_TAG, "Invalid key count: %d", num_keys);
        return ESP_FAIL;
    }

    size_t required_bytes = 4 + num_keys * KEY_SIZE;
    if (key_partition->size < required_bytes) {
        ESP_LOGE(
            LOG_TAG,
            "Key partition too small (%zu bytes), need at least %zu",
            key_partition->size,
            required_bytes
        );
        return ESP_FAIL;
    }

    ESP_LOGI(LOG_TAG, "Loaded %d keys", num_keys);
    return ESP_OK;
}

/* ---------------- GAP ---------------- */

static void esp_gap_cb(esp_gap_ble_cb_event_t event,
                       esp_ble_gap_cb_param_t *param)
{
    switch (event) {

    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        esp_ble_gap_start_advertising(&ble_adv_params);
        break;

    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        // Stop almost immediately → ~1 packet
        esp_ble_gap_stop_advertising();
        break;

    default:
        break;
    }
}

/* ---------------- Rotation ---------------- */

static void rotate_and_advertise(uint32_t key_index)
{
    if (read_key(key_index, key_buf) != ESP_OK) {
        ESP_LOGE(LOG_TAG, "Failed to read key %d", key_index + 1);
        return;
    }

    set_addr_from_key(rnd_addr, key_buf);
    set_payload_from_key(adv_data, key_buf);

    ESP_LOGI(LOG_TAG,
        "Minute tick → key %d/%d | %02X:%02X:%02X:%02X:%02X:%02X",
        key_index + 1, num_keys,
        rnd_addr[0], rnd_addr[1], rnd_addr[2],
        rnd_addr[3], rnd_addr[4], rnd_addr[5]);

    ESP_ERROR_CHECK(esp_ble_gap_set_rand_addr(rnd_addr));
    ESP_ERROR_CHECK(
        esp_ble_gap_config_adv_data_raw(adv_data, sizeof(adv_data))
    );
}

static void rotation_timer_cb(TimerHandle_t xTimer)
{
    current_key = (current_key + 1) % num_keys;
    rotate_and_advertise(current_key);
}

/* ---------------- Main ---------------- */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_ERROR_CHECK(
        esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT)
    );

    esp_bt_controller_config_t bt_cfg =
        BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    set_max_tx_power();

    ESP_ERROR_CHECK(
        esp_ble_gap_register_callback(esp_gap_cb)
    );

    if (load_keys() != ESP_OK) {
        ESP_LOGE(LOG_TAG, "No keys loaded, aborting");
        return;
    }

    /* First advertisement immediately */
    rotate_and_advertise(0);

    /* Every 60 seconds thereafter */
    rotation_timer = xTimerCreate(
        "rotate",
        pdMS_TO_TICKS(ROTATION_INTERVAL_MS),
        pdTRUE,
        NULL,
        rotation_timer_cb
    );

    xTimerStart(rotation_timer, 0);

    ESP_LOGI(LOG_TAG, "Advertising once per minute (very low reliability)");
}
