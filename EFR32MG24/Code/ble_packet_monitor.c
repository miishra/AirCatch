/* ble_packet_monitor_seeed_xiao.c
 *
 * High-throughput BLE IQ streamer for Seeed XIAO MG24
 * Optimized polling version with PRE/POST trigger capture
 *
 * Pin Configuration for XIAO MG24 (EUSART0/SPI0):
 * - D8  = PA03 = SPI CLK  (Clock)
 * - D9  = PA04 = SPI MISO (Master In Slave Out) 
 * - D10 = PA05 = SPI MOSI (Master Out Slave In)
 * - D7  = PC07 = CS       (Chip Select)
 *
 * Key optimizations from working xG24 code:
 * - Proper CS timing with delays
 * - Back-to-back transfer support
 * - Multi-chunk processing per cycle
 * - Energy threshold tuning
 */

#include "ble_packet_monitor.h"
#include "rail_ble.h"

#include "em_cmu.h"
#include "em_gpio.h"
#include "em_core.h"
#include "em_eusart.h"
#include "em_ldma.h"
#include "em_device.h"
#include "rail.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define TEST_FIXED_IQ           0
#define ENERGY_THRESH_INIT      100000U
#define ENERGY_THRESH_MIN       2000U
#define ENERGY_THRESH_MAX       60000000U
#define ENERGY_ADJUST_PCT       1000U       // Step size for auto tuning
#define TARGET_MBPS             5U        // Desired sustained TX rate

/* ====================================
 * XIAO MG24 SPI CONFIGURATION
 * Using EUSART0 (D7-D10 pins)
 * ==================================== */
#define SPI_EUSART              EUSART0
#define SPI_EUSART_CLK          cmuClock_EUSART0
#define SPI_EUSART_ROUTE_INDEX  0

/* XIAO MG24 Pin Mapping */
#define SPI_SCLK_PORT  gpioPortA
#define SPI_SCLK_PIN   3          // PA03 = D8

#define SPI_MOSI_PORT  gpioPortA
#define SPI_MOSI_PIN   5          // PA05 = D10

#define SPI_MISO_PORT  gpioPortA
#define SPI_MISO_PIN   4          // PA04 = D9

#define SPI_CS_PORT    gpioPortC
#define SPI_CS_PIN     7          // PC07 = D7

/* Tunable parameters - Optimized for high throughput */
#define CHUNK_BYTES             2048
#define RING_N                  120     // 100 * 2KB = 200KB total buffer
#define RX_FIFO_SIZE            4096u     // Must be larger than CHUNK_BYTES
#define RX_FIFO_THRESHOLD       2020      // Fire ISR when this much data available

#define PRETRIGGER_CHUNKS       1         // Reduced from 1 - less history
#define POSTTRIGGER_CHUNKS      1         // Post-trigger capture chunks

_Static_assert((CHUNK_BYTES % 4) == 0, "CHUNK_BYTES must be multiple of 4");

/* Queues */
__ALIGNED(4) static uint8_t  g_chunks[RING_N][CHUNK_BYTES];
static uint8_t  g_free_q[RING_N], g_ready_q[RING_N], g_tx_q[RING_N];
static volatile uint8_t g_free_h, g_free_t, g_free_n;
static volatile uint8_t g_ready_h, g_ready_t, g_ready_n;
static volatile uint8_t g_tx_h, g_tx_t, g_tx_n;

static uint8_t g_hist_q[RING_N];
static volatile uint8_t g_hist_h, g_hist_t, g_hist_n;

static volatile uint32_t g_dropped_bytes = 0;
static volatile uint32_t g_chunks_sent = 0;
static volatile uint64_t g_bytes_sent = 0;
static volatile uint32_t g_energy_thresh = ENERGY_THRESH_INIT;
static volatile uint32_t g_start_time = 0;
static volatile uint32_t g_last_stats_time = 0;
static volatile bool g_capturing_active = false;

static volatile uint16_t g_chunk_seed = 0;
static uint16_t g_chunk_counter = 0;

/* LDMA resources - Polling mode (no IRQ) */
static const unsigned int LDMA_CHANNEL_TX = 0;
static volatile bool g_ldma_active = false;
static volatile uint8_t g_current_tx_idx = 0xFF;

/* RAIL RX FIFO */
__ALIGNED(RAIL_FIFO_ALIGNMENT) static uint8_t rx_fifo[RX_FIFO_SIZE];
static volatile RAIL_Events_t g_pending_events = 0;

/* LDMA descriptor ring */
static LDMA_Descriptor_t desc_ring[RING_N] __ALIGNED(4);

/* Trigger state machine */
enum {
    CAP_STATE_IDLE = 0,
    CAP_STATE_POST
};
static uint8_t cap_state = CAP_STATE_IDLE;
static uint8_t post_remaining = 0;

/* Forward declarations */
static void spi_init(void);
static void ldma_init_system(void);
static bool ldma_start_tx(void);
static void ldma_stop_tx(void);
static void ldma_poll_completion(void);
static uint32_t calculate_iq_energy_local(const uint8_t *iq_data, uint16_t num_bytes);

/* Queue helpers */
static bool q_pop(volatile uint8_t *h, volatile uint8_t *n, uint8_t *q, uint8_t *out)
{
    if (*n == 0) return false;
    *out = q[*h];
    *h = (uint8_t)((*h + 1) % RING_N);
    (*n)--;
    return true;
}

static void q_push(volatile uint8_t *t, volatile uint8_t *n, uint8_t *q, uint8_t idx)
{
    q[*t] = idx;
    *t = (uint8_t)((*t + 1) % RING_N);
    (*n)++;
}

/* =======================
 * LDMA polling - Based on working xG24 implementation
 * CS timing optimized for continuous transfer
 * ======================= */
static void ldma_poll_completion(void)
{
    if (!g_ldma_active) return;

    // Check if transfer is done
    uint32_t chdone = LDMA->CHDONE;
    if (!(chdone & (1u << LDMA_CHANNEL_TX))) {
        return;  // Still busy
    }

    // Transfer complete
    g_chunks_sent++;
    g_bytes_sent += CHUNK_BYTES;
    
    // MINIMAL timing delays for maximum throughput
    // for (volatile int i = 0; i < 900; i++);  // Minimal delay
    GPIO_PinOutSet(SPI_CS_PORT, SPI_CS_PIN);
    for (volatile int i = 0; i < 600; i++);  // Reduced from 700
    GPIO_PinOutClear(SPI_CS_PORT, SPI_CS_PIN);

    // Return completed chunk to free queue
    if (g_current_tx_idx != 0xFF) {
        CORE_DECLARE_IRQ_STATE;
        CORE_ENTER_CRITICAL();
        q_push(&g_free_t, &g_free_n, g_free_q, g_current_tx_idx);
        CORE_EXIT_CRITICAL();
        g_current_tx_idx = 0xFF;
    }

    // Get next chunk
    CORE_DECLARE_IRQ_STATE;
    CORE_ENTER_CRITICAL();
    uint8_t next_idx;
    bool have_next = q_pop(&g_tx_h, &g_tx_n, g_tx_q, &next_idx);
    CORE_EXIT_CRITICAL();

    if (have_next) {
        g_current_tx_idx = next_idx;
        
        // Fast restart: update LINK register and trigger
        LDMA->CH[LDMA_CHANNEL_TX].LINK = (uint32_t)&desc_ring[next_idx] & _LDMA_CH_LINK_LINKADDR_MASK;
        BUS_RegMaskedClear(&LDMA->CHDONE, (1u << LDMA_CHANNEL_TX));
        LDMA->LINKLOAD = (1u << LDMA_CHANNEL_TX);
    } else {
        // All done - deassert CS
        g_ldma_active = false;
    }
}

static void fill_fixed_iq(uint8_t *dest, uint16_t num_bytes)
{
    int16_t *p = (int16_t *)dest;
    uint16_t n = num_bytes / 2;

    for (uint16_t i = 0; i < n; i += 2) {
        p[i + 0] = 30000;   // I
        p[i + 1] = -20000;  // Q
    }
}

/* =======================
 * LDMA initialization
 * ======================= */
static void ldma_init_system(void)
{
    CMU_ClockEnable(cmuClock_LDMA, true);

#if defined(LDMA_EN_EN)
    if (!(LDMA->EN & LDMA_EN_EN)) {
        LDMA->EN = LDMA_EN_EN;
    }
#endif

    // Disable our channel
#if defined(_LDMA_CHDIS_MASK)
    LDMA->CHDIS = (1u << LDMA_CHANNEL_TX);
#else
    BUS_RegMaskedClear(&LDMA->CHEN, (1u << LDMA_CHANNEL_TX));
#endif

    // Build descriptors for each chunk
    for (uint32_t i = 0; i < RING_N; i++) {
        desc_ring[i] = (LDMA_Descriptor_t)LDMA_DESCRIPTOR_SINGLE_M2P_BYTE(
            &g_chunks[i][0],
            &SPI_EUSART->TXDATA,
            CHUNK_BYTES
        );
        
        // Single-shot, no interrupt
        desc_ring[i].xfer.doneIfs = 0;
        desc_ring[i].xfer.link = 0;
        desc_ring[i].xfer.linkMode = 0;
    }
}

/* Stamp metadata into chunk header */
static void stamp_chunk_metadata(uint8_t *chunk)
{
    if (chunk == NULL) return;

    // Write seed (0xDEEB) in big-endian
    chunk[0] = (uint8_t)(g_chunk_seed >> 8);
    chunk[1] = (uint8_t)(g_chunk_seed & 0xFF);
    
    // Compute checksums for validation
    uint8_t checksum = 0, checksum2 = 0;
    for (uint32_t i = 4; i < 10; i++) {
        checksum ^= chunk[i];
    }
    for (uint32_t i = CHUNK_BYTES - 10; i < CHUNK_BYTES - 1; i++) {
        checksum2 ^= chunk[i];
    }
    chunk[2] = checksum;
    chunk[3] = checksum2;
}

/* Start LDMA transfer */
static bool ldma_start_tx(void)
{
    if (g_ldma_active) return false;

    CORE_DECLARE_IRQ_STATE;
    CORE_ENTER_CRITICAL();
    uint8_t idx;
    bool have = q_pop(&g_tx_h, &g_tx_n, g_tx_q, &idx);
    CORE_EXIT_CRITICAL();

    if (!have) return false;

    g_current_tx_idx = idx;

    // Assert CS with minimal setup time
    GPIO_PinOutClear(SPI_CS_PORT, SPI_CS_PIN);
    for (volatile int i = 0; i < 10; i++);  // Minimal setup time

    // Configure LDMA for EUSART0 TX
#if defined(LDMAXBAR)
    LDMAXBAR->CH[LDMA_CHANNEL_TX].REQSEL = ldmaPeripheralSignal_EUSART0_TXFL;
#else
    LDMA->CH[LDMA_CHANNEL_TX].REQSEL = ldmaPeripheralSignal_EUSART0_TXFL;
#endif

    LDMA->CH[LDMA_CHANNEL_TX].LOOP = 0;
    LDMA->CH[LDMA_CHANNEL_TX].CFG = 
        (1 << _LDMA_CH_CFG_ARBSLOTS_SHIFT) |
        (0 << _LDMA_CH_CFG_SRCINCSIGN_SHIFT) |
        (0 << _LDMA_CH_CFG_DSTINCSIGN_SHIFT);

    // Set descriptor address
    LDMA->CH[LDMA_CHANNEL_TX].LINK = (uint32_t)&desc_ring[idx] & _LDMA_CH_LINK_LINKADDR_MASK;

    // Clear done flag and start
    BUS_RegMaskedClear(&LDMA->CHDONE, (1u << LDMA_CHANNEL_TX));
    LDMA->LINKLOAD = (1u << LDMA_CHANNEL_TX);
    
    g_ldma_active = true;

    return true;
}

static void ldma_stop_tx(void)
{
    if (!g_ldma_active) return;

    // Wait for completion
    while (!(LDMA->CHDONE & (1u << LDMA_CHANNEL_TX))) {
        /* spin */
    }
    BUS_RegMaskedClear(&LDMA->CHDONE, (1u << LDMA_CHANNEL_TX));

#if defined(_LDMA_CHDIS_MASK)
    LDMA->CHDIS = (1u << LDMA_CHANNEL_TX);
#else
    BUS_RegMaskedClear(&LDMA->CHEN, (1u << LDMA_CHANNEL_TX));
#endif

    g_ldma_active = false;
    g_current_tx_idx = 0xFF;
    GPIO_PinOutSet(SPI_CS_PORT, SPI_CS_PIN);
}

/* SPI initialization for Seeed XIAO MG24 */
static void spi_init(void)
{
    // Reset queues
    g_free_h = g_free_t = 0; g_free_n = 0;
    g_ready_h = g_ready_t = 0; g_ready_n = 0;
    g_tx_h = g_tx_t = 0; g_tx_n = 0;
    g_hist_h = g_hist_t = 0; g_hist_n = 0;

    memset(g_chunks, 0, sizeof(g_chunks));

    g_chunk_seed = 0xDEEBu;
    g_chunk_counter = 0;

    // Initialize free queue
    for (uint8_t i = 0; i < RING_N; i++) {
        g_free_q[i] = i;
        g_free_n++;
    }
    g_free_t = RING_N;

    // Enable clocks
    CMU_ClockEnable(cmuClock_GPIO, true);
    CMU_ClockEnable(SPI_EUSART_CLK, true);

    // GPIO Setup for XIAO MG24
    GPIO_PinModeSet(SPI_SCLK_PORT, SPI_SCLK_PIN, gpioModePushPull, 0);  // D8
    GPIO_PinModeSet(SPI_MOSI_PORT, SPI_MOSI_PIN, gpioModePushPull, 0);  // D10
    GPIO_PinModeSet(SPI_MISO_PORT, SPI_MISO_PIN, gpioModeInputPull, 0); // D9
    GPIO_PinModeSet(SPI_CS_PORT,   SPI_CS_PIN,   gpioModePushPull, 1);  // D7

    // Route EUSART0 pins
    GPIO->EUSARTROUTE[SPI_EUSART_ROUTE_INDEX].TXROUTE =
        ((uint32_t)SPI_MOSI_PORT << _GPIO_EUSART_TXROUTE_PORT_SHIFT) |
        ((uint32_t)SPI_MOSI_PIN  << _GPIO_EUSART_TXROUTE_PIN_SHIFT);

    GPIO->EUSARTROUTE[SPI_EUSART_ROUTE_INDEX].RXROUTE =
        ((uint32_t)SPI_MISO_PORT << _GPIO_EUSART_RXROUTE_PORT_SHIFT) |
        ((uint32_t)SPI_MISO_PIN  << _GPIO_EUSART_RXROUTE_PIN_SHIFT);

#if defined(_GPIO_EUSART_SCLKROUTE_PORT_SHIFT)
    GPIO->EUSARTROUTE[SPI_EUSART_ROUTE_INDEX].SCLKROUTE =
        ((uint32_t)SPI_SCLK_PORT << _GPIO_EUSART_SCLKROUTE_PORT_SHIFT) |
        ((uint32_t)SPI_SCLK_PIN  << _GPIO_EUSART_SCLKROUTE_PIN_SHIFT);
#else
    GPIO->EUSARTROUTE[SPI_EUSART_ROUTE_INDEX].CLKROUTE =
        ((uint32_t)SPI_SCLK_PORT << _GPIO_EUSART_CLKROUTE_PORT_SHIFT) |
        ((uint32_t)SPI_SCLK_PIN  << _GPIO_EUSART_CLKROUTE_PIN_SHIFT);
#endif

    uint32_t routeen = GPIO_EUSART_ROUTEEN_TXPEN | GPIO_EUSART_ROUTEEN_RXPEN;
#if defined(GPIO_EUSART_ROUTEEN_SCLKPEN)
    routeen |= GPIO_EUSART_ROUTEEN_SCLKPEN;
#elif defined(GPIO_EUSART_ROUTEEN_CLKPEN)
    routeen |= GPIO_EUSART_ROUTEEN_CLKPEN;
#endif
    GPIO->EUSARTROUTE[SPI_EUSART_ROUTE_INDEX].ROUTEEN = routeen;

    // Init EUSART SPI with MSB-first for slave compatibility
    EUSART_SpiAdvancedInit_TypeDef advInit = {
        .csPolarity = eusartCsActiveLow,
        .invertIO = eusartInvertIODisable,
        .autoCsEnable = false,
        .msbFirst = true,  // MSB first - critical for SPI slave
        .autoCsSetupTime = 0,
        .autoCsHoldTime = 0,
        .autoInterFrameTime = 0,
        .autoTxEnable = false,
        .defaultTxData = 0,
        .dmaWakeUpOnRx = false,
        .prsRxEnable = false,
        .prsRxChannel = 0,
        .prsClockEnable = false,
        .prsClockChannel = 0,
        .RxFifoWatermark = eusartRxFiFoWatermark1Frame,
        .TxFifoWatermark = eusartTxFiFoWatermark1Frame,
        .forceLoad = false,
        .setupWindow = 0
    };

    EUSART_SpiInit_TypeDef init = EUSART_SPI_MASTER_INIT_DEFAULT_HF;
    init.clockMode = eusartClockMode0;
    init.bitRate = 13000000;  // 13 MHz SPI clock - maximum speed
    init.advancedSettings = &advInit;
    EUSART_SpiInit(SPI_EUSART, &init);

    GPIO_PinOutSet(SPI_CS_PORT, SPI_CS_PIN);

    ldma_init_system();
    g_last_stats_time = 0;
}

/* IQ energy calculation */
static uint32_t calculate_iq_energy_local(const uint8_t *iq_data, uint16_t num_bytes)
{
    uint64_t energy = 0;
    const int16_t *samples = (const int16_t *)iq_data;
    uint16_t num_samples = num_bytes / 2;
    if (num_samples > 128) num_samples = 128;
    
    for (uint16_t i = 0; i < num_samples; i++) {
        int32_t s = samples[i];
        energy += (uint32_t)(s * s);
    }
    return (num_samples > 0) ? (uint32_t)(energy / num_samples) : 0;
}

/* Public API */
void ble_packet_monitor_init(RAIL_Handle_t rail_handle)
{
    for(volatile int i = 0; i < 100000; i++);

    printf("# Initializing BLE IQ monitor for Seeed XIAO MG24...\r\n");
    printf("# Pin Config: D8=PA03(CLK), D9=PA04(MISO), D10=PA05(MOSI), D7=PC07(CS)\r\n");
        printf("# Auto energy threshold start=%u (min=%u, max=%u), target=%u Mbps\r\n",
            (unsigned)g_energy_thresh,
            (unsigned)ENERGY_THRESH_MIN,
            (unsigned)ENERGY_THRESH_MAX,
            (unsigned)TARGET_MBPS);

    if (rail_handle == NULL) {
        printf("# FATAL: RAIL handle NULL\r\n");
        return;
    }

    spi_init();

    RAIL_Idle(rail_handle, RAIL_IDLE_ABORT, true);
    if (RAIL_BLE_Init(rail_handle) != RAIL_STATUS_NO_ERROR) {
        printf("# ERROR: RAIL_BLE_Init failed\r\n");
    }

    RAIL_BLE_ConfigChannelRadioParams(rail_handle, 0x555555, 0x8E89BED6, 37, true);

    RAIL_StateTransitions_t transitions = {
        .success = RAIL_RF_STATE_RX,
        .error = RAIL_RF_STATE_RX
    };
    RAIL_SetRxTransitions(rail_handle, &transitions);

    RAIL_DataConfig_t data_config = {
        .txSource = TX_PACKET_DATA,
        .rxSource = RX_IQDATA_FILTLSB,
        .txMethod = FIFO_MODE,
        .rxMethod = FIFO_MODE,
    };
    RAIL_ConfigData(rail_handle, &data_config);

    uint16_t fifo_size = RX_FIFO_SIZE;
    RAIL_SetRxFifo(rail_handle, rx_fifo, &fifo_size);
    RAIL_SetRxFifoThreshold(rail_handle, RX_FIFO_THRESHOLD);
    RAIL_ResetFifo(rail_handle, false, true);

    RAIL_Events_t ev = RAIL_EVENT_RX_FIFO_ALMOST_FULL | RAIL_EVENT_RX_FIFO_OVERFLOW;
    RAIL_ConfigEvents(rail_handle, ev, ev);

    RAIL_StartRx(rail_handle, 0, NULL);
    g_start_time = RAIL_GetTime();
    g_last_stats_time = g_start_time;

    uint32_t bitrate = RAIL_GetBitRate(rail_handle);
    uint32_t symbolrate = RAIL_GetSymbolRate(rail_handle);

    printf("# Seeed XIAO MG24 BLE IQ streaming READY @ 20 MHz SPI (OPTIMIZED)\r\n");
    printf("# Buffer: %u x %u B = %lu KB\r\n",
           RING_N, CHUNK_BYTES, (unsigned long)(RING_N * CHUNK_BYTES / 1024));
    printf("# RAIL: bitrate=%u bps, symbolrate=%u sps\r\n", bitrate, symbolrate);
}

/* ISR event handler */
void ble_packet_monitor_on_event(RAIL_Handle_t rail_handle, RAIL_Events_t events)
{
    (void)rail_handle;
    g_pending_events |= events;

    if (events & (RAIL_EVENT_RX_FIFO_ALMOST_FULL | RAIL_EVENT_RX_FIFO_OVERFLOW)) {
        if (g_free_n == 0) {
            uint8_t junk[256];
            uint16_t avail = RAIL_GetRxFifoBytesAvailable(rail_handle);
            while (avail > 1000) {
                uint16_t chunk = (avail > sizeof(junk)) ? sizeof(junk) : avail;
                RAIL_ReadRxFifo(rail_handle, junk, chunk);
                // printf("# WARNING: RX FIFO overflow, dropped %u bytes\r\n", (unsigned)avail);
                avail -= chunk;
                g_dropped_bytes += chunk;
                
            }
            return;
        }

        uint8_t idx = g_free_q[g_free_h];
        uint8_t *dest = g_chunks[idx];
        
        #if TEST_FIXED_IQ
            fill_fixed_iq(dest + 4, CHUNK_BYTES - 4);
            uint16_t got = CHUNK_BYTES - 4;
        #else
            uint16_t got = RAIL_ReadRxFifo(rail_handle, dest + 4, CHUNK_BYTES - 4);
        #endif

        if (got > 0) {
            // Pad to 4-byte boundary
            uint16_t remainder = got % 4;
            if (remainder != 0) {
                uint16_t pad_bytes = 4 - remainder;
                memset(dest + 4 + got, 0, pad_bytes);
                got += pad_bytes;
            }
            
            // Zero-fill rest
            if (got < (CHUNK_BYTES - 4)) {
                memset(dest + 4 + got, 0, (CHUNK_BYTES - 4) - got);
            }

            CORE_DECLARE_IRQ_STATE;
            CORE_ENTER_CRITICAL();
            g_free_h = (uint8_t)((g_free_h + 1) % RING_N);
            g_free_n--;
            q_push(&g_ready_t, &g_ready_n, g_ready_q, idx);
            CORE_EXIT_CRITICAL();
        }
    }
}

/* Main processing loop - FIXED: Process multiple chunks aggressively */
void ble_packet_monitor_process(RAIL_Handle_t rail_handle)
{
    (void)rail_handle;

    // Poll LDMA completion multiple times per cycle
    for (int i = 0; i < 5; i++) {
        ldma_poll_completion();
    }

    CORE_DECLARE_IRQ_STATE;
    CORE_ENTER_CRITICAL();
    RAIL_Events_t ev = g_pending_events;
    g_pending_events = 0;
    CORE_EXIT_CRITICAL();

    if (ev & RAIL_EVENT_RX_FIFO_OVERFLOW) {
        RAIL_ResetFifo(rail_handle, false, true);
        g_dropped_bytes += CHUNK_BYTES;
    }

    // Process ready buffers - with energy trigger logic (drain aggressively)
    for (int iter = 0; iter < g_ready_n; ++iter) {
        uint8_t idx;
        CORE_DECLARE_IRQ_STATE;
        CORE_ENTER_CRITICAL();
        bool have = q_pop(&g_ready_h, &g_ready_n, g_ready_q, &idx);
        CORE_EXIT_CRITICAL();

        if (!have) break;

        // Calculate energy from IQ data (skip 4-byte header)
        uint32_t energy = calculate_iq_energy_local(g_chunks[idx] + 4, CHUNK_BYTES - 4);

        // Trigger logic with history
        if (cap_state == CAP_STATE_IDLE) {
            if (energy > g_energy_thresh) {
                // Trigger detected: push history (oldest->newest) to TX
                CORE_DECLARE_IRQ_STATE;
                CORE_ENTER_CRITICAL();
                uint8_t pre_idx;
                while (g_hist_n > 0) {
                    q_pop(&g_hist_h, &g_hist_n, g_hist_q, &pre_idx);
                    stamp_chunk_metadata(g_chunks[pre_idx]);
                    q_push(&g_tx_t, &g_tx_n, g_tx_q, pre_idx);
                }
                // Push the triggering chunk
                stamp_chunk_metadata(g_chunks[idx]);
                q_push(&g_tx_t, &g_tx_n, g_tx_q, idx);
                CORE_EXIT_CRITICAL();

                g_capturing_active = true;
                cap_state = CAP_STATE_POST;
                post_remaining = POSTTRIGGER_CHUNKS;

            } else {
                // No trigger → add to history (keep at most PRETRIGGER_CHUNKS)
                CORE_DECLARE_IRQ_STATE;
                CORE_ENTER_CRITICAL();
                q_push(&g_hist_t, &g_hist_n, g_hist_q, idx);
                // If history grew too large, pop oldest and return to free
                if (g_hist_n > PRETRIGGER_CHUNKS) {
                    uint8_t old_idx;
                    q_pop(&g_hist_h, &g_hist_n, g_hist_q, &old_idx);
                    q_push(&g_free_t, &g_free_n, g_free_q, old_idx);
                }
                CORE_EXIT_CRITICAL();
            }
        } else { // CAP_STATE_POST
            // In post-capture mode: send this chunk
            CORE_DECLARE_IRQ_STATE;
            CORE_ENTER_CRITICAL();
            stamp_chunk_metadata(g_chunks[idx]);
            q_push(&g_tx_t, &g_tx_n, g_tx_q, idx);
            CORE_EXIT_CRITICAL();
            
            if (post_remaining > 0) post_remaining--;
            if (energy > g_energy_thresh) {
                // Retrigger: reset post counter
                post_remaining = POSTTRIGGER_CHUNKS;
            }
            if (post_remaining == 0) {
                cap_state = CAP_STATE_IDLE;
                g_capturing_active = false;  // Reset capture flag
            }
        }
    }

    // Start LDMA if idle and chunks available
    if (!g_ldma_active && g_tx_n > 0) {
        ldma_start_tx();
    }

    // Stats every 5 seconds
    uint32_t now = RAIL_GetTime();
    if (g_last_stats_time == 0) g_last_stats_time = now;
    if ((now - g_last_stats_time) >= 5000000U) {
        uint32_t kb_sent = (uint32_t)(g_bytes_sent / 1024);
        uint32_t elapsed_us = now - g_last_stats_time;
        uint32_t mbps = 0;
        if (elapsed_us > 1000000U) {
            mbps = (uint32_t)((g_bytes_sent * 8) / elapsed_us);
        }
        // Auto-tune energy threshold to hold target throughput and avoid drops
        bool had_drop = (g_dropped_bytes != 0);
        uint32_t new_thresh = g_energy_thresh;
        uint32_t upper_target = (uint32_t)(TARGET_MBPS * 11U / 10U);
        uint32_t lower_target = (uint32_t)(TARGET_MBPS * 9U / 10U);

        // Bound the adjustment step to avoid slamming to min/max when ENERGY_ADJUST_PCT is large
        uint32_t delta = (g_energy_thresh * ENERGY_ADJUST_PCT) / 100U;
        if (delta == 0) delta = 1;
        uint32_t delta_cap = g_energy_thresh / 2U;  // never move more than 50% per step
        if (delta > delta_cap) delta = delta_cap;

        if (had_drop || (mbps > upper_target)) {
            new_thresh = g_energy_thresh + delta;
        } else if (!had_drop && (mbps < lower_target)) {
            if (g_energy_thresh > delta) {
                new_thresh = g_energy_thresh - delta;
            } else {
                new_thresh = ENERGY_THRESH_MIN;
            }
        }

        if (new_thresh < ENERGY_THRESH_MIN) new_thresh = ENERGY_THRESH_MIN;
        if (new_thresh > ENERGY_THRESH_MAX) new_thresh = ENERGY_THRESH_MAX;
        g_energy_thresh = new_thresh;

        printf("# TX: chunks=%lu (%lu KB), dropped=%lu, speed=%lu Mbps, "
               "tx_q=%u, ready=%u, free=%u, hist=%u, cap=%s, ethresh=%u\r\n",
               (unsigned long)g_chunks_sent,
               (unsigned long)kb_sent,
               (unsigned long)g_dropped_bytes,
               (unsigned long)mbps,
               (unsigned)g_tx_n,
               (unsigned)g_ready_n,
               (unsigned)g_free_n,
               (unsigned)g_hist_n,
               g_capturing_active ? "YES" : "NO",
               (unsigned)g_energy_thresh);
        g_last_stats_time = now;
        g_chunks_sent = 0;
        g_bytes_sent = 0;
        g_dropped_bytes = 0;
    }
}

void ble_packet_monitor_stop(void)
{
    ldma_stop_tx();
}