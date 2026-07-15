/*
 * ESP32 Firmware - ASCON-128 Audio Pipeline  [BRAM-DECRYPT / REAL-TIME]
 * *** NO LEVEL SHIFTER VERSION ***
 *
 * BUG FIXES APPLIED:
 *
 * [BUG2-FIX] Muffled/slow audio — waitFifoNotEmpty and sendFifoRead delays
 * [BUG1-FIX] 255-chunk hard limit — fixed upstream (total_chunks_out 10-bit)
 * [BUG3-FIX] [Dec done] looping — fixed in uart_controller_menu.v (FPGA side)
 * [BUG4-FIX] >255 chunk decrypt truncation — buildFrame and sendEndOfSession
 *   now write both byte114 (LSB) and byte115 (upper 2 bits) of total_chunks.
 * [BUG5-FIX] Low volume — expand 8-bit back to full 32-bit range
 * [BUG6-FIX] Half-speed audio — stereo-interleaved I2S TX frames
 * [BUG7-FIX] Stereo mismatch on mic capture — dma_buf widened to CHUNK_SIZE*2
 * [BUG8-FIX] INMP441 bit extraction + DC removal — IIR high-pass filter
 *             removes the large DC offset that caused static/noise playback
 * [BUG9-FIX] Pitch/speed drift — use_apll enabled on both I2S ports
 * [BUG10-FIX] Mic static/dropouts — DMA buf count/len increased
 */

#include <Arduino.h>
#include <driver/i2s.h>
#include <SPI.h>

// ─── I2S format compatibility ─────────────────────────────────────────────────
#if defined(ARDUINO_ESP32_RELEASE_2) || ESP_ARDUINO_VERSION_MAJOR >= 2
  #define I2S_FORMAT_STD  I2S_COMM_FORMAT_STAND_I2S
#else
  #define I2S_FORMAT_STD  I2S_COMM_FORMAT_I2S
#endif

// ─── Configuration ────────────────────────────────────────────────────────────
#define SAMPLE_RATE        16050  // [SLOW-FIX] nudged from 16000: APLL
                                  // rounds down at 16000 Hz causing ~0.3%
                                  // slow playback; 16050 corrects the lock
#define MAX_RECORD_SECS    3
#define CHUNK_SIZE         64
#define MAX_CHUNKS         ((SAMPLE_RATE * MAX_RECORD_SECS + CHUNK_SIZE - 1) / CHUNK_SIZE)
#define FRAME_BYTES        256
#define SPI_CLOCK_HZ       1000000

#define ASCON_WAIT_MS      30
#define MAX_RETRIES        80

// [BUG2-FIX] RETRY_DELAY_MS: was 5 ms → 0.
#define RETRY_DELAY_MS     0

#define FSM_POLL_RETRIES   1000
#define FSM_POLL_DELAY_MS  50

#define FSM_GUARD_POLLS       2
#define FSM_GUARD_DELAY_MS    8

#define ZERO_MISO_EXTRA_WAIT_MS   25
#define ZERO_MISO_MAX_RETRIES      5

#define SPI_CS_SETUP_US    50

// [BUG8-FIX] INMP441 DC removal:
// The INMP441 outputs a large DC offset (~80M counts) that dominates the
// 32-bit I2S word. The "audio" without filtering is mostly this DC bias,
// which sounds like static and noise when played back.
// Fix: use the full signed 32-bit word with an IIR high-pass filter to
// remove DC before downscaling to 8-bit PCM.
// Alpha=0.995 gives ~25 Hz cutoff at 16 kHz — removes DC and sub-bass rumble
// while preserving all voice frequencies (300 Hz+).
#define MIC_DC_ALPHA        0.945f  // [CRISP-FIX] 0.995 cutoff=13 Hz caused phase
                                  // lag/smearing; 0.9 cutoff=255 Hz removes DC
                                  // while keeping voice crisp and present
#define MIC_GAIN_SHIFT      21   // right-shift after DC removal to fit int8 range

// ─── MISO offsets ─────────────────────────────────────────────────────────────
#define MISO_SENTINEL      64
#define MISO_CT_START      0
#define MISO_CT_LEN        64
#define MISO_TAG_START     65
#define MISO_TAG_LEN       16
#define MISO_NONCE_START   81
#define MISO_NONCE_LEN     16
#define MISO_KEYECHO_START 97
#define MISO_KEYECHO_LEN   16
#define POLL_KEY_START     0
#define POLL_KEY_LEN       16
#define POLL_FSM_BYTE      96
#define POLL_FIFO_BYTE     97    // bit[7] = fifo_not_empty

// ─── MOSI frame offsets ───────────────────────────────────────────────────────
#define MOSI_TOTAL_CHUNKS     114   // byte 114 = total_chunks[7:0]  (LSB)
#define MOSI_TOTAL_CHUNKS_HI  115   // byte 115 = total_chunks[9:8]  (2 MSBs)

#define FSM_ENC_READY      0xA5
#define FSM_DEC_READY      0x5A

// ─── Pins ─────────────────────────────────────────────────────────────────────
#define PIN_BTN      4
#define PIN_SPI_CS   5
#define I2S_MIC      I2S_NUM_0
#define I2S_SPK      I2S_NUM_1

// ─── Per-chunk encrypted packet ───────────────────────────────────────────────
struct AudioPacket {
    uint8_t ct   [CHUNK_SIZE];
    uint8_t tag  [MISO_TAG_LEN];
    uint8_t nonce[MISO_NONCE_LEN];
    uint8_t len;
    bool    valid;
};

// ─── Global state ─────────────────────────────────────────────────────────────
static AudioPacket* enc_packets     = nullptr;
static uint32_t     enc_chunk_count = 0;
static uint8_t      spi_frame[FRAME_BYTES];
static uint8_t      spi_resp [FRAME_BYTES];
static uint8_t      active_key[16]  = {0};
static bool         key_valid       = false;

// ═══════════════════════════════════════════════════════════════════════════════
// SPI PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════════

static void spiTransact(void)
{
    SPI.beginTransaction(SPISettings(SPI_CLOCK_HZ, MSBFIRST, SPI_MODE0));
    digitalWrite(PIN_SPI_CS, LOW);
    delayMicroseconds(SPI_CS_SETUP_US);
    SPI.transferBytes(spi_frame, spi_resp, FRAME_BYTES);
    delayMicroseconds(2);
    digitalWrite(PIN_SPI_CS, HIGH);
    SPI.endTransaction();
    delayMicroseconds(50);
}

static void pollFpga(void)
{
    memset(spi_frame, 0, FRAME_BYTES);
    spiTransact();
}

static void dumpBytes(const char* label, const uint8_t* buf, int n)
{
    Serial.print(label);
    for (int i = 0; i < n; i++) Serial.printf("%02X ", buf[i]);
    Serial.println();
}

static bool isAllZero(const uint8_t* buf, int n)
{
    for (int i = 0; i < n; i++) if (buf[i]) return false;
    return true;
}

static bool tryCapturePollKey(void)
{
    if (spi_resp[MISO_SENTINEL] != 0x00) return false;
    if (isAllZero(&spi_resp[POLL_KEY_START], POLL_KEY_LEN)) return false;
    memcpy(active_key, &spi_resp[POLL_KEY_START], POLL_KEY_LEN);
    key_valid = true;
    return true;
}

// ─── Wait for uart_fsm_state on MISO[96] ─────────────────────────────────────
static bool waitForFsmState(uint8_t expected, uint32_t chunk_idx)
{
    int attempt = 0;

    while (attempt < FSM_POLL_RETRIES) {

        pollFpga();

        uint8_t sentinel = spi_resp[MISO_SENTINEL];
        uint8_t fsm      = spi_resp[POLL_FSM_BYTE];

        if (!key_valid && sentinel == 0x00)
            if (tryCapturePollKey()) {
                Serial.print(F("[KEY] Captured: "));
                dumpBytes("", active_key, 16);
            }

        if (fsm == expected) {
            if (attempt > 0)
                Serial.printf("[FSM] chunk %u: 0x%02X confirmed attempt %d\n",
                              chunk_idx, expected, attempt);

            if (expected == FSM_ENC_READY) {
                bool guard_ok = true;
                for (int g = 0; g < FSM_GUARD_POLLS && guard_ok; g++) {
                    delay(FSM_GUARD_DELAY_MS);
                    pollFpga();
                    if (!key_valid && spi_resp[MISO_SENTINEL] == 0x00)
                        tryCapturePollKey();
                    if (spi_resp[POLL_FSM_BYTE] != expected) {
                        Serial.printf("[WARN] chunk %u: FSM dropped during guard (g=%d) → re-wait\n",
                                      chunk_idx, g);
                        guard_ok = false;
                        attempt  = 0;
                    }
                }
                if (!guard_ok) {
                    delay(FSM_POLL_DELAY_MS);
                    continue;
                }
            }
            return true;
        }

        if (attempt < 3 || attempt % 50 == 0)
            Serial.printf("[FSM] chunk %u attempt %d: sentinel=0x%02X fsm=0x%02X (want 0x%02X)\n",
                          chunk_idx, attempt, sentinel, fsm, expected);

        delay(FSM_POLL_DELAY_MS);
        attempt++;
    }

    Serial.printf("[ERR] FSM 0x%02X not reached at chunk %u\n", expected, chunk_idx);
    return false;
}

// ─── Build MOSI frame ─────────────────────────────────────────────────────────
static void buildFrame(uint8_t type,
                       const uint8_t* nonce,
                       const uint8_t* dec_tag,
                       const uint8_t* payload,
                       uint8_t payload_len,
                       uint16_t total_chunks = 0)
{
    memset(spi_frame, 0, FRAME_BYTES);
    spi_frame[0] = type;
    memcpy(&spi_frame[1],  active_key, 16);
    if (nonce)   memcpy(&spi_frame[17], nonce,   16);
    if (dec_tag) memcpy(&spi_frame[33], dec_tag, 16);
    spi_frame[49] = payload_len;
    if (payload && payload_len > 0)
        memcpy(&spi_frame[50], payload, payload_len);
    if (total_chunks > 0) {
        spi_frame[MOSI_TOTAL_CHUNKS]    = (uint8_t)(total_chunks & 0xFF);
        spi_frame[MOSI_TOTAL_CHUNKS_HI] = (uint8_t)((total_chunks >> 8) & 0x03);
    }
}

// ─── Poll for ASCON result sentinel=0xA5 ─────────────────────────────────────
static bool retrieveResult(uint32_t chunk_idx)
{
    delay(ASCON_WAIT_MS);

    int zero_retries = 0;
    int attempt      = 0;

    while (attempt <= MAX_RETRIES) {

        pollFpga();

        if (isAllZero(spi_resp, FRAME_BYTES)) {
            if (zero_retries < ZERO_MISO_MAX_RETRIES) {
                zero_retries++;
                delay(ZERO_MISO_EXTRA_WAIT_MS);
                continue;
            }
            Serial.printf("[ERR] chunk %u: persistent all-zero MISO\n", chunk_idx);
            return false;
        }

        if (spi_resp[MISO_SENTINEL] == 0xA5) {
            if (attempt > 0)
                Serial.printf("[RESULT] chunk %u on attempt %d\n", chunk_idx, attempt);
            return true;
        }

        if (RETRY_DELAY_MS > 0) delay(RETRY_DELAY_MS);
        attempt++;
    }

    Serial.printf("[ERR] No result at chunk %u after %d retries\n",
                  chunk_idx, MAX_RETRIES);
    return false;
}

// ─── Poll MISO[97] bit[7] for FPGA BRAM FIFO not-empty ──────────────────────
static bool waitFifoNotEmpty(uint32_t chunk_idx,
                             uint32_t max_polls   = 200,
                             uint32_t poll_delay  = 0)
{
    for (uint32_t i = 0; i < max_polls; i++) {
        pollFpga();
        if (spi_resp[MISO_SENTINEL] == 0x00) {
            if (spi_resp[POLL_FIFO_BYTE] & 0x80) {
                return true;
            }
        }
        if (poll_delay > 0) delay(poll_delay);
    }
    Serial.printf("[ERR] chunk %u: FIFO never became non-empty\n", chunk_idx);
    return false;
}

// ─── Send cmd 0x04 FIFO read and return the plaintext ────────────────────────
static bool sendFifoRead(uint32_t chunk_idx, uint8_t* dst)
{
    memset(spi_frame, 0, FRAME_BYTES);
    spi_frame[0] = 0x04;
    memcpy(&spi_frame[1], active_key, 16);
    spiTransact();

    if (spi_resp[MISO_SENTINEL] == 0xA5) {
        bool tag_ok = !isAllZero(&spi_resp[MISO_TAG_START], MISO_TAG_LEN);
        if (!tag_ok)
            Serial.printf("[WARN] chunk %u: BRAM tag verdict FAIL\n", chunk_idx);
        memcpy(dst, &spi_resp[MISO_CT_START], CHUNK_SIZE);
        return true;
    }

    delay(2);
    pollFpga();
    if (spi_resp[MISO_SENTINEL] == 0xA5) {
        bool tag_ok = !isAllZero(&spi_resp[MISO_TAG_START], MISO_TAG_LEN);
        if (!tag_ok)
            Serial.printf("[WARN] chunk %u: BRAM tag verdict FAIL (retry)\n", chunk_idx);
        memcpy(dst, &spi_resp[MISO_CT_START], CHUNK_SIZE);
        return true;
    }

    Serial.printf("[ERR] FIFO rd chunk %u: no 0xA5 sentinel\n", chunk_idx);
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// I2S
// ═══════════════════════════════════════════════════════════════════════════════

static void initMic(void)
{
    i2s_config_t cfg = {
        .mode                 = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX),
        .sample_rate          = SAMPLE_RATE,
        .bits_per_sample      = I2S_BITS_PER_SAMPLE_32BIT,
        .channel_format       = I2S_CHANNEL_FMT_ONLY_LEFT,
        .communication_format = I2S_FORMAT_STD,
        .intr_alloc_flags     = ESP_INTR_FLAG_LEVEL1,
        // [BUG10-FIX] Increased DMA buffer count and length to reduce
        // mic underruns that caused static in the captured audio.
        // dma_buf_count: 8  → 16
        // dma_buf_len:   64 → 128
        .dma_buf_count        = 16,
        .dma_buf_len          = 128,
        // [BUG9-FIX] use_apll: false → true.
        // Without APLL the ESP32 derives the I2S clock from the APB bus
        // (80 MHz), which cannot divide evenly to 16000 Hz. The resulting
        // clock error causes the mic to run slightly fast or slow, producing
        // lower-pitched / slower playback over multi-second recordings.
        // APLL generates a precise dedicated PLL for the exact sample rate.
        .use_apll             = true,
        .fixed_mclk           = 0
    };
    i2s_pin_config_t pins = {
        .mck_io_num   = I2S_PIN_NO_CHANGE,
        .bck_io_num   = 26, .ws_io_num = 25,
        .data_out_num = I2S_PIN_NO_CHANGE, .data_in_num = 22
    };
    ESP_ERROR_CHECK(i2s_driver_install(I2S_MIC, &cfg, 0, NULL));
    ESP_ERROR_CHECK(i2s_set_pin(I2S_MIC, &pins));
    i2s_zero_dma_buffer(I2S_MIC);
}

static void initSpeaker(void)
{
    i2s_config_t cfg = {
        .mode                 = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX),
        .sample_rate          = SAMPLE_RATE,
        .bits_per_sample      = I2S_BITS_PER_SAMPLE_32BIT,
        .channel_format       = I2S_CHANNEL_FMT_ONLY_LEFT,
        .communication_format = I2S_FORMAT_STD,
        .intr_alloc_flags     = ESP_INTR_FLAG_LEVEL1,
        .dma_buf_count        = 8,
        .dma_buf_len          = 128,
        // [BUG9-FIX] use_apll: false → true.
        // Speaker must use the same APLL-derived clock as the mic so that
        // the playback rate exactly matches the capture rate. Mismatched
        // clocks (even if both are "close") produce pitch shift on output.
        // [SLOW-FIX] dma_buf_count 4→8, dma_buf_len 64→128 to match mic
        // DMA geometry. Mismatched buffer sizes caused the TX DMA ring to
        // drain faster than the RX ring filled, producing slightly slow
        // playback (~3-5% speed deficit).
        .use_apll             = true,
        .tx_desc_auto_clear   = true,
        .fixed_mclk           = 0
    };
    i2s_pin_config_t pins = {
        .mck_io_num   = I2S_PIN_NO_CHANGE,
        .bck_io_num   = 27, .ws_io_num = 14,
        .data_out_num = 13, .data_in_num = I2S_PIN_NO_CHANGE
    };
    ESP_ERROR_CHECK(i2s_driver_install(I2S_SPK, &cfg, 0, NULL));
    ESP_ERROR_CHECK(i2s_set_pin(I2S_SPK, &pins));
    i2s_zero_dma_buffer(I2S_SPK);
}

// [BUG4-FIX] total_chunks widened uint8_t → uint16_t.
static void sendEndOfSession(uint16_t total_chunks = 0)
{
    memset(spi_frame, 0, FRAME_BYTES);
    spi_frame[0] = 0x05;
    memcpy(&spi_frame[1], active_key, 16);
    spi_frame[MOSI_TOTAL_CHUNKS]    = (uint8_t)(total_chunks & 0xFF);
    spi_frame[MOSI_TOTAL_CHUNKS_HI] = (uint8_t)((total_chunks >> 8) & 0x03);
    spiTransact();
    Serial.println(F("[ENC] End-of-session frame sent (cmd 0x05)."));
}

// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME ENCRYPT PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

static bool recordAndEncryptRealtime(void)
{
    if (!key_valid) {
        Serial.println(F("[ERR] No active key."));
        return false;
    }

    Serial.print(F("[ENC] Recording + encrypting. Key: "));
    dumpBytes("", active_key, 16);
    Serial.println(F("[ENC] Release button to stop (up to 3 s)."));

    enc_chunk_count = 0;
    uint32_t total_samples = 0;
    const uint32_t max_samples = (uint32_t)SAMPLE_RATE * MAX_RECORD_SECS;
    const uint8_t enc_total_placeholder = 0xFF;

    // [BUG7-FIX] dma_buf widened to CHUNK_SIZE*2: I2S_CHANNEL_FMT_ONLY_LEFT
    // in master-RX still delivers stereo-interleaved words [L,R,L,R,...].
    // Only Left-channel words (even indices) hold real audio; odd indices
    // are zero (Right channel). Buffer must be 2x to hold both.
    int32_t  dma_buf[CHUNK_SIZE * 2];

    // [BUG8-FIX] IIR high-pass filter state for DC removal.
    // Persists across chunks so the filter is continuous over the recording.
    float    dc_filter_x = 0.0f;   // previous raw input sample
    float    dc_filter_y = 0.0f;   // previous filtered output
    uint8_t  pcm8_pending[CHUNK_SIZE];
    uint8_t  n_pending   = 0;
    bool     has_pending = false;

    while (true) {
        bool button_held = (digitalRead(PIN_BTN) == LOW);
        bool limit_hit   = (enc_chunk_count >= MAX_CHUNKS ||
                            total_samples   >= max_samples);

        // ── Step 1: Read next I2S chunk ───────────────────────────────────────
        uint8_t pcm8_new[CHUNK_SIZE] = {0};
        uint8_t n_new = 0;

        if (button_held && !limit_hit) {
            size_t bytes_read = 0;
            i2s_read(I2S_MIC, dma_buf, sizeof(dma_buf), &bytes_read, portMAX_DELAY);
            // [BUG7-FIX] Divide word count by 2 (stereo pairs → mono samples).
            // Step dma_buf[i*2] to read only Left-channel words.
            uint32_t n_smp = (bytes_read / sizeof(int32_t)) / 2;
            if (n_smp > 0) {
                uint32_t remaining = max_samples - total_samples;
                if (n_smp > remaining)  n_smp = remaining;
                if (n_smp > CHUNK_SIZE) n_smp = CHUNK_SIZE;
                for (uint32_t i = 0; i < n_smp; i++) {
                    // [BUG8-FIX] INMP441 DC removal via IIR high-pass filter.
                    //
                    // Root cause of static/noise: the INMP441 outputs a large
                    // DC offset (~80 million counts in 32-bit signed) that
                    // completely dominates the raw word. Using any fixed bit
                    // shift (>> 8, >> 16, >> 24) extracts a mix of DC + signal,
                    // which sounds like low-frequency rumble and static.
                    //
                    // Fix: treat the full signed 32-bit word as the input to
                    // an IIR high-pass filter:
                    //   y[n] = x[n] - x[n-1] + ALPHA * y[n-1]
                    // This removes all DC and sub-bass below ~25 Hz, leaving
                    // clean voice (300 Hz+) in the residual.
                    //
                    // After filtering, right-shift by MIC_GAIN_SHIFT (21) to
                    // scale the float residual into int8_t range, then offset
                    // by 128 to convert to unsigned uint8_t for the pipeline.
                    float raw_f = (float)(int32_t)dma_buf[i * 2];
                    float filtered = raw_f - dc_filter_x + MIC_DC_ALPHA * dc_filter_y;
                    dc_filter_x = raw_f;
                    dc_filter_y = filtered;
                    int32_t scaled = (int32_t)(filtered) >> MIC_GAIN_SHIFT;
                    if (scaled >  127) scaled =  127;
                    if (scaled < -128) scaled = -128;
                    pcm8_new[i] = (uint8_t)((int8_t)scaled + 128);
                }
                n_new = (uint8_t)n_smp;
            }
        }

        // ── Step 2: Collect ASCON result for the PREVIOUS chunk ───────────────
        if (has_pending) {
            bool ok = false;
            int zero_retries = 0;
            for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
                pollFpga();
                if (isAllZero(spi_resp, FRAME_BYTES)) {
                    if (zero_retries < ZERO_MISO_MAX_RETRIES) {
                        zero_retries++;
                        delay(ZERO_MISO_EXTRA_WAIT_MS);
                        continue;
                    }
                    Serial.printf("[ERR] chunk %u: all-zero MISO\n", enc_chunk_count);
                    break;
                }
                if (spi_resp[MISO_SENTINEL] == 0xA5) { ok = true; break; }
            }

            if (!ok) {
                sendEndOfSession((uint16_t)enc_chunk_count);
                return false;
            }

            AudioPacket& pkt = enc_packets[enc_chunk_count];
            memset(&pkt, 0, sizeof(AudioPacket));
            memcpy(pkt.ct,    &spi_resp[MISO_CT_START],    MISO_CT_LEN);
            memcpy(pkt.tag,   &spi_resp[MISO_TAG_START],   MISO_TAG_LEN);
            memcpy(pkt.nonce, &spi_resp[MISO_NONCE_START], MISO_NONCE_LEN);
            pkt.len   = n_pending;
            pkt.valid = !isAllZero(pkt.nonce, MISO_NONCE_LEN);

            if (!pkt.valid)
                Serial.printf("[WARN] chunk %u: all-zero nonce — invalid\n", enc_chunk_count);
            if (memcmp(&spi_resp[MISO_KEYECHO_START], active_key, 16) != 0) {
                Serial.printf("[WARN] chunk %u: key echo mismatch!\n", enc_chunk_count);
                pkt.valid = false;
            }

            total_samples += n_pending;
            enc_chunk_count++;
            has_pending = false;

            if (enc_chunk_count % 50 == 0 || enc_chunk_count == 1)
                Serial.printf("[ENC] Chunk %u OK (%.2f s)\n",
                              enc_chunk_count, (float)total_samples / SAMPLE_RATE);
        }

        // ── Step 3: Send the new chunk ────────────────────────────────────────
        if (n_new > 0) {
            memcpy(pcm8_pending, pcm8_new, n_new);
            n_pending = n_new;

            buildFrame(0x01, nullptr, nullptr, pcm8_new, n_new, enc_total_placeholder);
            spiTransact();
            has_pending = true;
        }

        // ── Step 4: Exit when button released AND pipeline drained ────────────
        if (!button_held && !has_pending) break;
        if (limit_hit    && !has_pending) break;
    }

    sendEndOfSession((uint16_t)enc_chunk_count);
    Serial.printf("[ENC] Done. %u chunks, %.2f s.\n",
                  enc_chunk_count, (float)(enc_chunk_count * CHUNK_SIZE) / SAMPLE_RATE);
    Serial.println(F("================================================"));
    Serial.println(F("  Encryption complete."));
    Serial.printf("  Total chunks: %u\n", enc_chunk_count);
    Serial.println(F("  PuTTY: press [4], type key, TAP button."));
    Serial.println(F("================================================"));
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DECRYPT + PLAY — BRAM FIFO PATH
// ═══════════════════════════════════════════════════════════════════════════════

static void decryptAndPlay(void)
{
    if (enc_chunk_count == 0) {
        Serial.println(F("[PLAY] No encrypted audio. Record first."));
        return;
    }

    Serial.println(F("[DEC] Waiting for FPGA dec-ready (0x5A)..."));
    Serial.println(F("      Press [4] in PuTTY and type the key now."));

    key_valid = false;

    if (!waitForFsmState(FSM_DEC_READY, 0)) {
        Serial.println(F("[ERR] FPGA dec-ready timeout."));
        return;
    }

    if (!key_valid) {
        for (int i = 0; i < 20 && !key_valid; i++) {
            delay(30);
            pollFpga();
            if (spi_resp[MISO_SENTINEL] == 0x00)
                tryCapturePollKey();
        }
    }

    if (!key_valid) {
        Serial.println(F("[ERR] Cannot read key. Check PuTTY [4] + key."));
        return;
    }

    Serial.print(F("[DEC] Key: "));
    dumpBytes("", active_key, 16);
    Serial.printf("[DEC] Decrypting + streaming %u chunks via BRAM FIFO.\n",
                  enc_chunk_count);

    // [BUG4-FIX] dec_total: uint8_t→uint16_t, 255-cap removed.
    const uint16_t dec_total = (uint16_t)enc_chunk_count;

    uint8_t  pt_chunk[CHUNK_SIZE];
    uint32_t tag_fail_count = 0;
    uint32_t skip_count     = 0;
    uint32_t total_played   = 0;

    i2s_zero_dma_buffer(I2S_SPK);

    for (uint32_t ci = 0; ci < enc_chunk_count; ci++) {

        AudioPacket& pkt = enc_packets[ci];

        if (!pkt.valid) {
            Serial.printf("[SKIP] chunk %u: invalid packet\n", ci);
            skip_count++;
            memset(pt_chunk, 0x80, pkt.len ? pkt.len : CHUNK_SIZE);
            goto play_chunk;
        }

        // ── Step A: Send 0x02 decrypt frame ──────────────────────────────────
        buildFrame(0x02, pkt.nonce, pkt.tag, pkt.ct, CHUNK_SIZE, dec_total);
        spiTransact();

        // ── Step B: Poll MISO[97] bit[7] = fifo_not_empty ────────────────────
        if (!waitFifoNotEmpty(ci, 200, 0)) {
            Serial.printf("[ERR] chunk %u: FIFO timeout, using silence\n", ci);
            tag_fail_count++;
            memset(pt_chunk, 0x80, CHUNK_SIZE);
            goto play_chunk;
        }

        // ── Step C: Send cmd 0x04 — FIFO read ────────────────────────────────
        if (!sendFifoRead(ci, pt_chunk)) {
            tag_fail_count++;
            memset(pt_chunk, 0x80, CHUNK_SIZE);
            if (tag_fail_count > 5) {
                Serial.println(F("[ERR] Too many FIFO read failures, aborting."));
                return;
            }
            goto play_chunk;
        }

        // ── Diagnostic: log first 3 chunks' plaintext bytes ──────────────────
        if (ci < 3) {
            Serial.printf("[DBG] chunk %u pt_chunk: ", ci);
            dumpBytes("", pt_chunk, 16);
        }

        play_chunk:
        {
            // ── Step D: Write plaintext to I2S speaker ────────────────────────
            // [BUG6-FIX] Stereo-interleaved TX: write Left+Right word pair per
            // sample so the DMA ring fills at the correct rate for the stereo
            // BCK/WS clock. Writing only Left words caused half-speed playback.
            // [BUG5-FIX] Expand 8-bit unsigned PCM to full 32-bit signed range:
            // (int32_t)((int8_t)(s-128)) << 24 fills all 32 bits at full scale.

            uint8_t n = pkt.valid ? pkt.len : (uint8_t)CHUNK_SIZE;

            int32_t tmp[CHUNK_SIZE * 2];
            for (uint8_t i = 0; i < n; i++) {
                int32_t sample = (int32_t)((int8_t)(pt_chunk[i] - 128)) << 24;
                tmp[i * 2]     = sample;  // Left channel  → DAC output
                tmp[i * 2 + 1] = 0;       // Right channel → silent
            }

            size_t bw = 0;
            i2s_write(I2S_SPK, tmp, (size_t)n * 2 * sizeof(int32_t), &bw, portMAX_DELAY);
            total_played += n;

            if ((ci + 1) % 50 == 0 || ci == 0)
                Serial.printf("[DEC] Chunk %u OK (%.2f s)\n",
                              ci + 1, (float)total_played / SAMPLE_RATE);
        }
    }

    Serial.printf("[PLAY] Done. %.2f s played. tag_fails=%u skipped=%u / %u chunks\n",
                  (float)total_played / SAMPLE_RATE,
                  tag_fail_count, skip_count, enc_chunk_count);
    if (tag_fail_count == 0 && skip_count == 0)
        Serial.println(F("[PLAY] All chunks OK — BRAM FIFO decrypt pipeline."));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SETUP
// ═══════════════════════════════════════════════════════════════════════════════

void setup(void)
{
    Serial.begin(115200);
    delay(500);

    Serial.println(F("\n================================================"));
    Serial.println(F("  ASCON-128 Real-Time Audio Encryption"));
    Serial.println(F("  BRAM FIFO Decrypt / Real-Time Record"));
    Serial.println(F("================================================"));
    Serial.println(F("  ENCRYPT: PuTTY [3] + key → HOLD button"));
    Serial.println(F("  DECRYPT: PuTTY [4] + key → TAP button"));
    Serial.println(F("================================================\n"));

    enc_packets = (AudioPacket*)malloc(MAX_CHUNKS * sizeof(AudioPacket));
    if (!enc_packets) {
        Serial.println(F("[FATAL] malloc failed for enc_packets"));
        while (true) delay(1000);
    }
    memset(enc_packets, 0, MAX_CHUNKS * sizeof(AudioPacket));

    uint32_t enc_size = (uint32_t)MAX_CHUNKS * sizeof(AudioPacket);
    Serial.printf("[MEM] enc_packets: %u KB | free heap: %u KB\n",
                  enc_size / 1024, ESP.getFreeHeap() / 1024);
    Serial.printf("[CFG] MAX_CHUNKS=%u  CHUNK_SIZE=%u  SAMPLE_RATE=%u\n",
                  MAX_CHUNKS, CHUNK_SIZE, SAMPLE_RATE);

    pinMode(PIN_BTN,    INPUT_PULLUP);
    pinMode(PIN_SPI_CS, OUTPUT);
    digitalWrite(PIN_SPI_CS, HIGH);

    SPI.begin();
    initSpeaker();
    initMic();
    Serial.println(F("[OK] Ready."));
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP
// ═══════════════════════════════════════════════════════════════════════════════

void loop(void)
{
    if (digitalRead(PIN_BTN) != LOW) return;
    delay(20);
    if (digitalRead(PIN_BTN) != LOW) return;

    uint32_t press_start = millis();
    while (digitalRead(PIN_BTN) == LOW && (millis() - press_start) < 300)
        delay(5);

    if (digitalRead(PIN_BTN) == LOW) {
        // ── HOLD: encrypt ─────────────────────────────────────────────────────
        Serial.println(F("\n[BTN] HOLD — record + encrypt."));
        Serial.println(F("[ENC] Waiting for FPGA enc-ready (0xA5)..."));
        Serial.println(F("      Press [3] in PuTTY and type 16-char key NOW."));

        key_valid = false;
        if (!waitForFsmState(FSM_ENC_READY, 0)) {
            Serial.println(F("[ERR] FPGA enc-ready timeout."));
            while (digitalRead(PIN_BTN) == LOW) delay(10);
            return;
        }

        if (!key_valid) {
            for (int i = 0; i < 20 && !key_valid; i++) {
                delay(30);
                pollFpga();
                if (spi_resp[MISO_SENTINEL] == 0x00)
                    if (tryCapturePollKey()) {
                        Serial.print(F("[KEY] Captured: "));
                        dumpBytes("", active_key, 16);
                    }
            }
        }

        if (!key_valid) {
            Serial.println(F("[ERR] Cannot read key. Check PuTTY [3] + key."));
            while (digitalRead(PIN_BTN) == LOW) delay(10);
            return;
        }

        if (digitalRead(PIN_BTN) != LOW) {
            Serial.println(F("[WARN] Button released — cancelled."));
            return;
        }

        enc_chunk_count = 0;
        recordAndEncryptRealtime();

    } else {
        // ── TAP: decrypt via BRAM FIFO ────────────────────────────────────────
        Serial.println(F("\n[BTN] TAP — decrypt + play (BRAM FIFO)."));
        if (enc_chunk_count == 0) {
            Serial.println(F("[ERR] No encrypted data. HOLD to record first."));
            return;
        }
        decryptAndPlay();
    }
}