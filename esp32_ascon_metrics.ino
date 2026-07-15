#include <Arduino.h>
#include <driver/i2s.h>
#include <SPI.h>
#include <math.h>

#if defined(ARDUINO_ESP32_RELEASE_2) || ESP_ARDUINO_VERSION_MAJOR >= 2
  #define I2S_FORMAT_STD  I2S_COMM_FORMAT_STAND_I2S
#else
  #define I2S_FORMAT_STD  I2S_COMM_FORMAT_I2S
#endif

// ── Config ────────────────────────────────────────────────────────────────────
#define SAMPLE_RATE        16050
#define MAX_RECORD_SECS    3
#define CHUNK_SIZE         64
#define MAX_CHUNKS         ((SAMPLE_RATE * MAX_RECORD_SECS + CHUNK_SIZE - 1) / CHUNK_SIZE)
#define FRAME_BYTES        256
#define SPI_CLOCK_HZ       1000000

#define ASCON_WAIT_MS      30
#define MAX_RETRIES        80
#define RETRY_DELAY_MS     0

#define FSM_POLL_RETRIES   1000
#define FSM_POLL_DELAY_MS  50
#define FSM_GUARD_POLLS    2
#define FSM_GUARD_DELAY_MS 8

#define ZERO_MISO_EXTRA_WAIT_MS  25
#define ZERO_MISO_MAX_RETRIES     5

#define SPI_CS_SETUP_US    50
#define MIC_DC_ALPHA       0.945f
#define MIC_GAIN_SHIFT     21

// ── MISO/MOSI offsets ─────────────────────────────────────────────────────────
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
#define POLL_FIFO_BYTE     97
#define MOSI_TOTAL_CHUNKS    114
#define MOSI_TOTAL_CHUNKS_HI 115

#define FSM_ENC_READY  0xA5
#define FSM_DEC_READY  0x5A

// ── Pins ──────────────────────────────────────────────────────────────────────
#define PIN_BTN    4
#define PIN_SPI_CS 5
#define I2S_MIC    I2S_NUM_0
#define I2S_SPK    I2S_NUM_1

// ── Per-chunk encrypted packet ────────────────────────────────────────────────
struct AudioPacket {
    uint8_t ct   [CHUNK_SIZE];
    uint8_t tag  [MISO_TAG_LEN];
    uint8_t nonce[MISO_NONCE_LEN];
    uint8_t len;
    bool    valid;
};

// ── Global state ──────────────────────────────────────────────────────────────
static AudioPacket* enc_packets     = nullptr;
static uint32_t     enc_chunk_count = 0;
static uint8_t      spi_frame[FRAME_BYTES];
static uint8_t      spi_resp [FRAME_BYTES];
static uint8_t      active_key[16]  = {0};
static bool         key_valid       = false;

// pcm_pre_enc  : uint8 PCM captured after IIR filter+gain, before SPI encrypt
// pcm_post_dec : uint8 PCM received from BRAM FIFO decrypt, before I2S play
static uint8_t* pcm_pre_enc  = nullptr;
static uint8_t* pcm_post_dec = nullptr;

static uint32_t metrics_tag_ok_count     = 0;
static uint32_t metrics_chunk_drop_count = 0;

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
                if (!guard_ok) { delay(FSM_POLL_DELAY_MS); continue; }
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

static bool retrieveResult(uint32_t chunk_idx)
{
    delay(ASCON_WAIT_MS);
    int zero_retries = 0;
    int attempt      = 0;
    while (attempt <= MAX_RETRIES) {
        pollFpga();
        if (isAllZero(spi_resp, FRAME_BYTES)) {
            if (zero_retries < ZERO_MISO_MAX_RETRIES) { zero_retries++; delay(ZERO_MISO_EXTRA_WAIT_MS); continue; }
            Serial.printf("[ERR] chunk %u: persistent all-zero MISO\n", chunk_idx);
            return false;
        }
        if (spi_resp[MISO_SENTINEL] == 0xA5) {
            if (attempt > 0) Serial.printf("[RESULT] chunk %u on attempt %d\n", chunk_idx, attempt);
            return true;
        }
        if (RETRY_DELAY_MS > 0) delay(RETRY_DELAY_MS);
        attempt++;
    }
    Serial.printf("[ERR] No result at chunk %u after %d retries\n", chunk_idx, MAX_RETRIES);
    return false;
}

static bool waitFifoNotEmpty(uint32_t chunk_idx, uint32_t max_polls = 200, uint32_t poll_delay = 0)
{
    for (uint32_t i = 0; i < max_polls; i++) {
        pollFpga();
        if (spi_resp[MISO_SENTINEL] == 0x00 && (spi_resp[POLL_FIFO_BYTE] & 0x80))
            return true;
        if (poll_delay > 0) delay(poll_delay);
    }
    Serial.printf("[ERR] chunk %u: FIFO never became non-empty\n", chunk_idx);
    return false;
}

static bool sendFifoRead(uint32_t chunk_idx, uint8_t* dst)
{
    memset(spi_frame, 0, FRAME_BYTES);
    spi_frame[0] = 0x04;
    memcpy(&spi_frame[1], active_key, 16);
    spiTransact();
    if (spi_resp[MISO_SENTINEL] == 0xA5) {
        bool tag_ok = !isAllZero(&spi_resp[MISO_TAG_START], MISO_TAG_LEN);
        if (!tag_ok) Serial.printf("[WARN] chunk %u: BRAM tag verdict FAIL\n", chunk_idx);
        memcpy(dst, &spi_resp[MISO_CT_START], CHUNK_SIZE);
        return true;
    }
    delay(2);
    pollFpga();
    if (spi_resp[MISO_SENTINEL] == 0xA5) {
        bool tag_ok = !isAllZero(&spi_resp[MISO_TAG_START], MISO_TAG_LEN);
        if (!tag_ok) Serial.printf("[WARN] chunk %u: BRAM tag verdict FAIL (retry)\n", chunk_idx);
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
        .dma_buf_count        = 16,
        .dma_buf_len          = 128,
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
// METRICS
// ═══════════════════════════════════════════════════════════════════════════════

#define FFT_LEN 256

static void fft256(float* re, float* im)
{
    for (int i = 1, j = 0; i < FFT_LEN; i++) {
        int bit = FFT_LEN >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            float tr = re[i]; re[i] = re[j]; re[j] = tr;
            float ti = im[i]; im[i] = im[j]; im[j] = ti;
        }
    }
    for (int len = 2; len <= FFT_LEN; len <<= 1) {
        float ang = -2.0f * (float)M_PI / (float)len;
        float wRe = cosf(ang), wIm = sinf(ang);
        for (int i = 0; i < FFT_LEN; i += len) {
            float curRe = 1.0f, curIm = 0.0f;
            for (int k = 0; k < len / 2; k++) {
                float uRe = re[i+k],       uIm = im[i+k];
                float vRe = re[i+k+len/2], vIm = im[i+k+len/2];
                float tvRe = vRe*curRe - vIm*curIm;
                float tvIm = vRe*curIm + vIm*curRe;
                re[i+k]       = uRe + tvRe;  im[i+k]       = uIm + tvIm;
                re[i+k+len/2] = uRe - tvRe;  im[i+k+len/2] = uIm - tvIm;
                float nextRe = curRe*wRe - curIm*wIm;
                float nextIm = curRe*wIm + curIm*wRe;
                curRe = nextRe; curIm = nextIm;
            }
        }
    }
}

static void powerSpectrum(const uint8_t* samples, uint32_t n_samples, float* ps)
{
    static float re[FFT_LEN], im[FFT_LEN];
    uint32_t use = (n_samples >= FFT_LEN) ? FFT_LEN : n_samples;
    for (int i = 0; i < FFT_LEN; i++) {
        float w = 0.5f * (1.0f - cosf(2.0f*(float)M_PI*i / (FFT_LEN-1)));
        float s = (i < (int)use) ? ((float)(int8_t)(samples[i] - 128)) : 0.0f;
        re[i] = s * w;
        im[i] = 0.0f;
    }
    fft256(re, im);
    for (int k = 0; k < FFT_LEN/2; k++) {
        float mag2 = re[k]*re[k] + im[k]*im[k];
        ps[k] = 10.0f * log10f(mag2 + 1e-6f);
    }
}

static void computeMetrics(void)
{
    if (!pcm_pre_enc || !pcm_post_dec || enc_chunk_count == 0) {
        Serial.println(F("[METRICS] No data."));
        return;
    }

    uint32_t total_samples = enc_chunk_count * CHUNK_SIZE;

    // ── Step 1: Wide cross-correlation to find true lag ────────────────────
    // Search ±256 samples. XCORR_MAX_LAG=64 was the ceiling AND the answer,
    // so the old code never saw the real lag. The lag is structural (one
    // CHUNK_SIZE = FPGA pipeline delay) and is expected/harmless.
    uint32_t xcorr_samples = (total_samples > 16384) ? 16384 : total_samples;
    const int32_t WIDE_LAG = 256;

    float    best_r   = -2.0f;
    int32_t  best_lag = 0;
    {
        double sumA = 0, sumB = 0;
        for (uint32_t i = 0; i < xcorr_samples; i++) {
            sumA += (int8_t)(pcm_pre_enc[i]  - 128);
            sumB += (int8_t)(pcm_post_dec[i] - 128);
        }
        float meanA = (float)(sumA / xcorr_samples);
        float meanB = (float)(sumB / xcorr_samples);

        double varA = 0, varB = 0;
        for (uint32_t i = 0; i < xcorr_samples; i++) {
            float da = (float)(int8_t)(pcm_pre_enc[i]  - 128) - meanA;
            float db = (float)(int8_t)(pcm_post_dec[i] - 128) - meanB;
            varA += da * da;
            varB += db * db;
        }
        float norm = sqrtf((float)varA * (float)varB);

        for (int32_t lag = -WIDE_LAG; lag <= WIDE_LAG; lag++) {
            double acc = 0;
            for (uint32_t i = 0; i < xcorr_samples; i++) {
                int32_t j = (int32_t)i + lag;
                if (j < 0 || j >= (int32_t)xcorr_samples) continue;
                float da = (float)(int8_t)(pcm_pre_enc[i]  - 128) - meanA;
                float db = (float)(int8_t)(pcm_post_dec[j] - 128) - meanB;
                acc += da * db;
            }
            float r = (norm < 1e-6f) ? 0.0f : (float)acc / norm;
            if (r > best_r) { best_r = r; best_lag = lag; }
        }
    }

    // ── Step 2: Compute aligned window ────────────────────────────────────
    // pre[i]  corresponds to  post[i + best_lag]
    // Only the overlapping region is valid for RMSE/SNR/LSD.
    int32_t  lag              = best_lag;
    uint32_t align_start_pre  = (lag >= 0) ? 0            : (uint32_t)(-lag);
    uint32_t align_start_post = (lag >= 0) ? (uint32_t)lag : 0;
    uint32_t lag_abs          = (lag >= 0) ? (uint32_t)lag : (uint32_t)(-lag);
    uint32_t align_n          = (lag_abs < total_samples) ? (total_samples - lag_abs) : 0;

    // ── Step 3: DC offset over aligned region ─────────────────────────────
    double sum_pre = 0, sum_post = 0;
    for (uint32_t i = 0; i < align_n; i++) {
        sum_pre  += (int8_t)(pcm_pre_enc [align_start_pre  + i] - 128);
        sum_post += (int8_t)(pcm_post_dec[align_start_post + i] - 128);
    }
    float dc_pre  = align_n ? (float)(sum_pre  / align_n) : 0.0f;
    float dc_post = align_n ? (float)(sum_post / align_n) : 0.0f;
    float dc_corr = dc_pre - dc_post;

    // ── Step 4: RMSE (aligned + DC-corrected) ─────────────────────────────
    double mse = 0.0;
    for (uint32_t i = 0; i < align_n; i++) {
        float s    = (float)(int8_t)(pcm_pre_enc [align_start_pre  + i] - 128);
        float d    = (float)(int8_t)(pcm_post_dec[align_start_post + i] - 128) + dc_corr;
        float diff = s - d;
        mse += diff * diff;
    }
    float rmse = align_n ? sqrtf((float)(mse / align_n)) : 0.0f;

    // ── Step 5: SNR (aligned + DC-corrected) ──────────────────────────────
    double sig_power = 0.0, noise_power = 0.0;
    for (uint32_t i = 0; i < align_n; i++) {
        float s = (float)(int8_t)(pcm_pre_enc [align_start_pre  + i] - 128);
        float d = (float)(int8_t)(pcm_post_dec[align_start_post + i] - 128) + dc_corr;
        sig_power   += s * s;
        noise_power += (s - d) * (s - d);
    }
    float snr_db = (noise_power < 1e-6) ? 99.9f
                 : 10.0f * log10f((float)(sig_power / noise_power));

    // ── Step 6: LSD (aligned — must match RMSE window) ────────────────────
    // Previously called on full unaligned buffers → LSD≈10 dB even when
    // RMSE=0, because the FFT sees a phase-shifted copy of the same signal.
    // Fix: pass the lag-aligned pointers and aligned length.
    static float ps_pre[FFT_LEN/2], ps_post[FFT_LEN/2];
    powerSpectrum(pcm_pre_enc  + align_start_pre,  align_n, ps_pre);
    powerSpectrum(pcm_post_dec + align_start_post, align_n, ps_post);
    double lsd_sum = 0.0;
    for (int k = 0; k < FFT_LEN/2; k++) {
        float d = ps_pre[k] - ps_post[k];
        lsd_sum += d * d;
    }
    float lsd_db = sqrtf((float)(lsd_sum / (FFT_LEN/2)));

    float tag_pct  = 100.0f * metrics_tag_ok_count    / (float)enc_chunk_count;
    float drop_pct = 100.0f * metrics_chunk_drop_count / (float)enc_chunk_count;

    Serial.println(F("================================================"));
    Serial.println(F("  ASCON-128 AUDIO METRICS"));
    Serial.println(F("================================================"));
    Serial.printf("[METRICS] Samples     : %u  (%.2f s)\n",
                  total_samples, (float)total_samples / SAMPLE_RATE);
    Serial.printf("[METRICS] DC pre/post : %.2f / %.2f  (correction=%.2f)\n",
                  dc_pre, dc_post, dc_corr);
    Serial.printf("[METRICS] XCORR_PEAK  : %.4f  (1.0 = identical waveform)\n", best_r);
    Serial.printf("[METRICS] XCORR_LAG   : %d samples  (one CHUNK_SIZE = FPGA pipeline delay, expected)\n", (int)lag);
    Serial.printf("[METRICS] Aligned N   : %u samples\n", align_n);
    Serial.printf("[METRICS] RMSE        : %.4f  (0 = perfect, >10 = audible)\n", rmse);
    Serial.printf("[METRICS] SNR         : %.2f dB  (>40 = transparent, <10 = degraded)\n", snr_db);
    Serial.printf("[METRICS] LSD         : %.2f dB  (<2 = perceptually clean, >8 = noticeable)\n", lsd_db);
    Serial.printf("[METRICS] TAG_OK      : %u / %u  (%.1f%%)\n",
                  metrics_tag_ok_count, enc_chunk_count, tag_pct);
    Serial.printf("[METRICS] CHUNK_DROP  : %u / %u  (%.1f%%)\n",
                  metrics_chunk_drop_count, enc_chunk_count, drop_pct);
    Serial.println(F("------------------------------------------------"));
    Serial.printf("[METRICS] RMSE=%.4f SNR=%.2f LSD=%.2f XCORR=%.4f XCORR_LAG=%d TAG_OK=%u/%u CHUNK_DROP=%u/%u\n",
                  rmse, snr_db, lsd_db, best_r, (int)lag,
                  metrics_tag_ok_count, enc_chunk_count,
                  metrics_chunk_drop_count, enc_chunk_count);
    Serial.println(F("================================================"));
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
    if (pcm_pre_enc)
        memset(pcm_pre_enc, 0x80, (size_t)MAX_CHUNKS * CHUNK_SIZE);

    uint32_t total_samples = 0;
    const uint32_t max_samples = (uint32_t)SAMPLE_RATE * MAX_RECORD_SECS;
    const uint8_t enc_total_placeholder = 0xFF;

    int32_t dma_buf[CHUNK_SIZE * 2];
    float   dc_filter_x = 0.0f;
    float   dc_filter_y = 0.0f;

    uint8_t  pcm8_pending[CHUNK_SIZE];
    uint8_t  n_pending        = 0;
    bool     has_pending      = false;

    uint32_t pending_chunk_idx = 0;
    uint8_t  pcm8_for_metrics[CHUNK_SIZE];

    while (true) {
        bool button_held = (digitalRead(PIN_BTN) == LOW);
        bool limit_hit   = (enc_chunk_count >= MAX_CHUNKS ||
                            total_samples   >= max_samples);

        // Step 1: Read next I2S chunk
        uint8_t pcm8_new[CHUNK_SIZE] = {0};
        uint8_t n_new = 0;

        if (button_held && !limit_hit) {
            size_t bytes_read = 0;
            i2s_read(I2S_MIC, dma_buf, sizeof(dma_buf), &bytes_read, portMAX_DELAY);
            uint32_t n_smp = (bytes_read / sizeof(int32_t)) / 2;
            if (n_smp > 0) {
                uint32_t remaining = max_samples - total_samples;
                if (n_smp > remaining)  n_smp = remaining;
                if (n_smp > CHUNK_SIZE) n_smp = CHUNK_SIZE;
                for (uint32_t i = 0; i < n_smp; i++) {
                    float raw_f   = (float)(int32_t)dma_buf[i * 2];
                    float filtered = raw_f - dc_filter_x + MIC_DC_ALPHA * dc_filter_y;
                    dc_filter_x   = raw_f;
                    dc_filter_y   = filtered;
                    int32_t scaled = (int32_t)(filtered) >> MIC_GAIN_SHIFT;
                    if (scaled >  127) scaled =  127;
                    if (scaled < -128) scaled = -128;
                    pcm8_new[i] = (uint8_t)((int8_t)scaled + 128);
                }
                n_new = (uint8_t)n_smp;
            }
        }

        // Step 2: Collect ASCON result for the previous chunk
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
                Serial.printf("[WARN] chunk %u: all-zero nonce\n", enc_chunk_count);
            if (memcmp(&spi_resp[MISO_KEYECHO_START], active_key, 16) != 0) {
                Serial.printf("[WARN] chunk %u: key echo mismatch!\n", enc_chunk_count);
                pkt.valid = false;
            }

            total_samples += n_pending;

            if (pcm_pre_enc && pending_chunk_idx < MAX_CHUNKS) {
                uint8_t* dst = pcm_pre_enc + (pending_chunk_idx * CHUNK_SIZE);
                memcpy(dst, pcm8_for_metrics, n_pending);
                if (n_pending < CHUNK_SIZE)
                    memset(dst + n_pending, 0x80, CHUNK_SIZE - n_pending);
            }

            enc_chunk_count++;
            has_pending = false;

            if (enc_chunk_count % 50 == 0 || enc_chunk_count == 1)
                Serial.printf("[ENC] Chunk %u OK (%.2f s)\n",
                              enc_chunk_count, (float)total_samples / SAMPLE_RATE);
        }

        // Step 3: Send the new chunk
        if (n_new > 0) {
            memcpy(pcm8_pending, pcm8_new, n_new);
            n_pending = n_new;
            pending_chunk_idx = enc_chunk_count;
            memcpy(pcm8_for_metrics, pcm8_new, n_new);

            buildFrame(0x01, nullptr, nullptr, pcm8_new, n_new, enc_total_placeholder);
            spiTransact();
            has_pending = true;
        }

        // Step 4: Exit conditions
        if (!button_held && !has_pending) break;
        if (limit_hit    && !has_pending) break;
    }

    // Flush the last in-flight chunk
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
                break;
            }
            if (spi_resp[MISO_SENTINEL] == 0xA5) { ok = true; break; }
        }
        if (ok) {
            AudioPacket& pkt = enc_packets[enc_chunk_count];
            memset(&pkt, 0, sizeof(AudioPacket));
            memcpy(pkt.ct,    &spi_resp[MISO_CT_START],    MISO_CT_LEN);
            memcpy(pkt.tag,   &spi_resp[MISO_TAG_START],   MISO_TAG_LEN);
            memcpy(pkt.nonce, &spi_resp[MISO_NONCE_START], MISO_NONCE_LEN);
            pkt.len   = n_pending;
            pkt.valid = !isAllZero(pkt.nonce, MISO_NONCE_LEN);
            if (pcm_pre_enc && pending_chunk_idx < MAX_CHUNKS) {
                uint8_t* dst = pcm_pre_enc + (pending_chunk_idx * CHUNK_SIZE);
                memcpy(dst, pcm8_for_metrics, n_pending);
                if (n_pending < CHUNK_SIZE)
                    memset(dst + n_pending, 0x80, CHUNK_SIZE - n_pending);
            }
            total_samples += n_pending;
            enc_chunk_count++;
        }
        has_pending = false;
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
// DECRYPT + PLAY
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
            delay(30); pollFpga();
            if (spi_resp[MISO_SENTINEL] == 0x00) tryCapturePollKey();
        }
    }
    if (!key_valid) {
        Serial.println(F("[ERR] Cannot read key. Check PuTTY [4] + key."));
        return;
    }

    Serial.print(F("[DEC] Key: "));
    dumpBytes("", active_key, 16);
    Serial.printf("[DEC] Decrypting + streaming %u chunks via BRAM FIFO.\n", enc_chunk_count);

    const uint16_t dec_total = (uint16_t)enc_chunk_count;
    uint8_t  pt_chunk[CHUNK_SIZE];
    uint32_t tag_fail_count = 0;
    uint32_t skip_count     = 0;
    uint32_t total_played   = 0;

    metrics_tag_ok_count     = 0;
    metrics_chunk_drop_count = 0;
    if (pcm_post_dec)
        memset(pcm_post_dec, 0x80, (size_t)MAX_CHUNKS * CHUNK_SIZE);

    i2s_zero_dma_buffer(I2S_SPK);

    for (uint32_t ci = 0; ci < enc_chunk_count; ci++) {

        AudioPacket& pkt = enc_packets[ci];
        bool chunk_ok  = true;
        bool is_silence = false;

        if (!pkt.valid) {
            Serial.printf("[SKIP] chunk %u: invalid packet\n", ci);
            skip_count++;
            metrics_chunk_drop_count++;
            memset(pt_chunk, 0x80, pkt.len ? pkt.len : CHUNK_SIZE);
            is_silence = true;
            chunk_ok   = false;
            goto play_chunk;
        }

        // Step A: Send 0x02 decrypt frame
        buildFrame(0x02, pkt.nonce, pkt.tag, pkt.ct, CHUNK_SIZE, dec_total);
        spiTransact();

        // Step B: Poll MISO[97] bit[7] = fifo_not_empty
        if (!waitFifoNotEmpty(ci, 200, 0)) {
            Serial.printf("[ERR] chunk %u: FIFO timeout, using silence\n", ci);
            tag_fail_count++;
            metrics_chunk_drop_count++;
            memset(pt_chunk, 0x80, CHUNK_SIZE);
            is_silence = true;
            chunk_ok   = false;
            goto play_chunk;
        }

        // Step C: Send cmd 0x04 — FIFO read
        if (!sendFifoRead(ci, pt_chunk)) {
            tag_fail_count++;
            metrics_chunk_drop_count++;
            memset(pt_chunk, 0x80, CHUNK_SIZE);
            is_silence = true;
            chunk_ok   = false;
            if (tag_fail_count > 5) {
                Serial.println(F("[ERR] Too many FIFO read failures, aborting."));
                computeMetrics();
                return;
            }
            goto play_chunk;
        }

        metrics_tag_ok_count++;

        if (ci < 3) {
            Serial.printf("[DBG] chunk %u pt_chunk: ", ci);
            dumpBytes("", pt_chunk, 16);
        }

        play_chunk:
        {
            if (pcm_post_dec && ci < MAX_CHUNKS) {
                uint8_t* dst = pcm_post_dec + (ci * CHUNK_SIZE);
                memcpy(dst, pt_chunk, CHUNK_SIZE);
            }

            uint8_t n = pkt.valid ? pkt.len : (uint8_t)CHUNK_SIZE;
            int32_t tmp[CHUNK_SIZE * 2];
            for (uint8_t i = 0; i < n; i++) {
                int32_t sample = (int32_t)((int8_t)(pt_chunk[i] - 128)) << 24;
                tmp[i * 2]     = sample;
                tmp[i * 2 + 1] = 0;
            }
            size_t bw = 0;
            i2s_write(I2S_SPK, tmp, (size_t)n * 2 * sizeof(int32_t), &bw, portMAX_DELAY);
            total_played += n;

            if ((ci + 1) % 50 == 0 || ci == 0)
                Serial.printf("[DEC] Chunk %u OK (%.2f s)\n",
                              ci + 1, (float)total_played / SAMPLE_RATE);

            (void)chunk_ok; (void)is_silence;
        }
    }

    Serial.printf("[PLAY] Done. %.2f s played. tag_fails=%u skipped=%u / %u chunks\n",
                  (float)total_played / SAMPLE_RATE,
                  tag_fail_count, skip_count, enc_chunk_count);
    if (tag_fail_count == 0 && skip_count == 0)
        Serial.println(F("[PLAY] All chunks OK — BRAM FIFO decrypt pipeline."));

    computeMetrics();
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
    Serial.println(F("  + PCM Capture & Quality Metrics"));
    Serial.println(F("================================================"));
    Serial.println(F("  ENCRYPT: PuTTY [3] + key → HOLD button"));
    Serial.println(F("  DECRYPT: PuTTY [4] + key → TAP button"));
    Serial.println(F("  METRICS printed automatically after decrypt"));
    Serial.println(F("================================================\n"));

    enc_packets = (AudioPacket*)malloc(MAX_CHUNKS * sizeof(AudioPacket));
    if (!enc_packets) {
        Serial.println(F("[FATAL] malloc failed for enc_packets"));
        while (true) delay(1000);
    }
    memset(enc_packets, 0, MAX_CHUNKS * sizeof(AudioPacket));

    size_t pcm_buf_size = (size_t)MAX_CHUNKS * CHUNK_SIZE;

    pcm_pre_enc = (uint8_t*)malloc(pcm_buf_size);
    if (!pcm_pre_enc) {
        Serial.println(F("[FATAL] malloc failed for pcm_pre_enc"));
        while (true) delay(1000);
    }
    memset(pcm_pre_enc, 0x80, pcm_buf_size);

    pcm_post_dec = (uint8_t*)malloc(pcm_buf_size);
    if (!pcm_post_dec) {
        Serial.println(F("[FATAL] malloc failed for pcm_post_dec"));
        while (true) delay(1000);
    }
    memset(pcm_post_dec, 0x80, pcm_buf_size);

    uint32_t enc_size = (uint32_t)MAX_CHUNKS * sizeof(AudioPacket);
    Serial.printf("[MEM] enc_packets  : %u KB\n", enc_size / 1024);
    Serial.printf("[MEM] pcm_pre_enc  : %u KB\n", (uint32_t)pcm_buf_size / 1024);
    Serial.printf("[MEM] pcm_post_dec : %u KB\n", (uint32_t)pcm_buf_size / 1024);
    Serial.printf("[MEM] free heap    : %u KB\n", ESP.getFreeHeap() / 1024);
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
        // HOLD → encrypt
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
                delay(30); pollFpga();
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
        // TAP → decrypt + metrics
        Serial.println(F("\n[BTN] TAP — decrypt + play (BRAM FIFO) + metrics."));
        if (enc_chunk_count == 0) {
            Serial.println(F("[ERR] No encrypted data. HOLD to record first."));
            return;
        }
        decryptAndPlay();
    }
}