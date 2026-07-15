`timescale 1ns / 1ps
//=============================================================================
// UART Controller - ASCON-128 Menu System  (Audio + Text Edition)
//
// RECTIFICATION LOG (this version - v9 - REAL-TIME STREAMING)
// ──────────────────────────────────────
// [FIX-REALTIME] "Watchdog fires during real-time streaming"
//   Root cause: AUD_IDLE_TIMEOUT was 500 ms.  For real-time operation
//   the ESP32 records and encrypts simultaneously.  The watchdog starts
//   counting the moment the FPGA enters S_AUD_ENC_WAIT_SPI.  Any delay
//   on the ESP32 side (mic DMA startup, button debounce) consumed this
//   500 ms window before the first chunk could arrive.
//   Fix: AUD_IDLE_TIMEOUT 50_000_000 (500 ms) -> 1_000_000_000 (10 s).
//   aud_idle_cnt widened from 26 bits to 30 bits (2^30 > 10^9).
//   The watchdog still fires on genuine ESP32 disconnect, returning
//   cleanly to the main menu.
//
// ──────────────────────────────────────
// [BUG5-FIX] "spi_audio_seen triggered by text-encrypt frames (type 0x03)"
//   Root cause: The spi_audio_seen latch was set whenever spi_frame_type was
//   0x01 OR 0x03.  Frame type 0x03 is a text-encrypt frame (not audio).
//   If a 0x03 frame arrived while the FPGA was in S_AUD_ENC_WAIT_SPI the FSM
//   would advance to S_AUD_ENC_LAUNCH prematurely with wrong payload data.
//   Fix: limit spi_audio_seen to type 0x01 (audio encrypt) only.
//
// [BUG6b-FIX] "total_chunks_lat not reset between encrypt and decrypt sessions"
//   Root cause: total_chunks_lat was latched from the encrypt session and
//   never cleared when entering the decrypt flow.  enc_chunk_idx was reset in
//   S_AUD_DEC_PR_COMP but total_chunks_lat was not, causing the decrypt
//   progress percentage to use the stale encrypt chunk count.
//   Fix: add `total_chunks_lat <= 8'd0` in S_AUD_DEC_PR_COMP alongside the
//   existing enc_chunk_idx reset.
//
// All prior fixes (BUG1-BUG4, BUG6, R1-R3, K1-K5, A, B, C, 6, 8, 11, 12)
// are retained unchanged.
//
// [BUG1-FIX] "First attempt fails, needs double reset"
//   Root cause: On startup the FSM jumps to S_BANNER before rst_int_n
//   deasserts (MMCM lock takes ~10 ms).  The TRNG warm_cnt and internal
//   state registers are still in a partial reset state when S_WAIT_RNG is
//   first reached.  Solution: add a 200 ms power-on hold counter
//   (POR_CYCLES) that keeps the FSM in S_POR_HOLD before allowing any
//   transition to S_BANNER.  This replaces the need for a double reset.
//
// [BUG2-FIX] "Menu doesn't appear after encryption / option 4 unreachable"
//   Root cause: S_AUD_ENC_DONE held rx_state = S_AUD_ENC_DONE while
//   printing the "Press any key" string, then transitioned to S_WAIT_KEY.
//   But the condition check `!tx_str_active && !tx_str_done && !tx_busy &&
//   !tx_fired` was never simultaneously satisfied when all flags cleared in
//   the same clock, causing a one-cycle miss that kept the FSM stuck.
//   Fix: S_AUD_ENC_DONE now unconditionally goes to S_WAIT_KEY after the
//   string print completes (tx_str_done).  An explicit `led_waiting <= 0`
//   is added in S_WAIT_KEY to ensure LED state is consistent.
//
// [BUG3-FIX] "Encryption of chunks takes a lot of time"
//   Root cause: The FSM was not holding uart_fsm_state = 0xA5 between
//   chunks.  After each ascon_done pulse it briefly revisited S_AUD_ENC_PR_COMP
//   to print "[Encrypting...]" which (a) takes many UART cycles and (b)
//   caused the ESP32's waitForFsmState() to see 0x00 between chunks.
//   Fix: uart_fsm_state = 0xA5 is now asserted in BOTH S_AUD_ENC_WAIT_SPI
//   AND S_AUD_ENC_LAUNCH (the only state the FPGA revisits while waiting
//   for the next chunk SPI frame). The per-chunk print is removed.
//   The FPGA stays armed with fsm=0xA5 continuously until all chunks arrive.
//   A 500 ms idle watchdog (AUD_IDLE_TIMEOUT) auto-exits to S_AUD_ENC_DONE.
//
// [BUG4-FIX] "Tag mismatch - FPGA and ESP32 don't know when to start decrypt"
//   Root cause: S_AUD_DEC_LAUNCH emitted uart_fsm_state=0x5A but immediately
//   checked ascon_done_latch on the same cycle, causing a 1-cycle window
//   where the ESP32 could send a frame before the FPGA cleared its internal
//   state.  Fix: add a 1-cycle arm delay (dec_arm_r) in S_AUD_DEC_LAUNCH
//   so that on the first cycle we only drive 0x5A, and on the second cycle
//   we begin watching for ascon_done_latch.  Also, the nonce used for decrypt
//   comparison is explicitly latched from the SPI nonce field (not from
//   nonce_out which can change).
//
// [BUG6-FIX] "Percentage completion display"
//   Added ENC/DEC progress display using ANSI escape sequences.
//   The FPGA prints "\r\033[33m[ENC  X%]\033[0m" on the same line for
//   each incoming SPI chunk (total_chunks_in received from ESP32 via
//   spi_frame byte[114]).  For decrypt, prints cyan "[DEC X%]".
//   A new sub-FSM (TX_PROGRESS) handles the percentage string.
//
// All prior fixes (R1, R2, R3, K1-K5, A, B, C, 6, 8, 11, 12) retained.
//=============================================================================

// RECTIFICATION LOG (this patch - FIX-DDG-TAG)
// ──────────────────────────────────────
// [FIX-DDG-TAG] "All decrypt chunks show the same TAG in the serial debug print"
//   Root cause: In S_AUD_DEC_LAUNCH the debug snapshot used:
//     ddg_tag_snap <= ascon_tag;
//   For decrypt mode (dec_tag_override=1) the ASCON core state machine jumps
//   directly to ST_DEC_INIT, bypassing the encrypt path entirely.  Therefore
//   tag_out (= ascon_tag) is NEVER updated during a decrypt operation and
//   retains the value set in the very last ST_ENC_FINAL_W - which was the
//   final chunk's encryption tag from the preceding encrypt session.  This
//   stale value (e.g. 15A9D0EC019867E80C2B8E6148259416) was printed for
//   EVERY decrypt chunk regardless of the per-chunk expected tag.
//   Fix: replace ascon_tag with spi_tag_dbg, which is the per-chunk expected
//   tag that the ESP32 sent in MOSI[33-48].  This is already wired into
//   uart_controller_menu via the spi_tag_dbg input port and is valid for
//   the entire duration of S_AUD_DEC_LAUNCH -> S_AUD_DEC_DONE.
//   NOTE: the tag_match verdict (stored_match / OK/FAIL) is computed by the
//   ASCON core comparing the internally-derived tag against dec_tag_lat
//   (= dec_tag_in_out = spi_tag_dbg at launch time), so OK/FAIL has always
//   been correct - only the displayed TAG value was wrong.
//
// ALT-C MODIFICATIONS
// ───────────────────
// [ALTC-NODEC-DBGPRINT] Removed S_AUD_DEC_DBG and S_AUD_DEC_PR_PLAY from
//   the decrypt hot path.  The decrypt loop now goes:
//     S_AUD_DEC_LAUNCH → S_AUD_DEC_WAIT → S_AUD_DEC_DONE → S_AUD_DEC_LAUNCH
//   No UART printing occurs between decrypt chunks.  UART prints are deferred
//   to S_AUD_DEC_DONE only (progress bar at the end of the full session).
//   uart_fsm_state=0x5A is held continuously through all decrypt states,
//   eliminating the FSM re-arm race that caused per-chunk tag failures.
//
// [ALTC-REMOVE-S_AUD_DEC_TX] S_AUD_DEC_TX (ATX_VERIFY_LBL print) removed
//   from the per-chunk path.  Verify print runs once at session end.
//
// [ALTC-DEC-DONE-PRINT] S_AUD_DEC_DONE now prints a summary line and loops
//   back to S_AUD_DEC_LAUNCH until all chunks are processed, then goes to
//   S_WAIT_KEY.  total_chunks_lat drives the loop exit condition.
//
// ALL PRIOR FIXES RETAINED.
//
// [FIX-ENC-NODEBUG] "PuTTY ENC log truncates mid-session (e.g. 216/377 chunks)"
//   Root cause: S_AUD_ENC_LAUNCH/S_AUD_ENC_WAIT routed every encrypted chunk
//   through S_AUD_ENC_DBG which prints ~70 UART chars per chunk.  At 115200
//   baud that costs ~6 ms per chunk.  With 64-sample audio chunks at 16 kHz
//   each chunk period is only ~4 ms → the UART print is 1.5× slower than
//   real-time.  The FSM fell behind, the aud_idle_expired watchdog eventually
//   fired, and S_AUD_ENC_DONE was entered prematurely, truncating the UART log.
//   The actual encrypt completed correctly (ESP32 got all chunks); only the
//   PuTTY display was cut short.
//   Fix: bypass S_AUD_ENC_DBG in both S_AUD_ENC_LAUNCH and S_AUD_ENC_WAIT,
//   going directly to S_AUD_PROGRESS (progress bar only, ~15 chars ≈ 1.3 ms).
//   S_AUD_ENC_DBG state and all snapshot logic are retained intact for any
//   future non-real-time use.
//
// [FIX-PCT-WIDTH] "Progress percentage wrong for >255 chunk sessions"
//   Root cause: enc_launch_pct and enc_wait_pct used `reg [7:0] tc` local
//   variables to hold the total chunk count.  With total_chunks_lat=377 the
//   8-bit variable truncated to 377 & 0xFF = 121, making pct_val compute
//   100% at chunk 121 and wrap back to low values after that.
//   Fix: widen both local variables to `reg [9:0]` to match total_chunks_lat.

module uart_controller_menu #(
    parameter CLK_FREQ  = 100_000_000,
    parameter BAUD_RATE = 115_200
)(
    input  wire         clk,
    input  wire         rst_n,

    input  wire         uart_rx_pin,
    output wire         uart_tx_pin,

    // TRNG
    input  wire [127:0] trng_nonce,
    input  wire         trng_valid,

    // ASCON core
    output reg  [127:0] key_out,
    output reg  [127:0] nonce_out,
    output reg  [63:0]  aad_out,
    output reg  [511:0] pt_out,
    output reg  [6:0]   pt_len_bytes_out,
    output reg          ascon_start,
    input  wire         ascon_done,
    input  wire         ascon_tag_match,
    input  wire [511:0] ascon_ct,
    input  wire [127:0] ascon_tag,
    input  wire [511:0] ascon_pt_dec,

    // Decrypt-override
    output reg          dec_tag_override_out,
    output reg [127:0]  dec_tag_in_out,

    // SPI frame signals
    input  wire         spi_frame_valid,
    input  wire [7:0]   spi_frame_type,
    // [FIX-TYPLAG] Pre-gated type-0x01 pulse from top (timing-correct).
    // Raw spi_frame_valid & (spi_frame_type==0x01) fails because frame_type_out
    // lags frame_valid by 1 cycle; this signal uses the spi_fv_prev2 one-shot.
    input  wire         spi_audio_frame_in,

    // FSM state output for SPI polling
    output reg  [7:0]   uart_fsm_state,

    // Audio key typed in PuTTY - delivered to ESP32 via MISO poll bytes 0..15
    output reg  [127:0] audio_key_out,

    // [BUG6] Total chunk count from ESP32 via SPI byte[114]
    input  wire [9:0]   total_chunks_in,

    // [DBG-DEC] Raw SPI frame fields for decrypt debug print
    input  wire [511:0] spi_ct_dbg,      // payload (CT) from ESP32 MOSI[50-113]
    input  wire [127:0] spi_nonce_dbg,   // nonce from ESP32 MOSI[17-32]
    input  wire [127:0] spi_tag_dbg,     // tag from ESP32 MOSI[33-48]

    // LEDs
    output reg          led_waiting,
    output reg          led_computing
);

    //=========================================================================
    // UART SUB-MODULES
    //=========================================================================
    wire [7:0] rx_byte;
    wire       rx_valid;
    reg  [7:0] tx_byte;
    reg        tx_send;
    wire       tx_busy;

    uart_rx #(.CLK_FREQ(CLK_FREQ), .BAUD_RATE(BAUD_RATE)) urx (
        .clk(clk), .rst_n(rst_n), .rx(uart_rx_pin),
        .data(rx_byte), .data_valid(rx_valid)
    );
    uart_tx #(.CLK_FREQ(CLK_FREQ), .BAUD_RATE(BAUD_RATE)) utx (
        .clk(clk), .rst_n(rst_n), .data(tx_byte), .send(tx_send),
        .tx(uart_tx_pin), .busy(tx_busy)
    );

    //=========================================================================
    // [BUG1] POWER-ON RESET HOLD
    // 200 ms @ 100 MHz = 20,000,000 cycles.  Keeps FSM in S_POR_HOLD
    // until MMCM lock + TRNG warm-up are both complete.
    //=========================================================================
    localparam POR_CYCLES = 20_000_000;
    reg [24:0] por_cnt;
    reg        por_done;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            por_cnt  <= 25'd0;
            por_done <= 1'b0;
        end else begin
            if (!por_done) begin
                if (por_cnt == POR_CYCLES[24:0] - 25'd1)
                    por_done <= 1'b1;
                else
                    por_cnt <= por_cnt + 25'd1;
            end
        end
    end

    //=========================================================================
    // [FIX-REALTIME] AUD ENC IDLE WATCHDOG
    // Increased from 500 ms to 10 s to support real-time streaming from ESP32.
    // The original 500 ms timeout was designed for store-and-forward (record
    // first, then encrypt).  For real-time operation the ESP32 records and
    // encrypts simultaneously in a pipeline, so the inter-chunk gap can be
    // as long as one I2S DMA buffer fill (~4 ms at 16 kHz / 64 samples).
    // 10 s gives comfortable headroom and still auto-exits cleanly if the
    // ESP32 disconnects mid-stream.
    //
    // 10 s @ 100 MHz = 1,000,000,000 cycles.  Requires 30-bit counter
    // (2^30 = 1,073,741,824 > 1,000,000,000).  Counter widened from 26→30 bits.
    //=========================================================================
    localparam AUD_IDLE_TIMEOUT = 1_000_000_000;
    reg [29:0] aud_idle_cnt;
    wire       aud_idle_expired = (aud_idle_cnt == AUD_IDLE_TIMEOUT[29:0] - 30'd1);

    //=========================================================================
    // TX INTERLOCK
    //=========================================================================
    reg        send_req;
    reg        tx_fired;
    reg        tx_busy_d;
    reg [3:0]  tx_gap_cnt;
    wire tx_busy_fall = ~tx_busy & tx_busy_d;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_send <= 1'b0; tx_busy_d <= 1'b0; tx_gap_cnt <= 4'd0;
        end else begin
            tx_busy_d <= tx_busy;
            tx_send   <= 1'b0;
            if (send_req && !tx_busy && (tx_gap_cnt == 0)) tx_send <= 1'b1;
            if (tx_busy_fall)         tx_gap_cnt <= 4'd1;
            else if (tx_gap_cnt != 0) tx_gap_cnt <= tx_gap_cnt - 4'd1;
        end
    end

    //=========================================================================
    // HEX HELPER
    //=========================================================================
    function [7:0] nibble_to_hex;
        input [3:0] nib;
        nibble_to_hex = (nib < 4'd10) ? (8'h30 + nib) : (8'h37 + nib);
    endfunction

    //=========================================================================
    // DECIMAL HELPER (for percentage: 0-100)
    //=========================================================================
    function [23:0] pct_to_ascii;  // returns 3 bytes: hundreds, tens, ones
        input [6:0] pct;           // 0..100
        reg [6:0] h, t, o, rem;
        begin
            h   = pct / 7'd100;
            rem = pct - h * 7'd100;
            t   = rem / 7'd10;
            o   = rem - t * 7'd10;
            pct_to_ascii = {8'h30 + {1'b0, h}, 8'h30 + {1'b0, t}, 8'h30 + {1'b0, o}};
        end
    endfunction

    //=========================================================================
    // BUFFERS
    //=========================================================================
    reg [127:0] key_buf;
    reg [4:0]   key_cnt;

    reg [127:0] audio_key_buf;

    (* keep = "true" *) reg [55:0]  aad_raw;
    (* keep = "true" *) reg [2:0]   aad_len;
    (* keep = "true" *) reg [7:0]   pt_bytes [0:63];
    reg [6:0]   pt_len;

    reg [127:0] stored_nonce;
    reg [511:0] stored_ct;
    reg [127:0] stored_tag;
    reg         stored_match;
    reg [511:0] stored_pt_dec;
    reg [6:0]   stored_pt_len;
    reg [6:0]   stored_ct_chars;

    reg [127:0] audio_stored_nonce;
    reg [127:0] audio_stored_tag;
    reg         audio_enc_result_ready;

    (* keep = "true" *) reg mode_decrypt;
    reg enc_result_ready;

    //=========================================================================
    // spi_audio_seen sticky latch
    //=========================================================================
    reg spi_audio_seen;

    //=========================================================================
    // ascon_done_latch
    //=========================================================================
    reg ascon_done_latch;

    //=========================================================================
    // [BUG6] Progress tracking
    //=========================================================================
    reg [9:0]  enc_chunk_idx;     // current chunk being processed (max 1023)
    reg [9:0]  total_chunks_lat;  // latched from total_chunks_in on EOS frame
    reg [6:0]  pct_val;           // 0..100 percent
    // Verilog-2001: part-select on function call is not allowed.
    // Evaluate pct_to_ascii combinationally into a wire, then index the wire.
    wire [23:0] pct_ascii_tmp = pct_to_ascii(pct_val);
    // show_progress removed: FSM transitions directly to S_AUD_PROGRESS via rx_state

    //=========================================================================
    // [BUG4] Decrypt arm delay
    //=========================================================================
    reg dec_arm_r;    // 1 = armed, 0 = first cycle (just set 0x5A, don't act)

    //=========================================================================
    // STRING ROM
    //=========================================================================
    // tx_str_rom: 88-byte scratchpad written procedurally - kept as flip-flops.
    // The ram_style attribute was removed; Vivado cannot infer a RAM from this
    // pattern (individual indexed writes inside case statements with full reset).
    reg [7:0] tx_str_rom [0:87];
    reg [6:0] tx_str_len;
    reg [6:0] tx_str_idx;
    reg       tx_str_active;
    reg       tx_str_done;

    //=========================================================================
    // PT DECODE
    //=========================================================================
    reg [6:0]  pt_dec_len;
    reg [5:0]  tx_pt_idx;

    //=========================================================================
    // MAIN FSM STATES
    //=========================================================================
    localparam [6:0]
        S_POR_HOLD         = 7'd63,   // [BUG1] power-on hold
        S_BANNER           = 7'd0,
        S_MENU             = 7'd1,
        S_MENU_WAIT        = 7'd2,
        S_PR_KEY           = 7'd3,
        S_RD_KEY           = 7'd4,
        S_PR_PT            = 7'd7,
        S_RD_PT            = 7'd8,
        S_WAIT_RNG         = 7'd9,
        S_LAUNCH_ENC       = 7'd10,
        S_WAIT_ENC         = 7'd11,
        S_TX_ENC           = 7'd12,
        S_PR_KEY_D         = 7'd13,
        S_RD_KEY_D         = 7'd14,
        S_LAUNCH_DEC       = 7'd15,
        S_WAIT_DEC         = 7'd16,
        S_TX_DEC           = 7'd17,
        S_DONE             = 7'd18,
        S_NO_DATA          = 7'd19,
        S_WAIT_KEY         = 7'd20,
        S_PT_COMMIT        = 7'd21,
        // Audio Encrypt
        S_AUD_ENC_PR_KEY   = 7'd22,
        S_AUD_ENC_RD_KEY   = 7'd23,
        S_AUD_ENC_WAIT_RNG = 7'd24,
        S_AUD_ENC_PR_REC   = 7'd25,
        S_AUD_ENC_WAIT_SPI = 7'd26,  // [BUG3] stays here between chunks
        S_AUD_ENC_PR_COMP  = 7'd27,  // only used once before first chunk
        S_AUD_ENC_LAUNCH   = 7'd28,  // [BUG3] also holds fsm=0xA5
        S_AUD_ENC_WAIT     = 7'd29,
        S_AUD_ENC_TX       = 7'd30,
        S_AUD_ENC_DONE     = 7'd31,
        // Audio Decrypt
        S_AUD_DEC_PR_KEY   = 7'd32,
        S_AUD_DEC_RD_KEY   = 7'd33,
        S_AUD_DEC_PR_COMP  = 7'd34,
        S_AUD_DEC_LAUNCH   = 7'd35,
        S_AUD_DEC_WAIT     = 7'd36,
        S_AUD_DEC_TX       = 7'd37,
        S_AUD_DEC_PR_PLAY  = 7'd38,
        S_AUD_DEC_DONE     = 7'd39,
        S_NO_AUD_DATA      = 7'd40,
        // [BUG6] Progress print state
        S_AUD_PROGRESS     = 7'd41,
        // [DBG-ENC] Per-chunk encrypt debug print state
        S_AUD_ENC_DBG      = 7'd42,
        // [DBG-DEC] Per-chunk decrypt debug print state
        S_AUD_DEC_DBG      = 7'd43;

    (* fsm_encoding = "one_hot" *) reg [6:0] rx_state;
    reg [6:0] progress_return_state;  // state to return to after progress print

    //=========================================================================
    // TX RESPONSE SUB-FSM
    //=========================================================================
    localparam [4:0]
        TX_COMPUTING      = 5'd0,
        TX_LBL_NONCE      = 5'd1,  TX_NONCE     = 5'd2,  TX_CRLF_N  = 5'd3,
        TX_LBL_AAD        = 5'd4,  TX_AAD       = 5'd5,  TX_CRLF_A  = 5'd6,
        TX_LBL_CT         = 5'd19, TX_CT        = 5'd20, TX_CRLF_C  = 5'd21,
        TX_LBL_TAG        = 5'd7,  TX_TAG       = 5'd8,  TX_CRLF_T  = 5'd9,
        TX_LBL_PLAIN      = 5'd10, TX_PLAIN     = 5'd11, TX_CRLF_P  = 5'd12,
        TX_LBL_VERIFY     = 5'd13, TX_VERIFY    = 5'd14, TX_CRLF_V  = 5'd15,
        TX_DONE_CRLF      = 5'd16,
        TX_FINISH         = 5'd17;

    localparam [3:0]
        ATX_NONCE_LBL    = 4'd0,  ATX_NONCE    = 4'd1,  ATX_NONCE_CRLF = 4'd2,
        ATX_TAG_LBL      = 4'd3,  ATX_TAG      = 4'd4,  ATX_TAG_CRLF   = 4'd5,
        ATX_VERIFY_LBL   = 4'd6,  ATX_VERIFY   = 4'd7,  ATX_VERIFY_CRLF= 4'd8,
        ATX_FINISH       = 4'd9;

    // [DBG-DEC-PRINT] Per-chunk decrypt serial print sub-FSM states.
    // Prints: "\r\n[DECnnn] PT=XXXXXXXXXXXXXXXX TAG=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX OK/FAIL\r\n"
    localparam [3:0]
        DDG_HDR      = 4'd0,   // "\r\n[DEC"
        DDG_IDX      = 4'd1,   // 3-digit chunk index + "]"
        DDG_PT_LBL   = 4'd2,   // " PT="
        DDG_PT_HEX   = 4'd3,   // 16 hex chars (first 8 bytes of plaintext)
        DDG_TAG_LBL  = 4'd4,   // " TAG="
        DDG_TAG_HEX  = 4'd5,   // 32 hex chars (full 16-byte tag)
        DDG_VERDICT  = 4'd6,   // " OK\r\n" or " FAIL\r\n"
        DDG_DONE     = 4'd7;

    // [BUG6] Progress print sub-FSM
    localparam [3:0]
        PRG_CR      = 4'd0,   // \r
        PRG_ESC     = 4'd1,   // ESC [
        PRG_COLOR   = 4'd2,   // 33m (enc=yellow) or 36m (dec=cyan)
        PRG_LBRACKET= 4'd3,   // [
        PRG_MODE    = 4'd4,   // "ENC " or "DEC "
        PRG_SPACE   = 4'd5,   // space after mode
        PRG_PCT_H   = 4'd6,   // hundreds digit
        PRG_PCT_T   = 4'd7,   // tens digit
        PRG_PCT_O   = 4'd8,   // ones digit
        PRG_PERCENT = 4'd9,   // '%'
        PRG_RBRACKET= 4'd10,  // ]
        PRG_RESET   = 4'd11,  // ESC[0m
        PRG_DONE    = 4'd12;

    reg [4:0] tx_state;
    reg [3:0] atx_state;
    reg [3:0] prg_state;   // [BUG6]
    reg [5:0] tx_char_cnt;
    reg [6:0] ct_nibble_cnt; // [BUG1-FIX] dedicated 7-bit counter for TX_CT (128 nibbles max)
    reg       prg_is_dec;  // 0=enc(yellow), 1=dec(cyan)

    // [DBG-ENC] Per-chunk encrypt debug print sub-FSM
    localparam [3:0]
        DBG_HDR      = 4'd0,   // "\r\n[ENC0" label
        DBG_IDX      = 4'd1,   // chunk index digits
        DBG_CT_LBL   = 4'd2,   // "] CT="
        DBG_CT_HEX   = 4'd3,   // 16 CT hex chars (8 bytes)
        DBG_TAG_LBL  = 4'd4,   // " TAG="
        DBG_TAG_HEX  = 4'd5,   // 32 TAG hex chars (16 bytes) 
        DBG_CRLF     = 4'd6,   // "\r\n"
        DBG_DONE     = 4'd7;

    reg [3:0]   dbg_state;
    reg [9:0]   dbg_chunk_idx_snap;   // snapshot of enc_chunk_idx at time of debug trigger
    reg [511:0] dbg_ct_snap;          // snapshot of ascon_ct
    reg [127:0] dbg_tag_snap;         // snapshot of ascon_tag
    reg [5:0]   dbg_char_cnt;         // nibble counter for hex printing

    // [DBG-DEC] Decrypt-side snapshots (SPI frame fields)
    reg [3:0]   ddg_state;            // dec debug sub-FSM
    reg [9:0]   ddg_chunk_idx_snap;
    reg         dec_done_sent_r;     // prevents DDG_DONE re-printing "[Dec done]"
    reg [63:0]  ddg_ct_snap;          // first 8 bytes of CT from ESP32
    reg [127:0] ddg_nonce_snap;       // nonce from ESP32
    reg [127:0] ddg_tag_snap;         // tag from ESP32
    reg [63:0]  ddg_pt_snap;          // first 8 bytes of decrypted plaintext
    reg [5:0]   ddg_char_cnt;

    //=========================================================================
    // AAD PADDING
    //=========================================================================
    function [63:0] pad_aad;
        input [55:0] raw;
        input [2:0]  len;
        reg [63:0] tmp;
        integer k;
        begin
            tmp = 64'd0;
            for (k = 0; k < 7; k = k + 1) begin
                if (k < len)
                    tmp[63 - k*8 -: 8] = raw[55 - k*8 -: 8];
            end
            case (len)
                3'd0: tmp[63:56] = 8'h80;
                3'd1: tmp[55:48] = 8'h80;
                3'd2: tmp[47:40] = 8'h80;
                3'd3: tmp[39:32] = 8'h80;
                3'd4: tmp[31:24] = 8'h80;
                3'd5: tmp[23:16] = 8'h80;
                3'd6: tmp[15:8]  = 8'h80;
                3'd7: tmp[7:0]   = 8'h80;
            endcase
            pad_aad = tmp;
        end
    endfunction

    //=========================================================================
    // PT LENGTH FINDER
    //=========================================================================
    function [6:0] find_pt_len;
        input [511:0] pt_data;
        input         tag_ok;
        integer bi;
        integer found;
        begin
            found = 0;
            if (tag_ok) begin
                found = 64;
                for (bi = 0; bi < 64; bi = bi + 1) begin
                    if (pt_data[511 - bi*8 -: 8] == 8'h80 && found == 64)
                        found = bi;
                end
                if (found == 64) found = 0;
            end
            find_pt_len = found[6:0];
        end
    endfunction

    //=========================================================================
    // PT PADDING
    //=========================================================================
    function [511:0] pad_pt_bytes;
        input [5:0] len;
        reg [511:0] tmp;
        integer k;
        begin
            tmp = 512'd0;
            for (k = 0; k < 64; k = k + 1) begin
                if (k < len)
                    tmp[511 - k*8 -: 8] = pt_bytes[k];
            end
            case (len)
                6'd0:  tmp[511:504] = 8'h80; 6'd1:  tmp[503:496] = 8'h80;
                6'd2:  tmp[495:488] = 8'h80; 6'd3:  tmp[487:480] = 8'h80;
                6'd4:  tmp[479:472] = 8'h80; 6'd5:  tmp[471:464] = 8'h80;
                6'd6:  tmp[463:456] = 8'h80; 6'd7:  tmp[455:448] = 8'h80;
                6'd8:  tmp[447:440] = 8'h80; 6'd9:  tmp[439:432] = 8'h80;
                6'd10: tmp[431:424] = 8'h80; 6'd11: tmp[423:416] = 8'h80;
                6'd12: tmp[415:408] = 8'h80; 6'd13: tmp[407:400] = 8'h80;
                6'd14: tmp[399:392] = 8'h80; 6'd15: tmp[391:384] = 8'h80;
                6'd16: tmp[383:376] = 8'h80; 6'd17: tmp[375:368] = 8'h80;
                6'd18: tmp[367:360] = 8'h80; 6'd19: tmp[359:352] = 8'h80;
                6'd20: tmp[351:344] = 8'h80; 6'd21: tmp[343:336] = 8'h80;
                6'd22: tmp[335:328] = 8'h80; 6'd23: tmp[327:320] = 8'h80;
                6'd24: tmp[319:312] = 8'h80; 6'd25: tmp[311:304] = 8'h80;
                6'd26: tmp[303:296] = 8'h80; 6'd27: tmp[295:288] = 8'h80;
                6'd28: tmp[287:280] = 8'h80; 6'd29: tmp[279:272] = 8'h80;
                6'd30: tmp[271:264] = 8'h80; 6'd31: tmp[263:256] = 8'h80;
                6'd32: tmp[255:248] = 8'h80; 6'd33: tmp[247:240] = 8'h80;
                6'd34: tmp[239:232] = 8'h80; 6'd35: tmp[231:224] = 8'h80;
                6'd36: tmp[223:216] = 8'h80; 6'd37: tmp[215:208] = 8'h80;
                6'd38: tmp[207:200] = 8'h80; 6'd39: tmp[199:192] = 8'h80;
                6'd40: tmp[191:184] = 8'h80; 6'd41: tmp[183:176] = 8'h80;
                6'd42: tmp[175:168] = 8'h80; 6'd43: tmp[167:160] = 8'h80;
                6'd44: tmp[159:152] = 8'h80; 6'd45: tmp[151:144] = 8'h80;
                6'd46: tmp[143:136] = 8'h80; 6'd47: tmp[135:128] = 8'h80;
                6'd48: tmp[127:120] = 8'h80; 6'd49: tmp[119:112] = 8'h80;
                6'd50: tmp[111:104] = 8'h80; 6'd51: tmp[103:96]  = 8'h80;
                6'd52: tmp[95:88]   = 8'h80; 6'd53: tmp[87:80]   = 8'h80;
                6'd54: tmp[79:72]   = 8'h80; 6'd55: tmp[71:64]   = 8'h80;
                6'd56: tmp[63:56]   = 8'h80; 6'd57: tmp[55:48]   = 8'h80;
                6'd58: tmp[47:40]   = 8'h80; 6'd59: tmp[39:32]   = 8'h80;
                6'd60: tmp[31:24]   = 8'h80; 6'd61: tmp[23:16]   = 8'h80;
                6'd62: tmp[15:8]    = 8'h80; 6'd63: tmp[7:0]     = 8'h80;
            endcase
            pad_pt_bytes = tmp;
        end
    endfunction

    //=========================================================================
    // uart_fsm_state combinational output  [BUG3 updated] [FIX-PR_REC]
    // 0xA5 = enc-ready: asserted from S_AUD_ENC_WAIT_RNG onwards so the
    //        ESP32 sees 0xA5 as soon as the key is accepted, not only after
    //        the "Press button" string has finished printing.
    //        Previously only S_AUD_ENC_WAIT_SPI / S_AUD_ENC_LAUNCH drove 0xA5.
    //        The "Press button" print state (S_AUD_ENC_PR_REC) took ~30 ms at
    //        115200 baud, during which uart_fsm_state was 0x00.  The ESP32's
    //        waitForFsmState() timed out before S_AUD_ENC_WAIT_SPI was reached.
    // 0x5A = dec-ready (S_AUD_DEC_LAUNCH and S_AUD_DEC_WAIT)
    // 0x00 = any other state
    //
    // [FIX-5A-DELAY] CRITICAL: S_AUD_DEC_PR_KEY and S_AUD_DEC_RD_KEY must
    //   drive 0x00, NOT 0x5A.  The old code asserted 0x5A as soon as the user
    //   pressed [4], BEFORE the decrypt key had been typed and latched into
    //   audio_key_out.  The ESP32's waitForFsmState(0x5A) returned immediately,
    //   then fired the first 0x02 SPI frame while audio_key_out was still the
    //   stale encrypt-session key → tag mismatch on early chunks.
    //   Fix: 0x5A only from S_AUD_DEC_PR_COMP onwards, i.e. after the key has
    //   been fully received and audio_key_out has been non-blocking-assigned.
    //   By the time ESP32 polls and sees 0x5A the key is already settled.
    //=========================================================================
    always @(*) begin
        case (rx_state)
            // [FIX-EARLYREADY] Assert 0xA5 from the moment the user presses [3]
            S_AUD_ENC_PR_KEY    : uart_fsm_state = 8'hA5;
            S_AUD_ENC_RD_KEY    : uart_fsm_state = 8'hA5;
            S_AUD_ENC_WAIT_RNG  : uart_fsm_state = 8'hA5;
            S_AUD_ENC_PR_REC    : uart_fsm_state = 8'hA5;
            S_AUD_ENC_WAIT_SPI  : uart_fsm_state = 8'hA5;
            S_AUD_ENC_LAUNCH    : uart_fsm_state = 8'hA5;
            S_AUD_ENC_DBG       : uart_fsm_state = 8'hA5;
            // [FIX-5A-DELAY] Drive 0x00 while user is still typing the decrypt
            // key so the ESP32 cannot fire 0x02 frames before audio_key_out
            // is fully written.  0x5A only rises from S_AUD_DEC_PR_COMP onward.
            S_AUD_DEC_PR_KEY    : uart_fsm_state = 8'h00;  // key not ready yet
            S_AUD_DEC_RD_KEY    : uart_fsm_state = 8'h00;  // still receiving key
            // [ALTC-NODEC-DBGPRINT] Hold 0x5A through ALL decrypt loop states.
            // No per-chunk UART printing -> FSM never drops from 0x5A during decrypt.
            S_AUD_DEC_PR_COMP   : uart_fsm_state = 8'h5A;
            S_AUD_DEC_LAUNCH    : uart_fsm_state = 8'h5A;
            S_AUD_DEC_WAIT      : uart_fsm_state = 8'h5A;
            S_AUD_DEC_TX        : uart_fsm_state = 8'h5A;
            S_AUD_DEC_PR_PLAY   : uart_fsm_state = 8'h00;  // key fail reprint - key not ready
            S_AUD_DEC_DONE      : uart_fsm_state = 8'h5A;
            S_AUD_DEC_DBG       : uart_fsm_state = 8'h5A;
            S_AUD_PROGRESS      : uart_fsm_state = prg_is_dec ? 8'h5A : 8'hA5;
            default             : uart_fsm_state = 8'h00;
        endcase
    end

    //=========================================================================
    // spi_audio_seen sticky latch
    // [FIX-SEEN] Merged into the main FSM always block to eliminate the
    // multi-driver conflict (two always blocks cannot both drive the same reg).
    // All set/clear assignments are now inside the main FSM block below.
    //=========================================================================

    //=========================================================================
    // MAIN FSM
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_state             <= S_POR_HOLD;  // [BUG1]
            ascon_start          <= 1'b0;
            dec_tag_override_out <= 1'b0;
            dec_tag_in_out       <= 128'd0;
            key_out              <= 128'd0;
            nonce_out            <= 128'd0;
            aad_out              <= 64'd0;
            pt_out               <= 512'd0;
            pt_len_bytes_out     <= 7'd0;
            key_buf              <= 128'd0;
            key_cnt              <= 5'd0;
            aad_raw              <= 56'd0;
            aad_len              <= 3'd0;
            pt_len               <= 7'd0;
            stored_nonce         <= 128'd0;
            stored_ct            <= 512'd0;
            stored_tag           <= 128'd0;
            stored_match         <= 1'b0;
            stored_pt_dec        <= 512'd0;
            stored_pt_len        <= 7'd0;
            stored_ct_chars      <= 7'd0;
            audio_stored_nonce   <= 128'd0;
            audio_stored_tag     <= 128'd0;
            audio_enc_result_ready <= 1'b0;
            enc_result_ready     <= 1'b0;
            audio_key_buf        <= 128'd0;
            audio_key_out        <= 128'd0;
            mode_decrypt         <= 1'b0;
            ascon_done_latch     <= 1'b0;
            spi_audio_seen       <= 1'b0;
            led_waiting          <= 1'b0;
            led_computing        <= 1'b0;
            tx_str_idx           <= 7'd0;
            tx_str_active        <= 1'b0;
            tx_str_done          <= 1'b0;
            tx_fired             <= 1'b0;
            send_req             <= 1'b0;
            tx_byte              <= 8'd0;
            tx_state             <= TX_COMPUTING;
            atx_state            <= ATX_NONCE_LBL;
            prg_state            <= PRG_CR;
            prg_is_dec           <= 1'b0;
            tx_char_cnt          <= 6'd0;
            ct_nibble_cnt        <= 7'd0;
            pt_dec_len           <= 7'd0;
            tx_pt_idx            <= 6'd0;
            enc_chunk_idx        <= 10'd0;
            total_chunks_lat     <= 10'd0;
            pct_val              <= 7'd0;
            progress_return_state<= S_AUD_ENC_LAUNCH;
            dec_arm_r            <= 1'b0;
            aud_idle_cnt         <= 30'd0;
            dbg_state            <= DBG_HDR;
            dbg_chunk_idx_snap   <= 10'd0;
            dbg_ct_snap          <= 512'd0;
            dbg_tag_snap         <= 128'd0;
            dbg_char_cnt         <= 6'd0;
            ddg_state            <= DDG_HDR;
            ddg_chunk_idx_snap   <= 10'd0;
            ddg_ct_snap          <= 64'd0;
            ddg_nonce_snap       <= 128'd0;
            ddg_tag_snap         <= 128'd0;
            ddg_pt_snap          <= 64'd0;
            ddg_char_cnt         <= 6'd0;
            dec_done_sent_r      <= 1'b0;
            begin : rst_pt
                integer ci;
                for (ci = 0; ci < 64; ci = ci + 1)
                    pt_bytes[ci] <= 8'd0;
            end
            tx_str_len <= 7'd0;
            begin : rst_rom
                integer ri;
                for (ri = 0; ri < 88; ri = ri + 1)
                    tx_str_rom[ri] <= 8'd0;
            end
        end else begin
            // Default deasserts
            ascon_start  <= 1'b0;
            send_req     <= 1'b0;

            // [FIX-DONELATCH] Guard: do not set ascon_done_latch when S_AUD_DEC_LAUNCH
            // is in its arm cycle (dec_arm_r=0), because that same cycle writes
            // ascon_done_latch <= 1'b0 in the LAUNCH branch.  Two non-blocking
            // assignments to the same register in the same always block are
            // synthesis-tool dependent (last write wins, or first write wins,
            // or a warning is issued).  Guarding here removes the conflict entirely:
            // the arm cycle's explicit clear always wins, and the NEXT cycle the
            // real ascon_done from the 0x02 frame will be captured cleanly.
            if (ascon_done && !(rx_state == S_AUD_DEC_LAUNCH && !dec_arm_r))
                ascon_done_latch <= 1'b1;

            // [FIX-SEEN] spi_audio_seen set: only type-0x01 audio-encrypt frames.
            // [BUG5-FIX] Text-encrypt (0x03) frames must never set this flag.
            // [FIX-TYPLAG] Use spi_audio_frame_in (pre-gated from top) instead of
            // raw spi_frame_valid & (spi_frame_type==0x01).  The raw check failed
            // because frame_type_out is 0x00 on the first cycle frame_valid rises.
            // Clear assignments live in S_AUD_ENC_LAUNCH and S_AUD_ENC_PR_COMP.
            if (spi_audio_frame_in)
                spi_audio_seen <= 1'b1;

            // ── String-sender sub-FSM ─────────────────────────────────────────
            if (tx_busy_fall) tx_fired <= 1'b0;

            if (tx_str_active) begin
                if (!tx_busy && !tx_fired) begin
                    tx_byte       <= tx_str_rom[tx_str_idx];
                    send_req      <= 1'b1;
                    tx_fired      <= 1'b1;
                    tx_str_idx    <= tx_str_idx + 7'd1;
                    if (tx_str_idx == tx_str_len - 7'd1) begin
                        tx_str_active <= 1'b0;
                        tx_str_done   <= 1'b1;
                    end
                end
            end else begin
                tx_str_done <= 1'b0;
            end
            // ─────────────────────────────────────────────────────────────────

            case (rx_state)

                //--------------------------------------------------------------
                // [BUG1] POWER-ON HOLD: wait until POR timer + TRNG ready
                //--------------------------------------------------------------
                S_POR_HOLD: begin
                    if (por_done && trng_valid)
                        rx_state <= S_BANNER;
                end

                //--------------------------------------------------------------
                // BANNER
                //--------------------------------------------------------------
                S_BANNER: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h3D; tx_str_rom[3]  <= 8'h3D; tx_str_rom[4]  <= 8'h3D;
                        tx_str_rom[5]  <= 8'h3D; tx_str_rom[6]  <= 8'h3D; tx_str_rom[7]  <= 8'h3D;
                        tx_str_rom[8]  <= 8'h3D; tx_str_rom[9]  <= 8'h3D; tx_str_rom[10] <= 8'h3D;
                        tx_str_rom[11] <= 8'h3D; tx_str_rom[12] <= 8'h3D; tx_str_rom[13] <= 8'h3D;
                        tx_str_rom[14] <= 8'h3D; tx_str_rom[15] <= 8'h3D; tx_str_rom[16] <= 8'h3D;
                        tx_str_rom[17] <= 8'h3D; tx_str_rom[18] <= 8'h3D; tx_str_rom[19] <= 8'h3D;
                        tx_str_rom[20] <= 8'h3D; tx_str_rom[21] <= 8'h3D; tx_str_rom[22] <= 8'h3D;
                        tx_str_rom[23] <= 8'h3D; tx_str_rom[24] <= 8'h3D; tx_str_rom[25] <= 8'h3D;
                        tx_str_rom[26] <= 8'h3D; tx_str_rom[27] <= 8'h3D; tx_str_rom[28] <= 8'h3D;
                        tx_str_rom[29] <= 8'h3D; tx_str_rom[30] <= 8'h3D; tx_str_rom[31] <= 8'h0D;
                        tx_str_rom[32] <= 8'h0A;
                        tx_str_rom[33] <= 8'h41; tx_str_rom[34] <= 8'h53; tx_str_rom[35] <= 8'h43;
                        tx_str_rom[36] <= 8'h4F; tx_str_rom[37] <= 8'h4E; tx_str_rom[38] <= 8'h2D;
                        tx_str_rom[39] <= 8'h31; tx_str_rom[40] <= 8'h32; tx_str_rom[41] <= 8'h38;
                        tx_str_rom[42] <= 8'h20; tx_str_rom[43] <= 8'h43; tx_str_rom[44] <= 8'h52;
                        tx_str_rom[45] <= 8'h59; tx_str_rom[46] <= 8'h50; tx_str_rom[47] <= 8'h54;
                        tx_str_rom[48] <= 8'h4F; tx_str_rom[49] <= 8'h20; tx_str_rom[50] <= 8'h53;
                        tx_str_rom[51] <= 8'h59; tx_str_rom[52] <= 8'h53; tx_str_rom[53] <= 8'h54;
                        tx_str_rom[54] <= 8'h45; tx_str_rom[55] <= 8'h4D; tx_str_rom[56] <= 8'h0D;
                        tx_str_rom[57] <= 8'h0A;
                        tx_str_rom[58] <= 8'h3D; tx_str_rom[59] <= 8'h3D; tx_str_rom[60] <= 8'h3D;
                        tx_str_rom[61] <= 8'h3D; tx_str_rom[62] <= 8'h3D; tx_str_rom[63] <= 8'h3D;
                        tx_str_rom[64] <= 8'h3D; tx_str_rom[65] <= 8'h3D; tx_str_rom[66] <= 8'h3D;
                        tx_str_rom[67] <= 8'h3D; tx_str_rom[68] <= 8'h3D; tx_str_rom[69] <= 8'h3D;
                        tx_str_rom[70] <= 8'h3D; tx_str_rom[71] <= 8'h3D; tx_str_rom[72] <= 8'h3D;
                        tx_str_rom[73] <= 8'h3D; tx_str_rom[74] <= 8'h3D; tx_str_rom[75] <= 8'h3D;
                        tx_str_rom[76] <= 8'h3D; tx_str_rom[77] <= 8'h3D; tx_str_rom[78] <= 8'h3D;
                        tx_str_rom[79] <= 8'h3D; tx_str_rom[80] <= 8'h3D; tx_str_rom[81] <= 8'h3D;
                        tx_str_rom[82] <= 8'h3D; tx_str_rom[83] <= 8'h3D; tx_str_rom[84] <= 8'h3D;
                        tx_str_rom[85] <= 8'h3D; tx_str_rom[86] <= 8'h0D; tx_str_rom[87] <= 8'h0A;
                        tx_str_len    <= 7'd88;
                        tx_str_idx    <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_MENU;
                    end
                end

                //--------------------------------------------------------------
                // MENU
                //--------------------------------------------------------------
                S_MENU: begin
                    if (!tx_str_active && !tx_str_done) begin
                        // "[1] Encrypt Text\r\n[2] Decrypt Text\r\n[3] Encrypt Audio\r\n[4] Decrypt Audio\r\nSelect (1-4): "
                        tx_str_rom[0]  <= 8'h5B; tx_str_rom[1]  <= 8'h31; tx_str_rom[2]  <= 8'h5D;
                        tx_str_rom[3]  <= 8'h20; tx_str_rom[4]  <= 8'h45; tx_str_rom[5]  <= 8'h6E;
                        tx_str_rom[6]  <= 8'h63; tx_str_rom[7]  <= 8'h72; tx_str_rom[8]  <= 8'h79;
                        tx_str_rom[9]  <= 8'h70; tx_str_rom[10] <= 8'h74; tx_str_rom[11] <= 8'h20;
                        tx_str_rom[12] <= 8'h54; tx_str_rom[13] <= 8'h65; tx_str_rom[14] <= 8'h78;
                        tx_str_rom[15] <= 8'h74; tx_str_rom[16] <= 8'h0D; tx_str_rom[17] <= 8'h0A;
                        tx_str_rom[18] <= 8'h5B; tx_str_rom[19] <= 8'h32; tx_str_rom[20] <= 8'h5D;
                        tx_str_rom[21] <= 8'h20; tx_str_rom[22] <= 8'h44; tx_str_rom[23] <= 8'h65;
                        tx_str_rom[24] <= 8'h63; tx_str_rom[25] <= 8'h72; tx_str_rom[26] <= 8'h79;
                        tx_str_rom[27] <= 8'h70; tx_str_rom[28] <= 8'h74; tx_str_rom[29] <= 8'h20;
                        tx_str_rom[30] <= 8'h54; tx_str_rom[31] <= 8'h65; tx_str_rom[32] <= 8'h78;
                        tx_str_rom[33] <= 8'h74; tx_str_rom[34] <= 8'h0D; tx_str_rom[35] <= 8'h0A;
                        tx_str_rom[36] <= 8'h5B; tx_str_rom[37] <= 8'h33; tx_str_rom[38] <= 8'h5D;
                        tx_str_rom[39] <= 8'h20; tx_str_rom[40] <= 8'h45; tx_str_rom[41] <= 8'h6E;
                        tx_str_rom[42] <= 8'h63; tx_str_rom[43] <= 8'h72; tx_str_rom[44] <= 8'h79;
                        tx_str_rom[45] <= 8'h70; tx_str_rom[46] <= 8'h74; tx_str_rom[47] <= 8'h20;
                        tx_str_rom[48] <= 8'h41; tx_str_rom[49] <= 8'h75; tx_str_rom[50] <= 8'h64;
                        tx_str_rom[51] <= 8'h69; tx_str_rom[52] <= 8'h6F; tx_str_rom[53] <= 8'h0D;
                        tx_str_rom[54] <= 8'h0A;
                        tx_str_rom[55] <= 8'h5B; tx_str_rom[56] <= 8'h34; tx_str_rom[57] <= 8'h5D;
                        tx_str_rom[58] <= 8'h20; tx_str_rom[59] <= 8'h44; tx_str_rom[60] <= 8'h65;
                        tx_str_rom[61] <= 8'h63; tx_str_rom[62] <= 8'h72; tx_str_rom[63] <= 8'h79;
                        tx_str_rom[64] <= 8'h70; tx_str_rom[65] <= 8'h74; tx_str_rom[66] <= 8'h20;
                        tx_str_rom[67] <= 8'h41; tx_str_rom[68] <= 8'h75; tx_str_rom[69] <= 8'h64;
                        tx_str_rom[70] <= 8'h69; tx_str_rom[71] <= 8'h6F; tx_str_rom[72] <= 8'h0D;
                        tx_str_rom[73] <= 8'h0A;
                        tx_str_rom[74] <= 8'h53; tx_str_rom[75] <= 8'h65; tx_str_rom[76] <= 8'h6C;
                        tx_str_rom[77] <= 8'h65; tx_str_rom[78] <= 8'h63; tx_str_rom[79] <= 8'h74;
                        tx_str_rom[80] <= 8'h20; tx_str_rom[81] <= 8'h28; tx_str_rom[82] <= 8'h31;
                        tx_str_rom[83] <= 8'h2D; tx_str_rom[84] <= 8'h34; tx_str_rom[85] <= 8'h29;
                        tx_str_rom[86] <= 8'h3A; tx_str_rom[87] <= 8'h20;
                        tx_str_len    <= 7'd88;
                        tx_str_idx    <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_MENU_WAIT;
                    end
                end

                S_MENU_WAIT: begin
                    if (rx_valid) begin
                        case (rx_byte)
                            8'h31: begin
                                mode_decrypt         <= 1'b0;
                                dec_tag_override_out <= 1'b0;
                                tx_byte  <= 8'h31; send_req <= 1'b1;
                                rx_state <= S_PR_KEY;
                            end
                            8'h32: begin
                                mode_decrypt         <= 1'b1;
                                dec_tag_override_out <= 1'b1;
                                tx_byte  <= 8'h32; send_req <= 1'b1;
                                rx_state <= enc_result_ready ? S_PR_KEY_D : S_NO_DATA;
                            end
                            8'h33: begin
                                tx_byte  <= 8'h33; send_req <= 1'b1;
                                rx_state <= S_AUD_ENC_PR_KEY;
                            end
                            8'h34: begin
                                tx_byte  <= 8'h34; send_req <= 1'b1;
                                rx_state <= audio_enc_result_ready ? S_AUD_DEC_PR_KEY : S_NO_AUD_DATA;
                            end
                            default: ;
                        endcase
                    end
                end

                //==============================================================
                // TEXT ENCRYPT FLOW
                //==============================================================
                S_PR_KEY: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h4B; tx_str_rom[3]  <= 8'h65; tx_str_rom[4]  <= 8'h79;
                        tx_str_rom[5]  <= 8'h20; tx_str_rom[6]  <= 8'h20; tx_str_rom[7]  <= 8'h28;
                        tx_str_rom[8]  <= 8'h31; tx_str_rom[9]  <= 8'h36; tx_str_rom[10] <= 8'h20;
                        tx_str_rom[11] <= 8'h63; tx_str_rom[12] <= 8'h68; tx_str_rom[13] <= 8'h61;
                        tx_str_rom[14] <= 8'h72; tx_str_rom[15] <= 8'h73; tx_str_rom[16] <= 8'h29;
                        tx_str_rom[17] <= 8'h3A; tx_str_rom[18] <= 8'h20;
                        tx_str_len    <= 7'd19; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        key_buf <= 128'd0; key_cnt <= 5'd0;
                    end else if (tx_str_done) begin
                        rx_state <= S_RD_KEY;
                    end
                end

                S_RD_KEY: begin
                    if (rx_valid && rx_byte != 8'h0D && rx_byte != 8'h0A) begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= rx_byte; send_req <= 1'b1; tx_fired <= 1'b1;
                        end
                        case (key_cnt)
                            5'd0:  key_buf[127:120] <= rx_byte;
                            5'd1:  key_buf[119:112] <= rx_byte;
                            5'd2:  key_buf[111:104] <= rx_byte;
                            5'd3:  key_buf[103:96]  <= rx_byte;
                            5'd4:  key_buf[95:88]   <= rx_byte;
                            5'd5:  key_buf[87:80]   <= rx_byte;
                            5'd6:  key_buf[79:72]   <= rx_byte;
                            5'd7:  key_buf[71:64]   <= rx_byte;
                            5'd8:  key_buf[63:56]   <= rx_byte;
                            5'd9:  key_buf[55:48]   <= rx_byte;
                            5'd10: key_buf[47:40]   <= rx_byte;
                            5'd11: key_buf[39:32]   <= rx_byte;
                            5'd12: key_buf[31:24]   <= rx_byte;
                            5'd13: key_buf[23:16]   <= rx_byte;
                            5'd14: key_buf[15:8]    <= rx_byte;
                            5'd15: key_buf[7:0]     <= rx_byte;
                            default: ;
                        endcase
                        key_cnt <= key_cnt + 5'd1;
                        if (key_cnt == 5'd15) begin
                            key_out  <= {key_buf[127:8], rx_byte};
                            key_cnt  <= 5'd0;
                            rx_state <= S_PR_PT;
                        end
                    end
                end

                S_PR_PT: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h54; tx_str_rom[3]  <= 8'h65; tx_str_rom[4]  <= 8'h78;
                        tx_str_rom[5]  <= 8'h74; tx_str_rom[6]  <= 8'h20; tx_str_rom[7]  <= 8'h28;
                        tx_str_rom[8]  <= 8'h31; tx_str_rom[9]  <= 8'h2D; tx_str_rom[10] <= 8'h36;
                        tx_str_rom[11] <= 8'h34; tx_str_rom[12] <= 8'h20; tx_str_rom[13] <= 8'h63;
                        tx_str_rom[14] <= 8'h68; tx_str_rom[15] <= 8'h61; tx_str_rom[16] <= 8'h72;
                        tx_str_rom[17] <= 8'h73; tx_str_rom[18] <= 8'h2C; tx_str_rom[19] <= 8'h20;
                        tx_str_rom[20] <= 8'h45; tx_str_rom[21] <= 8'h6E; tx_str_rom[22] <= 8'h74;
                        tx_str_rom[23] <= 8'h65; tx_str_rom[24] <= 8'h72; tx_str_rom[25] <= 8'h29;
                        tx_str_rom[26] <= 8'h3A; tx_str_rom[27] <= 8'h20;
                        tx_str_len    <= 7'd28; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        begin : pt_clr
                            integer ci;
                            for (ci = 0; ci < 64; ci = ci + 1)
                                pt_bytes[ci] <= 8'd0;
                        end
                        pt_len <= 7'd0;
                    end else if (tx_str_done) begin
                        rx_state <= S_RD_PT;
                    end
                end

                S_RD_PT: begin
                    if (rx_valid) begin
                        if (rx_byte == 8'h0D || rx_byte == 8'h0A) begin
                            if (pt_len > 7'd0) begin
                                pt_out   <= pad_pt_bytes(pt_len[5:0]);
                                rx_state <= S_WAIT_RNG;
                            end
                        end else if ((rx_byte == 8'h08 || rx_byte == 8'h7F) && pt_len > 7'd0) begin
                            pt_len <= pt_len - 7'd1;
                            tx_byte  <= 8'h08; send_req <= 1'b1;
                            tx_str_rom[0] <= 8'h20; tx_str_rom[1] <= 8'h08;
                            tx_str_len <= 7'd2; tx_str_idx <= 7'd0;
                            tx_str_active <= 1'b1;
                        end else if (rx_byte >= 8'h20 && rx_byte < 8'h7F && pt_len < 7'd64) begin
                            tx_byte  <= rx_byte; send_req <= 1'b1;
                            case (pt_len)
                                7'd0:  pt_bytes[0]  <= rx_byte; 7'd1:  pt_bytes[1]  <= rx_byte;
                                7'd2:  pt_bytes[2]  <= rx_byte; 7'd3:  pt_bytes[3]  <= rx_byte;
                                7'd4:  pt_bytes[4]  <= rx_byte; 7'd5:  pt_bytes[5]  <= rx_byte;
                                7'd6:  pt_bytes[6]  <= rx_byte; 7'd7:  pt_bytes[7]  <= rx_byte;
                                7'd8:  pt_bytes[8]  <= rx_byte; 7'd9:  pt_bytes[9]  <= rx_byte;
                                7'd10: pt_bytes[10] <= rx_byte; 7'd11: pt_bytes[11] <= rx_byte;
                                7'd12: pt_bytes[12] <= rx_byte; 7'd13: pt_bytes[13] <= rx_byte;
                                7'd14: pt_bytes[14] <= rx_byte; 7'd15: pt_bytes[15] <= rx_byte;
                                7'd16: pt_bytes[16] <= rx_byte; 7'd17: pt_bytes[17] <= rx_byte;
                                7'd18: pt_bytes[18] <= rx_byte; 7'd19: pt_bytes[19] <= rx_byte;
                                7'd20: pt_bytes[20] <= rx_byte; 7'd21: pt_bytes[21] <= rx_byte;
                                7'd22: pt_bytes[22] <= rx_byte; 7'd23: pt_bytes[23] <= rx_byte;
                                7'd24: pt_bytes[24] <= rx_byte; 7'd25: pt_bytes[25] <= rx_byte;
                                7'd26: pt_bytes[26] <= rx_byte; 7'd27: pt_bytes[27] <= rx_byte;
                                7'd28: pt_bytes[28] <= rx_byte; 7'd29: pt_bytes[29] <= rx_byte;
                                7'd30: pt_bytes[30] <= rx_byte; 7'd31: pt_bytes[31] <= rx_byte;
                                7'd32: pt_bytes[32] <= rx_byte; 7'd33: pt_bytes[33] <= rx_byte;
                                7'd34: pt_bytes[34] <= rx_byte; 7'd35: pt_bytes[35] <= rx_byte;
                                7'd36: pt_bytes[36] <= rx_byte; 7'd37: pt_bytes[37] <= rx_byte;
                                7'd38: pt_bytes[38] <= rx_byte; 7'd39: pt_bytes[39] <= rx_byte;
                                7'd40: pt_bytes[40] <= rx_byte; 7'd41: pt_bytes[41] <= rx_byte;
                                7'd42: pt_bytes[42] <= rx_byte; 7'd43: pt_bytes[43] <= rx_byte;
                                7'd44: pt_bytes[44] <= rx_byte; 7'd45: pt_bytes[45] <= rx_byte;
                                7'd46: pt_bytes[46] <= rx_byte; 7'd47: pt_bytes[47] <= rx_byte;
                                7'd48: pt_bytes[48] <= rx_byte; 7'd49: pt_bytes[49] <= rx_byte;
                                7'd50: pt_bytes[50] <= rx_byte; 7'd51: pt_bytes[51] <= rx_byte;
                                7'd52: pt_bytes[52] <= rx_byte; 7'd53: pt_bytes[53] <= rx_byte;
                                7'd54: pt_bytes[54] <= rx_byte; 7'd55: pt_bytes[55] <= rx_byte;
                                7'd56: pt_bytes[56] <= rx_byte; 7'd57: pt_bytes[57] <= rx_byte;
                                7'd58: pt_bytes[58] <= rx_byte; 7'd59: pt_bytes[59] <= rx_byte;
                                7'd60: pt_bytes[60] <= rx_byte; 7'd61: pt_bytes[61] <= rx_byte;
                                7'd62: pt_bytes[62] <= rx_byte; 7'd63: pt_bytes[63] <= rx_byte;
                                default: ;
                            endcase
                            pt_len <= pt_len + 7'd1;
                        end
                    end
                end

                S_PT_COMMIT: begin
                    rx_state <= S_WAIT_RNG;
                end

                S_WAIT_RNG: begin
                    if (trng_valid) begin
                        nonce_out <= trng_nonce;
                        aad_out   <= {trng_nonce[127:72], 8'h80};
                        aad_raw   <= trng_nonce[127:72];
                        aad_len   <= 3'd7;
                        rx_state  <= S_LAUNCH_ENC;
                    end
                end

                S_LAUNCH_ENC: begin
                    pt_len_bytes_out <= pt_len;
                    ascon_start      <= 1'b1;
                    led_computing    <= 1'b1;
                    led_waiting      <= 1'b0;
                    rx_state         <= S_WAIT_ENC;
                end

                S_WAIT_ENC: begin
                    if (ascon_done) begin
                        stored_nonce     <= nonce_out;
                        stored_pt_len    <= pt_len;
                        stored_ct_chars  <= (((pt_len + 7'd7) >> 3) << 4) - 7'd1;
                        stored_ct        <= ascon_ct;
                        stored_tag       <= ascon_tag;
                        stored_match     <= ascon_tag_match;
                        enc_result_ready <= 1'b1;
                        led_computing    <= 1'b0;
                        tx_state         <= TX_COMPUTING;
                        tx_char_cnt      <= 6'd0;
                        rx_state         <= S_TX_ENC;
                    end
                end

                //==============================================================
                // TEXT DECRYPT FLOW
                //==============================================================
                S_PR_KEY_D: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h4B; tx_str_rom[3]  <= 8'h65; tx_str_rom[4]  <= 8'h79;
                        tx_str_rom[5]  <= 8'h20; tx_str_rom[6]  <= 8'h20; tx_str_rom[7]  <= 8'h28;
                        tx_str_rom[8]  <= 8'h31; tx_str_rom[9]  <= 8'h36; tx_str_rom[10] <= 8'h20;
                        tx_str_rom[11] <= 8'h63; tx_str_rom[12] <= 8'h68; tx_str_rom[13] <= 8'h61;
                        tx_str_rom[14] <= 8'h72; tx_str_rom[15] <= 8'h73; tx_str_rom[16] <= 8'h29;
                        tx_str_rom[17] <= 8'h3A; tx_str_rom[18] <= 8'h20;
                        tx_str_len    <= 7'd19; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        key_buf <= 128'd0; key_cnt <= 5'd0;
                    end else if (tx_str_done) begin
                        rx_state <= S_RD_KEY_D;
                    end
                end

                S_RD_KEY_D: begin
                    if (rx_valid && rx_byte != 8'h0D && rx_byte != 8'h0A) begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= rx_byte; send_req <= 1'b1; tx_fired <= 1'b1;
                        end
                        case (key_cnt)
                            5'd0:  key_buf[127:120] <= rx_byte;
                            5'd1:  key_buf[119:112] <= rx_byte;
                            5'd2:  key_buf[111:104] <= rx_byte;
                            5'd3:  key_buf[103:96]  <= rx_byte;
                            5'd4:  key_buf[95:88]   <= rx_byte;
                            5'd5:  key_buf[87:80]   <= rx_byte;
                            5'd6:  key_buf[79:72]   <= rx_byte;
                            5'd7:  key_buf[71:64]   <= rx_byte;
                            5'd8:  key_buf[63:56]   <= rx_byte;
                            5'd9:  key_buf[55:48]   <= rx_byte;
                            5'd10: key_buf[47:40]   <= rx_byte;
                            5'd11: key_buf[39:32]   <= rx_byte;
                            5'd12: key_buf[31:24]   <= rx_byte;
                            5'd13: key_buf[23:16]   <= rx_byte;
                            5'd14: key_buf[15:8]    <= rx_byte;
                            5'd15: key_buf[7:0]     <= rx_byte;
                            default: ;
                        endcase
                        key_cnt <= key_cnt + 5'd1;
                        if (key_cnt == 5'd15) begin
                            key_out  <= {key_buf[127:8], rx_byte};
                            key_cnt  <= 5'd0;
                            rx_state <= S_LAUNCH_DEC;
                        end
                    end
                end

                S_LAUNCH_DEC: begin
                    dec_tag_in_out   <= stored_tag;
                    pt_out           <= stored_ct;
                    nonce_out        <= stored_nonce;
                    pt_len_bytes_out <= stored_pt_len;
                    ascon_start      <= 1'b1;
                    led_computing    <= 1'b1;
                    led_waiting      <= 1'b0;
                    rx_state         <= S_WAIT_DEC;
                end

                S_WAIT_DEC: begin
                    if (ascon_done) begin
                        stored_match  <= ascon_tag_match;
                        stored_pt_dec <= ascon_pt_dec;
                        pt_dec_len    <= find_pt_len(ascon_pt_dec, ascon_tag_match);
                        led_computing <= 1'b0;
                        tx_state      <= TX_COMPUTING;
                        tx_char_cnt   <= 6'd0;
                        rx_state      <= S_TX_DEC;
                    end
                end

                //==============================================================
                // AUDIO ENCRYPT FLOW
                //==============================================================
                S_AUD_ENC_PR_KEY: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h2D; tx_str_rom[3]  <= 8'h2D;
                        tx_str_rom[4]  <= 8'h20; tx_str_rom[5]  <= 8'h41;
                        tx_str_rom[6]  <= 8'h55; tx_str_rom[7]  <= 8'h44;
                        tx_str_rom[8]  <= 8'h49; tx_str_rom[9]  <= 8'h4F;
                        tx_str_rom[10] <= 8'h20; tx_str_rom[11] <= 8'h45;
                        tx_str_rom[12] <= 8'h4E; tx_str_rom[13] <= 8'h43;
                        tx_str_rom[14] <= 8'h52; tx_str_rom[15] <= 8'h59;
                        tx_str_rom[16] <= 8'h50; tx_str_rom[17] <= 8'h54;
                        tx_str_rom[18] <= 8'h20; tx_str_rom[19] <= 8'h2D;
                        tx_str_rom[20] <= 8'h2D; tx_str_rom[21] <= 8'h0D;
                        tx_str_rom[22] <= 8'h0A;
                        tx_str_rom[23] <= 8'h4B; tx_str_rom[24] <= 8'h65;
                        tx_str_rom[25] <= 8'h79; tx_str_rom[26] <= 8'h20;
                        tx_str_rom[27] <= 8'h28; tx_str_rom[28] <= 8'h31;
                        tx_str_rom[29] <= 8'h36; tx_str_rom[30] <= 8'h20;
                        tx_str_rom[31] <= 8'h63; tx_str_rom[32] <= 8'h68;
                        tx_str_rom[33] <= 8'h61; tx_str_rom[34] <= 8'h72;
                        tx_str_rom[35] <= 8'h73; tx_str_rom[36] <= 8'h29;
                        tx_str_rom[37] <= 8'h3A; tx_str_rom[38] <= 8'h20;
                        tx_str_len    <= 7'd39; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        audio_key_buf <= 128'd0; key_cnt <= 5'd0;
                    end else if (tx_str_done) begin
                        rx_state <= S_AUD_ENC_RD_KEY;
                    end
                end

                S_AUD_ENC_RD_KEY: begin
                    if (rx_valid && rx_byte != 8'h0D && rx_byte != 8'h0A) begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= rx_byte; send_req <= 1'b1; tx_fired <= 1'b1;
                        end
                        case (key_cnt)
                            5'd0:  audio_key_buf[127:120] <= rx_byte;
                            5'd1:  audio_key_buf[119:112] <= rx_byte;
                            5'd2:  audio_key_buf[111:104] <= rx_byte;
                            5'd3:  audio_key_buf[103:96]  <= rx_byte;
                            5'd4:  audio_key_buf[95:88]   <= rx_byte;
                            5'd5:  audio_key_buf[87:80]   <= rx_byte;
                            5'd6:  audio_key_buf[79:72]   <= rx_byte;
                            5'd7:  audio_key_buf[71:64]   <= rx_byte;
                            5'd8:  audio_key_buf[63:56]   <= rx_byte;
                            5'd9:  audio_key_buf[55:48]   <= rx_byte;
                            5'd10: audio_key_buf[47:40]   <= rx_byte;
                            5'd11: audio_key_buf[39:32]   <= rx_byte;
                            5'd12: audio_key_buf[31:24]   <= rx_byte;
                            5'd13: audio_key_buf[23:16]   <= rx_byte;
                            5'd14: audio_key_buf[15:8]    <= rx_byte;
                            5'd15: audio_key_buf[7:0]     <= rx_byte;
                            default: ;
                        endcase
                        key_cnt <= key_cnt + 5'd1;
                        if (key_cnt == 5'd15) begin
                            audio_key_out <= {audio_key_buf[127:8], rx_byte};
                            key_cnt       <= 5'd0;
                            rx_state      <= S_AUD_ENC_WAIT_RNG;
                        end
                    end
                end

                S_AUD_ENC_WAIT_RNG: begin
                    if (trng_valid) begin
                        nonce_out <= trng_nonce;
                        aad_out   <= 64'h8000000000000000;
                        rx_state  <= S_AUD_ENC_PR_REC;
                    end
                end

                S_AUD_ENC_PR_REC: begin
                    if (!tx_str_active && !tx_str_done) begin
                        // "[Press button on ESP32 to record audio...]\r\n"
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h5B;
                        tx_str_rom[3]  <= 8'h50; tx_str_rom[4]  <= 8'h72; tx_str_rom[5]  <= 8'h65;
                        tx_str_rom[6]  <= 8'h73; tx_str_rom[7]  <= 8'h73;
                        tx_str_rom[8]  <= 8'h20; tx_str_rom[9]  <= 8'h62; tx_str_rom[10] <= 8'h75;
                        tx_str_rom[11] <= 8'h74; tx_str_rom[12] <= 8'h74; tx_str_rom[13] <= 8'h6F;
                        tx_str_rom[14] <= 8'h6E;
                        tx_str_rom[15] <= 8'h20; tx_str_rom[16] <= 8'h6F; tx_str_rom[17] <= 8'h6E;
                        tx_str_rom[18] <= 8'h20; tx_str_rom[19] <= 8'h45; tx_str_rom[20] <= 8'h53;
                        tx_str_rom[21] <= 8'h50; tx_str_rom[22] <= 8'h33; tx_str_rom[23] <= 8'h32;
                        tx_str_rom[24] <= 8'h20; tx_str_rom[25] <= 8'h74; tx_str_rom[26] <= 8'h6F;
                        tx_str_rom[27] <= 8'h20; tx_str_rom[28] <= 8'h72; tx_str_rom[29] <= 8'h65;
                        tx_str_rom[30] <= 8'h63; tx_str_rom[31] <= 8'h6F; tx_str_rom[32] <= 8'h72;
                        tx_str_rom[33] <= 8'h64;
                        tx_str_rom[34] <= 8'h20; tx_str_rom[35] <= 8'h61; tx_str_rom[36] <= 8'h75;
                        tx_str_rom[37] <= 8'h64; tx_str_rom[38] <= 8'h69; tx_str_rom[39] <= 8'h6F;
                        tx_str_rom[40] <= 8'h2E; tx_str_rom[41] <= 8'h2E; tx_str_rom[42] <= 8'h2E;
                        tx_str_rom[43] <= 8'h5D;
                        tx_str_rom[44] <= 8'h0D; tx_str_rom[45] <= 8'h0A;
                        tx_str_len    <= 7'd46; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        led_waiting   <= 1'b1;
                        // [BUG6] Reset chunk counters
                        enc_chunk_idx    <= 10'd0;
                        total_chunks_lat <= 10'd0;
                        spi_audio_seen   <= 1'b0;  // [FIX-SEEN] discard any early poll frame
                    end else if (tx_str_done) begin
                        rx_state <= S_AUD_ENC_WAIT_SPI;
                        aud_idle_cnt <= 30'd0;
                    end
                end

                // [BUG3] S_AUD_ENC_WAIT_SPI stays here between ALL chunks
                // uart_fsm_state = 0xA5 here, ESP32 sends each chunk, we go
                // to S_AUD_ENC_LAUNCH to process it, then come right back here.
                S_AUD_ENC_WAIT_SPI: begin
                    if (spi_audio_seen) begin
                        led_waiting  <= 1'b0;
                        aud_idle_cnt <= 30'd0;
                        // [BUG6] latch total_chunks every frame (not just first).
                        // CRITICAL: must NOT guard with (total_chunks_lat==0) because
                        // the latch and the rx_state transition are both non-blocking
                        // assignments on the same clock edge.  If guarded, the latch
                        // fires but total_chunks_lat is STILL 0 when S_AUD_ENC_LAUNCH
                        // reads it on the very next cycle for chunk 0 → [ENC 000%].
                        // Writing unconditionally means the value reaches
                        // S_AUD_ENC_LAUNCH one cycle later as intended.
                        if (total_chunks_in != 10'd0)
                            total_chunks_lat <= total_chunks_in;
                        rx_state <= S_AUD_ENC_LAUNCH;
                    end else begin
                        // Idle watchdog: auto-exit after 500 ms with no frame
                        if (aud_idle_expired) begin
                            aud_idle_cnt <= 30'd0;
                            rx_state     <= S_AUD_ENC_DONE;
                        end else begin
                            aud_idle_cnt <= aud_idle_cnt + 30'd1;
                        end
                    end
                end

                // [BUG3] S_AUD_ENC_LAUNCH also drives uart_fsm_state=0xA5
                // (see combinational block above).  This removes the gap where
                // fsm=0x00 would have appeared while printing per-chunk text.
                //
                // [FIX-SEEN] Clear spi_audio_seen immediately on entering this
                // state so that S_AUD_ENC_WAIT_SPI (which we return to after
                // each chunk) does not instantly re-fire on the stale latch
                // from the chunk we just dispatched.  Without this clear the
                // FSM races through WAIT_SPI → LAUNCH for chunk N without ever
                // waiting for chunk N+1 to arrive over SPI.
                S_AUD_ENC_LAUNCH: begin
                    led_computing    <= 1'b1;
                    spi_audio_seen   <= 1'b0;   // [FIX-SEEN] consume the latch here
                    if (ascon_done_latch) begin
                        ascon_done_latch       <= 1'b0;
                        audio_stored_nonce     <= nonce_out;
                        audio_stored_tag       <= ascon_tag;
                        audio_enc_result_ready <= 1'b1;
                        led_computing          <= 1'b0;
                        // [BUG6] compute percentage and trigger progress print
                        // Use total_chunks_in as fallback for chunk 0 (total_chunks_lat
                        // non-blocking write from WAIT_SPI hasn't propagated yet).
                        begin : enc_launch_pct
                            reg [9:0] tc;  // [FIX-PCT-WIDTH] was 8-bit, truncated >255 chunks
                            tc = (total_chunks_lat != 10'd0) ? total_chunks_lat : total_chunks_in;
                            if (tc != 8'd0) begin
                                pct_val <= ((enc_chunk_idx + 10'd1) >= tc) ? 7'd100
                                           : (7'd0 | (((enc_chunk_idx + 10'd1) * 10'd100) / tc));
                            end else begin
                                pct_val <= 7'd0;
                            end
                        end
                        enc_chunk_idx          <= enc_chunk_idx + 10'd1;
                        prg_is_dec             <= 1'b0;
                        prg_state              <= PRG_CR;
                        progress_return_state  <= S_AUD_ENC_WAIT_SPI;
                        // [FIX-ENC-NODEBUG] Snapshot retained for post-session use,
                        // but the hot path skips S_AUD_ENC_DBG entirely.
                        // Per-chunk UART print (~70 chars @ 115200 baud = ~6 ms)
                        // cannot keep up with real-time 4 ms/chunk audio.
                        // Printing caused the FPGA to fall behind: aud_idle_expired
                        // fired mid-session and the PuTTY log truncated at ~216/377
                        // chunks. Fix: go directly to S_AUD_PROGRESS (progress bar
                        // only), which returns to S_AUD_ENC_WAIT_SPI without delay.
                        dbg_ct_snap            <= ascon_ct;
                        dbg_tag_snap           <= ascon_tag;
                        dbg_chunk_idx_snap     <= enc_chunk_idx;
                        dbg_state              <= DBG_HDR;
                        dbg_char_cnt           <= 6'd0;
                        rx_state               <= S_AUD_PROGRESS;   // [FIX-ENC-NODEBUG]
                    end else begin
                        rx_state <= S_AUD_ENC_WAIT;
                    end
                end

                S_AUD_ENC_WAIT: begin
                    if (ascon_done_latch) begin
                        ascon_done_latch       <= 1'b0;
                        audio_stored_nonce     <= nonce_out;
                        audio_stored_tag       <= ascon_tag;
                        audio_enc_result_ready <= 1'b1;
                        led_computing          <= 1'b0;
                        begin : enc_wait_pct
                            reg [9:0] tc2;  // [FIX-PCT-WIDTH] was 8-bit, truncated >255 chunks
                            tc2 = (total_chunks_lat != 10'd0) ? total_chunks_lat : total_chunks_in;
                            if (tc2 != 8'd0) begin
                                pct_val <= ((enc_chunk_idx + 10'd1) >= tc2) ? 7'd100
                                           : (7'd0 | (((enc_chunk_idx + 10'd1) * 10'd100) / tc2));
                            end else begin
                                pct_val <= 7'd0;
                            end
                        end
                        enc_chunk_idx          <= enc_chunk_idx + 10'd1;
                        prg_is_dec             <= 1'b0;
                        prg_state              <= PRG_CR;
                        progress_return_state  <= S_AUD_ENC_WAIT_SPI;
                        // [FIX-ENC-NODEBUG] Same fix as S_AUD_ENC_LAUNCH above.
                        dbg_ct_snap            <= ascon_ct;
                        dbg_tag_snap           <= ascon_tag;
                        dbg_chunk_idx_snap     <= enc_chunk_idx;
                        dbg_state              <= DBG_HDR;
                        dbg_char_cnt           <= 6'd0;
                        rx_state               <= S_AUD_PROGRESS;   // [FIX-ENC-NODEBUG]
                    end
                end

                // [BUG6] Progress print state - prints "\r\033[33m[ENC XX%]\033[0m"
                // or "\r\033[36m[DEC XX%]\033[0m" using the ANSI sub-FSM below
                S_AUD_PROGRESS: begin
                    if (prg_state == PRG_DONE)
                        rx_state <= progress_return_state;
                end

                //--------------------------------------------------------------
                // [DBG-ENC] Per-chunk encryption debug print
                // Prints: "\r\n[ENCn] CT=XXXXXXXXXXXXXXXX TAG=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\n"
                // where n = chunk index (decimal tens+ones), CT = first 8 bytes hex,
                // TAG = full 16 bytes hex.
                // After printing, transitions to S_AUD_PROGRESS (which goes to S_AUD_ENC_WAIT_SPI).
                //--------------------------------------------------------------
                S_AUD_ENC_DBG: begin
                    if (!tx_busy && !tx_fired) begin
                        case (dbg_state)
                            DBG_HDR: begin
                                // Print "\r\n[ENC"
                                case (dbg_char_cnt)
                                    6'd0: tx_byte <= 8'h0D;  // \r
                                    6'd1: tx_byte <= 8'h0A;  // \n
                                    6'd2: tx_byte <= 8'h5B;  // [
                                    6'd3: tx_byte <= 8'h45;  // E
                                    6'd4: tx_byte <= 8'h4E;  // N
                                    6'd5: tx_byte <= 8'h43;  // C
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd5) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_IDX;
                                end
                            end
                            DBG_IDX: begin
                                // Print 3-digit chunk index then "]"
                                case (dbg_char_cnt)
                                    6'd0: tx_byte <= 8'h30 + {4'd0, dbg_chunk_idx_snap / 10'd100};
                                    6'd1: tx_byte <= 8'h30 + {4'd0, (dbg_chunk_idx_snap % 10'd100) / 10'd10};
                                    6'd2: tx_byte <= 8'h30 + {4'd0, dbg_chunk_idx_snap % 10'd10};
                                    6'd3: tx_byte <= 8'h5D;  // ]
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd3) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_CT_LBL;
                                end
                            end
                            DBG_CT_LBL: begin
                                // Print " CT="
                                case (dbg_char_cnt)
                                    6'd0: tx_byte <= 8'h20;  // space
                                    6'd1: tx_byte <= 8'h43;  // C
                                    6'd2: tx_byte <= 8'h54;  // T
                                    6'd3: tx_byte <= 8'h3D;  // =
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd3) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_CT_HEX;
                                end
                            end
                            DBG_CT_HEX: begin
                                // Print 16 hex chars = 8 bytes of CT (top 8 bytes, bits 511..448)
                                case (dbg_char_cnt)
                                    6'd0:  tx_byte <= nibble_to_hex(dbg_ct_snap[511:508]);
                                    6'd1:  tx_byte <= nibble_to_hex(dbg_ct_snap[507:504]);
                                    6'd2:  tx_byte <= nibble_to_hex(dbg_ct_snap[503:500]);
                                    6'd3:  tx_byte <= nibble_to_hex(dbg_ct_snap[499:496]);
                                    6'd4:  tx_byte <= nibble_to_hex(dbg_ct_snap[495:492]);
                                    6'd5:  tx_byte <= nibble_to_hex(dbg_ct_snap[491:488]);
                                    6'd6:  tx_byte <= nibble_to_hex(dbg_ct_snap[487:484]);
                                    6'd7:  tx_byte <= nibble_to_hex(dbg_ct_snap[483:480]);
                                    6'd8:  tx_byte <= nibble_to_hex(dbg_ct_snap[479:476]);
                                    6'd9:  tx_byte <= nibble_to_hex(dbg_ct_snap[475:472]);
                                    6'd10: tx_byte <= nibble_to_hex(dbg_ct_snap[471:468]);
                                    6'd11: tx_byte <= nibble_to_hex(dbg_ct_snap[467:464]);
                                    6'd12: tx_byte <= nibble_to_hex(dbg_ct_snap[463:460]);
                                    6'd13: tx_byte <= nibble_to_hex(dbg_ct_snap[459:456]);
                                    6'd14: tx_byte <= nibble_to_hex(dbg_ct_snap[455:452]);
                                    6'd15: tx_byte <= nibble_to_hex(dbg_ct_snap[451:448]);
                                    default: tx_byte <= 8'h2E;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd15) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_TAG_LBL;
                                end
                            end
                            DBG_TAG_LBL: begin
                                // Print " TAG="
                                case (dbg_char_cnt)
                                    6'd0: tx_byte <= 8'h20;  // space
                                    6'd1: tx_byte <= 8'h54;  // T
                                    6'd2: tx_byte <= 8'h41;  // A
                                    6'd3: tx_byte <= 8'h47;  // G
                                    6'd4: tx_byte <= 8'h3D;  // =
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd4) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_TAG_HEX;
                                end
                            end
                            DBG_TAG_HEX: begin
                                // Print 32 hex chars = 16 bytes of TAG (bits 127..0)
                                case (dbg_char_cnt)
                                    6'd0:  tx_byte <= nibble_to_hex(dbg_tag_snap[127:124]);
                                    6'd1:  tx_byte <= nibble_to_hex(dbg_tag_snap[123:120]);
                                    6'd2:  tx_byte <= nibble_to_hex(dbg_tag_snap[119:116]);
                                    6'd3:  tx_byte <= nibble_to_hex(dbg_tag_snap[115:112]);
                                    6'd4:  tx_byte <= nibble_to_hex(dbg_tag_snap[111:108]);
                                    6'd5:  tx_byte <= nibble_to_hex(dbg_tag_snap[107:104]);
                                    6'd6:  tx_byte <= nibble_to_hex(dbg_tag_snap[103:100]);
                                    6'd7:  tx_byte <= nibble_to_hex(dbg_tag_snap[99:96]);
                                    6'd8:  tx_byte <= nibble_to_hex(dbg_tag_snap[95:92]);
                                    6'd9:  tx_byte <= nibble_to_hex(dbg_tag_snap[91:88]);
                                    6'd10: tx_byte <= nibble_to_hex(dbg_tag_snap[87:84]);
                                    6'd11: tx_byte <= nibble_to_hex(dbg_tag_snap[83:80]);
                                    6'd12: tx_byte <= nibble_to_hex(dbg_tag_snap[79:76]);
                                    6'd13: tx_byte <= nibble_to_hex(dbg_tag_snap[75:72]);
                                    6'd14: tx_byte <= nibble_to_hex(dbg_tag_snap[71:68]);
                                    6'd15: tx_byte <= nibble_to_hex(dbg_tag_snap[67:64]);
                                    6'd16: tx_byte <= nibble_to_hex(dbg_tag_snap[63:60]);
                                    6'd17: tx_byte <= nibble_to_hex(dbg_tag_snap[59:56]);
                                    6'd18: tx_byte <= nibble_to_hex(dbg_tag_snap[55:52]);
                                    6'd19: tx_byte <= nibble_to_hex(dbg_tag_snap[51:48]);
                                    6'd20: tx_byte <= nibble_to_hex(dbg_tag_snap[47:44]);
                                    6'd21: tx_byte <= nibble_to_hex(dbg_tag_snap[43:40]);
                                    6'd22: tx_byte <= nibble_to_hex(dbg_tag_snap[39:36]);
                                    6'd23: tx_byte <= nibble_to_hex(dbg_tag_snap[35:32]);
                                    6'd24: tx_byte <= nibble_to_hex(dbg_tag_snap[31:28]);
                                    6'd25: tx_byte <= nibble_to_hex(dbg_tag_snap[27:24]);
                                    6'd26: tx_byte <= nibble_to_hex(dbg_tag_snap[23:20]);
                                    6'd27: tx_byte <= nibble_to_hex(dbg_tag_snap[19:16]);
                                    6'd28: tx_byte <= nibble_to_hex(dbg_tag_snap[15:12]);
                                    6'd29: tx_byte <= nibble_to_hex(dbg_tag_snap[11:8]);
                                    6'd30: tx_byte <= nibble_to_hex(dbg_tag_snap[7:4]);
                                    6'd31: tx_byte <= nibble_to_hex(dbg_tag_snap[3:0]);
                                    default: tx_byte <= 8'h2E;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd31) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_CRLF;
                                end
                            end
                            DBG_CRLF: begin
                                tx_byte      <= (dbg_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                dbg_char_cnt <= dbg_char_cnt + 6'd1;
                                if (dbg_char_cnt == 6'd1) begin
                                    dbg_char_cnt <= 6'd0;
                                    dbg_state    <= DBG_DONE;
                                end
                            end
                            DBG_DONE: begin
                                // Debug print complete: go to progress print, then WAIT_SPI
                                rx_state <= S_AUD_PROGRESS;
                            end
                            default: dbg_state <= DBG_HDR;
                        endcase
                    end
                end
                S_AUD_ENC_DONE: begin
                    // [FIX-TOTCHUNKS] Latch total_chunks_in here as the final
                    // authoritative chunk count BEFORE leaving the encrypt flow.
                    // Root cause of [Dec done] loop:
                    //   total_chunks_lat is only written in S_AUD_ENC_WAIT_SPI
                    //   (on 0x01 frames).  The 0x05 end-of-session frame arrives
                    //   AFTER the FSM exits S_AUD_ENC_WAIT_SPI via aud_idle_expired
                    //   into this state, so uart_controller_menu never sees the
                    //   eos_valid_r update.  If total_chunks_lat stayed 0 (e.g. old
                    //   bitstream, or 0x01 frames hadn't written it yet),
                    //   DDG_DONE's condition (total_chunks_lat != 0) was always false
                    //   → every chunk fell through to "all done" → printed
                    //   "[Dec done]" for every single chunk → 33 prints for 23 chunks.
                    // Fix: snapshot total_chunks_in here.  By this cycle the FPGA
                    //   has already seen all 0x01 frames AND the 0x05 frame (via
                    //   eos_valid_r in spi_slave_audio), so total_chunks_in holds
                    //   enc_chunk_count (23).  Guard with != 0 to avoid clobbering
                    //   a valid value with a stale zero on a spurious re-entry.
                    if (total_chunks_in != 10'd0)
                        total_chunks_lat <= total_chunks_in;
                    if (!tx_str_active && !tx_str_done) begin
                        // "\r\n\033[32m[Audio encrypted. Press [4] to decrypt]\033[0m\r\n"
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h1B; tx_str_rom[3]  <= 8'h5B;  // ESC [
                        tx_str_rom[4]  <= 8'h33; tx_str_rom[5]  <= 8'h32;  // 3 2
                        tx_str_rom[6]  <= 8'h6D;                            // m
                        tx_str_rom[7]  <= 8'h5B; tx_str_rom[8]  <= 8'h41; tx_str_rom[9]  <= 8'h75;
                        tx_str_rom[10] <= 8'h64; tx_str_rom[11] <= 8'h69; tx_str_rom[12] <= 8'h6F;
                        tx_str_rom[13] <= 8'h20; tx_str_rom[14] <= 8'h65; tx_str_rom[15] <= 8'h6E;
                        tx_str_rom[16] <= 8'h63; tx_str_rom[17] <= 8'h72; tx_str_rom[18] <= 8'h79;
                        tx_str_rom[19] <= 8'h70; tx_str_rom[20] <= 8'h74; tx_str_rom[21] <= 8'h65;
                        tx_str_rom[22] <= 8'h64; tx_str_rom[23] <= 8'h2E;
                        tx_str_rom[24] <= 8'h20; tx_str_rom[25] <= 8'h50; tx_str_rom[26] <= 8'h72;
                        tx_str_rom[27] <= 8'h65; tx_str_rom[28] <= 8'h73; tx_str_rom[29] <= 8'h73;
                        tx_str_rom[30] <= 8'h20; tx_str_rom[31] <= 8'h5B; tx_str_rom[32] <= 8'h34;
                        tx_str_rom[33] <= 8'h5D; tx_str_rom[34] <= 8'h20; tx_str_rom[35] <= 8'h74;
                        tx_str_rom[36] <= 8'h6F; tx_str_rom[37] <= 8'h20; tx_str_rom[38] <= 8'h64;
                        tx_str_rom[39] <= 8'h65; tx_str_rom[40] <= 8'h63; tx_str_rom[41] <= 8'h72;
                        tx_str_rom[42] <= 8'h79; tx_str_rom[43] <= 8'h70; tx_str_rom[44] <= 8'h74;
                        tx_str_rom[45] <= 8'h5D;
                        tx_str_rom[46] <= 8'h1B; tx_str_rom[47] <= 8'h5B;  // ESC [
                        tx_str_rom[48] <= 8'h30; tx_str_rom[49] <= 8'h6D;  // 0 m
                        tx_str_rom[50] <= 8'h0D; tx_str_rom[51] <= 8'h0A;
                        tx_str_len    <= 7'd52; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        led_waiting   <= 1'b1;
                    end else if (tx_str_done) begin
                        // [BUG2] clean transition to S_WAIT_KEY - no stuck condition
                        led_waiting <= 1'b0;
                        rx_state    <= S_WAIT_KEY;
                    end
                end

                //==============================================================
                // AUDIO DECRYPT FLOW
                //==============================================================
                S_AUD_DEC_PR_KEY: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h2D; tx_str_rom[3]  <= 8'h2D;
                        tx_str_rom[4]  <= 8'h20; tx_str_rom[5]  <= 8'h41;
                        tx_str_rom[6]  <= 8'h55; tx_str_rom[7]  <= 8'h44;
                        tx_str_rom[8]  <= 8'h49; tx_str_rom[9]  <= 8'h4F;
                        tx_str_rom[10] <= 8'h20; tx_str_rom[11] <= 8'h44;
                        tx_str_rom[12] <= 8'h45; tx_str_rom[13] <= 8'h43;
                        tx_str_rom[14] <= 8'h52; tx_str_rom[15] <= 8'h59;
                        tx_str_rom[16] <= 8'h50; tx_str_rom[17] <= 8'h54;
                        tx_str_rom[18] <= 8'h20; tx_str_rom[19] <= 8'h2D;
                        tx_str_rom[20] <= 8'h2D; tx_str_rom[21] <= 8'h0D;
                        tx_str_rom[22] <= 8'h0A;
                        tx_str_rom[23] <= 8'h4B; tx_str_rom[24] <= 8'h65;
                        tx_str_rom[25] <= 8'h79; tx_str_rom[26] <= 8'h20;
                        tx_str_rom[27] <= 8'h28; tx_str_rom[28] <= 8'h31;
                        tx_str_rom[29] <= 8'h36; tx_str_rom[30] <= 8'h20;
                        tx_str_rom[31] <= 8'h63; tx_str_rom[32] <= 8'h68;
                        tx_str_rom[33] <= 8'h61; tx_str_rom[34] <= 8'h72;
                        tx_str_rom[35] <= 8'h73; tx_str_rom[36] <= 8'h29;
                        tx_str_rom[37] <= 8'h3A; tx_str_rom[38] <= 8'h20;
                        tx_str_len    <= 7'd39; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        audio_key_buf <= 128'd0; key_cnt <= 5'd0;
                    end else if (tx_str_done) begin
                        rx_state <= S_AUD_DEC_RD_KEY;
                    end
                end

                S_AUD_DEC_RD_KEY: begin
                    if (rx_valid) begin
                        if (rx_byte == 8'h0D || rx_byte == 8'h0A) begin
                            // Enter pressed before 16 chars - key fail
                            audio_key_buf <= 128'd0;
                            key_cnt       <= 5'd0;
                            rx_state      <= S_AUD_DEC_PR_PLAY;  // key fail print
                        end else begin
                            if (!tx_busy && !tx_fired) begin
                                tx_byte <= rx_byte; send_req <= 1'b1; tx_fired <= 1'b1;
                            end
                            case (key_cnt)
                                5'd0:  audio_key_buf[127:120] <= rx_byte;
                                5'd1:  audio_key_buf[119:112] <= rx_byte;
                                5'd2:  audio_key_buf[111:104] <= rx_byte;
                                5'd3:  audio_key_buf[103:96]  <= rx_byte;
                                5'd4:  audio_key_buf[95:88]   <= rx_byte;
                                5'd5:  audio_key_buf[87:80]   <= rx_byte;
                                5'd6:  audio_key_buf[79:72]   <= rx_byte;
                                5'd7:  audio_key_buf[71:64]   <= rx_byte;
                                5'd8:  audio_key_buf[63:56]   <= rx_byte;
                                5'd9:  audio_key_buf[55:48]   <= rx_byte;
                                5'd10: audio_key_buf[47:40]   <= rx_byte;
                                5'd11: audio_key_buf[39:32]   <= rx_byte;
                                5'd12: audio_key_buf[31:24]   <= rx_byte;
                                5'd13: audio_key_buf[23:16]   <= rx_byte;
                                5'd14: audio_key_buf[15:8]    <= rx_byte;
                                5'd15: audio_key_buf[7:0]     <= rx_byte;
                                default: ;
                            endcase
                            key_cnt <= key_cnt + 5'd1;
                            if (key_cnt == 5'd15) begin
                                audio_key_out <= {audio_key_buf[127:8], rx_byte};
                                key_cnt       <= 5'd0;
                                rx_state      <= S_AUD_DEC_PR_COMP;
                            end
                        end
                    end
                end

                S_AUD_DEC_PR_COMP: begin
                    // [R2] Clear stale latch before entering LAUNCH
                    ascon_done_latch <= 1'b0;
                    dec_arm_r        <= 1'b0;   // [BUG4] reset arm flag
                    enc_chunk_idx    <= 10'd0;    // reset progress counter for DEC
                    dec_done_sent_r  <= 1'b0;   // reset one-shot print flag for new session
                    // [FIX-DECPCT] Do NOT reset total_chunks_lat here.
                    // total_chunks_lat holds the total chunk count from the
                    // ENCRYPT session (latched via spi_slave_audio byte[114]
                    // on 0x01 frames).  Decrypt frames (0x02) do NOT carry
                    // total_chunks in byte[114] - that field is padding.
                    // Resetting total_chunks_lat to 0 here (the old BUG6b-FIX)
                    // discarded the only valid total count, causing pct_val to
                    // fall through to the else-100 branch and then jump back to
                    // formula values when the first decrypt frame accidentally
                    // sets total_chunks_lat to an unexpected byte[114] value.
                    // Fix: keep total_chunks_lat from the encrypt session intact
                    // across the decrypt loop - it is already the correct total.
                    spi_audio_seen   <= 1'b0;    // [FIX-SEEN] clear before first LAUNCH
                    if (!tx_str_active && !tx_str_done) begin
                        // "\r\n[Decrypting audio...]\r\n"
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;  // \r\n
                        tx_str_rom[2]  <= 8'h5B;
                        tx_str_rom[3]  <= 8'h44; tx_str_rom[4]  <= 8'h65; tx_str_rom[5]  <= 8'h63;
                        tx_str_rom[6]  <= 8'h72; tx_str_rom[7]  <= 8'h79; tx_str_rom[8]  <= 8'h70;
                        tx_str_rom[9]  <= 8'h74; tx_str_rom[10] <= 8'h69; tx_str_rom[11] <= 8'h6E;
                        tx_str_rom[12] <= 8'h67;
                        tx_str_rom[13] <= 8'h20; tx_str_rom[14] <= 8'h61; tx_str_rom[15] <= 8'h75;
                        tx_str_rom[16] <= 8'h64; tx_str_rom[17] <= 8'h69; tx_str_rom[18] <= 8'h6F;
                        tx_str_rom[19] <= 8'h2E; tx_str_rom[20] <= 8'h2E; tx_str_rom[21] <= 8'h2E;
                        tx_str_rom[22] <= 8'h5D; tx_str_rom[23] <= 8'h0D; tx_str_rom[24] <= 8'h0A;
                        tx_str_len    <= 7'd25; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_AUD_DEC_LAUNCH;
                    end
                end

                // [ALTC-NODEC-DBGPRINT] S_AUD_DEC_LAUNCH: arm delay then watch
                // for ascon_done. [FIX-STALE-LATCH] Clear ascon_done_latch on
                // the arm cycle (dec_arm_r=0) to purge any done pulse that
                // arrived from a previous encrypt/end-of-session operation before
                // the first real 0x02 frame has been processed.
                // [BUG4] dec_arm_r: first cycle only asserts 0x5A, second cycle
                // starts watching ascon_done_latch.
                S_AUD_DEC_LAUNCH: begin
                    led_computing <= 1'b1;
                    aud_idle_cnt  <= 30'd0;
                    if (!dec_arm_r) begin
                        dec_arm_r        <= 1'b1;
                        ascon_done_latch <= 1'b0;  // [FIX-STALE-LATCH] purge stale pulse
                    end else if (ascon_done_latch) begin
                        ascon_done_latch     <= 1'b0;
                        stored_match         <= ascon_tag_match;
                        dec_tag_override_out <= 1'b0;
                        led_computing        <= 1'b0;
                        // [ALTC] Compute progress percentage, skip all UART printing.
                        // S_AUD_DEC_DONE immediately loops back to LAUNCH.
                        pct_val <= (total_chunks_lat != 10'd0 &&
                                    (enc_chunk_idx + 10'd1) < total_chunks_lat)
                                   ? (7'd0 | (((enc_chunk_idx + 10'd1) * 10'd100) / total_chunks_lat))
                                   : 7'd100;
                        enc_chunk_idx <= enc_chunk_idx + 10'd1;
                        // [DBG-DEC-PRINT] Snapshot plaintext (first 8 bytes) and
                        // tag for per-chunk serial print then go to DDG print state.
                        // [FIX-DDG-TAG] Use spi_tag_dbg (the expected tag sent by ESP32
                        // in MOSI[33-48]) NOT ascon_tag (tag_out from ASCON core).
                        // For dec_tag_override=1 the ASCON core skips ST_ENC_FINAL_W so
                        // tag_out is never updated and retains the last encrypt-session
                        // value -> every chunk printed the same stale tag (e.g.
                        // 15A9D0EC...).  spi_tag_dbg is the per-chunk expected tag which
                        // is what we want to show alongside the OK/FAIL verdict.
                        ddg_pt_snap        <= ascon_pt_dec[511:448]; // top 8 bytes
                        ddg_tag_snap       <= spi_tag_dbg;
                        ddg_chunk_idx_snap <= enc_chunk_idx;
                        ddg_state          <= DDG_HDR;
                        ddg_char_cnt       <= 6'd0;
                        rx_state           <= S_AUD_DEC_DONE;
                    end else begin
                        if (aud_idle_expired) begin
                            aud_idle_cnt  <= 30'd0;
                            led_computing <= 1'b0;
                            rx_state      <= S_AUD_DEC_DONE;
                        end else begin
                            aud_idle_cnt <= aud_idle_cnt + 30'd1;
                        end
                    end
                end

                // [ALTC-NODEC-DBGPRINT] S_AUD_DEC_WAIT unused in Alt-C path;
                // retained as a pass-through for backward compatibility.
                S_AUD_DEC_WAIT: begin
                    rx_state <= S_AUD_DEC_DONE;
                end

                // [ALTC-NODEC-DBGPRINT] S_AUD_DEC_TX unused in Alt-C path.
                S_AUD_DEC_TX: begin
                    rx_state <= S_AUD_DEC_DONE;
                end

                // [ALTC-NODEC-DBGPRINT] S_AUD_DEC_PR_PLAY repurposed as key-fail
                // print state for S_AUD_DEC_RD_KEY. Prints "\r\n[Key fail - enter
                // exactly 16 chars]\r\n" then loops back to S_AUD_DEC_PR_KEY.
                S_AUD_DEC_PR_PLAY: begin
                    if (!tx_str_active && !tx_str_done) begin
                        // "\r\n[Key fail - enter 16 chars]\r\n"
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;  // \r\n
                        tx_str_rom[2]  <= 8'h5B;                            // [
                        tx_str_rom[3]  <= 8'h4B; tx_str_rom[4]  <= 8'h65;  // Ke
                        tx_str_rom[5]  <= 8'h79; tx_str_rom[6]  <= 8'h20;  // y<sp>
                        tx_str_rom[7]  <= 8'h66; tx_str_rom[8]  <= 8'h61;  // fa
                        tx_str_rom[9]  <= 8'h69; tx_str_rom[10] <= 8'h6C;  // il
                        tx_str_rom[11] <= 8'h20; tx_str_rom[12] <= 8'h2D;  // <sp>-
                        tx_str_rom[13] <= 8'h20;                            // <sp>
                        tx_str_rom[14] <= 8'h65; tx_str_rom[15] <= 8'h6E;  // en
                        tx_str_rom[16] <= 8'h74; tx_str_rom[17] <= 8'h65;  // te
                        tx_str_rom[18] <= 8'h72; tx_str_rom[19] <= 8'h20;  // r<sp>
                        tx_str_rom[20] <= 8'h31; tx_str_rom[21] <= 8'h36;  // 16
                        tx_str_rom[22] <= 8'h20;                            // <sp>
                        tx_str_rom[23] <= 8'h63; tx_str_rom[24] <= 8'h68;  // ch
                        tx_str_rom[25] <= 8'h61; tx_str_rom[26] <= 8'h72;  // ar
                        tx_str_rom[27] <= 8'h73; tx_str_rom[28] <= 8'h5D;  // s]
                        tx_str_rom[29] <= 8'h0D; tx_str_rom[30] <= 8'h0A;  // \r\n
                        tx_str_len    <= 7'd31; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_AUD_DEC_PR_KEY;
                    end
                end

                // [BUG3-FIX] S_AUD_DEC_DONE: no per-chunk UART print.
                // Root cause of looping: old code routed EVERY chunk through
                // S_AUD_DEC_DBG which prints ~7.5 ms of UART data while holding
                // uart_fsm_state=0x5A.  During that window the ESP32 could queue
                // additional 0x02 frames.  After 255 chunks the dec_done_sent_r
                // re-entry logic raced → "[Dec done]" printed in a loop.
                // Fix: jump directly back to LAUNCH for every chunk; only enter
                // DBG state machine once to print the one-line "[Dec done]" summary.
                S_AUD_DEC_DONE: begin
                    dec_arm_r <= 1'b0;
                    // Guard: if total_chunks_lat not yet valid, keep looping.
                    if (total_chunks_lat == 10'd0 || enc_chunk_idx < total_chunks_lat) begin
                        rx_state <= S_AUD_DEC_LAUNCH;
                    end else begin
                        // All chunks complete - print styled completion message exactly once.
                        // "\r\n\033[32m[Audio decrypted. Press any key to exit]\033[0m\r\n"
                        // Mirrors the S_AUD_ENC_DONE green ANSI banner in style.
                        if (!tx_str_active && !dec_done_sent_r) begin
                            tx_str_rom[0]  <= 8'h0D; // \r
                            tx_str_rom[1]  <= 8'h0A; // \n
                            tx_str_rom[2]  <= 8'h1B; tx_str_rom[3]  <= 8'h5B; // ESC [
                            tx_str_rom[4]  <= 8'h33; tx_str_rom[5]  <= 8'h32; // 3 2
                            tx_str_rom[6]  <= 8'h6D;                           // m  => \033[32m (green)
                            tx_str_rom[7]  <= 8'h5B; // [
                            tx_str_rom[8]  <= 8'h41; // A
                            tx_str_rom[9]  <= 8'h75; // u
                            tx_str_rom[10] <= 8'h64; // d
                            tx_str_rom[11] <= 8'h69; // i
                            tx_str_rom[12] <= 8'h6F; // o
                            tx_str_rom[13] <= 8'h20; // (space)
                            tx_str_rom[14] <= 8'h64; // d
                            tx_str_rom[15] <= 8'h65; // e
                            tx_str_rom[16] <= 8'h63; // c
                            tx_str_rom[17] <= 8'h72; // r
                            tx_str_rom[18] <= 8'h79; // y
                            tx_str_rom[19] <= 8'h70; // p
                            tx_str_rom[20] <= 8'h74; // t
                            tx_str_rom[21] <= 8'h65; // e
                            tx_str_rom[22] <= 8'h64; // d
                            tx_str_rom[23] <= 8'h2E; // .
                            tx_str_rom[24] <= 8'h20; // (space)
                            tx_str_rom[25] <= 8'h50; // P
                            tx_str_rom[26] <= 8'h72; // r
                            tx_str_rom[27] <= 8'h65; // e
                            tx_str_rom[28] <= 8'h73; // s
                            tx_str_rom[29] <= 8'h73; // s
                            tx_str_rom[30] <= 8'h20; // (space)
                            tx_str_rom[31] <= 8'h61; // a
                            tx_str_rom[32] <= 8'h6E; // n
                            tx_str_rom[33] <= 8'h79; // y
                            tx_str_rom[34] <= 8'h20; // (space)
                            tx_str_rom[35] <= 8'h6B; // k
                            tx_str_rom[36] <= 8'h65; // e
                            tx_str_rom[37] <= 8'h79; // y
                            tx_str_rom[38] <= 8'h20; // (space)
                            tx_str_rom[39] <= 8'h74; // t
                            tx_str_rom[40] <= 8'h6F; // o
                            tx_str_rom[41] <= 8'h20; // (space)
                            tx_str_rom[42] <= 8'h65; // e
                            tx_str_rom[43] <= 8'h78; // x
                            tx_str_rom[44] <= 8'h69; // i
                            tx_str_rom[45] <= 8'h74; // t
                            tx_str_rom[46] <= 8'h5D; // ]
                            tx_str_rom[47] <= 8'h1B; tx_str_rom[48] <= 8'h5B; // ESC [
                            tx_str_rom[49] <= 8'h30; tx_str_rom[50] <= 8'h6D; // 0 m  => \033[0m (reset)
                            tx_str_rom[51] <= 8'h0D; tx_str_rom[52] <= 8'h0A; // \r\n
                            tx_str_len    <= 7'd53;
                            tx_str_idx    <= 7'd0;
                            tx_str_active <= 1'b1;
                            dec_done_sent_r <= 1'b1;
                        end else if (dec_done_sent_r && !tx_str_active) begin
                            dec_done_sent_r <= 1'b0;
                            rx_state <= S_WAIT_KEY;
                        end
                    end
                end

                //--------------------------------------------------------------
                // [DBG-DEC-PRINT] Per-chunk decrypt serial print state.
                // Prints: "\r\n[DECnnn] PT=XXXXXXXXXXXXXXXX TAG=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX OK/FAIL\r\n"
                //   nnn   = 3-digit chunk index
                //   PT    = first 8 bytes of decrypted plaintext (16 hex chars)
                //   TAG   = full 16-byte authentication tag (32 hex chars)
                //   OK/FAIL = tag verification verdict
                // After printing:
                //   if more chunks remain → S_AUD_DEC_LAUNCH (continue decrypt)
                //   if all done          → print "[Dec done]\r\n" then S_WAIT_KEY
                //--------------------------------------------------------------
                S_AUD_DEC_DBG: begin
                    if (!tx_busy && !tx_fired) begin
                        case (ddg_state)
                            DDG_HDR: begin
                                // Print "\r\n[DEC" (6 chars)
                                case (ddg_char_cnt)
                                    6'd0: tx_byte <= 8'h0D;  // \r
                                    6'd1: tx_byte <= 8'h0A;  // \n
                                    6'd2: tx_byte <= 8'h5B;  // [
                                    6'd3: tx_byte <= 8'h44;  // D
                                    6'd4: tx_byte <= 8'h45;  // E
                                    6'd5: tx_byte <= 8'h43;  // C
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd5) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_IDX;
                                end
                            end
                            DDG_IDX: begin
                                // Print 3-digit chunk index then "]"
                                case (ddg_char_cnt)
                                    6'd0: tx_byte <= 8'h30 + {4'd0, ddg_chunk_idx_snap / 10'd100};
                                    6'd1: tx_byte <= 8'h30 + {4'd0, (ddg_chunk_idx_snap % 10'd100) / 10'd10};
                                    6'd2: tx_byte <= 8'h30 + {4'd0, ddg_chunk_idx_snap % 10'd10};
                                    6'd3: tx_byte <= 8'h5D;  // ]
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd3) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_PT_LBL;
                                end
                            end
                            DDG_PT_LBL: begin
                                // Print " PT=" (4 chars)
                                case (ddg_char_cnt)
                                    6'd0: tx_byte <= 8'h20;  // space
                                    6'd1: tx_byte <= 8'h50;  // P
                                    6'd2: tx_byte <= 8'h54;  // T
                                    6'd3: tx_byte <= 8'h3D;  // =
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd3) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_PT_HEX;
                                end
                            end
                            DDG_PT_HEX: begin
                                // Print 16 hex chars = first 8 bytes of plaintext
                                case (ddg_char_cnt)
                                    6'd0:  tx_byte <= nibble_to_hex(ddg_pt_snap[63:60]);
                                    6'd1:  tx_byte <= nibble_to_hex(ddg_pt_snap[59:56]);
                                    6'd2:  tx_byte <= nibble_to_hex(ddg_pt_snap[55:52]);
                                    6'd3:  tx_byte <= nibble_to_hex(ddg_pt_snap[51:48]);
                                    6'd4:  tx_byte <= nibble_to_hex(ddg_pt_snap[47:44]);
                                    6'd5:  tx_byte <= nibble_to_hex(ddg_pt_snap[43:40]);
                                    6'd6:  tx_byte <= nibble_to_hex(ddg_pt_snap[39:36]);
                                    6'd7:  tx_byte <= nibble_to_hex(ddg_pt_snap[35:32]);
                                    6'd8:  tx_byte <= nibble_to_hex(ddg_pt_snap[31:28]);
                                    6'd9:  tx_byte <= nibble_to_hex(ddg_pt_snap[27:24]);
                                    6'd10: tx_byte <= nibble_to_hex(ddg_pt_snap[23:20]);
                                    6'd11: tx_byte <= nibble_to_hex(ddg_pt_snap[19:16]);
                                    6'd12: tx_byte <= nibble_to_hex(ddg_pt_snap[15:12]);
                                    6'd13: tx_byte <= nibble_to_hex(ddg_pt_snap[11:8]);
                                    6'd14: tx_byte <= nibble_to_hex(ddg_pt_snap[7:4]);
                                    6'd15: tx_byte <= nibble_to_hex(ddg_pt_snap[3:0]);
                                    default: tx_byte <= 8'h2E;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd15) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_TAG_LBL;
                                end
                            end
                            DDG_TAG_LBL: begin
                                // Print " TAG=" (5 chars)
                                case (ddg_char_cnt)
                                    6'd0: tx_byte <= 8'h20;  // space
                                    6'd1: tx_byte <= 8'h54;  // T
                                    6'd2: tx_byte <= 8'h41;  // A
                                    6'd3: tx_byte <= 8'h47;  // G
                                    6'd4: tx_byte <= 8'h3D;  // =
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd4) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_TAG_HEX;
                                end
                            end
                            DDG_TAG_HEX: begin
                                // Print 32 hex chars = full 16-byte authentication tag
                                case (ddg_char_cnt)
                                    6'd0:  tx_byte <= nibble_to_hex(ddg_tag_snap[127:124]);
                                    6'd1:  tx_byte <= nibble_to_hex(ddg_tag_snap[123:120]);
                                    6'd2:  tx_byte <= nibble_to_hex(ddg_tag_snap[119:116]);
                                    6'd3:  tx_byte <= nibble_to_hex(ddg_tag_snap[115:112]);
                                    6'd4:  tx_byte <= nibble_to_hex(ddg_tag_snap[111:108]);
                                    6'd5:  tx_byte <= nibble_to_hex(ddg_tag_snap[107:104]);
                                    6'd6:  tx_byte <= nibble_to_hex(ddg_tag_snap[103:100]);
                                    6'd7:  tx_byte <= nibble_to_hex(ddg_tag_snap[99:96]);
                                    6'd8:  tx_byte <= nibble_to_hex(ddg_tag_snap[95:92]);
                                    6'd9:  tx_byte <= nibble_to_hex(ddg_tag_snap[91:88]);
                                    6'd10: tx_byte <= nibble_to_hex(ddg_tag_snap[87:84]);
                                    6'd11: tx_byte <= nibble_to_hex(ddg_tag_snap[83:80]);
                                    6'd12: tx_byte <= nibble_to_hex(ddg_tag_snap[79:76]);
                                    6'd13: tx_byte <= nibble_to_hex(ddg_tag_snap[75:72]);
                                    6'd14: tx_byte <= nibble_to_hex(ddg_tag_snap[71:68]);
                                    6'd15: tx_byte <= nibble_to_hex(ddg_tag_snap[67:64]);
                                    6'd16: tx_byte <= nibble_to_hex(ddg_tag_snap[63:60]);
                                    6'd17: tx_byte <= nibble_to_hex(ddg_tag_snap[59:56]);
                                    6'd18: tx_byte <= nibble_to_hex(ddg_tag_snap[55:52]);
                                    6'd19: tx_byte <= nibble_to_hex(ddg_tag_snap[51:48]);
                                    6'd20: tx_byte <= nibble_to_hex(ddg_tag_snap[47:44]);
                                    6'd21: tx_byte <= nibble_to_hex(ddg_tag_snap[43:40]);
                                    6'd22: tx_byte <= nibble_to_hex(ddg_tag_snap[39:36]);
                                    6'd23: tx_byte <= nibble_to_hex(ddg_tag_snap[35:32]);
                                    6'd24: tx_byte <= nibble_to_hex(ddg_tag_snap[31:28]);
                                    6'd25: tx_byte <= nibble_to_hex(ddg_tag_snap[27:24]);
                                    6'd26: tx_byte <= nibble_to_hex(ddg_tag_snap[23:20]);
                                    6'd27: tx_byte <= nibble_to_hex(ddg_tag_snap[19:16]);
                                    6'd28: tx_byte <= nibble_to_hex(ddg_tag_snap[15:12]);
                                    6'd29: tx_byte <= nibble_to_hex(ddg_tag_snap[11:8]);
                                    6'd30: tx_byte <= nibble_to_hex(ddg_tag_snap[7:4]);
                                    6'd31: tx_byte <= nibble_to_hex(ddg_tag_snap[3:0]);
                                    default: tx_byte <= 8'h2E;
                                endcase
                                send_req     <= 1'b1; tx_fired <= 1'b1;
                                ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                if (ddg_char_cnt == 6'd31) begin
                                    ddg_char_cnt <= 6'd0;
                                    ddg_state    <= DDG_VERDICT;
                                end
                            end
                            DDG_VERDICT: begin
                                // Print " OK\r\n" (5 chars) or " FAIL\r\n" (7 chars)
                                // Use stored_match latched from S_AUD_DEC_LAUNCH
                                if (stored_match) begin
                                    // " OK\r\n"  - 5 chars
                                    case (ddg_char_cnt)
                                        6'd0: tx_byte <= 8'h20;  // space
                                        6'd1: tx_byte <= 8'h4F;  // O
                                        6'd2: tx_byte <= 8'h4B;  // K
                                        6'd3: tx_byte <= 8'h0D;  // \r
                                        6'd4: tx_byte <= 8'h0A;  // \n
                                        default: tx_byte <= 8'h20;
                                    endcase
                                    send_req     <= 1'b1; tx_fired <= 1'b1;
                                    ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                    if (ddg_char_cnt == 6'd4) begin
                                        ddg_char_cnt <= 6'd0;
                                        ddg_state    <= DDG_DONE;
                                    end
                                end else begin
                                    // " FAIL\r\n" - 7 chars
                                    case (ddg_char_cnt)
                                        6'd0: tx_byte <= 8'h20;  // space
                                        6'd1: tx_byte <= 8'h46;  // F
                                        6'd2: tx_byte <= 8'h41;  // A
                                        6'd3: tx_byte <= 8'h49;  // I
                                        6'd4: tx_byte <= 8'h4C;  // L
                                        6'd5: tx_byte <= 8'h0D;  // \r
                                        6'd6: tx_byte <= 8'h0A;  // \n
                                        default: tx_byte <= 8'h20;
                                    endcase
                                    send_req     <= 1'b1; tx_fired <= 1'b1;
                                    ddg_char_cnt <= ddg_char_cnt + 6'd1;
                                    if (ddg_char_cnt == 6'd6) begin
                                        ddg_char_cnt <= 6'd0;
                                        ddg_state    <= DDG_DONE;
                                    end
                                end
                            end
                            DDG_DONE: begin
                                // Branch: more chunks → back to LAUNCH; done → summary+exit
                                if (total_chunks_lat != 10'd0 && enc_chunk_idx < total_chunks_lat) begin
                                    // More chunks remain
                                    dec_done_sent_r <= 1'b0;
                                    ddg_state <= DDG_HDR;
                                    rx_state  <= S_AUD_DEC_LAUNCH;
                                end else begin
                                    // All chunks done - print "[Dec done]\r\n" ONCE then exit.
                                    // FIX: tx_str_done is auto-cleared every cycle tx_str_active=0,
                                    // so the FSM may never see it → infinite reprint.
                                    // Use dec_done_sent_r (sticky one-shot) instead.
                                    if (!dec_done_sent_r) begin
                                        // Fire the string exactly once
                                        if (!tx_str_active) begin
                                            tx_str_rom[0]  <= 8'h5B; // [
                                            tx_str_rom[1]  <= 8'h44; // D
                                            tx_str_rom[2]  <= 8'h65; // e
                                            tx_str_rom[3]  <= 8'h63; // c
                                            tx_str_rom[4]  <= 8'h20; //
                                            tx_str_rom[5]  <= 8'h64; // d
                                            tx_str_rom[6]  <= 8'h6F; // o
                                            tx_str_rom[7]  <= 8'h6E; // n
                                            tx_str_rom[8]  <= 8'h65; // e
                                            tx_str_rom[9]  <= 8'h5D; // ]
                                            tx_str_rom[10] <= 8'h0D; // \r
                                            tx_str_rom[11] <= 8'h0A; // \n
                                            tx_str_len    <= 7'd12; tx_str_idx <= 7'd0;
                                            tx_str_active <= 1'b1;
                                            dec_done_sent_r <= 1'b1;
                                        end
                                    end else if (!tx_str_active) begin
                                        // String has finished transmitting → safe to exit
                                        dec_done_sent_r <= 1'b0;
                                        ddg_state <= DDG_HDR;
                                        rx_state  <= S_WAIT_KEY;
                                    end
                                end
                            end
                            default: ddg_state <= DDG_HDR;
                        endcase
                    end
                end

                //==============================================================
                // NO DATA
                //==============================================================
                S_NO_DATA: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h5B; tx_str_rom[3]  <= 8'h21; tx_str_rom[4]  <= 8'h5D;
                        tx_str_rom[5]  <= 8'h20; tx_str_rom[6]  <= 8'h52; tx_str_rom[7]  <= 8'h75;
                        tx_str_rom[8]  <= 8'h6E; tx_str_rom[9]  <= 8'h20; tx_str_rom[10] <= 8'h45;
                        tx_str_rom[11] <= 8'h6E; tx_str_rom[12] <= 8'h63; tx_str_rom[13] <= 8'h72;
                        tx_str_rom[14] <= 8'h79; tx_str_rom[15] <= 8'h70; tx_str_rom[16] <= 8'h74;
                        tx_str_rom[17] <= 8'h20; tx_str_rom[18] <= 8'h66; tx_str_rom[19] <= 8'h69;
                        tx_str_rom[20] <= 8'h72; tx_str_rom[21] <= 8'h73; tx_str_rom[22] <= 8'h74;
                        tx_str_rom[23] <= 8'h2E; tx_str_rom[24] <= 8'h0D; tx_str_rom[25] <= 8'h0A;
                        tx_str_len    <= 7'd26; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_BANNER;
                    end
                end

                S_NO_AUD_DATA: begin
                    if (!tx_str_active && !tx_str_done) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h5B; tx_str_rom[3]  <= 8'h21; tx_str_rom[4]  <= 8'h5D;
                        tx_str_rom[5]  <= 8'h20; tx_str_rom[6]  <= 8'h52; tx_str_rom[7]  <= 8'h75;
                        tx_str_rom[8]  <= 8'h6E; tx_str_rom[9]  <= 8'h20;
                        tx_str_rom[10] <= 8'h41; tx_str_rom[11] <= 8'h75; tx_str_rom[12] <= 8'h64;
                        tx_str_rom[13] <= 8'h69; tx_str_rom[14] <= 8'h6F;
                        tx_str_rom[15] <= 8'h20; tx_str_rom[16] <= 8'h45; tx_str_rom[17] <= 8'h6E;
                        tx_str_rom[18] <= 8'h63; tx_str_rom[19] <= 8'h72; tx_str_rom[20] <= 8'h79;
                        tx_str_rom[21] <= 8'h70; tx_str_rom[22] <= 8'h74;
                        tx_str_rom[23] <= 8'h20; tx_str_rom[24] <= 8'h28; tx_str_rom[25] <= 8'h6F;
                        tx_str_rom[26] <= 8'h70; tx_str_rom[27] <= 8'h74; tx_str_rom[28] <= 8'h69;
                        tx_str_rom[29] <= 8'h6F; tx_str_rom[30] <= 8'h6E;
                        tx_str_rom[31] <= 8'h20; tx_str_rom[32] <= 8'h33;
                        tx_str_rom[33] <= 8'h29; tx_str_rom[34] <= 8'h20;
                        tx_str_rom[35] <= 8'h66; tx_str_rom[36] <= 8'h69; tx_str_rom[37] <= 8'h72;
                        tx_str_rom[38] <= 8'h73; tx_str_rom[39] <= 8'h74;
                        tx_str_rom[40] <= 8'h2E; tx_str_rom[41] <= 8'h0D; tx_str_rom[42] <= 8'h0A;
                        tx_str_len    <= 7'd43; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                    end else if (tx_str_done) begin
                        rx_state <= S_BANNER;
                    end
                end

                //==============================================================
                // DONE / WAIT KEY
                //==============================================================
                S_TX_ENC: begin
                    if (tx_state == TX_FINISH) begin
                        led_computing <= 1'b0;
                        rx_state      <= S_DONE;
                    end
                end

                S_TX_DEC: begin
                    if (tx_state == TX_FINISH) begin
                        led_computing <= 1'b0;
                        rx_state      <= S_DONE;
                    end
                end

                S_DONE: begin
                    if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                        tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                        tx_str_rom[2]  <= 8'h5B; tx_str_rom[3]  <= 8'h50;
                        tx_str_rom[4]  <= 8'h72; tx_str_rom[5]  <= 8'h65;
                        tx_str_rom[6]  <= 8'h73; tx_str_rom[7]  <= 8'h73;
                        tx_str_rom[8]  <= 8'h20; tx_str_rom[9]  <= 8'h61;
                        tx_str_rom[10] <= 8'h6E; tx_str_rom[11] <= 8'h79;
                        tx_str_rom[12] <= 8'h20; tx_str_rom[13] <= 8'h6B;
                        tx_str_rom[14] <= 8'h65; tx_str_rom[15] <= 8'h79;
                        tx_str_rom[16] <= 8'h20; tx_str_rom[17] <= 8'h74;
                        tx_str_rom[18] <= 8'h6F; tx_str_rom[19] <= 8'h20;
                        tx_str_rom[20] <= 8'h63; tx_str_rom[21] <= 8'h6F;
                        tx_str_rom[22] <= 8'h6E; tx_str_rom[23] <= 8'h74;
                        tx_str_rom[24] <= 8'h69; tx_str_rom[25] <= 8'h6E;
                        tx_str_rom[26] <= 8'h75; tx_str_rom[27] <= 8'h65;
                        tx_str_rom[28] <= 8'h2E; tx_str_rom[29] <= 8'h2E;
                        tx_str_rom[30] <= 8'h2E; tx_str_rom[31] <= 8'h5D;
                        tx_str_rom[32] <= 8'h0D; tx_str_rom[33] <= 8'h0A;
                        tx_str_len    <= 7'd34; tx_str_idx <= 7'd0;
                        tx_str_active <= 1'b1;
                        led_waiting   <= 1'b1;
                        rx_state      <= S_WAIT_KEY;
                    end
                end

                S_WAIT_KEY: begin
                    led_waiting <= 1'b0;  // [BUG2] clear LED on entry
                    if (rx_valid)
                        rx_state <= S_BANNER;
                end

                default: rx_state <= S_BANNER;
            endcase

            //==================================================================
            // [BUG6] PROGRESS PRINT SUB-FSM
            // Prints "\r\033[33m[ENC XX%]\033[0m" or "\r\033[36m[DEC XX%]\033[0m"
            // ANSI: \r = 0x0D  ESC = 0x1B  '[' = 0x5B
            //       "33m" = yellow (enc)  "36m" = cyan (dec)
            //       reset = ESC[0m = 0x1B 0x5B 0x30 0x6D
            //==================================================================
            if (rx_state == S_AUD_PROGRESS) begin
                case (prg_state)
                    PRG_CR: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte  <= 8'h0D;  // \r
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_ESC;
                        end
                    end
                    PRG_ESC: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte  <= 8'h1B;  // ESC
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_COLOR;
                        end
                    end
                    PRG_COLOR: begin
                        // Send "[33m" (yellow, enc) or "[36m" (cyan, dec)
                        // We send 3 bytes: '[' then '3' then '3'/'6' then 'm'
                        // Reuse tx_char_cnt: 0='[' 1='3' 2=color 3='m'
                        if (!tx_busy && !tx_fired) begin
                            case (tx_char_cnt[1:0])
                                2'd0: tx_byte <= 8'h5B;                              // [
                                2'd1: tx_byte <= 8'h33;                              // 3
                                2'd2: tx_byte <= prg_is_dec ? 8'h36 : 8'h33;        // 3(y) or 6(c)
                                2'd3: tx_byte <= 8'h6D;                              // m
                            endcase
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd3) begin
                                tx_char_cnt <= 6'd0;
                                prg_state   <= PRG_LBRACKET;
                            end
                        end
                    end
                    PRG_LBRACKET: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= 8'h5B;  // [
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_MODE;
                            tx_char_cnt <= 6'd0;
                        end
                    end
                    PRG_MODE: begin
                        // "ENC " or "DEC " (4 chars)
                        if (!tx_busy && !tx_fired) begin
                            case (tx_char_cnt[1:0])
                                2'd0: tx_byte <= prg_is_dec ? 8'h44 : 8'h45;  // D or E
                                2'd1: tx_byte <= prg_is_dec ? 8'h45 : 8'h4E;  // E or N
                                2'd2: tx_byte <= prg_is_dec ? 8'h43 : 8'h43;  // C     C
                                2'd3: tx_byte <= 8'h20;                        // space
                            endcase
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd3) begin
                                tx_char_cnt <= 6'd0;
                                prg_state   <= PRG_PCT_H;
                            end
                        end
                    end
                    PRG_PCT_H: begin
                        // hundreds digit (omit leading zero unless pct >= 100)
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= pct_ascii_tmp[23:16];
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            // Skip if 0 unless 100
                            if (pct_val < 7'd100) begin
                                if (pct_ascii_tmp[23:16] != 8'h30)
                                    prg_state <= PRG_PCT_T;
                                else
                                    prg_state <= PRG_PCT_T;  // always advance
                            end else begin
                                prg_state <= PRG_PCT_T;
                            end
                        end
                    end
                    PRG_PCT_T: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= pct_ascii_tmp[15:8];
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_PCT_O;
                        end
                    end
                    PRG_PCT_O: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= pct_ascii_tmp[7:0];
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_PERCENT;
                        end
                    end
                    PRG_PERCENT: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= 8'h25;  // %
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_RBRACKET;
                        end
                    end
                    PRG_RBRACKET: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte   <= 8'h5D;  // ]
                            send_req  <= 1'b1; tx_fired <= 1'b1;
                            prg_state <= PRG_RESET;
                            tx_char_cnt <= 6'd0;
                        end
                    end
                    PRG_RESET: begin
                        // Send ESC[0m  = 0x1B 0x5B 0x30 0x6D
                        if (!tx_busy && !tx_fired) begin
                            case (tx_char_cnt[1:0])
                                2'd0: tx_byte <= 8'h1B;
                                2'd1: tx_byte <= 8'h5B;
                                2'd2: tx_byte <= 8'h30;
                                2'd3: tx_byte <= 8'h6D;
                            endcase
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd3) begin
                                tx_char_cnt <= 6'd0;
                                prg_state   <= PRG_DONE;
                            end
                        end
                    end
                    PRG_DONE: begin end  // wait for rx_state to transition
                    default: prg_state <= PRG_DONE;
                endcase
            end

            //==================================================================
            // TEXT TX RESPONSE SUB-FSM
            //==================================================================
            if (rx_state == S_TX_ENC || rx_state == S_TX_DEC) begin
                case (tx_state)
                    TX_COMPUTING: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0]  <= 8'h0D; tx_str_rom[1]  <= 8'h0A;
                            tx_str_rom[2]  <= 8'h5B; tx_str_rom[3]  <= 8'h43; tx_str_rom[4]  <= 8'h6F;
                            tx_str_rom[5]  <= 8'h6D; tx_str_rom[6]  <= 8'h70; tx_str_rom[7]  <= 8'h75;
                            tx_str_rom[8]  <= 8'h74; tx_str_rom[9]  <= 8'h69; tx_str_rom[10] <= 8'h6E;
                            tx_str_rom[11] <= 8'h67; tx_str_rom[12] <= 8'h2E; tx_str_rom[13] <= 8'h2E;
                            tx_str_rom[14] <= 8'h2E; tx_str_rom[15] <= 8'h5D; tx_str_rom[16] <= 8'h0D;
                            tx_str_rom[17] <= 8'h0A;
                            tx_str_len    <= 7'd18; tx_str_idx <= 7'd0;
                            tx_str_active <= 1'b1;
                            tx_char_cnt   <= 6'd0;
                        end else if (tx_str_done) begin
                            tx_state <= (rx_state == S_TX_ENC) ? TX_LBL_NONCE : TX_LBL_PLAIN;
                        end
                    end
                    TX_LBL_NONCE: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h4E; tx_str_rom[1] <= 8'h4F; tx_str_rom[2] <= 8'h4E;
                            tx_str_rom[3] <= 8'h43; tx_str_rom[4] <= 8'h45; tx_str_rom[5] <= 8'h20;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1;
                        end else if (tx_str_done) begin
                            tx_state <= TX_NONCE; tx_char_cnt <= 6'd0;
                        end
                    end
                    TX_NONCE: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte     <= nibble_to_hex(stored_nonce[((6'd31 - tx_char_cnt) * 4) +: 4]);
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd31) begin tx_char_cnt <= 6'd0; tx_state <= TX_CRLF_N; end
                        end
                    end
                    TX_CRLF_N: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_LBL_CT; end
                        end
                    end
                    TX_LBL_CT: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h43; tx_str_rom[1] <= 8'h54; tx_str_rom[2] <= 8'h20;
                            tx_str_rom[3] <= 8'h20; tx_str_rom[4] <= 8'h20; tx_str_rom[5] <= 8'h20;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1;
                        end else if (tx_str_done) begin
                            tx_state <= TX_CT; tx_char_cnt <= 6'd0; ct_nibble_cnt <= 7'd0;
                        end
                    end
                    TX_CT: begin
                        // [BUG1-FIX] Use 7-bit ct_nibble_cnt with MSB-first index (127 downto 0)
                        // stored_ct[511:0]: ct_blk[0] occupies bits [511:448] (byte 63).
                        // Nibble index formula: (127 - ct_nibble_cnt)*4 reads MSB-first correctly.
                        if (!tx_str_active && !tx_busy && !tx_fired) begin
                            tx_byte        <= nibble_to_hex(stored_ct[((7'd127 - ct_nibble_cnt) * 4) +: 4]);
                            send_req       <= 1'b1; tx_fired <= 1'b1;
                            ct_nibble_cnt  <= ct_nibble_cnt + 7'd1;
                            if (ct_nibble_cnt == {1'b0, stored_ct_chars}) begin
                                ct_nibble_cnt <= 7'd0; tx_char_cnt <= 6'd0; tx_state <= TX_CRLF_C;
                            end
                        end
                    end
                    TX_CRLF_C: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_LBL_TAG; end
                        end
                    end
                    TX_LBL_TAG: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h54; tx_str_rom[1] <= 8'h41; tx_str_rom[2] <= 8'h47;
                            tx_str_rom[3] <= 8'h20; tx_str_rom[4] <= 8'h20; tx_str_rom[5] <= 8'h20;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1;
                        end else if (tx_str_done) begin
                            tx_state <= TX_TAG; tx_char_cnt <= 6'd0;
                        end
                    end
                    TX_TAG: begin
                        if (!tx_str_active && !tx_busy && !tx_fired) begin
                            tx_byte     <= nibble_to_hex(stored_tag[((6'd31 - tx_char_cnt) * 4) +: 4]);
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd31) begin tx_char_cnt <= 6'd0; tx_state <= TX_CRLF_T; end
                        end
                    end
                    TX_CRLF_T: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_DONE_CRLF; end
                        end
                    end
                    TX_LBL_PLAIN: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            if (stored_match) begin
                                tx_str_rom[0] <= 8'h50; tx_str_rom[1] <= 8'h6C; tx_str_rom[2] <= 8'h61;
                                tx_str_rom[3] <= 8'h69; tx_str_rom[4] <= 8'h6E; tx_str_rom[5] <= 8'h20;
                                tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20; tx_str_len <= 7'd8;
                            end else begin
                                tx_str_rom[0]  <= 8'h5B; tx_str_rom[1]  <= 8'h41; tx_str_rom[2]  <= 8'h75;
                                tx_str_rom[3]  <= 8'h74; tx_str_rom[4]  <= 8'h68; tx_str_rom[5]  <= 8'h20;
                                tx_str_rom[6]  <= 8'h66; tx_str_rom[7]  <= 8'h61; tx_str_rom[8]  <= 8'h69;
                                tx_str_rom[9]  <= 8'h6C; tx_str_rom[10] <= 8'h65; tx_str_rom[11] <= 8'h64;
                                tx_str_rom[12] <= 8'h20; tx_str_rom[13] <= 8'h2D; tx_str_rom[14] <= 8'h20;
                                tx_str_rom[15] <= 8'h77; tx_str_rom[16] <= 8'h72; tx_str_rom[17] <= 8'h6F;
                                tx_str_rom[18] <= 8'h6E; tx_str_rom[19] <= 8'h67; tx_str_rom[20] <= 8'h20;
                                tx_str_rom[21] <= 8'h6B; tx_str_rom[22] <= 8'h65; tx_str_rom[23] <= 8'h79;
                                tx_str_rom[24] <= 8'h5D; tx_str_rom[25] <= 8'h0D; tx_str_rom[26] <= 8'h0A;
                                tx_str_len <= 7'd27;
                            end
                            tx_str_idx <= 7'd0; tx_str_active <= 1'b1; tx_pt_idx <= 6'd0;
                        end else if (tx_str_done) begin
                            tx_state <= stored_match ? TX_PLAIN : TX_LBL_VERIFY;
                        end
                    end
                    TX_PLAIN: begin
                        if (!tx_str_active && !tx_busy && !tx_fired) begin
                            if (tx_pt_idx < pt_dec_len) begin
                                tx_byte   <= stored_pt_dec[(511 - tx_pt_idx * 8) -: 8];
                                send_req  <= 1'b1; tx_fired <= 1'b1;
                                tx_pt_idx <= tx_pt_idx + 6'd1;
                            end else begin
                                tx_state <= TX_CRLF_P; tx_char_cnt <= 6'd0;
                            end
                        end
                    end
                    TX_CRLF_P: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_LBL_VERIFY; end
                        end
                    end
                    TX_LBL_VERIFY: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h56; tx_str_rom[1] <= 8'h65; tx_str_rom[2] <= 8'h72;
                            tx_str_rom[3] <= 8'h69; tx_str_rom[4] <= 8'h66; tx_str_rom[5] <= 8'h79;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1; tx_char_cnt <= 6'd0;
                        end else if (tx_str_done) begin
                            tx_state <= TX_VERIFY;
                        end
                    end
                    TX_VERIFY: begin
                        if (!tx_str_active && !tx_busy && !tx_fired) begin
                            if (stored_match) begin
                                case (tx_char_cnt)
                                    6'd0: tx_byte <= 8'h59;
                                    6'd1: tx_byte <= 8'h45;
                                    6'd2: tx_byte <= 8'h53;
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req <= 1'b1; tx_fired <= 1'b1;
                                tx_char_cnt <= tx_char_cnt + 6'd1;
                                if (tx_char_cnt == 6'd2) begin tx_char_cnt <= 6'd0; tx_state <= TX_CRLF_V; end
                            end else begin
                                case (tx_char_cnt)
                                    6'd0: tx_byte <= 8'h4E;
                                    6'd1: tx_byte <= 8'h4F;
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req <= 1'b1; tx_fired <= 1'b1;
                                tx_char_cnt <= tx_char_cnt + 6'd1;
                                if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_CRLF_V; end
                            end
                        end
                    end
                    TX_CRLF_V: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_DONE_CRLF; end
                        end
                    end
                    TX_DONE_CRLF: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; tx_state <= TX_FINISH; end
                        end
                    end
                    TX_FINISH: begin end
                    default: tx_state <= TX_FINISH;
                endcase
            end

            //==================================================================
            // AUDIO TX RESPONSE SUB-FSM
            //==================================================================
            if (rx_state == S_AUD_ENC_TX || rx_state == S_AUD_DEC_TX) begin
                case (atx_state)
                    ATX_NONCE_LBL: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h4E; tx_str_rom[1] <= 8'h4F; tx_str_rom[2] <= 8'h4E;
                            tx_str_rom[3] <= 8'h43; tx_str_rom[4] <= 8'h45; tx_str_rom[5] <= 8'h20;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1;
                        end else if (tx_str_done) begin
                            atx_state <= ATX_NONCE; tx_char_cnt <= 6'd0;
                        end
                    end
                    ATX_NONCE: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte     <= nibble_to_hex(audio_stored_nonce[((6'd31 - tx_char_cnt)*4) +: 4]);
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd31) begin tx_char_cnt <= 6'd0; atx_state <= ATX_NONCE_CRLF; end
                        end
                    end
                    ATX_NONCE_CRLF: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin
                                tx_char_cnt <= 6'd0;
                                atx_state   <= (rx_state == S_AUD_ENC_TX) ? ATX_TAG_LBL : ATX_FINISH;
                            end
                        end
                    end
                    ATX_TAG_LBL: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h54; tx_str_rom[1] <= 8'h41; tx_str_rom[2] <= 8'h47;
                            tx_str_rom[3] <= 8'h20; tx_str_rom[4] <= 8'h20; tx_str_rom[5] <= 8'h20;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0; tx_str_active <= 1'b1;
                        end else if (tx_str_done) begin
                            atx_state <= ATX_TAG; tx_char_cnt <= 6'd0;
                        end
                    end
                    ATX_TAG: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte     <= nibble_to_hex(audio_stored_tag[((6'd31 - tx_char_cnt)*4) +: 4]);
                            send_req    <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd31) begin tx_char_cnt <= 6'd0; atx_state <= ATX_TAG_CRLF; end
                        end
                    end
                    ATX_TAG_CRLF: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; atx_state <= ATX_FINISH; end
                        end
                    end
                    ATX_VERIFY_LBL: begin
                        if (!tx_str_active && !tx_str_done && !tx_busy && !tx_fired) begin
                            tx_str_rom[0] <= 8'h56; tx_str_rom[1] <= 8'h65; tx_str_rom[2] <= 8'h72;
                            tx_str_rom[3] <= 8'h69; tx_str_rom[4] <= 8'h66; tx_str_rom[5] <= 8'h79;
                            tx_str_rom[6] <= 8'h3A; tx_str_rom[7] <= 8'h20;
                            tx_str_len <= 7'd8; tx_str_idx <= 7'd0;
                            tx_str_active <= 1'b1; tx_char_cnt <= 6'd0;
                        end else if (tx_str_done) begin
                            atx_state <= ATX_VERIFY;
                        end
                    end
                    ATX_VERIFY: begin
                        if (!tx_busy && !tx_fired) begin
                            if (stored_match) begin
                                case (tx_char_cnt)
                                    6'd0: tx_byte <= 8'h59;
                                    6'd1: tx_byte <= 8'h45;
                                    6'd2: tx_byte <= 8'h53;
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req <= 1'b1; tx_fired <= 1'b1;
                                tx_char_cnt <= tx_char_cnt + 6'd1;
                                if (tx_char_cnt == 6'd2) begin tx_char_cnt <= 6'd0; atx_state <= ATX_VERIFY_CRLF; end
                            end else begin
                                case (tx_char_cnt)
                                    6'd0: tx_byte <= 8'h4E;
                                    6'd1: tx_byte <= 8'h4F;
                                    default: tx_byte <= 8'h20;
                                endcase
                                send_req <= 1'b1; tx_fired <= 1'b1;
                                tx_char_cnt <= tx_char_cnt + 6'd1;
                                if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; atx_state <= ATX_VERIFY_CRLF; end
                            end
                        end
                    end
                    ATX_VERIFY_CRLF: begin
                        if (!tx_busy && !tx_fired) begin
                            tx_byte <= (tx_char_cnt == 6'd0) ? 8'h0D : 8'h0A;
                            send_req <= 1'b1; tx_fired <= 1'b1;
                            tx_char_cnt <= tx_char_cnt + 6'd1;
                            if (tx_char_cnt == 6'd1) begin tx_char_cnt <= 6'd0; atx_state <= ATX_FINISH; end
                        end
                    end
                    ATX_FINISH: begin end
                    default: atx_state <= ATX_FINISH;
                endcase
            end

        end // else (not reset)
    end // always

endmodule