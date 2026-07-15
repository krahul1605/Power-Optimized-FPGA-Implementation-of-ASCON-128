`timescale 1ns / 1ps
//=============================================================================
// ASCON-128 Menu System - ZCU104 Top Level  (Audio + Text Edition)
//
// RECTIFICATION LOG
// ─────────────────
// [FIX-KEY-DEC] CRITICAL: Audio decrypt was using spi_key_out (the key the
//   ESP32 mirrored back in MOSI bytes 1-16) as the ASCON key for ALL SPI
//   frames, including audio-decrypt (type-0x02) frames.
//
//   Root cause: The INPUT MUX assigned:
//     key_w = spi_real_frame ? spi_key_out : uart_key_out
//   For audio decrypt the ASCON core must use audio_key_w (the key the user
//   typed in PuTTY [4]), NOT spi_key_out.  spi_key_out carries active_key
//   from the ESP32 (the encrypt-session key), which happens to be the same
//   when both sessions use the same key, masking the bug.  When the user
//   deliberately re-enters a different decrypt key in PuTTY [4], the ASCON
//   core would still use the old encrypt key → tag-mismatch on every chunk.
//
//   Fix: introduce is_audio_dec = spi_real_frame & spi_dec_override.
//   For audio-decrypt frames: key_w = audio_key_w  (PuTTY [4] key)
//   For audio-encrypt frames: key_w = spi_key_out  (unchanged)
//   For UART text frames:     key_w = uart_key_out  (unchanged)
//
//   This makes the ASCON decrypt key consistent with what the ESP32 reads
//   back from poll-frame MISO[0-15] (audio_key_out = audio_key_w), so the
//   key-echo verification in retrieveResult() also passes correctly.
//
// All prior fixes (T1, T2, FIX-PROGRESS, FIX-5, FIX-12, BUG-N, nonce-snap,
// spi_real_frame gate) are retained unchanged.
//=============================================================================

// OPTION-2 MODIFICATIONS
// ──────────────────────
// [OPT2] BRAM FIFO and cmd 0x04 path removed.  Decrypt plaintext is returned
//   directly in the same 0x02 SPI transaction response (same as encrypt).
//   bram_fifo_dec not instantiated.  Stub wires (512'd0 / 1'b0) passed to
//   spi_slave_audio FIFO ports for compatibility.
//   [ALTC-CMD04] gate retained: frame_type 0x04 still excluded from ASCON
//   start (belt-and-suspenders; ESP32 no longer sends 0x04 frames).
//
// ALL PRIOR FIXES RETAINED.

module ascon128_top_menu (
    input  wire clk_p,
    input  wire clk_n,
    input  wire rst_n,

    input  wire uart_rx,
    output wire uart_tx,

    input  wire spi_sclk,
    input  wire spi_mosi,
    output wire spi_miso,
    input  wire spi_cs_n,

    output wire led_done,
    output wire led_tag_match,
    output wire led_running,
    output wire led_error,
    output wire led_waiting,
    output wire led_computing
);

    //=========================================================================
    // CLOCK: 125 MHz LVDS → 100 MHz via MMCM
    //=========================================================================
    wire clk_ibuf, clk_100mhz, clk_locked;

    IBUFDS #(
        .DIFF_TERM   ("FALSE"),
        .IBUF_LOW_PWR("FALSE"),
        .IOSTANDARD  ("LVDS")
    ) clk_ibufds (
        .I  (clk_p),
        .IB (clk_n),
        .O  (clk_ibuf)
    );

    wire clk_fb_raw, clk_fb_bufg;
    BUFG clk_fb_bufg_inst (.I(clk_fb_raw), .O(clk_fb_bufg));

    MMCME4_BASE #(
        .BANDWIDTH          ("OPTIMIZED"),
        .CLKFBOUT_MULT_F    (8.0),
        .CLKFBOUT_PHASE     (0.0),
        .CLKIN1_PERIOD      (8.0),
        .CLKOUT0_DIVIDE_F   (10.0),
        .CLKOUT0_DUTY_CYCLE (0.5),
        .CLKOUT0_PHASE      (0.0),
        .CLKOUT1_DIVIDE(1), .CLKOUT2_DIVIDE(1), .CLKOUT3_DIVIDE(1),
        .CLKOUT4_DIVIDE(1), .CLKOUT5_DIVIDE(1), .CLKOUT6_DIVIDE(1),
        .DIVCLK_DIVIDE      (1),
        .REF_JITTER1        (0.01),
        .STARTUP_WAIT       ("FALSE")
    ) mmcm_inst (
        .CLKIN1   (clk_ibuf),
        .CLKFBIN  (clk_fb_bufg),
        .CLKFBOUT (clk_fb_raw),
        .CLKFBOUTB(),
        .CLKOUT0  (clk_100mhz),
        .CLKOUT0B(), .CLKOUT1(), .CLKOUT1B(),
        .CLKOUT2(), .CLKOUT2B(), .CLKOUT3(), .CLKOUT3B(),
        .CLKOUT4(), .CLKOUT5(), .CLKOUT6(),
        .LOCKED   (clk_locked),
        .PWRDWN   (1'b0),
        .RST      (1'b0)
    );

    wire clk;
    BUFG clk_bufg (.I(clk_100mhz), .O(clk));

    wire rst_active = rst_n;
    reg  rst_int_n;
    always @(posedge clk or negedge clk_locked) begin
        if (!clk_locked) rst_int_n <= 1'b0;
        else             rst_int_n <= ~rst_active;
    end

    //=========================================================================
    // TRNG
    //=========================================================================
    wire [127:0] trng_nonce;
    wire         trng_valid;
    wire         session_done;

    trng_zcu104 trng_inst (
        .clk         (clk),
        .rst_n       (rst_int_n),
        .session_done(session_done),
        .nonce       (trng_nonce),
        .nonce_valid (trng_valid)
    );

    //=========================================================================
    // BRAM FIFO - stores decrypted plaintext chunks for FIFO-read path.
    //
    // [BRAM-DECRYPT] Restore bram_fifo_dec instantiation.
    //   Write port:  driven by ascon_done_w when a decrypt frame completes.
    //   Read port:   driven by spi_slave_audio on cmd 0x04 frames.
    //   fifo_not_empty: fed into SPI slave → MISO poll byte[97] MSB so the
    //                   ESP32 can poll readiness without burning an extra cmd.
    //   Flush:       asserted on the rising edge of uart_fsm_state==0x5A to
    //                drain any stale entries from a previous session.
    //
    // wr_tag_match:  ascon_tag_match_w captured at ascon_done_w so the
    //                tag verdict travels with its plaintext block.
    //=========================================================================
    wire [511:0] fifo_rd_data;
    wire         fifo_rd_en_w;          // driven by spi_slave_audio output reg
    wire         fifo_not_empty_w;
    wire         fifo_rd_tag_match_w;   // tag verdict for the head FIFO entry

    // [BRAM-FLUSH] Generate a one-cycle flush pulse when FSM transitions to
    // dec-ready (0x5A), clearing any leftover entries from a previous run.
    reg fsm_5A_prev_top;
    wire fifo_flush_w = (uart_fsm_state_w == 8'h5A) && !fsm_5A_prev_top;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n) fsm_5A_prev_top <= 1'b0;
        else            fsm_5A_prev_top <= (uart_fsm_state_w == 8'h5A);
    end

    // [BRAM-WRITE] Write on ascon_done only for decrypt frames (dec_override=1).
    // spi_dec_override_r is registered at spi_start_d1 and is stable here.
    wire fifo_wr_en_w = ascon_done_w & spi_dec_override_r;

    bram_fifo_dec #(
        .DEPTH (16),
        .ADDR_W(4)
    ) bram_fifo_inst (
        .clk          (clk),
        .rst_n        (rst_int_n),
        .wr_en        (fifo_wr_en_w),
        .wr_data      (ascon_pt_dec_w),
        .wr_tag_match (ascon_tag_match_w),
        .rd_en        (fifo_rd_en_w),
        .rd_data      (fifo_rd_data),
        .rd_tag_match (fifo_rd_tag_match_w),
        .fifo_not_empty(fifo_not_empty_w),
        .fifo_full    (),
        .flush        (fifo_flush_w)
    );

    //=========================================================================
    // ASCON-128 CORE WIRES
    //=========================================================================
    wire [127:0] key_w, nonce_w;
    wire [63:0]  aad_w;
    wire [511:0] pt_w;
    wire         ascon_start_w;
    wire         ascon_done_w;
    wire         ascon_tag_match_w;
    wire [511:0] ascon_ct_w, ascon_pt_dec_w;
    wire [127:0] ascon_tag_w;
    wire [6:0]   pt_len_bytes_w;
    wire         dec_tag_override_w;
    wire [127:0] dec_tag_in_w;

    //=========================================================================
    // ASCON-128 CORE
    //=========================================================================
    ascon128_complete_uart ascon_core (
        .clk              (clk),
        .rst_n            (rst_int_n),
        .start            (ascon_start_w),
        .key              (key_w),
        .nonce            (nonce_w),
        .aad_padded       (aad_w),
        .pt_padded        (pt_w),
        .pt_len_bytes     (pt_len_bytes_w),
        .dec_tag_override (dec_tag_override_w),
        .dec_tag_in       (dec_tag_in_w),
        .ciphertext       (ascon_ct_w),
        .tag_out          (ascon_tag_w),
        .plaintext_dec    (ascon_pt_dec_w),
        .done             (ascon_done_w),
        .tag_match        (ascon_tag_match_w),
        .session_done     (session_done)
    );

    //=========================================================================
    // SPI SLAVE
    //=========================================================================
    wire [127:0] spi_key_out, spi_nonce_out;
    wire [511:0] spi_payload_out;
    wire [6:0]   spi_payload_len;
    wire         spi_frame_valid;
    wire         spi_dec_override;
    wire [127:0] spi_dec_tag;
    wire [7:0]   spi_frame_type_w;

    // [T1] uart_fsm_state wire from UART controller to SPI slave
    wire [7:0]   uart_fsm_state_w;

    // [T2] audio_key_out wire - key typed in PuTTY, delivered to ESP32
    //      via MISO poll bytes 0..15, and now also used as the ASCON key
    //      for audio-decrypt frames. [FIX-KEY-DEC]
    wire [127:0] audio_key_w;

    // [BUG1-FIX] total_chunks from ESP32 via SPI bytes[114-115] (10-bit, up to 1023)
    wire [9:0]   spi_total_chunks_w;

    // nonce_snap must be declared before the SPI instance port connection.
    reg [127:0] nonce_snap;

    // [FIX-NONCE-LATCH] nonce_used latched at spi_start_pulse - declared here,
    // driven by the always block below (after spi_start_pulse is defined).
    reg [127:0] nonce_used;

    spi_slave_audio spi_inst (
        .clk            (clk),
        .rst_n          (rst_int_n),
        .spi_sclk       (spi_sclk),
        .spi_mosi       (spi_mosi),
        .spi_miso       (spi_miso),
        .spi_cs_n       (spi_cs_n),
        .key_out        (spi_key_out),
        .nonce_out      (spi_nonce_out),
        .payload_out    (spi_payload_out),
        .payload_len    (spi_payload_len),
        .dec_override   (spi_dec_override),
        .dec_tag_out    (spi_dec_tag),
        .frame_valid    (spi_frame_valid),
        .frame_type_out (spi_frame_type_w),
        .ct_in          (ascon_ct_w),
        .tag_in         (ascon_tag_w),
        .ascon_done     (ascon_done_w),
        .trng_nonce_in  (nonce_used),
        .pt_dec_in      (ascon_pt_dec_w),
        .tag_match_in   (ascon_tag_match_w),
        .uart_fsm_state (uart_fsm_state_w),
        .audio_key_out  (audio_key_w),
        .total_chunks_out (spi_total_chunks_w),
        // [BRAM-DECRYPT] BRAM FIFO connections (now active)
        .fifo_rd_data      (fifo_rd_data),
        .fifo_rd_en        (fifo_rd_en_w),
        .fifo_not_empty    (fifo_not_empty_w),
        .fifo_rd_tag_match (fifo_rd_tag_match_w)
    );

    //=========================================================================
    // FIX-5 + FIX-12 + FIX-TYPLAG: one-shot start pulse with 2-cycle pipeline.
    //
    // Root-cause timing bug fixed here:
    //   frame_valid and frame_type_out are both registered in spi_slave_audio.v
    //   in separate always blocks using non-blocking assignments (<=).
    //   Because both blocks update on the same rising clock edge:
    //
    //     Cycle N:   frame_valid_r = 1 (end of SPI frame detected)
    //     Cycle N+1: frame_valid   = 1   (frame_valid block fires)
    //                frame_type_out = 0x00 STILL (parse block's `if (frame_valid)`
    //                                sees the OLD frame_valid=0 pre-assignment value,
    //                                so it does NOT latch rx_buf yet)
    //     Cycle N+2: frame_valid   = 1   (still high, fv_stretch running)
    //                frame_type_out = 0x01 NOW valid (parse block saw frame_valid=1)
    //
    //   With the OLD one-register spi_fv_prev:
    //     N+1: spi_real_frame = frame_valid(1) & (frame_type_out(0x00)!=0) = 0
    //          spi_start_pulse_raw = 0 & ~0 = 0  (no start)
    //     N+2: spi_real_frame = frame_valid(1) & (frame_type_out(0x01)!=0) = 1
    //          spi_fv_prev = 1 (was frame_valid at N+1)
    //          spi_start_pulse_raw = 1 & ~1 = 0  (edge already consumed!)
    //   → ASCON never starts, tx_ready stays 0, every poll returns sentinel=0x00.
    //
    //   Fix: add a second register stage (spi_fv_prev2) so the one-shot fires
    //   at cycle N+2 when frame_type_out IS valid:
    //     N+1: spi_fv_prev  = 0 (prev of frame_valid at N)
    //          spi_fv_prev2 = 0 (prev of spi_fv_prev)
    //     N+2: spi_real_frame = 1 & (0x01!=0) = 1
    //          spi_fv_prev2 = 0 (was spi_fv_prev at N+1 = 0)
    //          spi_start_pulse_raw = 1 & ~0 = 1  ← ASCON starts ✓
    //     N+3: spi_fv_prev2 = 1 → one-shot deasserts ✓
    //=========================================================================
    reg spi_fv_prev, spi_fv_prev2;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n) begin
            spi_fv_prev  <= 1'b0;
            spi_fv_prev2 <= 1'b0;
        end else begin
            spi_fv_prev  <= spi_frame_valid;
            spi_fv_prev2 <= spi_fv_prev;
        end
    end

    wire spi_real_frame      = spi_frame_valid & (spi_frame_type_w != 8'h00);
    wire spi_start_pulse_raw = spi_real_frame_ascon & ~spi_fv_prev2;

    reg spi_start_d1, spi_start_d2;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n) begin
            spi_start_d1 <= 1'b0;
            spi_start_d2 <= 1'b0;
        end else begin
            spi_start_d1 <= spi_start_pulse_raw;
            spi_start_d2 <= spi_start_d1;
        end
    end
    wire spi_start_pulse = spi_start_d2;

    //=========================================================================
    // [FIX-DECMODE2] Registered copy of spi_dec_override.
    //
    // spi_dec_override is a combinational output of the SPI slave parse block.
    // It is evaluated from rx_buf inside `if (frame_valid)` which is a
    // 200-cycle stretched signal.  A poll frame arriving between the one-shot
    // spi_start_pulse_raw and the registered spi_start_d2 could flip
    // spi_dec_override from 1 (decrypt) back to 0 (encrypt), causing the
    // input mux to feed wrong key / nonce / dec_tag_override to the ASCON
    // core on its start cycle.
    //
    // Fix: capture spi_dec_override into spi_dec_override_r at spi_start_d1
    // (one cycle before ascon_start_w fires).  All mux signals use
    // spi_dec_override_r - stable and consistent with the frame that
    // triggered the start pulse.
    //=========================================================================
    reg spi_dec_override_r;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)
            spi_dec_override_r <= 1'b0;
        else if (spi_start_d1)
            spi_dec_override_r <= spi_dec_override;
    end

    //=========================================================================
    // NONCE SNAPSHOT
    // Captured on spi_start_d1 (1 cycle BEFORE spi_start_pulse = ascon_start_w)
    // so that ASCON latches the correct TRNG value.
    // Gated to type-0x01 (encrypt) frames only.
    // [BUG3-FIX] Guard with trng_valid to prevent capturing stale LFSR mid-warmup.
    //=========================================================================
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)
            nonce_snap <= 128'd0;
        else if (spi_start_d1 && (spi_frame_type_w == 8'h01) && trng_valid)
            nonce_snap <= trng_nonce;
    end

    //=========================================================================
    // NONCE USED LATCH  [FIX-NONCE-LATCH]
    //
    // Root cause of decrypt tag mismatch:
    //   tx_latch (inside spi_slave_audio) stores trng_nonce_in at ascon_done.
    //   trng_nonce_in was wired directly to nonce_snap - a register that is
    //   overwritten by the NEXT chunk's spi_start_d1.  In the streaming
    //   pipeline the timing is safe (ASCON finishes in ~4 µs, next chunk
    //   arrives in ~4 ms), but the wiring creates a fragile assumption.
    //
    //   More importantly, nonce_w for encrypt is:
    //     nonce_w = spi_real_frame & !spi_dec_override ? nonce_snap : ...
    //   nonce_snap is captured at spi_start_d1 (N+3).
    //   ASCON latches nonce_lat at spi_start_pulse = spi_start_d2 (N+4).
    //   Both read nonce_snap - consistent.  BUT: trng_nonce_in sent to
    //   spi_slave_audio is the live nonce_snap wire, not a held copy.
    //
    //   Fix: latch nonce_snap into nonce_used at spi_start_pulse - the exact
    //   cycle ASCON latches nonce_lat.  Feed nonce_used (not nonce_snap) as
    //   trng_nonce_in so tx_latch always stores the nonce ASCON actually used.
    //=========================================================================
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)
            nonce_used <= 128'd0;
        else if (spi_start_pulse && !spi_dec_override_r)
            nonce_used <= nonce_snap;
    end

    //=========================================================================
    // UART CONTROLLER
    //=========================================================================
    wire [127:0] uart_key_out, uart_nonce_out;
    wire [63:0]  uart_aad_out;
    wire [511:0] uart_pt_out;
    wire [6:0]   uart_pt_len;
    wire         uart_ascon_start;
    wire         uart_dec_override;
    wire [127:0] uart_dec_tag;
    wire         led_waiting_w, led_computing_w;

    // [FIX-TYPLAG] spi_audio_frame: type-0x01 one-shot pulse, timing-corrected.
    // [FIX-SPURIOUS-ENC] Gate on uart_fsm_state==0xA5: only notify the UART FSM
    // of an audio-encrypt frame when the FPGA is actually armed for encryption.
    // Without this gate, any type-0x01 SPI frame arriving while the FPGA is
    // idle sets spi_audio_seen and advances the FSM into S_AUD_ENC_LAUNCH.
    wire spi_audio_frame_in_w = spi_start_pulse_raw
                                & (spi_frame_type_w == 8'h01)
                                & (uart_fsm_state_w == 8'hA5);

    // [ALTC-CMD04] cmd 0x04 (FIFO read) must NOT trigger an ASCON start.
    // Gate spi_real_frame to exclude frame_type 0x04.
    wire spi_real_frame_ascon = spi_frame_valid & (spi_frame_type_w != 8'h00)
                                                & (spi_frame_type_w != 8'h04);

    uart_controller_menu #(
        .CLK_FREQ (100_000_000),
        .BAUD_RATE(115_200)
    ) uart_ctrl (
        .clk                  (clk),
        .rst_n                (rst_int_n),
        .uart_rx_pin          (uart_rx),
        .uart_tx_pin          (uart_tx),
        .trng_nonce           (trng_nonce),
        .trng_valid           (trng_valid),
        .key_out              (uart_key_out),
        .nonce_out            (uart_nonce_out),
        .aad_out              (uart_aad_out),
        .pt_out               (uart_pt_out),
        .ascon_start          (uart_ascon_start),
        .ascon_done           (ascon_done_w),
        .ascon_tag_match      (ascon_tag_match_w),
        .ascon_ct             (ascon_ct_w),
        .ascon_tag            (ascon_tag_w),
        .ascon_pt_dec         (ascon_pt_dec_w),
        .pt_len_bytes_out     (uart_pt_len),
        .dec_tag_override_out (uart_dec_override),
        .dec_tag_in_out       (uart_dec_tag),
        .spi_frame_valid      (spi_frame_valid),
        .spi_frame_type       (spi_frame_type_w),
        .spi_audio_frame_in   (spi_audio_frame_in_w),
        .uart_fsm_state       (uart_fsm_state_w),
        .audio_key_out        (audio_key_w),
        .total_chunks_in      (spi_total_chunks_w),
        // [FIX-DECWIRE] Connect debug ports for per-chunk decrypt print.
        // Previously unconnected → Vivado tied to 0 → DDG prints showed 0x00.
        .spi_ct_dbg           (spi_payload_out),
        .spi_nonce_dbg        (spi_nonce_out),
        .spi_tag_dbg          (spi_dec_tag),
        .led_waiting          (led_waiting_w),
        .led_computing        (led_computing_w)
    );

    //=========================================================================
    // INPUT MUX
    //
    // [FIX-KEY-DEC] is_audio_dec identifies audio-decrypt SPI frames.
    //   For these frames the ASCON key must be audio_key_w (PuTTY [4] key),
    //   NOT spi_key_out (the ESP32's mirrored active_key).
    //
    // [FIX-DECMODE2] Use spi_dec_override_r (registered at spi_start_d1)
    //   instead of the combinational spi_dec_override wire throughout the mux.
    //   This prevents a poll frame arriving between spi_start_pulse_raw and
    //   spi_start_d2 from flipping the mux sel at the exact ASCON start cycle.
    //
    // [FIX-KEY-STABLE] audio_key_w (uart_ctrl.audio_key_out) is written by a
    //   non-blocking assignment on the same clock edge that rx_state transitions
    //   to S_AUD_DEC_PR_COMP.  The updated value is not visible until the NEXT
    //   clock cycle.  If the ESP32 fires a 0x02 frame the instant 0x5A appears
    //   on the poll line it can race against audio_key_w still propagating,
    //   causing ASCON to use a stale encrypt-session key → tag mismatch on
    //   early chunks.
    //
    //   Fix: capture audio_key_w into audio_key_stable on the RISING EDGE of
    //   uart_fsm_state==0x5A.  At that cycle S_AUD_DEC_PR_COMP has already
    //   been entered (rx_state left S_AUD_DEC_RD_KEY, which drove fsm=0x00),
    //   so audio_key_out is fully settled.  All 0x02 decrypt frames then use
    //   audio_key_stable - a registered, glitch-free copy.
    //=========================================================================
    reg  [127:0] audio_key_stable;
    reg          fsm_5A_prev;

    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n) begin
            audio_key_stable <= 128'd0;
            fsm_5A_prev      <= 1'b0;
        end else begin
            fsm_5A_prev <= (uart_fsm_state_w == 8'h5A);
            // [FIX-KEYSTABLE] Capture audio_key_w on the FSM 0x5A rising edge
            // (as before) so the key is ready before the first 0x02 frame.
            // ALSO re-capture on every spi_start_d1 for a decrypt frame, so that
            // if audio_key_w is ever re-written mid-session (e.g. user re-enters
            // key) each chunk uses the key that was current at its dispatch cycle.
            if ((uart_fsm_state_w == 8'h5A) && !fsm_5A_prev)
                audio_key_stable <= audio_key_w;
            else if (spi_start_d1 && spi_dec_override)
                audio_key_stable <= audio_key_w;
        end
    end

    wire is_audio_dec = spi_real_frame & spi_dec_override_r; // type-0x02 frames

    assign key_w = spi_real_frame
                       ? (is_audio_dec ? audio_key_stable : spi_key_out)
                       : uart_key_out;

    assign nonce_w = spi_real_frame
                         ? (spi_dec_override_r ? spi_nonce_out : nonce_snap)
                         : uart_nonce_out;

    assign aad_w             = spi_real_frame ? 64'h8000000000000000 : uart_aad_out;
    assign pt_w              = spi_real_frame ? spi_payload_out      : uart_pt_out;
    assign pt_len_bytes_w    = spi_real_frame ? spi_payload_len      : uart_pt_len;
    assign dec_tag_override_w= spi_real_frame ? spi_dec_override_r   : uart_dec_override;
    assign dec_tag_in_w      = spi_real_frame ? spi_dec_tag          : uart_dec_tag;

    // [BUG3-FIX] For encrypt frames stall start if TRNG not yet valid.
    // Decrypt frames (dec_override=1) don't use the TRNG, pass through.
    //
    // [FIX-ASCON-START-GATE] CRITICAL: also gate on uart_fsm_state so the
    // ASCON core can only be started by SPI frames when the UART FSM has
    // actually armed it.
    //   - Encrypt (type 0x01, dec_override=0): require uart_fsm_state==0xA5.
    //     Without this gate every type-0x01 SPI frame fires ASCON regardless
    //     of whether the user has pressed [3] and entered a key in PuTTY,
    //     causing continuous encryption the moment 0xA5 is first polled.
    //   - Decrypt (type 0x02, dec_override=1): require uart_fsm_state==0x5A.
    //     Same issue on the decrypt side.
    wire spi_fsm_armed = spi_dec_override_r ? (uart_fsm_state_w == 8'h5A)
                                             : (uart_fsm_state_w == 8'hA5);

    // [FIX-BUSY-V2] ascon_busy_r: set by ascon_start_w, cleared by ascon_done_w.
    // This is the CORRECT place to implement the busy guard - both signals are
    // already defined in this module.  The previous version set busy on
    // frame_valid_r (inside spi_slave_audio) which fired 2 cycles BEFORE
    // spi_start_pulse_gated, so it blocked the very start pulse it needed to
    // allow.  That caused a permanent deadlock: ASCON never started → done
    // never fired → busy never cleared → FIFO never filled.
    //
    // Correct timing:
    //   ascon_start_w=1 (cycle N)   → ascon_busy_r <= 1  (cycle N+1)
    //   ascon_done_w=1  (cycle N+K) → ascon_busy_r <= 0  (cycle N+K+1)
    //
    // The gate below suppresses the start pulse for the NEXT 0x02 frame while
    // busy=1.  Since the ESP32 now serializes (waits for FIFO before sending
    // the next chunk), this guard only fires if the ESP32 sends a second frame
    // before the FPGA finishes - belt-and-suspenders protection.
    reg ascon_busy_r;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)
            ascon_busy_r <= 1'b0;
        else if (ascon_start_w && spi_dec_override_r)
            ascon_busy_r <= 1'b1;
        else if (ascon_done_w)
            ascon_busy_r <= 1'b0;
    end

    // [FIX-BUSY-V2] Also block a new decrypt start while ascon_busy_r=1.
    wire spi_start_pulse_gated = spi_start_pulse
                                 && (spi_dec_override_r || trng_valid)
                                 && spi_fsm_armed
                                 && !(spi_dec_override_r && ascon_busy_r);

    assign ascon_start_w     = spi_real_frame ? spi_start_pulse_gated : uart_ascon_start;

    //=========================================================================
    // LED DRIVER
    //=========================================================================
    reg running_r;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)         running_r <= 1'b0;
        else if (ascon_start_w) running_r <= 1'b1;
        else if (ascon_done_w)  running_r <= 1'b0;
    end

    // [OPT2] FIFO-write counter removed; decrypt counter retained for debug.
    (* keep = "true" *) reg [31:0] decrypt_counter;
    always @(posedge clk or negedge rst_int_n) begin
        if (!rst_int_n)
            decrypt_counter <= 32'd0;
        else if (ascon_start_w)
            decrypt_counter <= decrypt_counter + 32'd1;
    end

    assign led_done      = ascon_done_w;
    assign led_tag_match = ascon_done_w &  ascon_tag_match_w;
    assign led_running   = running_r;
    assign led_error     = ascon_done_w & ~ascon_tag_match_w;
    assign led_waiting   = led_waiting_w;
    assign led_computing = led_computing_w;

endmodule