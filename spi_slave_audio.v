`timescale 1ns / 1ps
//=============================================================================
// SPI Slave - Audio / Text Frame Receiver for ZCU104
//
// BRAM-DECRYPT MODIFICATIONS
// ──────────────────────────
// [BRAM-RD] cmd 0x04 (FIFO read) path restored.
//   On a cmd-0x04 frame the slave:
//     1. Asserts fifo_rd_en for one cycle to dequeue the head entry.
//     2. Loads tx_latch from {fifo_rd_data, 0xA5, tag_verdict, 0, 0} one
//        cycle later (BRAM read latency = 1 cycle).
//   This keeps the same MISO layout as the direct-decrypt path so the
//   ESP32's retrieveResult() poll loop works unchanged.
//
// [BRAM-POLL] fifo_not_empty is embedded in poll-frame MISO byte[97]
//   (bit position 904 - 97*8 - 1 = 127 in the 904-bit tx_shift, counting
//   from MSB=bit903).  Actually byte[97] is at bits [55:48] of the
//   poll_frame_w 904-bit vector - see layout below.
//
// [BRAM-TAGVERD] rd_tag_match from the FIFO is latched one cycle after
//   fifo_rd_en fires, then used to build the tag-verdict field in tx_latch.
//
// ALL PRIOR FIXES RETAINED UNCHANGED.
//=============================================================================

module spi_slave_audio #(
    parameter FRAME_BYTES = 256
)(
    input  wire        clk,
    input  wire        rst_n,

    // SPI interface
    input  wire        spi_sclk,
    input  wire        spi_mosi,
    output reg         spi_miso,
    input  wire        spi_cs_n,

    // Parsed frame outputs (sys_clk domain)
    output reg  [127:0] key_out,
    output reg  [127:0] nonce_out,
    output reg  [511:0] payload_out,
    output reg  [6:0]   payload_len,
    output reg          dec_override,
    output reg  [127:0] dec_tag_out,
    output reg          frame_valid,
    output reg  [7:0]   frame_type_out,

    // ASCON result inputs (sys_clk domain)
    input  wire [511:0] ct_in,
    input  wire [127:0] tag_in,
    input  wire         ascon_done,
    input  wire [127:0] trng_nonce_in,
    input  wire [511:0] pt_dec_in,
    input  wire         tag_match_in,

    // UART FSM state for ESP32 polling on dummy frames
    input  wire [7:0]   uart_fsm_state,

    // Audio key from PuTTY - embedded in MISO poll bytes 0..15
    input  wire [127:0] audio_key_out,

    // Total chunk count from ESP32 in RX bytes[114-115] (10-bit, up to 1023 chunks)
    output reg  [9:0]   total_chunks_out,

    // FIFO ports - now ACTIVE for BRAM-decrypt path
    input  wire [511:0] fifo_rd_data,      // plaintext from BRAM FIFO
    output reg          fifo_rd_en,        // dequeue pulse (1 cycle)
    input  wire         fifo_not_empty,    // FIFO status for MISO poll byte[97]
    input  wire         fifo_rd_tag_match  // tag-match verdict from FIFO (valid 1 cycle after rd_en)
);

    //=========================================================================
    // 3-FF CDC synchronisers
    //=========================================================================
    (* ASYNC_REG = "TRUE" *) reg sclk_s0, sclk_s1, sclk_s2;
    (* ASYNC_REG = "TRUE" *) reg cs_s0,   cs_s1,   cs_s2;
    (* ASYNC_REG = "TRUE" *) reg mosi_s0, mosi_s1, mosi_s2;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sclk_s0 <= 1'b0; sclk_s1 <= 1'b0; sclk_s2 <= 1'b0;
            cs_s0   <= 1'b1; cs_s1   <= 1'b1; cs_s2   <= 1'b1;
            mosi_s0 <= 1'b0; mosi_s1 <= 1'b0; mosi_s2 <= 1'b0;
        end else begin
            sclk_s0 <= spi_sclk; sclk_s1 <= sclk_s0; sclk_s2 <= sclk_s1;
            cs_s0   <= spi_cs_n; cs_s1   <= cs_s0;   cs_s2   <= cs_s1;
            mosi_s0 <= spi_mosi; mosi_s1 <= mosi_s0; mosi_s2 <= mosi_s1;
        end
    end

    wire sclk_rise = ( sclk_s1 & ~sclk_s2);
    wire sclk_fall = (~sclk_s1 &  sclk_s2);
    wire cs_active = ~cs_s2;
    wire cs_fall   = (~cs_s2 &  cs_s1);
    wire cs_rise   = ( cs_s2 & ~cs_s1);

    //=========================================================================
    // RX shift register, byte counter and frame buffer
    //=========================================================================
    localparam FRAME_BITS = FRAME_BYTES * 8;

    reg [7:0]    shift_reg;
    reg [2:0]    bit_cnt;
    reg [7:0]    byte_cnt;
    reg [2047:0] rx_buf;

    wire [7:0] current_byte = {shift_reg[6:0], mosi_s2};
    reg        frame_valid_r;
    reg [7:0]  fv_stretch;
    reg [7:0]  rx_byte0;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            shift_reg     <= 8'h00;
            bit_cnt       <= 3'd0;
            byte_cnt      <= 8'd0;
            rx_buf        <= {FRAME_BITS{1'b0}};
            frame_valid   <= 1'b0;
            frame_valid_r <= 1'b0;
            fv_stretch    <= 8'd0;
            rx_byte0      <= 8'h00;
        end else begin
            if (frame_valid_r) begin
                fv_stretch    <= 8'd200;
                frame_valid_r <= 1'b0;
                frame_valid   <= 1'b1;
            end else if (fv_stretch != 8'd0) begin
                fv_stretch  <= fv_stretch - 8'd1;
                frame_valid <= 1'b1;
            end else begin
                frame_valid <= 1'b0;
            end

            if (!cs_active) begin
                bit_cnt  <= 3'd0;
                byte_cnt <= 8'd0;
            end else if (sclk_rise) begin
                shift_reg <= {shift_reg[6:0], mosi_s2};
                if (bit_cnt == 3'd7) begin
                    rx_buf[(FRAME_BYTES-1-byte_cnt)*8 +: 8] <= current_byte;
                    bit_cnt <= 3'd0;

                    if (byte_cnt == 8'd0)
                        rx_byte0 <= current_byte;
                    if (byte_cnt == FRAME_BYTES-1) begin
                        if (rx_byte0 != 8'h00)
                            frame_valid_r <= 1'b1;
                        byte_cnt <= 8'd0;
                    end else begin
                        byte_cnt <= byte_cnt + 8'd1;
                    end
                end else begin
                    bit_cnt <= bit_cnt + 3'd1;
                end
            end
        end
    end

    reg frame_valid_d;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) frame_valid_d <= 1'b0;
        else        frame_valid_d <= frame_valid;
    end
    wire frame_valid_rise = frame_valid & ~frame_valid_d;

    //=========================================================================
    // RX frame parse
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            frame_type_out   <= 8'h00;
            key_out          <= 128'h0;
            nonce_out        <= 128'h0;
            dec_tag_out      <= 128'h0;
            payload_len      <= 7'h0;
            payload_out      <= 512'h0;
            dec_override     <= 1'b0;
            total_chunks_out <= 10'h0;
        end else if (frame_valid_rise) begin
            frame_type_out   <= rx_buf[2047:2040];
            key_out          <= rx_buf[2039:1912];
            nonce_out        <= rx_buf[1911:1784];
            dec_tag_out      <= rx_buf[1783:1656];
            payload_len      <= rx_buf[1655:1648];
            payload_out      <= rx_buf[1647:1136];
            dec_override     <= (rx_buf[2047:2040] == 8'h02);
            // [BUG1-FIX] Read 10-bit chunk count from bytes 114 (LSB) + 115 [1:0] (MSB).
            // Accept from type-0x01 (encrypt per-chunk) AND type-0x05 (EOS frame).
            // The 0x05 frame carries the authoritative final count; 0x01 frames carry
            // the running count.  Guard against the 0xFF placeholder: the ESP32 now
            // sends 0 during recording and the real count in the EOS frame.
            if (rx_buf[2047:2040] == 8'h01 || rx_buf[2047:2040] == 8'h05)
                total_chunks_out <= { rx_buf[1121:1120], rx_buf[1135:1128] };
        end
    end

    //=========================================================================
    // POLL FRAME MISO layout (904 bits = 113 bytes sent LSB-frame first)
    //
    // Byte offset in MISO (ESP32 perspective, 0-indexed):
    //   [0-15]   audio_key_out   (128 bits)
    //   [16-63]  zero            (384 bits)
    //   [64]     zero            sentinel = 0x00 for poll
    //   [65-95]  zero
    //   [96]     uart_fsm_state  (8 bits)
    //   [97]     fifo_not_empty  packed into bit[0] of this byte
    //   [98-112] zero
    //
    // tx_shift is 904 bits.  Bit[903] = MISO byte[0] MSB.
    // Byte N occupies bits [903-N*8 : 896-N*8].
    // Byte 97 occupies bits [903-97*8 : 896-97*8] = [127 : 120].  Wait:
    //   903 - 97*8 = 903 - 776 = 127  → bits [127:120] = byte 97.
    //   We put fifo_not_empty in bit[127] (MSB of byte 97).
    //
    // Byte 96 (uart_fsm_state) = bits [135:128].
    // Byte 64 (sentinel 0x00)  = bits [391:384].
    //=========================================================================
    wire [903:0] poll_frame_w = {
        audio_key_out,                              // bytes 0-15   [903:776]
        384'd0,                                     // bytes 16-63  [775:392]
        8'h00,                                      // byte  64     [391:384]  sentinel=0
        248'd0,                                     // bytes 65-95  [383:136]
        uart_fsm_state,                             // byte  96     [135:128]
        {fifo_not_empty, 7'd0},                     // byte  97     [127:120]  MSB=fifo flag
        120'd0                                      // bytes 98-112 [119:0]
    };

    //=========================================================================
    // TX shift register / MISO path
    //=========================================================================
    reg [903:0] tx_latch;
    reg [903:0] tx_serve;
    reg [903:0] tx_shift;
    reg         tx_ready;
    reg         tx_ready_d;
    reg         tx_ready_prev;
    reg         dec_override_lat;
    reg         dec_mode_for_tx;

    // [BRAM-RD] State machine for cmd-0x04 FIFO read.
    // When frame_valid_rise fires for a 0x04 frame:
    //   Cycle N  : frame_valid_rise=1 → set fifo_rd_en, go to FIFO_WAIT
    //   Cycle N+1: BRAM output valid  → build tx_latch, set tx_ready
    //   Cycle N+2: tx_ready_prev detects rising edge → tx_serve = tx_latch
    reg        fifo_rd_pending;   // 0x04 frame seen, waiting 1 cycle for BRAM
    reg        fifo_tag_lat;      // latched tag_match one cycle after rd_en

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_latch         <= 904'd0;
            tx_serve         <= 904'd0;
            tx_shift         <= 904'd0;
            tx_ready         <= 1'b0;
            tx_ready_d       <= 1'b0;
            tx_ready_prev    <= 1'b0;
            dec_override_lat <= 1'b0;
            dec_mode_for_tx  <= 1'b0;
            spi_miso         <= 1'b0;
            fifo_rd_en       <= 1'b0;
            fifo_rd_pending  <= 1'b0;
            fifo_tag_lat     <= 1'b0;
        end else begin

            // Pipeline tx_ready by one cycle [FIX-MSB-RACE]
            tx_ready_d <= tx_ready;

            // Capture tx_latch → tx_serve on rising edge of tx_ready [FIX-MSB-RACE]
            tx_ready_prev <= tx_ready;
            if (tx_ready && !tx_ready_prev)
                tx_serve <= tx_latch;

            // Default: deassert single-cycle pulses
            fifo_rd_en <= 1'b0;

            // ── Frame type latch ──────────────────────────────────────────────
            if (frame_valid_r) begin
                dec_override_lat <= (rx_buf[2047:2040] == 8'h02);
            end
            if (frame_valid_rise) begin
                dec_mode_for_tx <= (rx_buf[2047:2040] == 8'h02);
            end

            // ── ASCON done → build TX result (enc or direct-dec) ─────────────
            // [FIX-DECMODE-STALE] use dec_override_lat (stable, set at frame_valid_r)
            if (ascon_done) begin
                dec_mode_for_tx <= dec_override_lat;
                if (dec_override_lat) begin
                    // Direct decrypt: return PT in same transaction response
                    tx_latch <= {
                        pt_dec_in,
                        8'hA5,
                        tag_match_in
                            ? 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                            : 128'h00000000000000000000000000000000,
                        128'h0,
                        128'h0
                    };
                end else begin
                    // Encrypt result
                    tx_latch <= {
                        ct_in,
                        8'hA5,
                        tag_in,
                        trng_nonce_in,
                        audio_key_out
                    };
                end
                tx_ready <= 1'b1;
            end

            // ── [BRAM-RD] cmd 0x04: issue FIFO read, latch result next cycle ─
            if (frame_valid_rise && (rx_buf[2047:2040] == 8'h04)) begin
                if (fifo_not_empty) begin
                    fifo_rd_en      <= 1'b1;   // dequeue head (BRAM output valid next cycle)
                    fifo_rd_pending <= 1'b1;
                end
                // If FIFO empty, tx_ready stays 0 → ESP32 gets poll frame (sentinel=0x00)
            end

            // ── [BRAM-RD] One cycle after fifo_rd_en: BRAM data valid ─────────
            if (fifo_rd_pending) begin
                fifo_rd_pending <= 1'b0;
                fifo_tag_lat    <= fifo_rd_tag_match;
                tx_latch <= {
                    fifo_rd_data,           // bytes 0-63: plaintext
                    8'hA5,                  // byte 64: sentinel
                    fifo_rd_tag_match
                        ? 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                        : 128'h00000000000000000000000000000000,
                    128'h0,
                    128'h0
                };
                tx_ready <= 1'b1;
            end

            // ── SPI Transaction Start (cs_fall = CS going HIGH = end of frame) ─
            if (cs_fall) begin
                if (tx_ready_d) begin
                    tx_shift      <= tx_serve;
                    tx_ready      <= 1'b0;
                    tx_ready_prev <= 1'b0;
                end else begin
                    tx_shift <= poll_frame_w;
                end
            end
            // Drive MISO MSB at actual transaction start (cs_rise = CS going LOW)
            else if (cs_rise) begin
                spi_miso <= tx_shift[903];
            end
            // Sequential bit streaming
            else if (cs_active && sclk_fall) begin
                spi_miso <= tx_shift[902];
                tx_shift <= {tx_shift[902:0], 1'b0};
            end
            else if (!cs_active) begin
                spi_miso <= 1'b0;
            end
        end
    end

endmodule