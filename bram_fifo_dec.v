`timescale 1ns / 1ps
//=============================================================================
// bram_fifo_dec.v  -  BRAM FIFO for decrypt pipeline (ALTC / BRAM-DECRYPT)
//
// Architecture:
//   FPGA decrypts each chunk → writes 64-byte plaintext + tag_match here
//   on ascon_done (wr_en pulse from top level).
//   ESP32 polls MISO byte[97] = fifo_not_empty.
//   ESP32 sends cmd 0x04 (FIFO read) → spi_slave_audio dequeues one entry
//   and returns it in MISO[0-63] (PT) + MISO[65-80] (tag verdict).
//
// tag_match storage:
//   A parallel 1-bit array `tag_mem[]` shadows the main PT BRAM at the same
//   address, written together and read together.  This avoids widening the
//   BRAM to 513 bits (odd widths cost extra LUTs) while keeping tag_match
//   aligned with its plaintext block.
//
// Parameters:
//   DEPTH  - number of 64-byte slots (power of 2; 16 recommended for 3-s audio)
//   ADDR_W - log2(DEPTH)
//=============================================================================

module bram_fifo_dec #(
    parameter DEPTH  = 16,
    parameter ADDR_W = 4        // log2(DEPTH); update if DEPTH changes
)(
    input  wire         clk,
    input  wire         rst_n,

    // Write port - assert wr_en for 1 cycle with valid wr_data on ascon_done
    input  wire         wr_en,
    input  wire [511:0] wr_data,        // 64 bytes of plaintext from ASCON
    input  wire         wr_tag_match,   // tag-match verdict for this chunk

    // Read port - assert rd_en for 1 cycle; rd_data valid NEXT cycle
    input  wire         rd_en,
    output reg  [511:0] rd_data,
    output reg          rd_tag_match,   // tag-match verdict for read chunk

    // Status
    output wire         fifo_not_empty,
    output wire         fifo_full,

    // Flush - assert for 1 cycle to drain the FIFO at session start
    input  wire         flush
);

    //=========================================================================
    // BRAM storage: DEPTH × 512-bit plaintext
    //=========================================================================
    (* ram_style = "block" *) reg [511:0] mem     [0:DEPTH-1];
    reg                                   tag_mem [0:DEPTH-1];   // 1-bit companion

    reg [ADDR_W-1:0] wr_ptr;
    reg [ADDR_W-1:0] rd_ptr;
    reg [ADDR_W:0]   count;    // extra bit: distinguishes full (DEPTH) from empty (0)

    assign fifo_not_empty = (count != 0);
    assign fifo_full      = (count == DEPTH[ADDR_W:0]);

    //=========================================================================
    // Write / read / flush
    //=========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            wr_ptr      <= {ADDR_W{1'b0}};
            rd_ptr      <= {ADDR_W{1'b0}};
            count       <= {(ADDR_W+1){1'b0}};
            rd_data     <= 512'd0;
            rd_tag_match<= 1'b0;
        end else if (flush) begin
            wr_ptr  <= {ADDR_W{1'b0}};
            rd_ptr  <= {ADDR_W{1'b0}};
            count   <= {(ADDR_W+1){1'b0}};
        end else begin
            // Write (drop silently when full)
            if (wr_en && !fifo_full) begin
                mem    [wr_ptr] <= wr_data;
                tag_mem[wr_ptr] <= wr_tag_match;
                wr_ptr          <= wr_ptr + {{(ADDR_W-1){1'b0}}, 1'b1};
                count           <= count  + {{ADDR_W{1'b0}},     1'b1};
            end

            // Read (hold rd_data when empty)
            if (rd_en && fifo_not_empty) begin
                rd_data      <= mem    [rd_ptr];
                rd_tag_match <= tag_mem[rd_ptr];
                rd_ptr       <= rd_ptr + {{(ADDR_W-1){1'b0}}, 1'b1};
                count        <= count  - {{ADDR_W{1'b0}},     1'b1};
            end
        end
    end

endmodule