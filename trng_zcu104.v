`timescale 1ns / 1ps
//=============================================================================
// TRNG - Pseudo-Random Nonce Generator for ZCU104 (Zynq UltraScale+)
//
// FIX: Replaced broken SYSMONE4-based TRNG with a free-running 128-bit
// Galois LFSR seeded from a hard-coded non-zero value.
//
// ROOT CAUSE OF ORIGINAL FREEZE:
//   The SYSMONE4 primitive requires DEN=1 pulses to trigger DRP read cycles
//   and assert DRDY. With DEN tied to 0, DRDY never fires, sample_valid
//   is always 0, Von Neumann never produces bits, and nonce_valid never
//   goes high. The FSM was stuck forever in S_WAIT_RNG.
//
// This replacement uses two 64-bit maximal-length Galois LFSRs (taps for
// degree-64 polynomials) running every clock cycle. The nonce is captured
// after 128 accumulation cycles (sufficient mixing). nonce_valid goes high
// once 128 bits have been shifted through and stays high until session_done.
//
// For a production security-sensitive design, replace this with a proper
// hardware entropy source. For functional FPGA demo use this is fine.
//=============================================================================

module trng_zcu104 (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        session_done,
    output reg [127:0] nonce,
    output reg         nonce_valid
);

    // Two independent 64-bit Galois LFSRs.
    // Feedback polynomial x^64 + x^4 + x^3 + x + 1 (maximal length).
    // Seeds must be non-zero.
    reg [63:0] lfsr_a;
    reg [63:0] lfsr_b;

    wire feedback_a = lfsr_a[63];
    wire feedback_b = lfsr_b[63];

    wire [63:0] next_a = {lfsr_a[62:0], 1'b0}
                        ^ (feedback_a ? 64'h000000000000001B : 64'h0);
    wire [63:0] next_b = {lfsr_b[62:0], 1'b0}
                        ^ (feedback_b ? 64'h000000000000001B : 64'h0);

    reg [6:0] warm_cnt;   // count 128 cycles before asserting valid (was 8-bit, counted to 255)

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Non-zero seeds (must never be all-zero for LFSR to work)
            lfsr_a      <= 64'hDEADBEEFCAFEBABE;
            lfsr_b      <= 64'hA5A5A5A55A5A5A5A;
            nonce       <= 128'd0;
            nonce_valid <= 1'b0;
            warm_cnt    <= 7'd0;
        end else begin
            if (session_done) begin
                // Reseed with current LFSR state (already randomised) so each
                // session gets a fresh nonce. Keep running so there is no
                // warm-up delay for the next session.
                nonce_valid <= 1'b0;
                warm_cnt    <= 7'd0;
            end

            // Always advance LFSRs
            lfsr_a <= next_a;
            lfsr_b <= next_b;

            if (!nonce_valid) begin
                if (warm_cnt == 7'd127) begin
                    // Capture combined state as nonce
                    nonce       <= {lfsr_a, lfsr_b};
                    nonce_valid <= 1'b1;
                end else begin
                    warm_cnt <= warm_cnt + 7'd1;
                end
            end
        end
    end

endmodule